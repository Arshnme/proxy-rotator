"""Front-ends that your bot talks to.

 1. Reverse gateway  (default :8787) - point your bot's Gemini base URL here. Requests are
    buffered, sent through the best proxy, and transparently retried on other proxies when a
    proxy fails or Gemini says "User location is not supported".
 2. HTTP CONNECT proxy (default :8118) - for libraries that only support HTTPS_PROXY.
 3. SOCKS5 proxy       (default :1080) - same, for SOCKS clients.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import time
from typing import Optional, Tuple

import aiohttp
from aiohttp import web
from yarl import URL

from .pool import Pool, Proxy, Stats
from .util import redact

log = logging.getLogger("rotator.gw")

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
       "transfer-encoding", "upgrade", "host", "content-length"}
MAX_ERR_BODY = 1 << 20


def _gerr(code: int, status: str, msg: str) -> web.Response:
    body = json.dumps({"error": {"code": code, "message": msg, "status": status}})
    return web.Response(status=code, body=body.encode(), content_type="application/json")


def classify_response(status: int, ctype: str, body: bytes) -> str:
    """-> geo | hijack | throttle | retry | final"""
    low = body[:4096].lower()
    if b"location is not supported" in low or (b"user location" in low and b"not supported" in low):
        return "geo"
    if "text/html" in ctype:
        return "hijack"
    if status == 429:
        return "throttle"
    if status in (500, 502, 503, 504):
        return "retry"
    return "final"


def classify_exc(e: BaseException) -> str:
    if isinstance(e, (asyncio.TimeoutError, aiohttp.ServerTimeoutError)):
        return "timeout"
    if isinstance(e, (aiohttp.ClientSSLError, aiohttp.ClientConnectorCertificateError)):
        return "hijack"
    if isinstance(e, (aiohttp.ServerDisconnectedError, aiohttp.ClientPayloadError)):
        return "soft"
    if isinstance(e, aiohttp.ClientOSError) and not isinstance(e, aiohttp.ClientConnectorError):
        return "soft"
    return "conn"


# ----------------------------------------------------------------- socks client
async def socks5_connect(port: int, host: str, dport: int, timeout: float) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    async def go():
        r, w = await asyncio.open_connection("127.0.0.1", port, limit=1 << 16)
        try:
            try:
                ip = ipaddress.ip_address(host)
                addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
            except ValueError:
                hb = host.encode("idna")
                addr = b"\x03" + bytes([len(hb)]) + hb
            w.write(b"\x05\x01\x00" + b"\x05\x01\x00" + addr + dport.to_bytes(2, "big"))
            if await r.readexactly(2) != b"\x05\x00":
                raise ConnectionError("socks greeting rejected")
            hdr = await r.readexactly(4)
            if hdr[1] != 0:
                raise ConnectionError("socks reply %d" % hdr[1])
            n = {1: 4, 4: 16}.get(hdr[3])
            if n is None:
                n = (await r.readexactly(1))[0]
            await r.readexactly(n + 2)
            return r, w
        except BaseException:
            w.close()
            raise
    return await asyncio.wait_for(go(), timeout)


async def pump(r1, w1, r2, w2) -> None:
    async def cp(r, w):
        try:
            while True:
                d = await r.read(65536)
                if not d:
                    break
                w.write(d)
                await w.drain()
        except Exception:
            pass
    t1 = asyncio.ensure_future(cp(r1, w2))
    t2 = asyncio.ensure_future(cp(r2, w1))
    try:
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (t1, t2):
            t.cancel()
        for w in (w1, w2):
            try:
                w.close()
            except Exception:
                pass


class Gateway:
    def __init__(self, cfg: dict, pool: Pool, stats: Stats) -> None:
        self.cfg = cfg
        self.pool = pool
        self.stats = stats
        self._runner: Optional[web.AppRunner] = None
        self._servers = []
        self._direct: Optional[aiohttp.ClientSession] = None
        self._auth = (cfg.get("proxy_auth") or "").strip()

    # ============================================================ lifecycle
    async def start(self) -> None:
        c = self.cfg
        listen = c["listen"]
        app = web.Application(client_max_size=int(c.get("max_body_mb", 64)) * 1024 * 1024)
        app.router.add_route("*", "/{tail:.*}", self.reverse)
        try:
            self._runner = web.AppRunner(app, access_log=None, handler_cancellation=True, keepalive_timeout=75)
        except TypeError:
            self._runner = web.AppRunner(app, access_log=None, keepalive_timeout=75)
        await self._runner.setup()
        await web.TCPSite(self._runner, listen, int(c["gateway_port"]), backlog=4096).start()
        log.info("gateway   http://%s:%s   (reverse -> %s)", listen, c["gateway_port"], c["upstream"])
        if c.get("http_port"):
            self._servers.append(await asyncio.start_server(self.handle_http, listen, int(c["http_port"]), backlog=4096, limit=1 << 16))
            log.info("http proxy http://%s:%s   (CONNECT)", listen, c["http_port"])
        if c.get("socks_port"):
            self._servers.append(await asyncio.start_server(self.handle_socks, listen, int(c["socks_port"]), backlog=4096, limit=1 << 16))
            log.info("socks5    socks5://%s:%s", listen, c["socks_port"])

    async def stop(self) -> None:
        for s in self._servers:
            s.close()
        if self._runner:
            await self._runner.cleanup()
        if self._direct:
            await self._direct.close()

    # ============================================================ reverse gateway
    async def reverse(self, request: web.Request) -> web.StreamResponse:
        c = self.cfg
        if request.path == "/__rotator/health":
            n = len(self.pool.active())
            return web.json_response({"ok": n > 0, "active": n}, status=200 if n else 503)
        tok = c.get("access_token")
        if tok and request.headers.get("X-Rotator-Token") != tok:
            return _gerr(401, "UNAUTHENTICATED", "bad or missing X-Rotator-Token")
        t0 = time.perf_counter()
        st = self.stats
        st.inflight += 1
        st.hit()
        status = 0
        ok = False
        try:
            body = await request.read()
            resp = await self._forward(request, body, t0)
            status = resp.status
            ok = status < 400
            return resp
        except (asyncio.CancelledError, ConnectionResetError):
            status = 499
            raise
        except Exception as e:  # noqa
            log.exception("gateway error: %s", redact(str(e)))
            status = 500
            return _gerr(500, "INTERNAL", "gateway error")
        finally:
            st.inflight -= 1
            st.done(status, (time.perf_counter() - t0) * 1000.0, ok)

    async def _forward(self, request: web.Request, body: bytes, t0: float) -> web.StreamResponse:
        c = self.cfg
        pool = self.pool
        method = request.method
        url = URL(c["upstream"].rstrip("/") + request.raw_path, encoded=True)
        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in HOP and not k.lower().startswith("x-rotator-")}
        key = request.headers.get("x-goog-api-key") or request.query.get("key") or ""
        max_att = int(c.get("max_attempts", 4))
        timeout = aiohttp.ClientTimeout(total=None, connect=float(c.get("connect_timeout", 5)),
                                        sock_connect=float(c.get("connect_timeout", 5)),
                                        sock_read=float(c.get("read_timeout", 180)))
        tried: set = set()
        attempts = 0
        last: Optional[Tuple[int, dict, bytes, Proxy]] = None
        while attempts < max_att:
            p = await pool.acquire(tried, wait=float(c.get("queue_wait", 4)) if attempts == 0 else 0.0)
            if p is None:
                break
            attempts += 1
            tried.add(p.id)
            if attempts > 1:
                self.stats.retries += 1
            t1 = time.perf_counter()
            released = False
            try:
                try:
                    up = await p.session().request(method, url, data=body or None, headers=headers,
                                                   allow_redirects=False, timeout=timeout)
                except asyncio.CancelledError:
                    raise
                except Exception as e:  # noqa
                    pool.on_failure(p, classify_exc(e), "%s: %s" % (type(e).__name__, e))
                    continue
                ttfb = (time.perf_counter() - t1) * 1000.0
                ctype = up.headers.get("Content-Type", "")
                if up.status < 400 and "text/html" not in ctype:
                    if key and up.status < 300:
                        pool.learn_key(key)
                    pool.on_success(p, ttfb)
                    released = True
                    return await self._stream(request, up, p, attempts)
                # error-ish response: read it fully and decide
                try:
                    data = await up.content.read(MAX_ERR_BODY)
                except Exception:
                    data = b""
                finally:
                    up.release()
                verdict = classify_response(up.status, ctype, data)
                hdrs = {k: v for k, v in up.headers.items() if k.lower() not in HOP}
                if verdict == "geo":
                    pool.on_geo(p, "gemini says: location not supported")
                    last = (up.status, hdrs, data, p)
                    continue
                if verdict == "hijack":
                    pool.on_failure(p, "hijack", "html response (%d)" % up.status)
                    last = (up.status, hdrs, data, p)
                    continue
                if verdict == "throttle":
                    pool.on_throttle(p)
                    last = (up.status, hdrs, data, p)
                    continue
                if verdict == "retry":
                    pool.on_failure(p, "5xx", "http %d" % up.status)
                    last = (up.status, hdrs, data, p)
                    continue
                pool.on_success(p, ttfb)       # app-level error (bad key, bad request...) = proxy is fine
                return self._buffered(up.status, hdrs, data, p, attempts)
            finally:
                if not released:
                    pool.release(p)
        # exhausted
        if last is not None and last[0] != 0:
            st_, hd_, bd_, pr_ = last
            if st_ in (429, 500, 502, 503, 504) and "text/html" not in hd_.get("Content-Type", ""):
                return self._buffered(st_, hd_, bd_, pr_, attempts)
        if c.get("fallback_direct"):
            return await self._direct_forward(request, body, url, headers)
        if attempts == 0:
            return _gerr(503, "UNAVAILABLE", "rotator: no healthy proxy available right now")
        return _gerr(502, "UNAVAILABLE", "rotator: all %d attempts failed" % attempts)

    def _buffered(self, status: int, hdrs: dict, data: bytes, p: Proxy, attempts: int) -> web.Response:
        h = {k: v for k, v in hdrs.items()}
        if self.cfg.get("debug_headers", True):
            h["X-Rotator-Proxy"] = p.id
            h["X-Rotator-Attempts"] = str(attempts)
        return web.Response(status=status, body=data, headers=h)

    async def _stream(self, request: web.Request, up: aiohttp.ClientResponse, p: Proxy, attempts: int) -> web.StreamResponse:
        resp = web.StreamResponse(status=up.status, reason=up.reason)
        for k, v in up.headers.items():
            if k.lower() not in HOP:
                resp.headers[k] = v
        if up.content_length is not None:
            resp.content_length = up.content_length
        if self.cfg.get("debug_headers", True):
            resp.headers["X-Rotator-Proxy"] = p.id
            resp.headers["X-Rotator-Attempts"] = str(attempts)
        clean = False
        try:
            await resp.prepare(request)
            async for chunk in up.content.iter_any():
                await resp.write(chunk)
            await resp.write_eof()
            clean = True
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.pool.on_failure(p, "soft", "stream: %s" % type(e).__name__)
            if request.transport:
                request.transport.close()
        except (ConnectionResetError, asyncio.CancelledError):
            raise
        finally:
            if clean:
                up.release()
            else:
                up.close()
            self.pool.release(p)
        return resp

    async def _direct_forward(self, request, body, url, headers) -> web.StreamResponse:
        if self._direct is None:
            self._direct = aiohttp.ClientSession(auto_decompress=False, trust_env=False,
                                                 skip_auto_headers=("Accept-Encoding", "User-Agent", "Accept"))
        async with self._direct.request(request.method, url, data=body or None, headers=headers,
                                        allow_redirects=False) as up:
            data = await up.read()
            h = {k: v for k, v in up.headers.items() if k.lower() not in HOP}
            h["X-Rotator-Proxy"] = "direct"
            return web.Response(status=up.status, body=data, headers=h)

    # ============================================================ CONNECT / SOCKS routing
    def _proxied(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        for s in self.cfg.get("proxy_hosts", []):
            s = s.lower().lstrip(".")
            if s == "*" or host == s or host.endswith("." + s):
                return True
        return False

    async def open_route(self, host: str, port: int):
        c = self.cfg
        if self._proxied(host):
            tried: set = set()
            for _ in range(int(c.get("max_attempts", 4))):
                p = await self.pool.acquire(tried, wait=float(c.get("queue_wait", 4)) if not tried else 0.0)
                if p is None:
                    break
                tried.add(p.id)
                t = time.perf_counter()
                try:
                    r, w = await socks5_connect(p.local_port, host, port, float(c.get("connect_timeout", 5)))
                except Exception as e:  # noqa
                    self.pool.release(p)
                    self.pool.on_failure(p, "conn", "connect: %s" % e)
                    continue
                self.pool.on_success(p, (time.perf_counter() - t) * 1000.0)
                return r, w, p
            raise ConnectionError("no working proxy")
        if c.get("other_hosts", "direct") == "direct":
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, limit=1 << 16), 10)
            return r, w, None
        raise PermissionError("host not allowed")

    # ============================================================ HTTP CONNECT
    async def handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        p: Optional[Proxy] = None
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split()
            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                return
            if self._auth:
                got = ""
                for ln in lines[1:]:
                    if ln.lower().startswith("proxy-authorization:"):
                        got = ln.split(":", 1)[1].strip()
                exp = "Basic " + base64.b64encode(self._auth.encode()).decode()
                if got != exp:
                    writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="rotator"\r\nContent-Length: 0\r\n\r\n')
                    return
            host, _, prt = parts[1].rpartition(":")
            host = host.strip("[]")
            try:
                r2, w2, p = await self.open_route(host, int(prt))
            except PermissionError:
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            except Exception:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await pump(reader, writer, r2, w2)
        except Exception:
            pass
        finally:
            if p is not None:
                self.pool.release(p)
            try:
                writer.close()
            except Exception:
                pass

    # ============================================================ SOCKS5 server
    async def handle_socks(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        p: Optional[Proxy] = None
        try:
            ver, n = await asyncio.wait_for(reader.readexactly(2), 15)
            methods = await reader.readexactly(n)
            if ver != 5:
                return
            if self._auth:
                if 2 not in methods:
                    writer.write(b"\x05\xff")
                    return
                writer.write(b"\x05\x02")
                await reader.readexactly(1)
                u = await reader.readexactly((await reader.readexactly(1))[0])
                pw = await reader.readexactly((await reader.readexactly(1))[0])
                if (u + b":" + pw).decode("utf-8", "ignore") != self._auth:
                    writer.write(b"\x01\x01")
                    return
                writer.write(b"\x01\x00")
            else:
                if 0 not in methods:
                    writer.write(b"\x05\xff")
                    return
                writer.write(b"\x05\x00")
            _, cmd, _, atyp = await reader.readexactly(4)
            if atyp == 1:
                host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
            elif atyp == 4:
                host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
            elif atyp == 3:
                host = (await reader.readexactly((await reader.readexactly(1))[0])).decode("idna")
            else:
                writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6)
                return
            port = int.from_bytes(await reader.readexactly(2), "big")
            if cmd != 1:
                writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return
            try:
                r2, w2, p = await self.open_route(host, port)
            except PermissionError:
                writer.write(b"\x05\x02\x00\x01" + b"\x00" * 6)
                return
            except Exception:
                writer.write(b"\x05\x04\x00\x01" + b"\x00" * 6)
                return
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await writer.drain()
            await pump(reader, writer, r2, w2)
        except Exception:
            pass
        finally:
            if p is not None:
                self.pool.release(p)
            try:
                writer.close()
            except Exception:
                pass
