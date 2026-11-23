"""Mock Gemini + fake SOCKS5 'proxies' for integration tests."""
import asyncio, json, sys, random
from aiohttp import web

OK_PORT, GEO_PORT = 9999, 9998
MODES = {41001: "good", 41002: "good", 41003: "slow", 41004: "geo", 41005: "dead", 41006: "hole", 41007: "good", 41008: "good"}
killed = set()
conns = {}

async def gem_ok(request):
    if request.headers.get("x-goog-api-key") != "TESTKEY" and request.query.get("key") != "TESTKEY":
        return web.json_response({"error": {"code": 400, "message": "API key not valid. Please pass a valid API key.", "status": "INVALID_ARGUMENT", "details": [{"reason": "API_KEY_INVALID"}]}}, status=400)
    path = request.path
    if path.endswith(":countTokens"):
        return web.json_response({"totalTokens": 1})
    if path.endswith(":streamGenerateContent"):
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await resp.prepare(request)
        for i in range(5):
            await resp.write(('data: {"candidates":[{"content":{"parts":[{"text":"chunk%d"}]}}]}\r\n\r\n' % i).encode())
            await asyncio.sleep(0.05)
        await resp.write_eof()
        return resp
    body = await request.json()
    await asyncio.sleep(random.uniform(0.02, 0.06))
    return web.json_response({"candidates": [{"content": {"parts": [{"text": "echo:" + json.dumps(body)[:40]}]}}]})

async def gem_geo(request):
    if not request.headers.get("x-goog-api-key"):
        return web.json_response({"error": {"code": 403, "message": "Method doesn't allow unregistered callers", "status": "PERMISSION_DENIED"}}, status=403)
    return web.json_response({"error": {"code": 400, "message": "User location is not supported for the API use.", "status": "FAILED_PRECONDITION"}}, status=400)

async def socks_handler(mode, r, w, port=0):
    conns.setdefault(port, set()).add(w)
    try:
        ver, n = await r.readexactly(2); await r.readexactly(n)
        w.write(b"\x05\x00")
        _, cmd, _, atyp = await r.readexactly(4)
        if atyp == 3:
            l = (await r.readexactly(1))[0]; await r.readexactly(l)
        elif atyp == 1: await r.readexactly(4)
        else: await r.readexactly(16)
        await r.readexactly(2)
        if mode == "dead":
            w.close(); return
        if mode == "hole":
            await asyncio.sleep(60); return
        if mode == "slow": await asyncio.sleep(0.3)
        port_ = GEO_PORT if mode == "geo" else OK_PORT
        r2, w2 = await asyncio.open_connection("127.0.0.1", port_)
        conns[port].add(w2)
        w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"); await w.drain()
        async def cp(a, b):
            try:
                while True:
                    d = await a.read(65536)
                    if not d: break
                    b.write(d); await b.drain()
            except Exception: pass
            finally:
                try: b.close()
                except Exception: pass
        await asyncio.gather(cp(r, w2), cp(r2, w))
    except Exception:
        pass
    finally:
        try: w.close()
        except Exception: pass

async def main():
    for port, h in ((OK_PORT, gem_ok), (GEO_PORT, gem_geo)):
        app = web.Application(); app.router.add_route("*", "/{t:.*}", h)
        runner = web.AppRunner(app, access_log=None); await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", port, backlog=4096).start()
    servers = {}
    for port, mode in MODES.items():
        servers[port] = await asyncio.start_server(lambda r, w, m=mode, pt=port: socks_handler(m, r, w, pt), "127.0.0.1", port, backlog=4096)
    # control: kill a socks server when file /tmp/kill_<port> appears
    print("mock ready", flush=True)
    import os
    while True:
        await asyncio.sleep(0.3)
        for port in list(servers):
            if os.path.exists("/tmp/kill_%d" % port) and port not in killed:
                killed.add(port); servers[port].close(); [x.close() for x in list(conns.get(port, []))]; print("killed", port, flush=True)

asyncio.run(main())
