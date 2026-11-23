"""Orchestrator: loads proxies, runs xray shards, health-checks against Gemini, serves traffic."""
from __future__ import annotations

import asyncio
import json
import logging
import random
import signal
import time
from collections import deque
from typing import Deque, List, Optional, Tuple

import aiohttp

from . import __version__
from .admin import Admin
from .gateway import Gateway, classify_response
import socket

from .parsers import ParsedProxy, parse_text
from .pool import ACTIVE, DEAD, NEW, TESTING, Pool, Proxy, Stats, mono
from .util import (DATA_DIR, PROXIES_FILE, REMOVED_FILE, RUN_DIR, STATE_FILE, atomic_write, load_config,
                   now, raise_nofile, redact, setup_logging)
from .xray import XrayManager, Shard

log = logging.getLogger("rotator.app")

LIVE_KEYS = {"strategy", "rotate_seconds", "max_attempts", "connect_timeout", "read_timeout", "queue_wait",
             "per_proxy_max_inflight", "test_timeout", "test_concurrency", "probe_interval", "auto_delete_dead",
             "api_keys", "probe_model", "fallback_direct", "debug_headers", "learn_key_from_traffic",
             "subscriptions", "log_level", "never_worked_max_fails", "geo_confirmations", "dead_retry_schedule",
             "other_hosts", "proxy_hosts", "sub_refresh_minutes", "max_body_mb", "ipv4_direct", "egress_mode"}


class App:
    def __init__(self) -> None:
        self.cfg = load_config()
        self.stats = Stats()
        self.pool = Pool(self.cfg, self.stats)
        self.xray = XrayManager(self.cfg)
        self.gw = Gateway(self.cfg, self.pool, self.stats)
        self.admin = Admin(self)
        self.sem = asyncio.Semaphore(int(self.cfg.get("test_concurrency", 40)))
        self.stop_event = asyncio.Event()
        self.tasks: List[asyncio.Task] = []
        self.sub_urls: set = set()
        self._file_mtime = 0.0
        self._restarts: Deque[float] = deque(maxlen=10)
        self._hinted_404 = False
        self.pool.on_first_key = self._on_first_key
        self.xray.on_shard_died = self._on_shard_died

    # ============================================================ run
    async def run(self) -> None:
        setup_logging(self.cfg.get("log_level", "INFO"))
        raise_nofile()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        if not self.xray.bin:
            log.error("xray not found. Run:  bash install.sh   (menu -> Install)")
            return
        self.xray.kill_orphans()
        log.info("Gemini Rotator %s | xray: %s", __version__, self.xray.bin)
        self._load_state()
        self.reload_file(first=True)
        self.ensure_builtin()
        await self.gw.start()
        await self.admin.start()
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.stop_event.set)
            except NotImplementedError:
                pass
        for coro in (self._provision_loop, self._health_loop, self._sources_loop, self._maintenance_loop):
            self.tasks.append(asyncio.ensure_future(coro()))
        log.info("ready - %d proxies loaded, testing...", len(self.pool.proxies))
        await self.stop_event.wait()
        await self.shutdown()

    async def shutdown(self) -> None:
        log.info("shutting down...")
        for t in self.tasks:
            t.cancel()
        await self.gw.stop()
        await self.admin.stop()
        self._save_state()
        self.flush_files()
        for p in list(self.pool.proxies.values()):
            await p.close()
        await self.xray.stop_all()

    # ============================================================ persistence
    def _load_state(self) -> None:
        if not STATE_FILE.exists():
            return
        try:
            st = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception as e:  # noqa
            log.warning("state.json unreadable: %s", e)
            return
        self.pool.graveyard = {k: float(v) for k, v in (st.get("graveyard") or {}).items()}
        n = 0
        for pid, d in (st.get("proxies") or {}).items():
            res = parse_text(d.get("raw", ""))
            if not res.proxies:
                continue
            p = self.pool.add(res.proxies[0], d.get("src", "file"))
            if p is None:
                continue
            p.label = d.get("label") or p.label
            p.added = d.get("added", p.added)
            p.ok, p.err = int(d.get("ok", 0)), int(d.get("err", 0))
            p.lat = d.get("lat")
            p.ever_ok = bool(d.get("ever_ok"))
            p.geo_hits = int(d.get("geo_hits", 0))
            p.last_ok = float(d.get("last_ok", 0))
            p.verified = bool(d.get("verified"))
            n += 1
        if n:
            log.info("restored %d proxies from state", n)

    def _save_state(self) -> None:
        try:
            atomic_write(STATE_FILE, json.dumps(self.pool.to_state(), ensure_ascii=False))
        except Exception as e:  # noqa
            log.warning("cannot save state: %s", e)

    def flush_files(self) -> None:
        """Write removals back to proxies.txt and archive them."""
        pool = self.pool
        if pool.removed_log:
            try:
                REMOVED_FILE.parent.mkdir(parents=True, exist_ok=True)
                with open(REMOVED_FILE, "a", encoding="utf-8") as f:
                    f.write("\n".join(pool.removed_log) + "\n")
                pool.removed_log.clear()
            except Exception as e:  # noqa
                log.warning("removed.txt: %s", e)
        ids = set(pool.pending_removals)
        if not ids or not PROXIES_FILE.exists():
            pool.pending_removals -= ids
            return
        try:
            lines = PROXIES_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
            out, changed = [], False
            for ln in lines:
                s = ln.strip()
                if s and not s.startswith("#"):
                    pids = {pp.id for pp in parse_text(ln).proxies}
                    if pids and pids <= ids:
                        changed = True
                        continue
                out.append(ln)
            if changed:
                atomic_write(PROXIES_FILE, "\n".join(out) + "\n")
                self._file_mtime = PROXIES_FILE.stat().st_mtime
        except Exception as e:  # noqa
            log.warning("cannot rewrite proxies.txt: %s", e)
        pool.pending_removals -= ids

    # ============================================================ built-in direct IPv4 egress
    @staticmethod
    def detect_ipv4() -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))     # no packet is sent, just picks the route
                return s.getsockname()[0]
        except Exception:
            return ""

    def ensure_builtin(self) -> None:
        """The 3x-ui trick: a freedom outbound with domainStrategy=UseIPv4 and sendThrough=<server IPv4>.
        Forcing IPv4 egress avoids the IPv6 geolocation that triggers Gemini 403 / 'location not supported'."""
        if "direct4" in self.pool.proxies:
            return
        st = str(self.cfg.get("ipv4_send_through", "auto") or "")
        ip = self.detect_ipv4() if st == "auto" else st
        ob = {"protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}}
        if ip:
            ob["sendThrough"] = ip
        pp = ParsedProxy("direct4", "direct", "server IPv4", ip or "server", 0, ob, "builtin:direct4")
        self.pool.add(pp, "builtin")
        log.info("built-in direct-IPv4 egress ready (sendThrough=%s), mode=%s", ip or "auto", self.pool.mode)

    # ============================================================ sources
    def reload_file(self, first: bool = False) -> Tuple[int, int]:
        if not PROXIES_FILE.exists():
            PROXIES_FILE.write_text("# one proxy per line - any format. See README.\n", encoding="utf-8")
        try:
            self._file_mtime = PROXIES_FILE.stat().st_mtime
            text = PROXIES_FILE.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return 0, 0
        res = parse_text(text)
        added = 0
        for pp in res.proxies:
            if pp.id in self.pool.pending_removals:
                continue
            if self.pool.add(pp, "file"):
                added += 1
        for u in res.sub_urls:
            self.sub_urls.add(u)
        if added or first:
            log.info("proxies.txt: %d new, %d total, %d unparsable line(s)", added, len(self.pool.proxies), len(res.errors))
        for e in res.errors[:5]:
            log.debug("  skip: %s", redact(e))
        return added, len(res.errors)

    async def fetch_sub(self, url: str) -> int:
        text = None
        try:
            async with aiohttp.ClientSession(trust_env=False, timeout=aiohttp.ClientTimeout(total=25)) as s:
                async with s.get(url, headers={"User-Agent": "v2rayN/6.0"}) as r:
                    text = await r.text()
        except Exception:
            p = self.pool.pick()
            if p:
                try:
                    async with p.session().get(url, headers={"User-Agent": "v2rayN/6.0"},
                                               timeout=aiohttp.ClientTimeout(total=25)) as r:
                        text = (await r.read()).decode("utf-8", "ignore")
                except Exception:
                    pass
        if not text:
            log.warning("subscription fetch failed: %s", redact(url[:60]))
            return 0
        res = parse_text(text)
        n = sum(1 for pp in res.proxies if self.pool.add(pp, "sub"))
        log.info("subscription %s: %d new proxies", redact(url[:50]), n)
        return n

    async def add_text(self, text: str, persist: bool = True) -> dict:
        res = parse_text(text)
        added, dup, lines = 0, 0, []
        seen_groups = set()
        for pp in res.proxies:
            p = self.pool.add(pp, "api")
            if p:
                added += 1
                if pp.group:
                    if pp.group not in seen_groups:
                        seen_groups.add(pp.group)
                        lines.append(pp.raw.split("://", 1)[1])
                else:
                    lines.append(pp.raw)
            else:
                dup += 1
        subs = 0
        for u in res.sub_urls:
            self.sub_urls.add(u)
            subs += await self.fetch_sub(u)
        if persist and lines:
            with open(PROXIES_FILE, "a", encoding="utf-8") as f:
                f.write("\n# added %s\n%s\n" % (time.strftime("%Y-%m-%d %H:%M"), "\n".join(lines)))
            self._file_mtime = PROXIES_FILE.stat().st_mtime
        return {"added": added, "duplicates": dup, "from_subscriptions": subs,
                "invalid": len(res.errors), "errors": [redact(e) for e in res.errors[:8]]}

    async def _sources_loop(self) -> None:
        last_sub = 0.0
        while True:
            await asyncio.sleep(2)
            try:
                if PROXIES_FILE.exists() and PROXIES_FILE.stat().st_mtime != self._file_mtime:
                    self.reload_file()
                every = float(self.cfg.get("sub_refresh_minutes", 60)) * 60
                if mono() - last_sub > every or (last_sub == 0 and (self.sub_urls or self.cfg.get("subscriptions"))):
                    last_sub = mono()
                    for u in set(self.cfg.get("subscriptions") or []) | self.sub_urls:
                        await self.fetch_sub(u)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("sources loop")

    # ============================================================ xray provisioning
    def _on_shard_died(self, sh: Shard) -> None:
        self._restarts.append(mono())
        for p in sh.members:
            if p.id in self.pool.proxies and p.shard == sh.id:
                p.shard = 0
                p.state = NEW
                self.pool._act = None
        self.pool.new_event.set()

    async def _provision_loop(self) -> None:
        size = max(1, int(self.cfg.get("shard_size", 50)))
        while True:
            await self.pool.new_event.wait()
            self.pool.new_event.clear()
            await asyncio.sleep(0.3)
            if len(self._restarts) >= 5 and mono() - self._restarts[-5] < 60:
                log.error("xray keeps crashing - cooling down 20s")
                await asyncio.sleep(20)
            new = [p for p in self.pool.proxies.values() if p.state == NEW and not p.shard]
            for i in range(0, len(new), size):
                chunk = new[i:i + size]
                try:
                    started = await self.xray.start_shard(chunk)
                except asyncio.CancelledError:
                    raise
                except Exception as e:  # noqa
                    log.error("cannot start xray shard: %s", e)
                    await asyncio.sleep(5)
                    self.pool.new_event.set()
                    break
                ok_ids = {p.id for p in started}
                for p in chunk:
                    if p.id in ok_ids:
                        self.pool.set_state(p, TESTING)
                        p.next_check = 0.0
                    else:
                        self.pool.remove(p, "xray rejected its config")

    # ============================================================ health
    async def _health_loop(self) -> None:
        while True:
            await asyncio.sleep(0.25)
            t = mono()
            for p in list(self.pool.proxies.values()):
                if p.state in (TESTING, ACTIVE, DEAD) and p.shard and not p.probing and p.next_check <= t:
                    p.probing = True
                    asyncio.ensure_future(self._test(p))

    async def _test(self, p: Proxy) -> None:
        try:
            async with self.sem:
                if p.id not in self.pool.proxies:
                    return
                verdict, ms, detail = await self.probe(p)
            if p.id in self.pool.proxies:
                self._apply(p, verdict, ms, detail)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("test error")
        finally:
            p.probing = False

    def _apply(self, p: Proxy, verdict: str, ms: float, detail: str) -> None:
        pool = self.pool
        if verdict in ("ok", "reachable"):
            if verdict == "ok":
                p.verified = True
            p.lat = ms if p.lat is None else p.lat * 0.6 + ms * 0.4
            p.last_ok = now()
            was = p.state
            if was != ACTIVE:
                pool.revive(p)
                if was == TESTING:
                    log.info("ACTIVE  %s  %dms  %s", p.name(), ms, "verified" if p.verified else "reachable (set an API key to verify Gemini)")
            else:
                p.fail_score = 0.0
            p.next_check = mono() + float(self.cfg.get("probe_interval", 60)) * random.uniform(0.8, 1.25)
        elif verdict == "geo":
            pool.on_geo(p, detail)
        else:
            if p.state == ACTIVE and p.fail_score < 1.0:
                p.fail_score += 1.0
                p.next_check = mono() + 4
            else:
                pool.mark_dead(p, detail)

    async def probe(self, p: Proxy) -> Tuple[str, float, str]:
        """-> (verdict, ms, detail); verdict in ok | reachable | geo | fail"""
        c = self.cfg
        key = self.pool.probe_key()
        base = c["upstream"].rstrip("/")
        tmo = float(c.get("test_timeout", 8))
        headers = {"User-Agent": "gemini-rotator-probe"}
        if key:
            url = "%s/v1beta/models/%s:countTokens" % (base, c.get("probe_model", "gemini-2.5-flash"))
            method, data = "POST", json.dumps({"contents": [{"parts": [{"text": "ping"}]}]}).encode()
            headers.update({"x-goog-api-key": key, "Content-Type": "application/json"})
        else:
            url, method, data = base + "/v1beta/models?pageSize=1", "GET", None
        t0 = time.perf_counter()
        try:
            async with p.session().request(method, url, data=data, headers=headers, allow_redirects=False,
                                           timeout=aiohttp.ClientTimeout(total=tmo, connect=tmo)) as r:
                body = await r.content.read(65536)
                status, ctype = r.status, r.headers.get("Content-Type", "")
        except asyncio.TimeoutError:
            return "fail", 0, "timeout"
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa
            return "fail", 0, ("%s: %s" % (type(e).__name__, e))[:100]
        ms = (time.perf_counter() - t0) * 1000.0
        verdict = classify_response(status, ctype, body)
        if verdict == "geo":
            return "geo", ms, "gemini: location not supported"
        if verdict == "hijack":
            return "fail", ms, "html page instead of API (hijacked/captive)"
        if status >= 500:
            return "fail", ms, "http %d" % status
        low = body[:2048].lower()
        if status == 200:
            return ("ok" if key else "reachable"), ms, "http 200"
        if key and (b"api_key_invalid" in low or b"api key not valid" in low or b"api key expired" in low):
            self.pool.drop_bad_key(key)
            return "reachable", ms, "key rejected"
        if status == 404 and key and not self._hinted_404:
            self._hinted_404 = True
            log.warning("probe model '%s' returned 404 - set a valid 'probe_model' in config.json for real verification",
                        c.get("probe_model"))
        return "reachable", ms, "http %d" % status

    def _on_first_key(self) -> None:
        log.info("API key learned from traffic - re-verifying proxies against Gemini")
        for p in self.pool.proxies.values():
            if p.state == ACTIVE and not p.verified:
                p.next_check = 0.0

    # ============================================================ maintenance
    async def _maintenance_loop(self) -> None:
        tick = 0
        while True:
            await asyncio.sleep(5)
            tick += 1
            try:
                self.flush_files()
                if tick % 3 == 0:
                    self._save_state()
                if tick % 12 == 0:
                    await self._compact()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("maintenance")

    async def _compact(self) -> None:
        """Merge sparse shards so dead proxies don't waste xray processes."""
        size = max(1, int(self.cfg.get("shard_size", 50)))
        weak: List[Shard] = []
        for sh in list(self.xray.shards.values()):
            sh.members = [p for p in sh.members if p.id in self.pool.proxies and p.shard == sh.id]
            if not sh.members:
                await self.xray.stop_shard(sh.id, grace=30)
            elif len(sh.members) <= size * 0.4:
                weak.append(sh)
        if len(weak) >= 2:
            members = [p for sh in weak for p in sh.members]
            started = await self.xray.start_shard(members)
            if started:
                for sh in weak:
                    asyncio.ensure_future(self.xray.stop_shard(sh.id, grace=60))
                log.info("compacted %d shards -> 1 (%d proxies)", len(weak), len(started))

    # ============================================================ admin operations
    def select(self, sel: str) -> List[Proxy]:
        sel = (sel or "").strip().lower()
        real = [p for p in self.pool.proxies.values() if p.src != "builtin"]
        if sel in ("all", "*"):
            return real
        if sel == "dead":
            return [p for p in real if p.state == DEAD]
        if sel == "unverified":
            return [p for p in self.pool.proxies.values() if p.state == ACTIVE and not p.verified]
        return [p for p in real
                if p.id.startswith(sel) or sel in p.host.lower() or sel in (p.label or "").lower()]

    def op_remove(self, sel: str) -> int:
        ps = self.select(sel)
        for p in ps:
            self.pool.remove(p, "removed by user")
        return len(ps)

    def op_recheck(self, sel: str) -> int:
        ps = self.select(sel or "all")
        if (sel or "all") in ("all", "*") and "direct4" in self.pool.proxies:
            ps.append(self.pool.proxies["direct4"])
        for p in ps:
            if p.state in (TESTING, ACTIVE, DEAD) and p.shard:
                p.next_check = 0.0
        return len(ps)

    def op_set_config(self, key: str, value) -> dict:
        from .util import save_config_key
        if key == "gemini_api_key":
            key, value = "api_keys", [value] if value else []
        if key in ("api_keys", "subscriptions", "proxy_hosts", "dead_retry_schedule") and isinstance(value, str):
            value = [x.strip() for x in value.replace(";", ",").split(",") if x.strip()]
            if key == "dead_retry_schedule":
                value = [int(x) for x in value]
        self.cfg[key] = value
        save_config_key(key, value)
        restart = key not in LIVE_KEYS
        if key == "api_keys":
            self.pool.keys = list(value)
            for p in self.pool.proxies.values():
                p.verified = False
                p.next_check = 0.0 if p.state in (ACTIVE, DEAD) else p.next_check
        elif key == "strategy":
            self.pool.strategy = value
        elif key in ("egress_mode", "ipv4_direct"):
            self.pool.refresh_mode()
        elif key == "test_concurrency":
            self.sem = asyncio.Semaphore(int(value))
        return {"key": key, "restart_required": restart}


async def amain() -> None:
    app = App()
    await app.run()


def main() -> None:
    try:
        import uvloop  # type: ignore
        uvloop.install()
    except Exception:
        pass
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
