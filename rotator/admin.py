"""Local admin API used by the CLI, the live dashboard and install.sh."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from aiohttp import web

from . import __version__
from .pool import MODES, STRATEGIES

if TYPE_CHECKING:  # pragma: no cover
    from .app import App

log = logging.getLogger("rotator.admin")


class Admin:
    def __init__(self, app: "App") -> None:
        self.app = app
        self._runner = None

    async def start(self) -> None:
        a = web.Application(middlewares=[self._auth], client_max_size=16 * 1024 * 1024)
        r = a.router
        r.add_get("/status", self.status)
        r.add_get("/metrics", self.metrics)
        r.add_get("/config", self.get_config)
        r.add_post("/config", self.set_config)
        r.add_post("/add", self.add)
        r.add_post("/remove", self.remove)
        r.add_post("/recheck", self.recheck)
        r.add_post("/strategy", self.strategy)
        r.add_post("/pin", self.pin)
        r.add_post("/mode", self.mode)
        r.add_post("/next", self.next_)
        r.add_post("/reload", self.reload)
        self._runner = web.AppRunner(a, access_log=None)
        await self._runner.setup()
        c = self.app.cfg
        await web.TCPSite(self._runner, c.get("admin_listen", "127.0.0.1"), int(c["admin_port"])).start()
        log.info("admin     http://%s:%s", c.get("admin_listen", "127.0.0.1"), c["admin_port"])

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()

    @web.middleware
    async def _auth(self, request, handler):
        tok = self.app.cfg.get("access_token")
        if tok and request.headers.get("X-Rotator-Token") != tok:
            return web.json_response({"error": "unauthorized"}, status=401)
        return await handler(request)

    # ---------------------------------------------------------------- handlers
    async def status(self, request):
        s = self.app.pool.snapshot()
        c = self.app.cfg
        s["version"] = __version__
        s["ports"] = {"gateway": c["gateway_port"], "http": c.get("http_port"), "socks": c.get("socks_port"),
                      "admin": c["admin_port"]}
        s["xray_shards"] = len(self.app.xray.shards)
        return web.json_response(s)

    async def metrics(self, request):
        s = self.app.pool.snapshot()
        r, c = s["requests"], s["counts"]
        lines = [
            "rotator_requests_total %d" % r["total"], "rotator_requests_ok_total %d" % r["ok"],
            "rotator_requests_failed_total %d" % r["failed"], "rotator_retries_total %d" % r["retries"],
            "rotator_inflight %d" % r["inflight"], "rotator_rps %s" % r["rps"],
            "rotator_latency_p50_ms %d" % r["p50"], "rotator_latency_p95_ms %d" % r["p95"],
            "rotator_proxies_active %d" % c.get("active", 0), "rotator_proxies_dead %d" % c.get("dead", 0),
            "rotator_proxies_removed_total %d" % s["removed_total"],
        ]
        return web.Response(text="\n".join(lines) + "\n")

    async def get_config(self, request):
        c = dict(self.app.cfg)
        c["api_keys"] = ["***%s" % k[-4:] for k in c.get("api_keys", [])]
        c.pop("gemini_api_key", None)
        if c.get("access_token"):
            c["access_token"] = "***"
        return web.json_response(c)

    async def set_config(self, request):
        d = await request.json()
        return web.json_response(self.app.op_set_config(d["key"], d["value"]))

    async def add(self, request):
        text = (await request.read()).decode("utf-8", "ignore")
        return web.json_response(await self.app.add_text(text))

    async def remove(self, request):
        d = await request.json()
        return web.json_response({"removed": self.app.op_remove(d.get("sel", ""))})

    async def recheck(self, request):
        d = await request.json() if request.can_read_body else {}
        return web.json_response({"queued": self.app.op_recheck(d.get("sel", "all"))})

    async def strategy(self, request):
        d = await request.json()
        name = d.get("name", "")
        if name not in STRATEGIES:
            return web.json_response({"error": "unknown strategy", "valid": list(STRATEGIES)}, status=400)
        self.app.op_set_config("strategy", name)
        return web.json_response({"strategy": name})

    async def mode(self, request):
        d = await request.json()
        name = d.get("name", "")
        if name == "enable":
            self.app.op_set_config("ipv4_direct", True)
        elif name == "disable":
            self.app.op_set_config("ipv4_direct", False)
        elif name in MODES:
            self.app.op_set_config("egress_mode", name)
            self.app.op_set_config("ipv4_direct", True)
        else:
            return web.json_response({"error": "unknown mode", "valid": list(MODES) + ["enable", "disable"]}, status=400)
        return web.json_response({"egress_mode": self.app.pool.mode, "ipv4_direct": self.app.cfg.get("ipv4_direct", True)})

    async def pin(self, request):
        d = await request.json()
        sel = d.get("sel", "")
        if not sel:
            self.app.pool.pinned = None
            return web.json_response({"pinned": None})
        ps = [p for p in self.app.select(sel)]
        if len(ps) != 1:
            return web.json_response({"error": "selector matches %d proxies" % len(ps)}, status=400)
        self.app.pool.pinned = ps[0].id
        return web.json_response({"pinned": ps[0].id, "proxy": ps[0].name()})

    async def next_(self, request):
        p = self.app.pool.force_next()
        return web.json_response({"now": p.name() if p else None, "id": p.id if p else None})

    async def reload(self, request):
        added, bad = self.app.reload_file()
        return web.json_response({"added": added, "unparsable": bad})
