"""CLI: talks to the running daemon through the local admin API.

  python -m rotator status [--live]      python -m rotator list [--all]
  python -m rotator add [text|-f file|-]  python -m rotator remove <sel>
  python -m rotator recheck [sel]        python -m rotator strategy [name]
  python -m rotator pin [sel]            python -m rotator next
  python -m rotator config [key [value]] python -m rotator parse [text|-f file|-]
  python -m rotator test <uri>           (offline, no daemon needed)
"""
from __future__ import annotations

import json
import shutil
import sys
import time
import urllib.error
import urllib.request

from .pool import STRATEGIES
from .util import load_config

C = {"r": "\033[31m", "g": "\033[32m", "y": "\033[33m", "b": "\033[34m", "c": "\033[36m", "d": "\033[2m",
     "B": "\033[1m", "0": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}


def col(k: str, s: str) -> str:
    return "%s%s%s" % (C[k], s, C["0"])


class Api:
    def __init__(self) -> None:
        cfg = load_config()
        host = cfg.get("admin_listen", "127.0.0.1")
        self.base = "http://%s:%s" % ("127.0.0.1" if host in ("0.0.0.0", "") else host, cfg["admin_port"])
        self.token = cfg.get("access_token", "")

    def call(self, method: str, path: str, data=None, raw: bytes = None, timeout: float = 30):
        body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
        req = urllib.request.Request(self.base + path, data=body, method=method)
        if self.token:
            req.add_header("X-Rotator-Token", self.token)
        if body is not None and raw is None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode())
            except Exception:
                raise SystemExit("error: HTTP %d" % e.code)
        except (urllib.error.URLError, ConnectionError, OSError):
            raise SystemExit(col("r", "rotator is not running") + " (start it from the menu or: bash install.sh start)")


STATE_COL = {"active": "g", "testing": "y", "new": "y", "dead": "r"}


def fmt_up(s: int) -> str:
    d, s = divmod(int(s), 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return ("%dd " % d if d else "") + "%02d:%02d:%02d" % (h, m, s)


def render(st: dict, show_all: bool = False, rows: int = 0) -> str:
    w = shutil.get_terminal_size((110, 30)).columns
    r, c = st["requests"], st["counts"]
    ok_pct = (100.0 * r["ok"] / r["total"]) if r["total"] else 100.0
    out = []
    out.append(col("B", " GEMINI ROTATOR %s " % st.get("version", "")) + col("d", " uptime " + fmt_up(st["uptime"])) +
               "   strategy: " + col("c", st["strategy"]) + "   egress: " + col("c", st.get("egress_mode", "?")) + ("   pinned: " + col("y", st["pinned"]) if st.get("pinned") else ""))
    out.append(" proxies  %s active  %s dead  %s testing/new   removed so far: %d   xray shards: %s" % (
        col("g", str(c.get("active", 0))), col("r", str(c.get("dead", 0))),
        col("y", str(c.get("testing", 0) + c.get("new", 0))), st["removed_total"], st.get("xray_shards", "?")))
    out.append(" traffic  %s req/s   inflight %d   total %d   ok %s   retried %d   p50 %dms   p95 %dms" % (
        col("B", "%.1f" % r["rps"]), r["inflight"], r["total"], col("g" if ok_pct > 98 else "y", "%.1f%%" % ok_pct),
        r["retries"], r["p50"], r["p95"]))
    out.append(" gemini key: " + (col("g", "known") + (" (learned from traffic)" if st.get("key_learned") else "")
                                  if st.get("key_known") else col("y", "not known - proxies are only 'reachable' until a key is configured or seen")))
    out.append(" ports    gateway :%s   http :%s   socks :%s" % (st["ports"]["gateway"], st["ports"]["http"], st["ports"]["socks"]))
    out.append("")
    hdr = " %-8s %-7s %-8s %-30s %7s %7s %5s %7s %6s  %s" % ("ID", "STATE", "PROTO", "ENDPOINT", "PROBE", "LIVE", "LOAD", "OK", "ERR", "NOTE")
    out.append(col("B", hdr[:w]))
    plist = st["proxies"]
    if not show_all:
        plist = [p for p in plist if p["state"] != "dead"] + [p for p in plist if p["state"] == "dead"]
    limit = rows or len(plist)
    for p in plist[:limit]:
        mark = "*" if p["id"] == st.get("sticky") and st["strategy"] in ("sticky", "timed") else (">" if p["id"] == st.get("pinned") else " ")
        note = ("verified" if p["verified"] and p["state"] == "active" else "") or p["last_err"][:34]
        ep = "%s:%s" % (p["host"][:24], p["port"])
        line = "%s%-8s %s %-8s %-30s %7s %7s %5d %7d %6d  %s" % (
            mark, p["id"], col(STATE_COL.get(p["state"], "d"), "%-7s" % p["state"]), p["scheme"][:8], ep,
            ("%dms" % p["lat"]) if p["lat"] else "-", ("%dms" % p["live_ms"]) if p["live_ms"] else "-",
            p["inflight"], p["ok"], p["err"], note)
        out.append(line)
    if len(plist) > limit:
        out.append(col("d", "  ... %d more (use: list --all)" % (len(plist) - limit)))
    return "\n".join(out)


def live(api: Api) -> None:
    sys.stdout.write("\033[?25l\033[2J")
    try:
        while True:
            try:
                st = api.call("GET", "/status", timeout=3)
                rows = max(5, shutil.get_terminal_size((110, 30)).lines - 11)
                txt = render(st, show_all=True, rows=rows)
            except SystemExit as e:
                txt = str(e)
            sys.stdout.write("\033[H" + "\n".join(l + "\033[K" for l in txt.split("\n")) +
                             "\033[J\n" + col("d", " Ctrl-C to exit") + "\033[K")
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write("\033[?25h\n")


def _read_input(args) -> str:
    if args and args[0] == "-f":
        return open(args[1], encoding="utf-8", errors="ignore").read()
    if not args or args[0] == "-":
        return sys.stdin.read()
    return " ".join(args)


def main() -> None:
    a = sys.argv[1:]
    cmd, rest = a[0], a[1:]
    api = Api()
    if cmd in ("status", "live", "dashboard"):
        if cmd != "status" or "--live" in rest or "-l" in rest:
            return live(api)
        print(render(api.call("GET", "/status")))
    elif cmd == "list":
        print(render(api.call("GET", "/status"), show_all=True))
    elif cmd == "add":
        r = api.call("POST", "/add", raw=_read_input(rest).encode(), timeout=120)
        print("added %d | duplicates %d | from subscriptions %d | invalid %d" % (
            r["added"], r["duplicates"], r["from_subscriptions"], r["invalid"]))
        for e in r["errors"]:
            print(col("y", "  skip: ") + e)
    elif cmd == "remove":
        print("removed", api.call("POST", "/remove", {"sel": rest[0] if rest else ""})["removed"])
    elif cmd == "recheck":
        print("queued", api.call("POST", "/recheck", {"sel": rest[0] if rest else "all"})["queued"])
    elif cmd == "strategy":
        if not rest:
            print(api.call("GET", "/status")["strategy"], "  (available: %s)" % ", ".join(STRATEGIES))
        else:
            print(api.call("POST", "/strategy", {"name": rest[0]}))
    elif cmd == "mode":
        if not rest:
            st = api.call("GET", "/status")
            print("egress mode:", st["egress_mode"], " ipv4_direct:", st["ipv4_direct"], " (hybrid | ipv4 | proxies | enable | disable)")
        else:
            print(api.call("POST", "/mode", {"name": rest[0]}))
    elif cmd == "pin":
        print(api.call("POST", "/pin", {"sel": rest[0] if rest else ""}))
    elif cmd == "next":
        print(api.call("POST", "/next", {}))
    elif cmd == "reload":
        print(api.call("POST", "/reload", {}))
    elif cmd == "config":
        if not rest:
            print(json.dumps(api.call("GET", "/config"), indent=2, ensure_ascii=False))
        elif len(rest) == 1:
            print(api.call("GET", "/config").get(rest[0]))
        else:
            val = " ".join(rest[1:])
            try:
                val = json.loads(val)
            except Exception:
                pass
            print(api.call("POST", "/config", {"key": rest[0], "value": val}))
    elif cmd == "parse":
        from .parsers import parse_text
        res = parse_text(_read_input(rest))
        for p in res.proxies:
            print(col("g", "OK  "), "%-7s %-28s %s" % (p.scheme, "%s:%s" % (p.host, p.port), p.label[:30]))
        for u in res.sub_urls:
            print(col("c", "SUB "), u)
        for e in res.errors:
            print(col("r", "BAD "), e)
        print("\n%d valid, %d subscription url(s), %d invalid" % (len(res.proxies), len(res.sub_urls), len(res.errors)))
    elif cmd == "test":
        import asyncio
        asyncio.run(_offline_test(" ".join(rest)))
    else:
        print(__doc__)
        raise SystemExit(1)


async def _offline_test(text: str) -> None:
    """Test URIs against Gemini without the daemon (uses a temporary xray)."""
    from .app import App
    from .pool import ACTIVE
    from .parsers import parse_text
    app = App()
    app.cfg["local_port_base"] = 47000
    app.xray.cfg = app.cfg
    app.xray._next_port = 47000
    if not app.xray.bin:
        raise SystemExit("xray not found - install first")
    res = parse_text(text)
    if not res.proxies:
        raise SystemExit("could not parse: " + "; ".join(res.errors[:3]))
    ps = [app.pool.add(pp, "test") for pp in res.proxies]
    ps = [p for p in ps if p]
    started = await app.xray.start_shard(ps)
    try:
        for p in started:
            v, ms, d = await app.probe(p)
            colr = {"ok": "g", "reachable": "y", "geo": "r", "fail": "r"}[v]
            print("%s  %-28s %s %dms %s" % (col(colr, "%-9s" % v.upper()), p.name(), "", ms, d))
        if not app.pool.probe_key():
            print(col("d", "(no API key configured: 'reachable' means TLS to Google works; set api_keys for a real Gemini check)"))
    finally:
        for p in ps:
            await p.close()
        await app.xray.stop_all()
