"""Proxy pool: state, scoring, switching strategies and failure accounting."""
from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from typing import Callable, Deque, Dict, List, Optional

import aiohttp
from aiohttp_socks import ProxyConnector

from .parsers import ParsedProxy
from .util import now, redact

log = logging.getLogger("rotator.pool")

NEW, TESTING, ACTIVE, DEAD = "new", "testing", "active", "dead"
MODES = ("hybrid", "ipv4", "proxies")
STRATEGIES = ("adaptive", "round_robin", "fastest", "random", "sticky", "timed")
FAIL_WEIGHT = {"conn": 1.0, "timeout": 1.0, "soft": 0.25, "5xx": 0.35, "hijack": 3.0}


def mono() -> float:
    return time.monotonic()


class Stats:
    def __init__(self) -> None:
        self.started = now()
        self.total = 0
        self.ok = 0
        self.failed = 0
        self.retries = 0
        self.inflight = 0
        self.removed = 0
        self.by_status: Dict[int, int] = {}
        self.lat: Deque[float] = deque(maxlen=2000)
        self._buckets: Deque[List[int]] = deque(maxlen=64)

    def hit(self) -> None:
        sec = int(time.time())
        if self._buckets and self._buckets[-1][0] == sec:
            self._buckets[-1][1] += 1
        else:
            self._buckets.append([sec, 1])

    def done(self, status: int, ms: float, ok: bool) -> None:
        self.total += 1
        if ok:
            self.ok += 1
        else:
            self.failed += 1
        self.by_status[status] = self.by_status.get(status, 0) + 1
        self.lat.append(ms)

    def rps(self, window: int = 5) -> float:
        cut = int(time.time()) - window
        return sum(c for s, c in self._buckets if s > cut) / float(window)

    def pct(self, q: float) -> float:
        if not self.lat:
            return 0.0
        data = sorted(self.lat)
        return data[min(len(data) - 1, int(len(data) * q))]


class Proxy:
    def __init__(self, pp: ParsedProxy, src: str = "file") -> None:
        self.id = pp.id
        self.label = pp.label
        self.scheme = pp.scheme
        self.host = pp.host
        self.port = pp.port
        self.outbound = pp.outbound
        self.raw = pp.raw
        self.group = pp.group
        self.src = src
        self.added = now()
        self.state = NEW
        self.local_port = 0
        self.shard = 0
        self.invalid = False
        self.inflight = 0
        self.ok = 0
        self.err = 0
        self.fail_score = 0.0
        self.lat: Optional[float] = None       # EWMA of probe latency (ms)
        self.live_ms: Optional[float] = None   # EWMA of live time-to-first-byte (ms)
        self.verified = False                  # True once a real Gemini call succeeded through it
        self.ever_ok = False
        self.geo_hits = 0
        self.dead_retries = 0
        self.last_ok = 0.0
        self.last_err = ""
        self.next_check = 0.0
        self.penalty_until = 0.0
        self.probing = False
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_port = 0

    # ---- http session over this proxy's local socks inbound
    def session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed or self._session_port != self.local_port:
            old = self._session
            conn = ProxyConnector.from_url(
                "socks5://127.0.0.1:%d" % self.local_port, rdns=True, limit=0, limit_per_host=0,
                keepalive_timeout=30, enable_cleanup_closed=True)
            self._session = aiohttp.ClientSession(
                connector=conn, auto_decompress=False, trust_env=False,
                cookie_jar=aiohttp.DummyCookieJar(),
                skip_auto_headers=("Accept-Encoding", "User-Agent", "Accept"))
            self._session_port = self.local_port
            if old is not None:
                asyncio.ensure_future(_close_later(old, 60))
        return self._session

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()

    def name(self) -> str:
        if self.src == "builtin":
            return "DIRECT server IPv4 (%s)" % self.host
        return "%s %s:%d" % (self.scheme, self.host, self.port)

    def score(self) -> float:
        lat = self.lat if self.lat else 700.0
        s = (lat + 30.0) * (1 + self.inflight)
        if not self.verified:
            s *= 1.5
        if self.fail_score:
            s *= 1 + self.fail_score
        return s

    def to_state(self) -> dict:
        return {"raw": self.raw, "label": self.label, "src": self.src, "added": self.added, "ok": self.ok,
                "err": self.err, "lat": self.lat, "ever_ok": self.ever_ok, "geo_hits": self.geo_hits,
                "last_ok": self.last_ok, "verified": self.verified}

    def to_public(self) -> dict:
        return {"id": self.id, "state": self.state, "scheme": self.scheme, "host": self.host, "port": self.port,
                "label": self.label, "lat": round(self.lat) if self.lat else None,
                "live_ms": round(self.live_ms) if self.live_ms else None, "inflight": self.inflight,
                "ok": self.ok, "err": self.err, "verified": self.verified, "geo_hits": self.geo_hits,
                "dead_retries": self.dead_retries, "last_err": self.last_err, "last_ok": self.last_ok,
                "src": self.src, "shard": self.shard}


async def _close_later(sess: aiohttp.ClientSession, delay: float) -> None:
    await asyncio.sleep(delay)
    try:
        await sess.close()
    except Exception:
        pass


class Pool:
    def __init__(self, cfg: dict, stats: Stats) -> None:
        self.cfg = cfg
        self.stats = stats
        self.proxies: Dict[str, Proxy] = {}
        self.graveyard: Dict[str, float] = {}
        self.pending_removals: set = set()
        self.removed_log: List[str] = []
        self.keys: List[str] = list(cfg.get("api_keys") or [])
        self.learned_keys: List[str] = []
        self.strategy = cfg.get("strategy", "adaptive")
        self.mode = "proxies"
        self._elig: Optional[List[Proxy]] = None
        self._elig_src = None
        self._elig_mode = ""
        self.refresh_mode()
        self.pinned: Optional[str] = None
        self.sticky_id: Optional[str] = None
        self.sticky_since = 0.0
        self._rr = 0
        self._act: Optional[List[Proxy]] = None
        self.new_event = asyncio.Event()
        self.on_removed: Optional[Callable[[Proxy], None]] = None
        self.on_first_key: Optional[Callable[[], None]] = None

    # ------------------------------------------------------------ membership
    def add(self, pp: ParsedProxy, src: str = "file") -> Optional[Proxy]:
        if pp.id in self.proxies:
            return None
        if src == "sub" and now() - self.graveyard.get(pp.id, 0) < 86400:
            return None
        self.graveyard.pop(pp.id, None)
        self.pending_removals.discard(pp.id)
        p = Proxy(pp, src)
        self.proxies[p.id] = p
        self.new_event.set()
        return p

    def remove(self, p: Proxy, reason: str, archive: bool = True) -> None:
        if self.proxies.pop(p.id, None) is None:
            return
        p.state = "removed"
        self._act = None
        self.graveyard[p.id] = now()
        self.pending_removals.add(p.id)
        self.stats.removed += 1
        if archive:
            self.removed_log.append("%s | %s | %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), reason, p.raw))
        if self.pinned == p.id:
            self.pinned = None
        log.info("REMOVED %s (%s)", p.name(), reason)
        asyncio.ensure_future(p.close())
        if self.on_removed:
            self.on_removed(p)

    def set_state(self, p: Proxy, state: str) -> None:
        if p.state != state:
            p.state = state
            self._act = None

    def active(self) -> List[Proxy]:
        if self._act is None:
            self._act = [p for p in self.proxies.values() if p.state == ACTIVE]
        return self._act

    def refresh_mode(self) -> None:
        m = self.cfg.get("egress_mode", "hybrid")
        if m not in MODES:
            m = "hybrid"
        self.mode = m if self.cfg.get("ipv4_direct", True) else "proxies"
        self._elig = None

    def eligible(self) -> List[Proxy]:
        act = self.active()
        if self._elig is None or self._elig_src is not act or self._elig_mode != self.mode:
            m = self.mode
            self._elig = [p for p in act if m == "hybrid" or (p.src == "builtin") == (m == "ipv4")]
            self._elig_src, self._elig_mode = act, m
        return self._elig

    def counts(self) -> Dict[str, int]:
        c = {NEW: 0, TESTING: 0, ACTIVE: 0, DEAD: 0}
        for p in self.proxies.values():
            c[p.state] = c.get(p.state, 0) + 1
        return c

    # ------------------------------------------------------------ selection
    def pick(self, exclude=()) -> Optional[Proxy]:
        act = self.eligible()
        if not act:
            return None
        t = mono()
        if self.pinned:
            pp = self.proxies.get(self.pinned)
            if pp and pp.state == ACTIVE and pp.id not in exclude:
                return pp
        cap = int(self.cfg.get("per_proxy_max_inflight", 64))
        cands = [p for p in act if p.id not in exclude]
        if not cands:
            return None
        ready = [p for p in cands if p.penalty_until <= t]
        cands = ready or cands
        free = [p for p in cands if p.inflight < cap]
        cands = free or cands
        st = self.strategy
        if st == "round_robin":
            self._rr = (self._rr + 1) % len(cands)
            return cands[self._rr]
        if st == "random":
            return random.choice(cands)
        if st == "fastest":
            return min(cands, key=Proxy.score)
        if st in ("sticky", "timed"):
            return self._pick_sticky(cands, exclude, t)
        # adaptive: power-of-three-choices on latency x load
        sample = cands if len(cands) <= 3 else random.sample(cands, 3)
        return min(sample, key=Proxy.score)

    def _pick_sticky(self, cands: List[Proxy], exclude, t: float) -> Proxy:
        cur = self.proxies.get(self.sticky_id) if self.sticky_id else None
        rotate = (self.strategy == "timed"
                  and t - self.sticky_since > float(self.cfg.get("rotate_seconds", 300)))
        if cur is not None and cur in cands and not rotate:
            return cur
        pool = [p for p in cands if not (rotate and cur is not None and p.id == cur.id)] or cands
        if self.strategy == "timed":
            pool.sort(key=lambda p: p.id)
            nxt = pool[0]
            if cur is not None:
                bigger = [p for p in pool if p.id > cur.id]
                nxt = bigger[0] if bigger else pool[0]
        else:
            nxt = min(pool, key=Proxy.score)
        self.sticky_id = nxt.id
        self.sticky_since = t
        return nxt

    def force_next(self) -> Optional[Proxy]:
        cur = self.sticky_id
        act = sorted(self.eligible(), key=lambda p: p.id)
        if not act:
            return None
        nxt = next((p for p in act if cur is None or p.id > cur), act[0])
        self.sticky_id, self.sticky_since = nxt.id, mono()
        self.pinned = None
        return nxt

    async def acquire(self, exclude=(), wait: float = 0.0) -> Optional[Proxy]:
        loop = asyncio.get_event_loop()
        end = loop.time() + wait
        while True:
            p = self.pick(exclude)
            if p is not None:
                p.inflight += 1
                return p
            if exclude or wait <= 0 or loop.time() >= end:
                return None
            await asyncio.sleep(0.05)

    @staticmethod
    def release(p: Proxy) -> None:
        if p.inflight > 0:
            p.inflight -= 1

    # ------------------------------------------------------------ feedback
    def on_success(self, p: Proxy, ttfb_ms: float) -> None:
        p.ok += 1
        p.last_ok = now()
        p.verified = True
        p.ever_ok = True
        if p.fail_score > 0:
            p.fail_score = max(0.0, p.fail_score - 0.5)
        p.live_ms = ttfb_ms if p.live_ms is None else p.live_ms * 0.8 + ttfb_ms * 0.2

    def on_failure(self, p: Proxy, kind: str, detail: str = "") -> None:
        w = FAIL_WEIGHT.get(kind, 1.0)
        p.err += 1
        p.fail_score += w
        p.last_err = redact(detail)[:140]
        t = mono()
        p.penalty_until = t + (1.0 if w < 1 else 3.0)
        if p.fail_score >= 3.0 and p.state == ACTIVE:
            p.next_check = 0.0          # urgent re-probe decides its fate
            p.penalty_until = t + 10.0

    def on_throttle(self, p: Proxy, cooldown: float = 8.0) -> None:
        p.penalty_until = mono() + cooldown

    def on_geo(self, p: Proxy, why: str = "geo-blocked") -> None:
        self.mark_dead(p, why, geo=True)

    # ------------------------------------------------------------ lifecycle
    def revive(self, p: Proxy) -> None:
        if p.state == DEAD:
            log.info("REVIVED %s", p.name())
        self.set_state(p, ACTIVE)
        p.dead_retries = 0
        p.fail_score = 0.0
        p.last_err = ""
        p.ever_ok = True
        if p.group:
            for o in list(self.proxies.values()):
                if o.group == p.group and o.id != p.id:
                    self.remove(o, "sibling protocol of %s works" % p.scheme, archive=False)

    def mark_dead(self, p: Proxy, reason: str, geo: bool = False) -> None:
        if p.state == "removed":
            return
        self.set_state(p, DEAD)
        p.last_err = reason
        p.fail_score = 0.0
        p.dead_retries += 1
        if geo:
            p.geo_hits += 1
        c = self.cfg
        sched = c.get("dead_retry_schedule") or [60]
        if c.get("auto_delete_dead", True) and p.src != "builtin":
            if geo and p.geo_hits >= int(c.get("geo_confirmations", 2)):
                return self.remove(p, "gemini geo-blocked")
            # Safety: only delete for connectivity failures when at least one other proxy works,
            # otherwise it is probably a local outage and we must not wipe the user's list.
            if self.active():
                if not p.ever_ok and p.dead_retries >= int(c.get("never_worked_max_fails", 2)):
                    return self.remove(p, "never worked: " + reason)
                if p.dead_retries > len(sched):
                    return self.remove(p, "dead too long: " + reason)
        p.next_check = mono() + sched[min(p.dead_retries - 1, len(sched) - 1)]
        log.info("DEAD    %s (%s) retest in %ds", p.name(), reason, sched[min(p.dead_retries - 1, len(sched) - 1)])

    # ------------------------------------------------------------ keys
    def learn_key(self, key: str) -> None:
        if not key or key in self.keys or key in self.learned_keys:
            return
        if not self.cfg.get("learn_key_from_traffic", True):
            return
        first = not self.keys and not self.learned_keys
        self.learned_keys = (self.learned_keys + [key])[-3:]
        if first and self.on_first_key:
            self.on_first_key()

    def probe_key(self) -> str:
        if self.keys:
            return self.keys[0]
        return self.learned_keys[0] if self.learned_keys else ""

    def drop_bad_key(self, key: str) -> None:
        if key in self.learned_keys:
            self.learned_keys.remove(key)

    # ------------------------------------------------------------ persistence
    def to_state(self) -> dict:
        return {"version": 2,
                "proxies": {i: p.to_state() for i, p in self.proxies.items() if p.src != "builtin"},
                "graveyard": {k: v for k, v in self.graveyard.items() if now() - v < 86400 * 2},
                "strategy": self.strategy, "pinned": self.pinned}

    def snapshot(self) -> dict:
        c = self.counts()
        order = {ACTIVE: 0, TESTING: 1, NEW: 2, DEAD: 3}
        plist = sorted(self.proxies.values(), key=lambda p: (order.get(p.state, 9), p.lat or 1e9))
        st = self.stats
        return {
            "uptime": int(now() - st.started), "strategy": self.strategy, "pinned": self.pinned, "egress_mode": self.mode,
            "ipv4_direct": bool(self.cfg.get("ipv4_direct", True)),
            "sticky": self.sticky_id, "counts": c, "total_proxies": len(self.proxies),
            "requests": {"total": st.total, "ok": st.ok, "failed": st.failed, "retries": st.retries,
                         "inflight": st.inflight, "rps": round(st.rps(), 1),
                         "p50": round(st.pct(0.5)), "p95": round(st.pct(0.95)), "by_status": st.by_status},
            "removed_total": st.removed,
            "key_known": bool(self.probe_key()), "key_learned": bool(self.learned_keys and not self.keys),
            "proxies": [p.to_public() for p in plist],
        }
