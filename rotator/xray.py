"""Runs many proxies inside a few Xray processes ("shards").

Every proxy gets its own local SOCKS5 inbound on 127.0.0.1:<port> that is routed to
exactly one outbound.  Removing a dead proxy never restarts anything; adding new
proxies only starts a new shard, so live traffic is never interrupted.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import signal
import socket
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .util import HOME, LOG_DIR, RUN_DIR, atomic_write

log = logging.getLogger("rotator.xray")


def find_xray() -> Optional[str]:
    cands = [HOME / "bin" / "xray", HOME / "xray", Path("/usr/local/bin/xray"), Path("/usr/bin/xray")]
    for c in cands:
        if c.exists() and os.access(c, os.X_OK):
            return str(c)
    return shutil.which("xray")


def _pdeathsig():
    """Make xray die if the parent dies (Linux)."""
    try:
        import ctypes
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGKILL)
    except Exception:
        pass


def port_free(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


async def port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), 0.4)
        w.close()
        return True
    except Exception:
        return False


class Shard:
    def __init__(self, sid: int, proc, cfg_path: Path, members: list):
        self.id = sid
        self.proc = proc
        self.cfg_path = cfg_path
        self.members = members
        self.stopping = False


class XrayManager:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.bin = find_xray()
        self.shards: Dict[int, Shard] = {}
        self._sid = 0
        self._next_port = int(cfg.get("local_port_base", 21000))
        self.on_shard_died: Optional[Callable[[Shard], None]] = None

    # ------------------------------------------------------------- ports
    def _alloc_ports(self, n: int) -> List[int]:
        ports: List[int] = []
        while len(ports) < n:
            p = self._next_port
            self._next_port += 1
            if self._next_port > 60000:
                self._next_port = int(self.cfg.get("local_port_base", 21000))
            if port_free(p):
                ports.append(p)
        return ports

    # ------------------------------------------------------------- orphan cleanup
    def kill_orphans(self) -> None:
        f = RUN_DIR / "xray-pids.json"
        if not f.exists():
            return
        try:
            for pid in json.loads(f.read_text()):
                try:
                    with open("/proc/%d/cmdline" % pid, "rb") as fh:
                        if b"xray" in fh.read():
                            os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass
        except Exception:
            pass
        f.unlink(missing_ok=True)

    def _save_pids(self) -> None:
        try:
            pids = [s.proc.pid for s in self.shards.values() if s.proc.returncode is None]
            atomic_write(RUN_DIR / "xray-pids.json", json.dumps(pids))
        except Exception:
            pass

    # ------------------------------------------------------------- config
    @staticmethod
    def _build(members: list, ports: List[int]) -> dict:
        inbounds, outbounds, rules = [], [], []
        for p, port in zip(members, ports):
            tag = "p" + p.id
            inbounds.append({"tag": "in-" + tag, "listen": "127.0.0.1", "port": port,
                             "protocol": "socks", "settings": {"auth": "noauth", "udp": False},
                             "sniffing": {"enabled": False}})
            ob = dict(p.outbound)
            ob["tag"] = "out-" + tag
            outbounds.append(ob)
            rules.append({"type": "field", "inboundTag": ["in-" + tag], "outboundTag": "out-" + tag})
        outbounds.append({"protocol": "freedom", "tag": "direct"})
        outbounds.append({"protocol": "blackhole", "tag": "block"})
        return {"log": {"loglevel": "error"},
                "policy": {"levels": {"0": {"handshake": 6, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5}}},
                "inbounds": inbounds, "outbounds": outbounds,
                "routing": {"domainStrategy": "AsIs", "rules": rules}}

    # ------------------------------------------------------------- start / stop
    async def start_shard(self, members: list) -> List:
        """Start a shard for `members`. Returns the members that could be started.
        If xray rejects the config, bisect to find (and drop) the bad outbound(s)."""
        if not members:
            return []
        if not self.bin:
            raise RuntimeError("xray binary not found (run: bash install.sh)")
        ports = self._alloc_ports(len(members))
        self._sid += 1
        sid = self._sid
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        cfg_path = RUN_DIR / ("shard-%d.json" % sid)
        atomic_write(cfg_path, json.dumps(self._build(members, ports)))
        logf = open(LOG_DIR / ("xray-%d.log" % sid), "wb")
        try:
            proc = await asyncio.create_subprocess_exec(
                self.bin, "run", "-config", str(cfg_path),
                stdout=logf, stderr=logf, stdin=asyncio.subprocess.DEVNULL, preexec_fn=_pdeathsig)
        finally:
            logf.close()
        ready = await self._wait_ready(proc, ports)
        if ready:
            sh = Shard(sid, proc, cfg_path, list(members))
            self.shards[sid] = sh
            for p, port in zip(members, ports):
                p.local_port = port
                p.shard = sid
            self._save_pids()
            asyncio.ensure_future(self._watch(sh))
            log.info("xray shard #%d up with %d proxies", sid, len(members))
            return list(members)
        # failed -> bisect
        await self._kill(proc)
        cfg_path.unlink(missing_ok=True)
        if len(members) == 1:
            log.warning("xray rejected proxy %s (%s) -> dropping", members[0].id, members[0].label or members[0].host)
            members[0].invalid = True
            return []
        mid = len(members) // 2
        a = await self.start_shard(members[:mid])
        b = await self.start_shard(members[mid:])
        return a + b

    async def _wait_ready(self, proc, ports: List[int], timeout: float = 10.0) -> bool:
        loop = asyncio.get_event_loop()
        end = loop.time() + timeout
        probe = [ports[0], ports[-1]]
        while loop.time() < end:
            if proc.returncode is not None:
                return False
            if all([await port_open(p) for p in probe]):
                await asyncio.sleep(0.05)
                if proc.returncode is None:
                    return True
                return False
            await asyncio.sleep(0.1)
        return False

    async def _watch(self, sh: Shard) -> None:
        rc = await sh.proc.wait()
        if sh.stopping:
            return
        log.error("xray shard #%d exited unexpectedly (code %s)", sh.id, rc)
        self.shards.pop(sh.id, None)
        self._save_pids()
        if self.on_shard_died:
            try:
                self.on_shard_died(sh)
            except Exception:
                log.exception("on_shard_died")

    async def _kill(self, proc) -> None:
        if proc.returncode is not None:
            return
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), 3)
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        except ProcessLookupError:
            pass

    async def stop_shard(self, sid: int, grace: float = 0.0) -> None:
        sh = self.shards.pop(sid, None)
        if not sh:
            return
        sh.stopping = True
        if grace:
            await asyncio.sleep(grace)
        await self._kill(sh.proc)
        sh.cfg_path.unlink(missing_ok=True)
        self._save_pids()
        log.info("xray shard #%d stopped", sid)

    async def stop_all(self) -> None:
        for sid in list(self.shards):
            await self.stop_shard(sid)
