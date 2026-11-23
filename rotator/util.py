from __future__ import annotations

import json
import logging
import logging.handlers
import os
import re
import resource
import time
from pathlib import Path

HOME = Path(os.environ.get("ROTATOR_HOME") or Path(__file__).resolve().parent.parent)
DATA_DIR = HOME / "data"
LOG_DIR = HOME / "logs"
RUN_DIR = HOME / "run"
CONFIG_FILE = HOME / "config.json"
PROXIES_FILE = HOME / "proxies.txt"
STATE_FILE = DATA_DIR / "state.json"
REMOVED_FILE = DATA_DIR / "removed.txt"

DEFAULT_CONFIG = {
    "listen": "127.0.0.1",
    "gateway_port": 8787,
    "http_port": 8118,
    "socks_port": 1080,
    "admin_port": 8790,
    "admin_listen": "127.0.0.1",
    "access_token": "",
    "proxy_auth": "",
    "upstream": "https://generativelanguage.googleapis.com",
    "api_keys": [],
    "gemini_api_key": "",
    "learn_key_from_traffic": True,
    "probe_model": "gemini-2.5-flash",
    "strategy": "adaptive",
    "ipv4_direct": True,
    "egress_mode": "hybrid",
    "ipv4_send_through": "auto",
    "rotate_seconds": 300,
    "max_attempts": 4,
    "connect_timeout": 5,
    "read_timeout": 180,
    "queue_wait": 4,
    "per_proxy_max_inflight": 64,
    "max_body_mb": 64,
    "test_timeout": 8,
    "test_concurrency": 40,
    "probe_interval": 60,
    "shard_size": 50,
    "local_port_base": 21000,
    "auto_delete_dead": True,
    "dead_retry_schedule": [20, 120, 600, 3600],
    "never_worked_max_fails": 2,
    "geo_confirmations": 2,
    "subscriptions": [],
    "sub_refresh_minutes": 60,
    "proxy_hosts": ["googleapis.com", "google.com", "gstatic.com", "googleusercontent.com", "ai.google.dev"],
    "other_hosts": "direct",
    "fallback_direct": False,
    "debug_headers": True,
    "log_level": "INFO",
}

_KEY_RE = re.compile(r"(key=)[^&\s\"']+", re.I)


def redact(s: str) -> str:
    return _KEY_RE.sub(r"\1***", s)


def now() -> float:
    return time.time()


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        try:
            user = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            cfg.update({k: v for k, v in user.items() if not k.startswith("_")})
        except Exception as e:  # noqa
            logging.getLogger("rotator").warning("bad config.json: %s", e)
    keys = [k.strip() for k in (cfg.get("api_keys") or []) if str(k).strip()]
    legacy = (cfg.get("gemini_api_key") or "").strip()
    if legacy and legacy not in keys:
        keys.append(legacy)
    cfg["api_keys"] = keys
    return cfg


def save_config_key(key: str, value) -> None:
    data = {}
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    data[key] = value
    atomic_write(CONFIG_FILE, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def setup_logging(level: str = "INFO", to_file: bool = True) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)-5s %(message)s", "%H:%M:%S")
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)
    if to_file:
        fh = logging.handlers.RotatingFileHandler(
            LOG_DIR / "rotator.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)


def raise_nofile() -> None:
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = hard if hard != resource.RLIM_INFINITY else 1048576
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass
