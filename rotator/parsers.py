"""Universal proxy parser: accepts almost anything a person might paste.

Supported: vless / vmess / trojan / ss / socks5 / http(s) URIs, bare ip:port
(tries both http and socks5), host:port:user:pass, user:pass@host:port,
xray JSON outbounds / full configs, base64 subscription blobs, and
subscription URLs (returned separately so the caller can fetch them).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

PROXY_SCHEMES = ("vless", "vmess", "trojan", "ss", "socks5", "socks5h", "socks", "http", "https")
UNSUPPORTED_SCHEMES = ("ssr", "hysteria", "hysteria2", "hy2", "tuic", "wireguard", "socks4", "socks4a", "juicity")

_URI_RE = re.compile(
    r"(?<![A-Za-z0-9])((?:vless|vmess|trojan|ssr|ss|socks5h|socks5|socks4a|socks4|socks|hysteria2|hysteria|hy2|tuic|wireguard|juicity|https?)://[^\s<>\"'`\\]+)",
    re.I,
)
_SPLIT_RE = re.compile(r"(?<=[^\s])(?=(?:vless|vmess|trojan|ssr|hysteria2|hy2|tuic)://)|(?<=[^A-Za-z0-9\s])(?=ss://)", re.I)
_B64_CHARS = re.compile(r"^[A-Za-z0-9+/_=\-\s]+$")
_HOSTPORT = r"(?P<host>\[[0-9a-fA-F:]+\]|[A-Za-z0-9][A-Za-z0-9.\-]*)"
_BARE_PATTERNS = [
    re.compile(r"^(?P<user>[^:@\s]+):(?P<pw>[^@\s]*)@" + _HOSTPORT + r":(?P<port>\d{2,5})$"),
    re.compile(r"^" + _HOSTPORT + r":(?P<port>\d{2,5}):(?P<user>[^:\s]+):(?P<pw>\S*)$"),
    re.compile(r"^" + _HOSTPORT + r":(?P<port>\d{2,5})@(?P<user>[^:\s]+):(?P<pw>\S*)$"),
    re.compile(r"^" + _HOSTPORT + r"[:\s,;|]+(?P<port>\d{2,5})$"),
]


@dataclass
class ParsedProxy:
    id: str
    scheme: str
    label: str
    host: str
    port: int
    outbound: Dict[str, Any]
    raw: str
    group: str = ""


@dataclass
class ParseResult:
    proxies: List[ParsedProxy] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    sub_urls: List[str] = field(default_factory=list)


class ParseError(ValueError):
    pass


# ----------------------------------------------------------------- helpers
def b64decode_lenient(s: str) -> bytes:
    s = re.sub(r"[^A-Za-z0-9+/_\-=]", "", s.strip())
    s = s.replace("-", "+").replace("_", "/").rstrip("=")
    if len(s) % 4 == 1:
        s = s[:-1]
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _qs(query: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True):
        out.setdefault(k.lower(), v)
    return out


def _split_hostport(hp: str, default_port: Optional[int] = None) -> Tuple[str, int]:
    hp = hp.strip().rstrip("/")
    m = re.match(r"^\[([0-9a-fA-F:]+)\](?::(\d+))?$", hp)
    if m:
        host, port = m.group(1), m.group(2)
    elif hp.count(":") == 1:
        host, port = hp.split(":")
    elif hp.count(":") == 0:
        host, port = hp, None
    else:
        raise ParseError("bad host:port")
    if not host:
        raise ParseError("empty host")
    if port in (None, ""):
        if default_port is None:
            raise ParseError("missing port")
        return host, default_port
    p = int(port)
    if not (0 < p < 65536):
        raise ParseError("bad port")
    return host, p


def _truthy(v: Optional[str]) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _make_id(outbound: Dict[str, Any]) -> str:
    blob = json.dumps(outbound, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(blob.encode()).hexdigest()[:8]


def _stream(network: str, security: str, *, sni: str, host_header: str, fp: str, alpn: str,
            path: str, p: Dict[str, str], allow_insecure: bool, address: str,
            header_type: str = "none") -> Dict[str, Any]:
    network = (network or "tcp").lower()
    if network in ("raw",):
        network = "tcp"
    if network == "splithttp":
        network = "xhttp"
    if network == "h2":
        network = "http"
    st: Dict[str, Any] = {"network": network}
    security = (security or "none").lower()
    server_name = sni or host_header or address
    if security == "tls":
        tls: Dict[str, Any] = {"serverName": server_name, "allowInsecure": allow_insecure}
        if fp:
            tls["fingerprint"] = fp
        if alpn:
            tls["alpn"] = [a for a in alpn.split(",") if a]
        st["security"] = "tls"
        st["tlsSettings"] = tls
    elif security == "reality":
        st["security"] = "reality"
        st["realitySettings"] = {
            "serverName": sni or address,
            "fingerprint": fp or "chrome",
            "publicKey": p.get("pbk", ""),
            "shortId": p.get("sid", ""),
            "spiderX": p.get("spx", ""),
        }
    if network == "ws":
        ws: Dict[str, Any] = {"path": path or "/"}
        if host_header:
            ws["headers"] = {"Host": host_header}
        st["wsSettings"] = ws
    elif network == "grpc":
        st["grpcSettings"] = {
            "serviceName": p.get("servicename") or (path or "").lstrip("/"),
            "multiMode": p.get("mode", "") == "multi",
        }
        if p.get("authority"):
            st["grpcSettings"]["authority"] = p["authority"]
    elif network == "http":
        st["httpSettings"] = {"path": path or "/", "host": [h for h in (host_header or "").split(",") if h]}
    elif network == "httpupgrade":
        st["httpupgradeSettings"] = {"path": path or "/", "host": host_header or ""}
    elif network == "xhttp":
        xs: Dict[str, Any] = {"path": path or "/", "mode": p.get("mode") or "auto"}
        if host_header:
            xs["host"] = host_header
        if p.get("extra"):
            try:
                xs["extra"] = json.loads(p["extra"])
            except Exception:
                pass
        st["xhttpSettings"] = xs
    elif network == "kcp":
        st["kcpSettings"] = {"header": {"type": header_type or "none"}, "seed": p.get("seed") or path or ""}
    elif network == "tcp":
        if (header_type or "none") == "http":
            st["tcpSettings"] = {"header": {"type": "http", "request": {
                "path": [x for x in (path or "/").split(",") if x],
                "headers": {"Host": [h for h in (host_header or "").split(",") if h]}}}}
    else:
        raise ParseError("unsupported transport: " + network)
    return st


# ----------------------------------------------------------------- URI parsers
def _userinfo_split(rest: str) -> Tuple[str, str, Dict[str, str], str]:
    """-> (userinfo, hostport, params, label)"""
    label = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        label = urllib.parse.unquote(frag)
    params: Dict[str, str] = {}
    if "?" in rest:
        rest, q = rest.split("?", 1)
        params = _qs(q)
    rest = rest.rstrip("/")
    if "@" not in rest:
        raise ParseError("missing '@'")
    userinfo, hostport = rest.rsplit("@", 1)
    return urllib.parse.unquote(userinfo), hostport, params, label


def parse_vless(uri: str) -> ParsedProxy:
    uuid, hostport, p, label = _userinfo_split(uri[len("vless://"):])
    host, port = _split_hostport(hostport, 443)
    st = _stream(p.get("type", "tcp"), p.get("security", "none"), sni=p.get("sni") or p.get("peer", ""),
                 host_header=p.get("host", ""), fp=p.get("fp", ""), alpn=p.get("alpn", ""),
                 path=urllib.parse.unquote(p.get("path", "")) or "", p=p,
                 allow_insecure=_truthy(p.get("allowinsecure")) or _truthy(p.get("insecure")),
                 address=host, header_type=p.get("headertype", "none"))
    user: Dict[str, Any] = {"id": uuid, "encryption": p.get("encryption") or "none"}
    if p.get("flow"):
        user["flow"] = p["flow"]
    ob = {"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
          "streamSettings": st}
    return ParsedProxy(_make_id(ob), "vless", label, host, port, ob, uri)


def parse_vmess(uri: str) -> ParsedProxy:
    body = uri[len("vmess://"):].split("#", 1)[0]
    try:
        data = json.loads(b64decode_lenient(body).decode("utf-8", "ignore"))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        raise ParseError("vmess payload is broken/truncated")
    if not isinstance(data, dict):
        raise ParseError("vmess payload is not an object")
    host = str(data.get("add") or "").strip()
    uuid = str(data.get("id") or "").strip()
    if not host or not uuid or not data.get("port"):
        raise ParseError("vmess is missing add/port/id (truncated?)")
    port = int(data["port"])
    net = str(data.get("net") or "tcp")
    tls = str(data.get("tls") or "none")
    st = _stream(net, "tls" if tls == "tls" else "none", sni=str(data.get("sni") or ""),
                 host_header=str(data.get("host") or ""), fp=str(data.get("fp") or ""),
                 alpn=str(data.get("alpn") or ""), path=str(data.get("path") or ""),
                 p={"servicename": str(data.get("path") or ""), "mode": str(data.get("mode") or "")},
                 allow_insecure=_truthy(str(data.get("allowInsecure") or data.get("insecure") or "")),
                 address=host, header_type=str(data.get("type") or "none"))
    ob = {"protocol": "vmess", "settings": {"vnext": [{"address": host, "port": port, "users": [
        {"id": uuid, "alterId": int(data.get("aid") or 0), "security": str(data.get("scy") or "auto")}]}]},
          "streamSettings": st}
    return ParsedProxy(_make_id(ob), "vmess", str(data.get("ps") or ""), host, port, ob, uri)


def parse_trojan(uri: str) -> ParsedProxy:
    pw, hostport, p, label = _userinfo_split(uri[len("trojan://"):])
    host, port = _split_hostport(hostport, 443)
    st = _stream(p.get("type", "tcp"), p.get("security", "tls"), sni=p.get("sni") or p.get("peer", ""),
                 host_header=p.get("host", ""), fp=p.get("fp", ""), alpn=p.get("alpn", ""),
                 path=urllib.parse.unquote(p.get("path", "")), p=p,
                 allow_insecure=_truthy(p.get("allowinsecure")) or _truthy(p.get("insecure")),
                 address=host, header_type=p.get("headertype", "none"))
    ob = {"protocol": "trojan", "settings": {"servers": [{"address": host, "port": port, "password": pw}]},
          "streamSettings": st}
    return ParsedProxy(_make_id(ob), "trojan", label, host, port, ob, uri)


def parse_ss(uri: str) -> ParsedProxy:
    rest = uri[len("ss://"):]
    label = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        label = urllib.parse.unquote(frag)
    params: Dict[str, str] = {}
    if "?" in rest:
        rest, q = rest.split("?", 1)
        params = _qs(q)
    rest = rest.rstrip("/")
    if params.get("plugin"):
        raise ParseError("ss plugin (obfs/v2ray-plugin) is not supported by xray")
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        userinfo = urllib.parse.unquote(userinfo)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            dec = b64decode_lenient(userinfo).decode("utf-8", "ignore")
            if ":" not in dec:
                raise ParseError("bad ss userinfo")
            method, password = dec.split(":", 1)
    else:
        dec = b64decode_lenient(rest).decode("utf-8", "ignore")
        if "@" not in dec or ":" not in dec.split("@", 1)[0]:
            raise ParseError("bad legacy ss payload")
        ui, hostport = dec.rsplit("@", 1)
        method, password = ui.split(":", 1)
    host, port = _split_hostport(hostport)
    ob = {"protocol": "shadowsocks",
          "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]},
          "streamSettings": {"network": "tcp"}}
    return ParsedProxy(_make_id(ob), "ss", label, host, port, ob, uri)


def _http_or_socks(scheme: str, host: str, port: int, user: str, pw: str, raw: str, label: str = "",
                   tls: bool = False) -> ParsedProxy:
    server: Dict[str, Any] = {"address": host, "port": port}
    if user:
        server["users"] = [{"user": user, "pass": pw}]
    proto = "http" if scheme in ("http", "https") else "socks"
    st: Dict[str, Any] = {"network": "tcp"}
    if tls:
        st["security"] = "tls"
        st["tlsSettings"] = {"serverName": host, "allowInsecure": False}
    ob = {"protocol": proto, "settings": {"servers": [server]}, "streamSettings": st}
    return ParsedProxy(_make_id(ob), "socks5" if proto == "socks" else scheme, label, host, port, ob, raw)


def parse_http_socks(uri: str) -> ParsedProxy:
    u = urllib.parse.urlsplit(uri)
    scheme = u.scheme.lower()
    if not u.hostname:
        raise ParseError("no host")
    default = {"http": 8080, "https": 443}.get(scheme, 1080)
    port = u.port or default
    scheme = "socks5" if scheme.startswith("socks") else scheme
    return _http_or_socks(scheme, u.hostname, port, urllib.parse.unquote(u.username or ""),
                          urllib.parse.unquote(u.password or ""), uri, urllib.parse.unquote(u.fragment or ""),
                          tls=(scheme == "https"))


def parse_uri(uri: str) -> ParsedProxy:
    uri = uri.strip().rstrip(".,;)")
    low = uri.lower()
    scheme = low.split("://", 1)[0] if "://" in low else ""
    if scheme in UNSUPPORTED_SCHEMES:
        raise ParseError("%s is not supported by xray" % scheme)
    try:
        if scheme == "vless":
            return parse_vless(uri)
        if scheme == "vmess":
            return parse_vmess(uri)
        if scheme == "trojan":
            return parse_trojan(uri)
        if scheme == "ss":
            return parse_ss(uri)
        if scheme in ("http", "https", "socks", "socks5", "socks5h"):
            return parse_http_socks(uri)
    except ParseError:
        raise
    except Exception as e:  # noqa
        raise ParseError("%s: %s" % (scheme or "unknown", e))
    raise ParseError("unknown scheme")


# ----------------------------------------------------------------- bare / json / blob
def parse_bare(line: str) -> List[ParsedProxy]:
    line = line.strip().strip(",;")
    for rx in _BARE_PATTERNS:
        m = rx.match(line)
        if not m:
            continue
        gd = m.groupdict()
        host = gd["host"].strip("[]")
        port = int(gd["port"])
        if not (0 < port < 65536):
            continue
        user, pw = gd.get("user") or "", gd.get("pw") or ""
        auth = ("%s:%s@" % (urllib.parse.quote(user, safe=""), urllib.parse.quote(pw, safe=""))) if user else ""
        hp = "[%s]" % host if ":" in host else host
        out = []
        grp = "bare:%s:%d" % (host, port)
        for sch in ("socks5", "http"):
            pp = _http_or_socks(sch, host, port, user, pw, "%s://%s%s:%d" % (sch, auth, hp, port))
            pp.group = grp
            out.append(pp)
        return out
    return []


_JSON_PROTOS = {"vless", "vmess", "trojan", "shadowsocks", "socks", "http"}


def _from_json(obj: Any, res: ParseResult) -> bool:
    found = False
    if isinstance(obj, list):
        for o in obj:
            found = _from_json(o, res) or found
        return found
    if not isinstance(obj, dict):
        return False
    if "outbounds" in obj and isinstance(obj["outbounds"], list):
        return _from_json(obj["outbounds"], res)
    proto = str(obj.get("protocol") or "").lower()
    if proto in _JSON_PROTOS:
        ob = {k: v for k, v in obj.items() if k not in ("tag", "sendThrough", "mux")}
        ob.setdefault("streamSettings", {"network": "tcp"})
        host, port = "?", 0
        try:
            s = ob.get("settings", {})
            node = (s.get("vnext") or s.get("servers") or [{}])[0]
            host, port = str(node.get("address", "?")), int(node.get("port", 0))
        except Exception:
            pass
        res.proxies.append(ParsedProxy(_make_id(ob), proto, "", host, port, ob, json.dumps(ob, separators=(",", ":"))))
        return True
    return False


def _looks_like_sub_url(u: str) -> bool:
    try:
        sp = urllib.parse.urlsplit(u)
    except ValueError:
        return False
    if sp.scheme.lower() not in ("http", "https") or not sp.hostname:
        return False
    return (sp.path not in ("", "/")) or bool(sp.query)


def parse_text(text: str, _depth: int = 0) -> ParseResult:
    res = ParseResult()
    seen = set()

    def add(pp: ParsedProxy) -> None:
        if pp.id not in seen:
            seen.add(pp.id)
            res.proxies.append(pp)

    text = text.replace("\r", "\n")
    stripped = text.strip()
    if not stripped:
        return res

    # 1) full JSON
    if stripped[0] in "{[":
        try:
            sub = ParseResult()
            if _from_json(json.loads(stripped), sub):
                for pp in sub.proxies:
                    add(pp)
                return res
        except json.JSONDecodeError:
            pass

    # 2) whole-text base64 subscription blob
    if "://" not in stripped and len(stripped) > 40 and _B64_CHARS.match(stripped) and _depth < 2:
        try:
            dec = b64decode_lenient(stripped).decode("utf-8", "ignore")
            if "://" in dec:
                return parse_text(dec, _depth + 1)
        except Exception:
            pass

    # 3) line by line (URIs may also be glued together)
    for raw_line in text.split("\n"):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        uris = [m.group(1) for m in _URI_RE.finditer(line)]
        expanded: List[str] = []
        for u in uris:
            expanded.extend([x for x in _SPLIT_RE.split(u) if x])
        if expanded:
            for u in expanded:
                low = u.lower()
                if low.startswith(("http://", "https://")) and _looks_like_sub_url(u):
                    res.sub_urls.append(u.rstrip(".,;)"))
                    continue
                try:
                    add(parse_uri(u))
                except ParseError as e:
                    res.errors.append("%s... -> %s" % (u[:48], e))
            continue
        if line.startswith("{"):
            try:
                sub = ParseResult()
                if _from_json(json.loads(line), sub):
                    for pp in sub.proxies:
                        add(pp)
                    continue
            except json.JSONDecodeError:
                pass
        bare = parse_bare(line)
        if bare:
            for pp in bare:
                add(pp)
            continue
        if len(line) > 40 and _B64_CHARS.match(line) and _depth < 2:
            try:
                dec = b64decode_lenient(line).decode("utf-8", "ignore")
                if "://" in dec:
                    sub2 = parse_text(dec, _depth + 1)
                    for pp in sub2.proxies:
                        add(pp)
                    res.errors.extend(sub2.errors)
                    continue
            except Exception:
                pass
        res.errors.append("unrecognized: %s" % line[:60])
    return res
