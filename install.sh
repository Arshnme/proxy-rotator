#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  Gemini Rotator - installer, service manager and interactive control panel
#
#  Interactive menu :  bash install.sh
#  Direct commands  :  bash install.sh <command>
#
#  install [--local] [--reset-config]   start  stop  restart  status  live
#  enable  disable  add [text|-f file]  list  remove <sel>  recheck [sel]
#  strategy [name]  next  pin [sel]  mode [hybrid|ipv4|proxies|enable|disable]
#  config [key [value]]  config-default  config-reset  logs  test <uri>  bot
#  update  uninstall
#
#  Config handling: an existing config.json is validated and used exactly as it
#  is - installing never rewrites your settings.  The shipped template is only
#  written when the file is missing; config-default prints it, config-reset
#  restores it (the previous file is kept as config.json.bak.<timestamp>).
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE="gemini-rotator"
UNIT="/etc/systemd/system/${SERVICE}.service"
VENV="$DIR/venv"
PY="$VENV/bin/python"
RUN="$DIR/run"
LOGS="$DIR/logs"
PIDFILE="$RUN/rotator.pid"
CONFIG="$DIR/config.json"
export ROTATOR_HOME="$DIR"

# ── ui ────────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[34m'; C=$'\033[36m'; D=$'\033[2m'; BD=$'\033[1m'; N=$'\033[0m'
else
  R=''; G=''; Y=''; B=''; C=''; D=''; BD=''; N=''
fi
info() { echo -e "${B}[i]${N} $*"; }
ok()   { echo -e "${G}[✓]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
err()  { echo -e "${R}[✗]${N} $*" >&2; }
die()  { err "$*"; exit 1; }
pause() { [[ -t 0 ]] && { echo; read -rp "  ${D}press Enter to continue...${N}" _; }; return 0; }
ask()  { local a; read -rp "  $1 ${D}[${2:-}]${N} " a; echo "${a:-${2:-}}"; }
yesno() { local a; read -rp "  $1 ${D}[${2:-y}/$([[ ${2:-y} == y ]] && echo n || echo y)]${N} " a; a="${a:-${2:-y}}"; [[ "$a" =~ ^[Yy] ]]; }

is_root()      { [[ $EUID -eq 0 ]]; }
has_systemd()  { command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; }
use_systemd()  { is_root && has_systemd && [[ -f "$UNIT" ]]; }
installed()    { [[ -x "$PY" && -x "$DIR/bin/xray" || -x "$PY" && -x /usr/local/bin/xray ]]; }

cfg_get() { # key [fallback] - never fails, prints the fallback if the file/key is unusable
  python3 - "$CONFIG" "$1" "${2:-}" <<'EOF' 2>/dev/null || echo "${2:-}"
import json, sys
try: d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception: d = {}
v = d.get(sys.argv[2], sys.argv[3])
print(json.dumps(v) if isinstance(v, (list, dict)) else v)
EOF
}
cfg_write() { # key json-value  (merges one key into config.json, creating it from the template first)
  [[ -f "$CONFIG" ]] || ensure_config
  python3 - "$CONFIG" "$1" "$2" <<'EOF'
import json, sys, os
p, key, raw = sys.argv[1], sys.argv[2], sys.argv[3]
try: d = json.load(open(p, encoding="utf-8"))
except Exception: d = {}
try: v = json.loads(raw)
except Exception: v = raw
d[key] = v
tmp = p + ".tmp"
open(tmp, "w", encoding="utf-8").write(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
os.replace(tmp, p)
EOF
}

# ── config.json ───────────────────────────────────────────────────────────────
#  The rotator reads $DIR/config.json and this installer treats it as the single
#  source of truth:
#    * an existing config.json is validated and used EXACTLY as it is - installing
#      or repairing never rewrites your settings;
#    * the shipped template below is written only when the file is missing
#      (fresh clone / deleted by hand), so a new machine comes up with the very
#      same settings that ship in the repository;
#    * only --reset-config / config-reset replaces the file, keeping a
#      timestamped backup of the previous one.
#  Keep this template in sync with config.json in the repository and with
#  DEFAULT_CONFIG in rotator/util.py (that file documents every other key).
default_config() {
  cat <<'JSON'
{
  "listen": "127.0.0.1",
  "gateway_port": 8787,
  "http_port": 8118,
  "socks_port": 1080,
  "admin_port": 8790,
  "access_token": "",
  "api_keys": [],
  "learn_key_from_traffic": true,
  "probe_model": "gemini-2.5-flash",
  "strategy": "adaptive",
  "ipv4_direct": true,
  "egress_mode": "ipv4",
  "max_attempts": 4,
  "connect_timeout": 5,
  "read_timeout": 180,
  "per_proxy_max_inflight": 64,
  "probe_interval": 60,
  "test_concurrency": 40,
  "auto_delete_dead": true,
  "fallback_direct": false
}
JSON
}

config_check() { # prints a one-line summary on success, the problem on failure
  python3 - "$CONFIG" <<'PY'
import json, sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
except Exception as e:
    sys.exit("not valid JSON (%s)" % e)
if not isinstance(cfg, dict):
    sys.exit("the file must contain a JSON object")

ports = []
for key in ("gateway_port", "http_port", "socks_port", "admin_port"):
    v = cfg.get(key)
    if v is None:
        ports.append("-")
        continue
    if isinstance(v, bool) or not isinstance(v, int) or not (0 <= v < 65536):
        sys.exit("%s must be a port number 0-65535 (0 disables http/socks), got %r" % (key, v))
    ports.append(str(v))
if not cfg.get("gateway_port"):
    sys.exit("gateway_port is required and cannot be 0")

strategy = cfg.get("strategy", "adaptive")
if strategy not in ("adaptive", "round_robin", "fastest", "random", "sticky", "timed"):
    sys.exit("unknown strategy %r (adaptive|round_robin|fastest|random|sticky|timed)" % strategy)
mode = cfg.get("egress_mode", "hybrid")
if mode not in ("hybrid", "ipv4", "proxies"):
    sys.exit("unknown egress_mode %r (hybrid|ipv4|proxies)" % mode)
if not str(cfg.get("listen", "127.0.0.1")).strip():
    sys.exit("listen must not be empty")
keys = len([k for k in (cfg.get("api_keys") or []) if str(k).strip()])
print("ports gateway/http/socks/admin=%s  strategy=%s  egress=%s  gemini key=%s"
      % ("/".join(ports), strategy, mode, "set" if keys else "not set"))
PY
}

ensure_config() { # [--reset-config]  create or validate config.json, never clobber it
  local reset=0 a
  for a in "$@"; do [[ "$a" == "--reset-config" || "$a" == "--reset" ]] && reset=1; done
  if [[ -f "$CONFIG" && $reset -eq 0 ]]; then
    local summary
    if ! summary="$(config_check 2>&1)"; then
      err "config.json is not usable: $summary"
      echo "    fix it by hand, or restore the shipped settings with:" >&2
      echo "      bash install.sh config-reset        (previous file is backed up)" >&2
      exit 1
    fi
    ok "config.json kept exactly as it is  ($summary)"
    return 0
  fi
  if [[ -f "$CONFIG" ]]; then
    local bak="$CONFIG.bak.$(date +%Y%m%d-%H%M%S)"
    cp -p "$CONFIG" "$bak" || die "cannot back up $CONFIG"
    ok "previous config.json saved as $(basename "$bak")"
  fi
  default_config > "$CONFIG.tmp" && mv "$CONFIG.tmp" "$CONFIG" || die "cannot write $CONFIG"
  config_check > /dev/null || die "the generated config.json did not validate - please report this"
  ok "config.json written from the shipped template"
}

# ── dependencies ──────────────────────────────────────────────────────────────
pkg_install() {
  local pk="$*"
  if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $pk
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q $pk
  elif command -v yum >/dev/null 2>&1; then yum install -y -q $pk
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache $pk
  elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm $pk
  else return 1; fi
}

ensure_deps() {
  local missing=()
  command -v python3 >/dev/null 2>&1 || missing+=(python3)
  command -v curl    >/dev/null 2>&1 || missing+=(curl)
  command -v unzip   >/dev/null 2>&1 || missing+=(unzip)
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import venv, ensurepip' 2>/dev/null || {
      if command -v apt-get >/dev/null 2>&1; then missing+=(python3-venv python3-pip); fi; }
  fi
  if ((${#missing[@]})); then
    is_root || die "missing: ${missing[*]} - install them (or re-run with sudo)."
    info "installing system packages: ${missing[*]}"
    pkg_install "${missing[@]}" ca-certificates || die "package install failed"
  fi
  python3 - <<'EOF' || die "Python 3.8+ is required"
import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)
EOF
}

setup_venv() {
  if [[ ! -x "$PY" ]]; then
    info "creating virtualenv..."
    python3 -m venv "$VENV" || die "venv creation failed (install python3-venv)"
  fi
  info "installing python packages..."
  "$PY" -m pip install -q --upgrade pip >/dev/null 2>&1 || true
  "$PY" -m pip install -q -r "$DIR/requirements.txt" || die "pip install failed"
  "$PY" -m pip install -q uvloop >/dev/null 2>&1 && ok "uvloop enabled (faster event loop)" || warn "uvloop not available - using default loop"
  ok "python environment ready"
}

xray_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "64" ;; aarch64|arm64) echo "arm64-v8a" ;;
    armv7l) echo "arm32-v7a" ;; i386|i686) echo "32" ;;
    *) die "unsupported CPU: $(uname -m)" ;;
  esac
}

install_xray() { # [--local] [--force]
  local local_mode=0 force=0 a
  for a in "$@"; do [[ "$a" == "--local" || "$a" == "--offline" ]] && local_mode=1; [[ "$a" == "--force" ]] && force=1; done
  mkdir -p "$DIR/bin"
  if [[ -x "$DIR/bin/xray" && $force -eq 0 ]]; then ok "xray present: $("$DIR/bin/xray" version | head -1)"; return 0; fi
  local file="Xray-linux-$(xray_arch).zip" tmp; tmp="$(mktemp -d)"
  if [[ $local_mode -eq 1 ]]; then
    [[ -f "$DIR/$file" ]] || die "offline mode: put $file next to install.sh"
    cp "$DIR/$file" "$tmp/x.zip"
  else
    info "downloading latest Xray-core ($file)..."
    curl -fL --retry 3 --connect-timeout 15 --progress-bar -o "$tmp/x.zip" \
      "https://github.com/XTLS/Xray-core/releases/latest/download/$file" \
      || { rm -rf "$tmp"; die "download failed (blocked? download $file manually, put it next to install.sh and run: bash install.sh install --local)"; }
  fi
  unzip -q -o "$tmp/x.zip" xray -d "$tmp" || { rm -rf "$tmp"; die "bad zip"; }
  install -m 755 "$tmp/xray" "$DIR/bin/xray"; rm -rf "$tmp"
  ok "xray installed: $("$DIR/bin/xray" version | head -1)"
}

# ── service control ───────────────────────────────────────────────────────────
write_service() {
  local owner; owner="$(stat -c %U "$DIR" 2>/dev/null || echo root)"
  cat > "$UNIT" <<EOF
[Unit]
Description=Gemini Rotator (Xray proxy pool + Gemini gateway)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$owner
WorkingDirectory=$DIR
Environment=ROTATOR_HOME=$DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=$PY -m rotator run
Restart=always
RestartSec=3
KillMode=mixed
TimeoutStopSec=15
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  ok "systemd service written ($UNIT)"
}

is_running() {
  if use_systemd; then systemctl is-active --quiet "$SERVICE" && return 0; fi
  [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null
}

autostart_state() {
  if use_systemd; then systemctl is-enabled --quiet "$SERVICE" 2>/dev/null && echo "ON" || echo "OFF"
  elif crontab -l 2>/dev/null | grep -q "$DIR/install.sh start"; then echo "ON (cron @reboot)"
  else echo "OFF"; fi
}

do_start() {
  installed || die "not installed yet - run: bash install.sh install"
  ensure_config
  if is_running; then ok "already running"; return 0; fi
  mkdir -p "$RUN" "$LOGS"
  if use_systemd; then systemctl start "$SERVICE"
  else
    ( cd "$DIR" && exec setsid nohup "$PY" -m rotator run >> "$LOGS/stdout.log" 2>&1 < /dev/null ) &
    echo $! > "$PIDFILE"; disown 2>/dev/null || true
  fi
  local i; for i in $(seq 1 40); do
    curl -fs --max-time 1 "http://127.0.0.1:$(cfg_get admin_port 8790)/status" >/dev/null 2>&1 && { ok "started"; return 0; }
    sleep 0.25
  done
  warn "started but admin API did not answer yet - check logs (menu 10)"
}

do_stop() {
  if use_systemd && systemctl is-active --quiet "$SERVICE"; then systemctl stop "$SERVICE"; ok "stopped"; return 0; fi
  if [[ -f "$PIDFILE" ]]; then
    local pid; pid="$(cat "$PIDFILE")"
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null
      local i; for i in $(seq 1 40); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
      kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null
    fi
    rm -f "$PIDFILE"; ok "stopped"
  else warn "not running"; fi
}

do_restart() { do_stop; sleep 1; do_start; }

do_enable() {
  installed || die "install first"
  if is_root && has_systemd; then
    [[ -f "$UNIT" ]] || write_service
    systemctl enable "$SERVICE" >/dev/null 2>&1 && ok "autostart ENABLED (systemd)"
  else
    ( crontab -l 2>/dev/null | grep -v "$DIR/install.sh start"; echo "@reboot sleep 15 && bash $DIR/install.sh start >/dev/null 2>&1" ) | crontab - \
      && ok "autostart ENABLED (cron @reboot)" || err "could not edit crontab"
  fi
}

do_disable() {
  if use_systemd; then systemctl disable "$SERVICE" >/dev/null 2>&1; ok "autostart DISABLED (systemd)"
  else ( crontab -l 2>/dev/null | grep -v "$DIR/install.sh start" ) | crontab - 2>/dev/null; ok "autostart DISABLED"; fi
}

do_install() {
  echo -e "\n${BD}Installing Gemini Rotator${N}"
  ensure_deps
  ensure_config "$@"
  setup_venv
  install_xray "$@"
  mkdir -p "$RUN" "$LOGS" "$DIR/data"
  [[ -f "$DIR/proxies.txt" ]] || echo "# paste proxies here, any format" > "$DIR/proxies.txt"
  if is_root && has_systemd; then
    write_service
    if [[ -t 0 ]]; then yesno "Start automatically on boot?" y && do_enable || do_disable; else do_enable; fi
  else
    warn "not root / no systemd: running in background-process mode (use 'enable' for cron autostart)"
  fi
  if [[ "$(cfg_get api_keys '[]')" == "[]" ]]; then
    info "no Gemini API key configured: proxies will be verified as 'reachable' only"
    info "add one later from the menu (8 -> 1) - the installer never edits config.json"
  fi
  ok "installation complete"
  if [[ -t 0 ]]; then yesno "Start now?" y && do_restart; else do_restart; fi
}

do_uninstall() {
  yesno "${R}Remove the service and stop everything?${N}" n || return 0
  do_stop; do_disable
  if is_root && [[ -f "$UNIT" ]]; then rm -f "$UNIT"; systemctl daemon-reload; ok "service removed"; fi
  if yesno "Also delete venv, bin/xray, data/ and logs/ (proxies.txt and config.json are kept)?" n; then
    rm -rf "$VENV" "$DIR/bin" "$DIR/data" "$LOGS" "$RUN"; ok "files removed"
  fi
  ok "uninstalled"
}

# ── helpers to talk to the daemon ─────────────────────────────────────────────
ctl() { [[ -x "$PY" ]] || die "not installed - run: bash install.sh install"; ( cd "$DIR" && "$PY" -m rotator "$@" ); }
need_running() { is_running || { warn "rotator is not running - start it first (menu 2)"; return 1; }; }

paste_block() { # -> prints temp file path with pasted text
  local tmp line blanks=0; tmp="$(mktemp)"
  echo "  Paste proxies in ANY format (vless/vmess/trojan/ss/socks5/http links, ip:port, JSON,"
  echo "  base64 subscription, subscription URL).  Finish: two empty lines, or type ${BD}done${N}, or Ctrl-D." >&2
  while IFS= read -r line; do
    case "${line,,}" in done|end|".") break ;; esac
    if [[ -z "${line//[[:space:]]/}" ]]; then blanks=$((blanks+1)); ((blanks>=2)) && break; continue; fi
    blanks=0; printf '%s\n' "$line" >> "$tmp"
  done
  echo "$tmp"
}

add_file() { # path
  [[ -s "$1" ]] || { warn "nothing to add"; return; }
  if is_running; then ctl add -f "$1"
  else
    ( echo; echo "# added $(date '+%F %H:%M')"; cat "$1" ) >> "$DIR/proxies.txt"
    ok "appended to proxies.txt (will be tested when the rotator starts)"
  fi
}

set_api_key() {
  echo "  Get a key at https://aistudio.google.com/apikey  (leave empty to clear)"
  local k; read -rsp "  API key: " k; echo
  if is_running; then ctl config api_keys "$( [[ -n "$k" ]] && printf '["%s"]' "$k" || echo '[]')" >/dev/null
  else cfg_write api_keys "$( [[ -n "$k" ]] && printf '["%s"]' "$k" || echo '[]')"; fi
  [[ -n "$k" ]] && ok "key saved - proxies will be re-verified against Gemini" || ok "key cleared"
}

show_bot() {
  local gp hp sp tok; gp="$(cfg_get gateway_port 8787)"; hp="$(cfg_get http_port 8118)"; sp="$(cfg_get socks_port 1080)"; tok="$(cfg_get access_token '')"
  cat <<EOF

${BD}Connect your Telegram bot${N}

${C}A) Recommended - change only the Gemini base URL (retries + failover are transparent)${N}
   Replace  https://generativelanguage.googleapis.com
   with     http://127.0.0.1:${gp}

   # aiohttp / requests / httpx - same path, same key
   URL = "http://127.0.0.1:${gp}/v1beta/models/gemini-2.5-flash:generateContent"
   r = await session.post(URL, headers={"x-goog-api-key": KEY}, json=payload)

   # official google-genai SDK
   from google import genai
   client = genai.Client(api_key=KEY, http_options={"base_url": "http://127.0.0.1:${gp}"})
EOF
  [[ -n "$tok" ]] && echo "   (add header  X-Rotator-Token: <your access_token>  to every request)"
  cat <<EOF

${C}B) HTTP proxy mode - only googleapis.com traffic goes through the pool, everything else (e.g. Telegram) goes direct${N}
   export HTTPS_PROXY=http://127.0.0.1:${hp}
   # or aiohttp: session.post(url, proxy="http://127.0.0.1:${hp}")

${C}C) SOCKS5${N}
   socks5://127.0.0.1:${sp}

Response headers  X-Rotator-Proxy / X-Rotator-Attempts  tell you which proxy served the call.
EOF
}

# ── sub-menus ─────────────────────────────────────────────────────────────────
menu_proxies() {
  while true; do
    clear; echo -e "${BD}  PROXY MANAGER${N}\n"
    echo "   1) Add proxies (paste, any format)"
    echo "   2) Add from a file"
    echo "   3) Add from a subscription URL"
    echo "   4) List proxies"
    echo "   5) Re-test all now"
    echo "   6) Remove dead proxies now"
    echo "   7) Remove one proxy (id / host / name)"
    echo "   8) Check how a text would be parsed (no changes)"
    echo "   9) Remove ALL proxies"
    echo "   0) Back"
    local c; read -rp "  > " c
    case "$c" in
      1) local t; t="$(paste_block)"; add_file "$t"; rm -f "$t"; pause ;;
      2) local f; f="$(ask 'Path to file' '')"; [[ -f "$f" ]] && add_file "$f" || warn "file not found"; pause ;;
      3) local u; u="$(ask 'Subscription URL' '')"; [[ -n "$u" ]] && { need_running && ctl add "$u" || cfg_write subscriptions "[\"$u\"]"; }; pause ;;
      4) need_running && ctl list; pause ;;
      5) need_running && ctl recheck all; pause ;;
      6) need_running && ctl remove dead; pause ;;
      7) local s; s="$(ask 'id / host / label' '')"; [[ -n "$s" ]] && need_running && ctl remove "$s"; pause ;;
      8) local t2; t2="$(paste_block)"; ctl parse -f "$t2"; rm -f "$t2"; pause ;;
      9) yesno "${R}Remove ALL proxies (they are archived in data/removed.txt)?${N}" n && need_running && ctl remove all; pause ;;
      0|"") return ;;
    esac
  done
}

menu_strategy() {
  while true; do
    clear; echo -e "${BD}  SWITCHING STRATEGY${N}   current: ${C}$(need_running >/dev/null 2>&1 && ctl strategy | awk '{print $1}' || cfg_get strategy adaptive)${N}\n"
    cat <<EOF
   1) adaptive     latency x load aware (power-of-3-choices) - best for many parallel requests  [default]
   2) fastest      always the lowest-latency proxy (can concentrate load)
   3) round_robin  strict rotation across all healthy proxies
   4) random       uniformly random healthy proxy
   5) sticky       stay on ONE proxy until it fails, then switch (old behaviour)
   6) timed        like sticky, but rotate to the next proxy every N seconds
   7) Switch to the next proxy NOW (sticky/timed)
   8) Pin a specific proxy (all traffic) / unpin
   9) Set rotate interval for 'timed' (seconds)
  ${BD}Egress mode${N}  (3x-ui style "freedom + UseIPv4 + sendThrough" direct route, fixes Gemini 403 / location errors)
  10) Choose egress mode:  hybrid (proxies + server IPv4) | ipv4 (server IPv4 only) | proxies (proxies only)
  11) Enable / disable the IPv4-direct feature          now: $(cfg_get ipv4_direct true), mode: $(cfg_get egress_mode hybrid)
   0) Back
EOF
    local c; read -rp "  > " c
    local name=""
    case "$c" in 1) name=adaptive;; 2) name=fastest;; 3) name=round_robin;; 4) name=random;; 5) name=sticky;; 6) name=timed;; esac
    if [[ -n "$name" ]]; then
      if is_running; then ctl strategy "$name"; else cfg_write strategy "\"$name\""; ok "saved (applies on next start)"; fi; pause
    else case "$c" in
      7) need_running && ctl next; pause ;;
      8) need_running && { ctl list; local s; s="$(ask 'id to pin (empty = unpin)' '')"; ctl pin "$s"; }; pause ;;
      9) local n; n="$(ask 'Seconds' "$(cfg_get rotate_seconds 300)")"; is_running && ctl config rotate_seconds "$n" || cfg_write rotate_seconds "$n"; pause ;;
      10) echo "   1) hybrid   - proxies + the server's own IPv4, balanced together"
          echo "   2) ipv4     - ONLY the server's own IPv4 (no proxies)"
          echo "   3) proxies  - ONLY proxies"
          local m; read -rp "  > " m
          case "$m" in 1) m=hybrid;; 2) m=ipv4;; 3) m=proxies;; *) m="";; esac
          if [[ -n "$m" ]]; then if is_running; then ctl mode "$m"; else cfg_write egress_mode "\"$m\""; cfg_write ipv4_direct true; ok "saved"; fi; fi; pause ;;
      11) if yesno "Enable the IPv4-direct feature?" y; then is_running && ctl mode enable || cfg_write ipv4_direct true; else is_running && ctl mode disable || cfg_write ipv4_direct false; fi; pause ;;
      0|"") return ;;
    esac; fi
  done
}

setcfg() { if is_running; then ctl config "$1" "$2"; else cfg_write "$1" "$2"; ok "saved (applies on next start)"; fi; }

menu_settings() {
  while true; do
    clear; echo -e "${BD}  SETTINGS${N}\n"
    cat <<EOF
   1) Gemini API key (real verification of every proxy)       now: $( [[ "$(cfg_get api_keys '[]')" == "[]" ]] && echo "none" || echo "set" )
   2) Auto-delete dead proxies                                now: $(cfg_get auto_delete_dead true)
   3) Learn API key from your bot's traffic                   now: $(cfg_get learn_key_from_traffic true)
   4) Max retry attempts per request                          now: $(cfg_get max_attempts 4)
   5) Connect timeout (s)                                     now: $(cfg_get connect_timeout 5)
   6) Read timeout (s) - long generations need more           now: $(cfg_get read_timeout 180)
   7) Health-probe interval (s)                               now: $(cfg_get probe_interval 60)
   8) Parallel health tests                                   now: $(cfg_get test_concurrency 40)
   9) Max parallel requests per proxy (soft cap)              now: $(cfg_get per_proxy_max_inflight 64)
  10) Listen address (127.0.0.1 = local only, 0.0.0.0 = network) now: $(cfg_get listen 127.0.0.1)
  11) Ports (gateway / http / socks / admin)                  now: $(cfg_get gateway_port 8787) / $(cfg_get http_port 8118) / $(cfg_get socks_port 1080) / $(cfg_get admin_port 8790)
  12) Generate / clear access token (protects gateway + admin)
  13) Fallback to DIRECT connection when no proxy works       now: $(cfg_get fallback_direct false)
  14) Subscription URLs (auto-refreshed)                      now: $(cfg_get subscriptions '[]')
  15) Show full config.json
  16) Reset config.json to the shipped template (backup kept)
   0) Back
EOF
    local c; read -rp "  > " c
    case "$c" in
      1) set_api_key; pause ;;
      2) yesno "Auto-delete dead proxies?" y && setcfg auto_delete_dead true || setcfg auto_delete_dead false; pause ;;
      3) yesno "Learn API key from traffic?" y && setcfg learn_key_from_traffic true || setcfg learn_key_from_traffic false; pause ;;
      4) setcfg max_attempts "$(ask 'Attempts' "$(cfg_get max_attempts 4)")"; pause ;;
      5) setcfg connect_timeout "$(ask 'Seconds' "$(cfg_get connect_timeout 5)")"; pause ;;
      6) setcfg read_timeout "$(ask 'Seconds' "$(cfg_get read_timeout 180)")"; pause ;;
      7) setcfg probe_interval "$(ask 'Seconds' "$(cfg_get probe_interval 60)")"; pause ;;
      8) setcfg test_concurrency "$(ask 'Parallel tests' "$(cfg_get test_concurrency 40)")"; pause ;;
      9) setcfg per_proxy_max_inflight "$(ask 'Requests' "$(cfg_get per_proxy_max_inflight 64)")"; pause ;;
      10) local l; l="$(ask 'Listen address' "$(cfg_get listen 127.0.0.1)")"
          if [[ "$l" != "127.0.0.1" ]]; then warn "Exposed to the network! Set an access token (12) and use a firewall."; fi
          cfg_write listen "\"$l\""; warn "restart required"; pause ;;
      11) cfg_write gateway_port "$(ask 'Gateway (reverse) port' "$(cfg_get gateway_port 8787)")"
          cfg_write http_port "$(ask 'HTTP proxy port (0 = off)' "$(cfg_get http_port 8118)")"
          cfg_write socks_port "$(ask 'SOCKS5 port (0 = off)' "$(cfg_get socks_port 1080)")"
          cfg_write admin_port "$(ask 'Admin API port' "$(cfg_get admin_port 8790)")"; warn "restart required"; pause ;;
      12) if yesno "Generate a new random token? (n = clear it)" y; then
            local t; t="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"; cfg_write access_token "\"$t\""; ok "token: $t"
          else cfg_write access_token '""'; ok "token cleared"; fi; warn "restart required"; pause ;;
      13) yesno "Allow direct fallback?" n && setcfg fallback_direct true || setcfg fallback_direct false; pause ;;
      14) local s; s="$(ask 'URL(s), comma separated (empty = none)' '')"
          local js; js="$(python3 -c 'import json,sys;print(json.dumps([x.strip() for x in sys.argv[1].split(",") if x.strip()]))' "$s")"; setcfg subscriptions "$js"; pause ;;
      15) python3 -c 'import json,sys;print(json.dumps(json.load(open(sys.argv[1],encoding="utf-8")),indent=2,ensure_ascii=False))' "$CONFIG"; pause ;;
      16) yesno "Replace config.json with the shipped template? (the current file is backed up)" n && { ensure_config --reset-config; warn "restart to apply ports/listen changes"; }; pause ;;
      0|"") if is_running && yesno "Restart now to apply port/listen changes?" n; then do_restart; fi; return ;;
    esac
  done
}

# ── main menu ─────────────────────────────────────────────────────────────────
header() {
  local st="${R}stopped${N}" info_line=""
  if is_running; then
    st="${G}running${N}"
    info_line="$(curl -fs --max-time 1 "http://127.0.0.1:$(cfg_get admin_port 8790)/status" 2>/dev/null | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin); c = d["counts"]; r = d["requests"]
    print("%d active / %d dead / %d testing   %s req/s   strategy: %s" % (c["active"], c["dead"], c["testing"]+c["new"], r["rps"], d["strategy"]))
except Exception: pass' 2>/dev/null)"
  fi
  echo -e "${BD}${C}  ╔══════════════════════════════════════════════════════════════╗"
  echo -e "  ║              GEMINI ROTATOR  -  control panel                ║"
  echo -e "  ╚══════════════════════════════════════════════════════════════╝${N}"
  echo -e "   status: $st    autostart: ${BD}$(autostart_state)${N}    installed: $(installed && echo "${G}yes${N}" || echo "${R}no${N}")"
  [[ -n "$info_line" ]] && echo -e "   ${D}$info_line${N}"
  echo
}

main_menu() {
  while true; do
    clear; header
    cat <<EOF
    1) Install / repair         (config.json is kept exactly as it is)
    2) Start        3) Stop        4) Restart
    5) Live dashboard (real-time status)
    6) Proxy manager        (add / list / remove / re-test)
    7) Switching strategy   (adaptive, fastest, round-robin, sticky, timed, pin)
    8) Settings             (API key, timeouts, ports, token...)
    9) Autostart on boot:   Enable / Disable
   10) Logs (follow)
   11) Test a proxy link against Gemini
   12) Bot integration code
   13) Update (xray core + python packages)
   14) Uninstall
    0) Exit
EOF
    local c; read -rp "  > " c
    case "$c" in
      1) do_install; pause ;;
      2) do_start; pause ;;
      3) do_stop; pause ;;
      4) do_restart; pause ;;
      5) need_running && ctl live; ;;
      6) menu_proxies ;;
      7) menu_strategy ;;
      8) menu_settings ;;
      9) if [[ "$(autostart_state)" == OFF ]]; then do_enable; else yesno "Autostart is ON. Disable it?" n && do_disable; fi; pause ;;
      10) if use_systemd; then journalctl -u "$SERVICE" -f -n 50; else tail -n 50 -f "$LOGS/rotator.log"; fi ;;
      11) local t; t="$(paste_block)"; ctl test "$(cat "$t")"; rm -f "$t"; pause ;;
      12) show_bot; pause ;;
      13) install_xray --force; setup_venv; is_running && do_restart; pause ;;
      14) do_uninstall; pause ;;
      0|q|"") echo; exit 0 ;;
    esac
  done
}

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,2\}//'; }

# ── dispatcher ────────────────────────────────────────────────────────────────
cd "$DIR"
cmd="${1:-}"; shift || true
case "$cmd" in
  "")        if [[ -t 0 ]]; then main_menu; else usage; fi ;;
  menu)      main_menu ;;
  install)   do_install "$@" ;;
  uninstall) do_uninstall ;;
  start)     do_start ;;
  stop)      do_stop ;;
  restart)   do_restart ;;
  enable)    do_enable ;;
  disable)   do_disable ;;
  status)    if is_running; then ctl status; else warn "not running"; fi ;;
  live)      need_running && ctl live ;;
  list)      need_running && ctl list ;;
  add)       if [[ $# -eq 0 ]]; then t="$(paste_block)"; add_file "$t"; rm -f "$t"
             elif [[ "$1" == "-f" ]]; then add_file "$2"
             else t="$(mktemp)"; printf '%s\n' "$*" > "$t"; add_file "$t"; rm -f "$t"; fi ;;
  remove)    need_running && ctl remove "${1:-}" ;;
  recheck)   need_running && ctl recheck "${1:-all}" ;;
  strategy)  need_running && ctl strategy "$@" ;;
  next)      need_running && ctl next ;;
  pin)       need_running && ctl pin "${1:-}" ;;
  mode)      need_running && ctl mode "$@" ;;
  config)    need_running && ctl config "$@" ;;
  config-default) default_config ;;
  config-reset)   ensure_config --reset-config; warn "restart the rotator to apply the new settings" ;;
  logs)      if use_systemd; then journalctl -u "$SERVICE" -f -n 50; else tail -n 50 -f "$LOGS/rotator.log"; fi ;;
  test)      ctl test "$*" ;;
  bot)       show_bot ;;
  update)    install_xray --force; setup_venv; is_running && do_restart ;;
  -h|--help|help) usage ;;
  *)         err "unknown command: $cmd"; usage; exit 1 ;;
esac
