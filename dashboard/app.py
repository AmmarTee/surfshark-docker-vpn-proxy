import json
import os
import random
import re
import subprocess
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Config paths
# ---------------------------------------------------------------------------
CONFIG_DIR = "/vpn/config"
AUTH_FILE = "/vpn/auth.txt"
AUTH_CLEAN = "/tmp/auth_clean.txt"
ACTIVE_OVPN = "/tmp/active.ovpn"
OPENVPN_LOG = "/var/log/openvpn.log"
OPENVPN_PID = "/var/run/openvpn.pid"
WG_CONFIG_DIR = "/vpn/wireguard"
WG_KEY_FILE = "/vpn/wireguard.txt"
WG_INTERFACE = "wg0"
WG_CONF = f"/etc/wireguard/{WG_INTERFACE}.conf"
WG_LOG = "/var/log/wireguard.log"
VPN_MODE_FILE = "/tmp/vpn_mode"
DATA_DIR = "/vpn/data"
AUTOSTART_FILE = "autostart.json"
LAST_SUCCESS_FILE = "last_success.json"

# Tunables (env-overridable)
OPENVPN_CONNECT_TIMEOUT = int(os.environ.get("OPENVPN_CONNECT_TIMEOUT", "75"))
WG_HANDSHAKE_TIMEOUT = int(os.environ.get("WG_HANDSHAKE_TIMEOUT", "15"))
HEALTH_PROBE_INTERVAL = int(os.environ.get("HEALTH_PROBE_INTERVAL", "30"))
HEALTH_PROBE_FAILS = int(os.environ.get("HEALTH_PROBE_FAILS", "2"))

IP_CHECK_URLS = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
]

# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------
SOCKS_PORT = int(os.environ.get("SOCKS_PORT", "1080"))
SOCKS_BIND = os.environ.get("SOCKS_BIND", "0.0.0.0")
HTTP_PROXY_ENABLED = True
HTTP_PROXY_PORT = int(os.environ.get("HTTP_PORT", "8888"))
HTTP_PROXY_BIND = os.environ.get("HTTP_BIND", "0.0.0.0")
AUTO_RECONNECT = True

# vpn_lock serializes all start/stop process manipulation.
vpn_lock = threading.Lock()
connected_since = None
_last_server_file = None  # last requested server filename
_last_vpn_mode = None  # "openvpn" or "wireguard"

# Operation state machine: idle | connecting | reconnecting | disconnecting
_op_lock = threading.Lock()
_op = {
    "state": "idle",
    "message": "",
    "target": None,
    "mode": None,
    "attempt": 0,
    "attempts_max": 0,
    "reason": None,
    "last_error": None,
}
# Set to ask an in-flight auto-reconnect loop to yield (user takeover).
_cancel_event = threading.Event()

# Managed child processes (owning the handle lets us reap them: no zombies,
# no pgrep on every status poll).
_proc_lock = threading.Lock()
_openvpn_proc = None
_socks_proc = None
_tinyproxy_proc = None

# Cached public IP — refreshed in the background, never in a request handler.
_vpn_ip = {"ip": None, "ts": 0}

# Event log (most recent last)
_event_lock = threading.Lock()
_event_log = []

# Bandwidth tracking
_bw = {
    "rx_speed": 0, "tx_speed": 0,
    "rx_total": 0, "tx_total": 0,
    "last_rx": 0, "last_tx": 0,
    "last_time": 0,
}

# Ping cache: {filename: {host, latency_ms, reachable, timestamp}}
_ping_cache = {}

# Geo-IP cache: {ip: {data..., _ts}}
_geoip_cache = {}

FILENAME_RE = re.compile(r"^[a-z]{2}-[a-z]{3}\.prod\.surfshark\.com_(tcp|udp)\.ovpn$")
WG_FILENAME_RE = re.compile(r"^[a-z]{2}-[a-z]{3}\.conf$")

# Country code to name mapping
COUNTRY_NAMES = {
    "ad": "Andorra", "ae": "UAE", "al": "Albania", "am": "Armenia",
    "ar": "Argentina", "at": "Austria", "au": "Australia", "az": "Azerbaijan",
    "ba": "Bosnia", "bd": "Bangladesh", "be": "Belgium", "bg": "Bulgaria",
    "bn": "Brunei", "bo": "Bolivia", "br": "Brazil", "bs": "Bahamas",
    "bt": "Bhutan", "bz": "Belize", "ca": "Canada", "ch": "Switzerland",
    "cl": "Chile", "co": "Colombia", "cr": "Costa Rica", "cy": "Cyprus",
    "cz": "Czech Republic", "de": "Germany", "dk": "Denmark", "dz": "Algeria",
    "ec": "Ecuador", "ee": "Estonia", "eg": "Egypt", "es": "Spain",
    "fi": "Finland", "fr": "France", "ge": "Georgia", "gh": "Ghana",
    "gl": "Greenland", "gr": "Greece", "hk": "Hong Kong", "hr": "Croatia",
    "hu": "Hungary", "id": "Indonesia", "ie": "Ireland", "il": "Israel",
    "im": "Isle of Man", "in": "India", "is": "Iceland", "it": "Italy",
    "jp": "Japan", "kh": "Cambodia", "kr": "South Korea", "kz": "Kazakhstan",
    "la": "Laos", "li": "Liechtenstein", "lk": "Sri Lanka", "lt": "Lithuania",
    "lu": "Luxembourg", "lv": "Latvia", "ma": "Morocco", "mc": "Monaco",
    "md": "Moldova", "me": "Montenegro", "mk": "North Macedonia",
    "mm": "Myanmar", "mn": "Mongolia", "mo": "Macau", "mt": "Malta",
    "mx": "Mexico", "my": "Malaysia", "ng": "Nigeria", "nl": "Netherlands",
    "no": "Norway", "np": "Nepal", "nz": "New Zealand", "pa": "Panama",
    "pe": "Peru", "ph": "Philippines", "pk": "Pakistan", "pl": "Poland",
    "pr": "Puerto Rico", "pt": "Portugal", "py": "Paraguay", "ro": "Romania",
    "rs": "Serbia", "sa": "Saudi Arabia", "se": "Sweden", "sg": "Singapore",
    "si": "Slovenia", "sk": "Slovakia", "th": "Thailand", "tr": "Turkey",
    "tw": "Taiwan", "ua": "Ukraine", "uk": "United Kingdom", "us": "United States",
    "uy": "Uruguay", "uz": "Uzbekistan", "ve": "Venezuela", "vn": "Vietnam",
    "za": "South Africa",
}

CITY_NAMES = {
    "adl": "Adelaide", "akl": "Auckland", "alg": "Algiers", "ams": "Amsterdam",
    "anr": "Antwerp", "ash": "Ashburn", "asu": "Asuncion", "ath": "Athens",
    "atl": "Atlanta", "bak": "Baku", "bcn": "Barcelona", "bdn": "Bend",
    "ber": "Berlin", "bkk": "Bangkok", "blp": "Belmopan", "bna": "Nashville",
    "bne": "Brisbane", "bod": "Bordeaux", "bog": "Bogota", "bos": "Boston",
    "bru": "Brussels", "bts": "Bratislava", "bua": "Buenos Aires",
    "bud": "Budapest", "buf": "Buffalo", "bwn": "Bandar Seri Begawan",
    "cai": "Cairo", "car": "Caracas", "chi": "Chicago", "clt": "Charlotte",
    "cmb": "Colombo", "cph": "Copenhagen", "dac": "Dhaka", "dal": "Dallas",
    "del": "Delhi", "den": "Denver", "dtw": "Detroit", "dub": "Dubai",
    "edi": "Edinburgh", "evn": "Yerevan", "fra": "Frankfurt", "gdn": "Gdansk",
    "gla": "Glasgow", "goh": "Nuuk", "hcm": "Ho Chi Minh", "hel": "Helsinki",
    "hkg": "Hong Kong", "hou": "Houston", "iev": "Kyiv", "iom": "Douglas",
    "ist": "Istanbul", "jak": "Jakarta", "jnb": "Johannesburg", "kan": "Kansas City",
    "khi": "Karachi", "ktm": "Kathmandu", "kul": "Kuala Lumpur",
    "lag": "Lagos", "las": "Las Vegas", "lax": "Los Angeles", "leu": "Andorra la Vella",
    "lim": "Lima", "lis": "Lisbon", "lju": "Ljubljana", "lon": "London",
    "ltm": "Latham", "mad": "Madrid", "man": "Manchester", "mcm": "Monaco",
    "mel": "Melbourne", "mfm": "Macau", "mia": "Miami", "mil": "Milan",
    "mla": "Valletta", "mnl": "Manila", "mon": "Montreal", "mrs": "Marseille",
    "mum": "Mumbai", "mvd": "Montevideo", "nas": "Nassau", "nic": "Nicosia",
    "nyc": "New York", "nyt": "Naypyidaw", "oma": "Omaha", "opo": "Porto", "osl": "Oslo",
    "pac": "Panama City", "par": "Paris", "pbh": "Thimphu", "per": "Perth",
    "phx": "Phoenix", "pnh": "Phnom Penh", "prg": "Prague", "qro": "Queretaro",
    "qvu": "Vaduz", "rab": "Rabat", "rig": "Riga", "rkv": "Reykjavik",
    "rom": "Rome", "ruh": "Riyadh", "san": "Santiago", "sao": "Sao Paulo",
    "sea": "Seattle", "seo": "Seoul", "sfo": "San Francisco",
    "sjc": "San Jose", "sjj": "Sarajevo", "sjn": "San Jose CR",
    "sju": "San Juan", "skp": "Skopje", "slc": "Salt Lake City",
    "sng": "Singapore", "sof": "Sofia", "sre": "Sucre", "ste": "Steinsel",
    "sto": "Stockholm", "syd": "Sydney", "tai": "Taipei", "tas": "Tashkent",
    "tbs": "Tbilisi", "tgd": "Podgorica", "tia": "Tirana", "tlv": "Tel Aviv",
    "tll": "Tallinn", "tok": "Tokyo", "tor": "Toronto", "uio": "Quito",
    "uln": "Ulaanbaatar", "ura": "Oral", "van": "Vancouver", "vie": "Vienna",
    "vlc": "Valencia", "vno": "Vilnius", "vte": "Vientiane", "waw": "Warsaw",
    "zag": "Zagreb", "zur": "Zurich",
}


def parse_ovpn_files():
    servers = []
    config_path = Path(CONFIG_DIR)
    if not config_path.exists():
        return servers
    for f in sorted(config_path.glob("*.ovpn")):
        name = f.stem
        match = re.match(r"^([a-z]{2})-([a-z]{3})\.prod\.surfshark\.com_(tcp|udp)$", name)
        if not match:
            continue
        country_code, city_code, protocol = match.groups()
        servers.append({
            "file": f.name,
            "country_code": country_code.upper(),
            "country": COUNTRY_NAMES.get(country_code, country_code.upper()),
            "city_code": city_code,
            "city": CITY_NAMES.get(city_code, city_code.upper()),
            "protocol": protocol.upper(),
        })
    return servers


def parse_wg_files():
    servers = []
    config_path = Path(WG_CONFIG_DIR)
    if not config_path.exists():
        return servers
    for f in sorted(config_path.glob("*.conf")):
        name = f.stem
        match = re.match(r"^([a-z]{2})-([a-z]{3})$", name)
        if not match:
            continue
        country_code, city_code = match.groups()
        servers.append({
            "file": f.name,
            "country_code": country_code.upper(),
            "country": COUNTRY_NAMES.get(country_code, country_code.upper()),
            "city_code": city_code,
            "city": CITY_NAMES.get(city_code, city_code.upper()),
            "protocol": "WG",
        })
    return servers


# ===========================================================================
# Persistent JSON helpers (atomic writes, lock-guarded)
# ===========================================================================

_data_lock = threading.Lock()


def _json_path(name):
    return os.path.join(DATA_DIR, name)


def load_json(name, default=None):
    path = _json_path(name)
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default if default is not None else []


def save_json(name, data):
    """Atomic write: temp file + rename so a crash never corrupts data."""
    with _data_lock:
        os.makedirs(DATA_DIR, exist_ok=True)
        path = _json_path(name)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, path)
        except OSError:
            pass


def _now_iso():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _add_event(kind, message):
    global _event_log
    with _event_lock:
        _event_log.append({"ts": _now_iso(), "kind": kind, "message": message})
        _event_log = _event_log[-400:]


def _get_events(limit):
    with _event_lock:
        return list(_event_log[-limit:])


# ===========================================================================
# Operation state machine
# ===========================================================================

def _set_op(**kw):
    with _op_lock:
        _op.update(kw)


def _get_op():
    with _op_lock:
        return dict(_op)


def _op_busy():
    with _op_lock:
        return _op["state"] != "idle"


# ===========================================================================
# Autostart / last-success persistence
# ===========================================================================

def _default_autostart_config():
    return {
        "enabled": False,
        "preferred_server": None,
        "preferred_mode": None,
        "retry_count": 3,
        "retry_delay_sec": 5,
        "failover_scope": "global",
    }


def _load_autostart_config():
    data = load_json(AUTOSTART_FILE, {})
    merged = _default_autostart_config()
    if isinstance(data, dict):
        merged.update(data)
    return merged


def _save_autostart_config(data):
    cfg = _default_autostart_config()
    cfg.update(data or {})
    save_json(AUTOSTART_FILE, cfg)


def _save_last_success(server_file, vpn_mode, vpn_ip=None):
    save_json(LAST_SUCCESS_FILE, {
        "server": server_file,
        "vpn_mode": vpn_mode,
        "vpn_ip": vpn_ip,
        "timestamp": time.time(),
    })


def _load_last_success():
    data = load_json(LAST_SUCCESS_FILE, {})
    if not isinstance(data, dict):
        return None
    if "server" not in data or "vpn_mode" not in data:
        return None
    return data


def _mode_and_server_valid(vpn_mode, server_file):
    if vpn_mode == "wireguard":
        return bool(server_file and WG_FILENAME_RE.match(server_file))
    return bool(server_file and FILENAME_RE.match(server_file))


# ===========================================================================
# Process helpers
# ===========================================================================

def _proc_alive(proc):
    return proc is not None and proc.poll() is None


def _pgrep(name):
    try:
        result = subprocess.run(
            ["pgrep", "-x", name], capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return int(result.stdout.strip().split("\n")[0])
    except (subprocess.TimeoutExpired, ValueError, OSError):
        pass
    return None


def _openvpn_running():
    with _proc_lock:
        if _proc_alive(_openvpn_proc):
            return True
    # Fallback: stray process not owned by us (e.g. logic error / manual start)
    return _pgrep("openvpn") is not None


def _socks_running():
    with _proc_lock:
        if _proc_alive(_socks_proc):
            return True
    return _pgrep("microsocks") is not None


def _tinyproxy_running():
    with _proc_lock:
        if _proc_alive(_tinyproxy_proc):
            return True
    return _pgrep("tinyproxy") is not None


def _terminate(proc, name, timeout=8):
    """Terminate a managed child and reap it. SIGKILL as last resort."""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        else:
            proc.wait()
    except OSError:
        pass


def _kill_strays(name):
    """Kill processes we don't own a handle for (stale from a crash)."""
    try:
        subprocess.run(["pkill", "-x", name], capture_output=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        pass


# ===========================================================================
# Credentials (handles CRLF / BOM / stray whitespace from Windows hosts)
# ===========================================================================

def _prepare_auth_file():
    """Sanitize auth.txt into a private temp copy OpenVPN can use.

    The mounted file frequently has CRLF line endings (Windows host) which
    makes OpenVPN send 'password\\r' and fail auth intermittently. It is also
    mounted read-only so chmod 600 on it never works.
    """
    try:
        with open(AUTH_FILE, encoding="utf-8-sig") as f:
            lines = [ln.strip() for ln in f.read().splitlines()]
    except OSError as e:
        return None, f"Cannot read credentials file: {e}"
    lines = [ln for ln in lines if ln]
    if len(lines) < 2:
        return None, "auth.txt must contain username on line 1 and password on line 2"
    try:
        fd = os.open(AUTH_CLEAN, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(lines[0] + "\n" + lines[1] + "\n")
    except OSError as e:
        return None, f"Cannot write sanitized credentials: {e}"
    return AUTH_CLEAN, None


def _read_wg_private_key():
    """WireGuard private key from wireguard.txt line 2 (CRLF-safe)."""
    try:
        with open(WG_KEY_FILE, encoding="utf-8-sig") as f:
            lines = [ln.strip() for ln in f.read().splitlines() if ln.strip()]
        if len(lines) >= 2:
            return lines[1]
    except OSError:
        pass
    return None


# ===========================================================================
# DNS management
# ===========================================================================

_DEFAULT_VPN_DNS = ["162.252.172.57", "149.154.159.92"]
_ORIGINAL_RESOLV = None


def _set_vpn_dns(dns_servers=None):
    global _ORIGINAL_RESOLV
    if _ORIGINAL_RESOLV is None:
        try:
            with open("/etc/resolv.conf") as f:
                _ORIGINAL_RESOLV = f.read()
        except OSError:
            _ORIGINAL_RESOLV = ""
    servers = dns_servers if dns_servers else _DEFAULT_VPN_DNS
    try:
        with open("/etc/resolv.conf", "w") as f:
            for s in servers:
                f.write(f"nameserver {s}\n")
    except OSError:
        pass


def _restore_dns():
    global _ORIGINAL_RESOLV
    if _ORIGINAL_RESOLV is not None:
        try:
            with open("/etc/resolv.conf", "w") as f:
                f.write(_ORIGINAL_RESOLV)
        except OSError:
            pass
        _ORIGINAL_RESOLV = None


# ===========================================================================
# Networking helpers
# ===========================================================================

def _interface_alive(iface):
    try:
        r = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


# The container's real gateway, recorded before any VPN touches routing.
_orig_gateway = {"via": None, "dev": None}

# Endpoint /32 host routes we added for WireGuard (cleaned up on stop so
# they don't accumulate across reconnects).
_endpoint_routes = set()


def _record_original_gateway():
    try:
        rt = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        m = re.search(r"default via (\S+) dev (\S+)", rt.stdout)
        if m and "tun" not in m.group(2) and m.group(2) != WG_INTERFACE:
            _orig_gateway["via"] = m.group(1)
            _orig_gateway["dev"] = m.group(2)
    except (subprocess.TimeoutExpired, OSError):
        pass


def _ensure_default_route():
    """If the default route vanished (e.g. wg0 was torn down and took the
    route with it), restore it via the original container gateway. Without
    this, a failed tunnel leaves the container with no connectivity at all
    and every subsequent reconnect attempt dies on DNS resolution."""
    if not _orig_gateway["via"]:
        return
    try:
        rt = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        if "default" in rt.stdout:
            return
        subprocess.run(
            ["ip", "route", "add", "default", "via", _orig_gateway["via"],
             "dev", _orig_gateway["dev"]],
            capture_output=True, text=True, timeout=5,
        )
        _add_event("route", f"Restored default route via {_orig_gateway['via']}")
    except (subprocess.TimeoutExpired, OSError):
        pass


def _probe_connectivity(timeout=5):
    """Fetch the public IP through the tunnel. Returns IP or None.

    This is the real health check: an interface can be 'up' while the
    tunnel is dead (ping-restart 0 in Surfshark configs means OpenVPN
    never notices on its own).
    """
    for url in IP_CHECK_URLS:
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", str(timeout), url],
                capture_output=True, text=True, timeout=timeout + 2,
            )
            ip = r.stdout.strip()
            if r.returncode == 0 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return ip
        except (subprocess.TimeoutExpired, OSError):
            pass
    return None


def _refresh_vpn_ip_async():
    """Refresh the cached public IP without blocking the caller."""
    def work():
        ip = _probe_connectivity()
        if ip:
            _vpn_ip["ip"] = ip
            _vpn_ip["ts"] = time.time()
    threading.Thread(target=work, daemon=True).start()


def _preserve_lan_routes():
    """Pin routes for LAN/Docker subnets so the dashboard stays reachable
    after the VPN takes over the default route."""
    try:
        rt = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        gw_match = re.search(r"default via (\S+) dev (\S+)", rt.stdout)
        if not gw_match:
            return
        gateway = gw_match.group(1)
        gw_dev = gw_match.group(2)

        lan_env = os.environ.get("LAN_NETWORK", "").strip()
        if lan_env:
            subnets = [s.strip() for s in lan_env.split(",") if s.strip()]
        else:
            addr = subprocess.run(
                ["ip", "-o", "-4", "addr", "show", "dev", gw_dev],
                capture_output=True, text=True, timeout=5,
            )
            subnets = []
            for line in addr.stdout.splitlines():
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", line)
                if m:
                    ip_part, prefix = m.group(1).split("/")
                    prefix_int = int(prefix)
                    octets = list(map(int, ip_part.split(".")))
                    mask = (0xFFFFFFFF << (32 - prefix_int)) & 0xFFFFFFFF
                    net = [
                        octets[0] & (mask >> 24 & 0xFF),
                        octets[1] & (mask >> 16 & 0xFF),
                        octets[2] & (mask >> 8 & 0xFF),
                        octets[3] & (mask & 0xFF),
                    ]
                    subnets.append(f"{net[0]}.{net[1]}.{net[2]}.{net[3]}/{prefix}")

        for subnet in subnets:
            subprocess.run(
                ["ip", "route", "add", subnet, "via", gateway, "dev", gw_dev],
                capture_output=True, text=True, timeout=5,
            )
        if subnets:
            _add_event("route", f"Preserved LAN routes: {', '.join(subnets)} via {gateway}")
    except Exception as e:
        _add_event("route", f"LAN route preservation warning: {e}")


# ===========================================================================
# Proxy management (microsocks + tinyproxy)
# ===========================================================================

TINYPROXY_CONF = "/etc/tinyproxy/tinyproxy.conf"


def _write_tinyproxy_conf():
    os.makedirs("/etc/tinyproxy", exist_ok=True)
    with open(TINYPROXY_CONF, "w") as f:
        f.write(
            f"Port {HTTP_PROXY_PORT}\n"
            f"Listen {HTTP_PROXY_BIND}\n"
            "Timeout 600\n"
            "Allow 0.0.0.0/0\n"
            "MaxClients 100\n"
            "ViaProxyName \"tinyproxy\"\n"
        )


def start_socks():
    global _socks_proc
    with _proc_lock:
        if _proc_alive(_socks_proc):
            return
        _kill_strays("microsocks")
        _add_event("proxy", f"Starting microsocks at {SOCKS_BIND}:{SOCKS_PORT}")
        _socks_proc = subprocess.Popen(
            ["microsocks", "-i", SOCKS_BIND, "-p", str(SOCKS_PORT)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


def stop_socks():
    global _socks_proc
    with _proc_lock:
        _terminate(_socks_proc, "microsocks")
        _socks_proc = None
        _kill_strays("microsocks")


def start_tinyproxy():
    global _tinyproxy_proc
    if not HTTP_PROXY_ENABLED:
        return
    with _proc_lock:
        if _proc_alive(_tinyproxy_proc):
            return
        _kill_strays("tinyproxy")
        _write_tinyproxy_conf()
        _add_event("proxy", f"Starting tinyproxy at {HTTP_PROXY_BIND}:{HTTP_PROXY_PORT}")
        # -d keeps it in the foreground so we own (and can reap) the process
        _tinyproxy_proc = subprocess.Popen(
            ["tinyproxy", "-d", "-c", TINYPROXY_CONF],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


def stop_tinyproxy():
    global _tinyproxy_proc
    with _proc_lock:
        _terminate(_tinyproxy_proc, "tinyproxy")
        _tinyproxy_proc = None
        _kill_strays("tinyproxy")


def _ensure_proxies():
    """Start any proxy that should be running but isn't. Idempotent."""
    if not _socks_running():
        start_socks()
    if HTTP_PROXY_ENABLED and not _tinyproxy_running():
        start_tinyproxy()


# ===========================================================================
# VPN status
# ===========================================================================

def _read_mode_file():
    try:
        with open(VPN_MODE_FILE) as f:
            return f.read().strip() or None
    except OSError:
        return None


def _current_server_name(vpn_mode):
    if vpn_mode == "wireguard":
        if os.path.exists(WG_CONF):
            try:
                with open(WG_CONF) as f:
                    for line in f:
                        if line.strip().startswith("Endpoint"):
                            parts = line.split("=", 1)
                            if len(parts) == 2:
                                return parts[1].strip().split(":")[0]
            except OSError:
                pass
    else:
        if os.path.exists(ACTIVE_OVPN):
            try:
                with open(ACTIVE_OVPN) as f:
                    for line in f:
                        if line.startswith("remote "):
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                return parts[1]
            except OSError:
                pass
    return None


def get_vpn_status():
    """Fast, non-blocking snapshot. No network calls here — the public IP
    comes from the background-refreshed cache."""
    vpn_mode = _read_mode_file() or "openvpn"

    if vpn_mode == "wireguard":
        connected = _interface_alive(WG_INTERFACE)
    else:
        connected = _openvpn_running() and _interface_alive("tun0")

    op = _get_op()
    return {
        "connected": connected,
        "vpn_mode": vpn_mode,
        "openvpn_running": _openvpn_running(),
        "socks_running": _socks_running(),
        "current_server": _current_server_name(vpn_mode) if connected else None,
        "vpn_ip": _vpn_ip["ip"] if connected else None,
        "socks_port": SOCKS_PORT,
        "socks_bind": SOCKS_BIND,
        "http_proxy_enabled": HTTP_PROXY_ENABLED,
        "http_proxy_port": HTTP_PROXY_PORT,
        "http_proxy_bind": HTTP_PROXY_BIND,
        "http_proxy_running": _tinyproxy_running(),
        "auto_reconnect": AUTO_RECONNECT,
        "connected_since": connected_since if connected else None,
        # Operation state for the non-blocking UI
        "op_state": op["state"],
        "op_message": op["message"],
        "op_target": op["target"],
        "op_mode": op["mode"],
        "op_attempt": op["attempt"],
        "op_attempts_max": op["attempts_max"],
        "op_reason": op["reason"],
        "last_error": op["last_error"],
        # Legacy aliases (kept for compatibility)
        "reconnecting": op["state"] == "reconnecting",
        "reconnect_attempts": op["attempt"],
        "last_reconnect_reason": op["reason"],
        "last_reconnect_error": op["last_error"],
        "last_action": op["state"],
    }


def read_log(lines=50):
    try:
        with open(OPENVPN_LOG) as f:
            all_lines = f.readlines()
            return "".join(all_lines[-lines:])
    except OSError:
        return "No log file yet."


def read_wg_log(lines=50):
    log_content = ""
    try:
        with open(WG_LOG) as f:
            all_lines = f.readlines()
            log_content = "".join(all_lines[-lines:])
    except OSError:
        log_content = "No WireGuard log yet.\n"

    try:
        result = subprocess.run(
            ["wg", "show"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            log_content += "\n--- WireGuard Interface Status ---\n"
            log_content += result.stdout
    except (subprocess.TimeoutExpired, OSError):
        pass

    return log_content


# ===========================================================================
# Connect / disconnect core (always called with vpn_lock held)
# ===========================================================================

def stop_vpn():
    """Stop OpenVPN, WireGuard, and both proxies."""
    global connected_since, _openvpn_proc
    _add_event("control", "Stopping VPN and proxies")

    with _proc_lock:
        _terminate(_openvpn_proc, "openvpn")
        _openvpn_proc = None
    _kill_strays("openvpn")

    # Tear down WireGuard and restore the default route it replaced
    try:
        route_info = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5
        )
        if WG_INTERFACE in route_info.stdout:
            all_routes = subprocess.run(
                ["ip", "route"], capture_output=True, text=True, timeout=5
            )
            for line in all_routes.stdout.splitlines():
                if "via" in line and WG_INTERFACE not in line:
                    m = re.search(r"via (\S+)", line)
                    if m:
                        gateway = m.group(1)
                        subprocess.run(["ip", "route", "del", "default"],
                                       capture_output=True, text=True, timeout=5)
                        subprocess.run(["ip", "route", "add", "default", "via", gateway],
                                       capture_output=True, text=True, timeout=5)
                        break
        subprocess.run(
            ["wg-quick", "down", WG_INTERFACE],
            capture_output=True, text=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Remove stale endpoint host routes from previous WG sessions
    for ep in list(_endpoint_routes):
        try:
            subprocess.run(["ip", "route", "del", ep],
                           capture_output=True, text=True, timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            pass
        _endpoint_routes.discard(ep)

    stop_socks()
    stop_tinyproxy()

    connected_since = None
    _vpn_ip["ip"] = None
    _restore_dns()
    _ensure_default_route()
    for fpath in [OPENVPN_PID, VPN_MODE_FILE]:
        try:
            os.remove(fpath)
        except OSError:
            pass


def _on_connected(server_file, vpn_mode):
    """Common post-connect bookkeeping."""
    global connected_since, _last_server_file, _last_vpn_mode
    with open(VPN_MODE_FILE, "w") as f:
        f.write(vpn_mode)
    connected_since = time.time()
    _last_server_file = server_file
    _last_vpn_mode = vpn_mode
    _ensure_proxies()
    recent = load_json("recent.json", [])
    entry = {
        "file": server_file,
        "vpn_mode": vpn_mode,
        "vpn_ip": _vpn_ip["ip"],
        "timestamp": time.time(),
    }
    recent = [r for r in recent if r.get("file") != server_file]
    recent.insert(0, entry)
    save_json("recent.json", recent[:20])
    _save_last_success(server_file, vpn_mode, _vpn_ip["ip"])
    _refresh_vpn_ip_async()


# Log lines that mean "give up now, retrying won't help this attempt"
_OVPN_FATAL_PATTERNS = [
    ("AUTH_FAILED", "Authentication failed — check the credentials in auth.txt"),
    ("auth-failure", "Authentication failed — check the credentials in auth.txt"),
    ("Cannot resolve host address", "Cannot resolve the server hostname (DNS problem)"),
    ("private key password verification failed", "Private key verification failed"),
]


def _scan_ovpn_log_for_fatal():
    try:
        with open(OPENVPN_LOG) as f:
            tail = f.read()[-8000:]
    except OSError:
        return None
    for needle, message in _OVPN_FATAL_PATTERNS:
        if needle in tail:
            return message
    return None


def start_vpn(config_file):
    """Start OpenVPN with the given config. Blocking — run from a worker."""
    global _openvpn_proc
    config_path = os.path.join(CONFIG_DIR, config_file)
    if not os.path.exists(config_path):
        return False, f"Config file not found: {config_file}"

    auth_path, auth_err = _prepare_auth_file()
    if auth_err:
        return False, auth_err

    _add_event("connect", f"OpenVPN connect requested: {config_file}")
    stop_vpn()
    time.sleep(0.5)
    _ensure_default_route()
    _preserve_lan_routes()

    with open(config_path) as src:
        content = src.read()
    # Normalize CRLF configs (added from a Windows host) and wire in auth
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    if re.search(r"^auth-user-pass", content, flags=re.MULTILINE):
        content = re.sub(r"^auth-user-pass.*$", f"auth-user-pass {auth_path}",
                         content, flags=re.MULTILINE)
    else:
        content += f"\nauth-user-pass {auth_path}\n"
    # Surfshark ships 'ping-restart 0' which disables dead-tunnel detection;
    # strip it — we override with sane keepalive flags below.
    content = re.sub(r"^ping-restart.*$", "", content, flags=re.MULTILINE)
    with open(ACTIVE_OVPN, "w") as dst:
        dst.write(content)

    with open(OPENVPN_LOG, "w") as f:
        f.write("")

    proc = subprocess.Popen(
        [
            "openvpn", "--config", ACTIVE_OVPN,
            "--log", OPENVPN_LOG,
            "--writepid", OPENVPN_PID,
            "--data-ciphers", "AES-256-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
            "--data-ciphers-fallback", "AES-256-CBC",
            "--auth-nocache",
            "--auth-retry", "none",
            "--connect-retry", "2",
            "--connect-retry-max", "3",
            "--resolv-retry", "15",
            # Detect and survive dead tunnels without dropping tun0
            "--ping", "15",
            "--ping-restart", "60",
            "--persist-tun",
            "--persist-key",
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    with _proc_lock:
        _openvpn_proc = proc

    deadline = time.time() + OPENVPN_CONNECT_TIMEOUT
    while time.time() < deadline:
        if _interface_alive("tun0"):
            _set_vpn_dns()
            _on_connected(config_file, "openvpn")
            _add_event("connect", f"OpenVPN connected: {config_file}")
            return True, "VPN connected successfully"
        # Fast-fail on fatal errors instead of burning the full timeout
        fatal = _scan_ovpn_log_for_fatal()
        if fatal:
            _add_event("connect", f"OpenVPN fatal: {fatal}")
            with _proc_lock:
                _terminate(_openvpn_proc, "openvpn", timeout=5)
                _openvpn_proc = None
            return False, fatal
        if proc.poll() is not None:
            fatal = _scan_ovpn_log_for_fatal()
            msg = fatal or "OpenVPN process exited unexpectedly. Check logs."
            _add_event("connect", f"OpenVPN exited: {msg}")
            return False, msg
        time.sleep(0.5)

    _add_event("connect", "OpenVPN tunnel failed to establish in time")
    with _proc_lock:
        _terminate(_openvpn_proc, "openvpn", timeout=5)
        _openvpn_proc = None
    return False, f"VPN tunnel failed to establish within {OPENVPN_CONNECT_TIMEOUT}s. Check logs."


def start_wireguard(config_file):
    """Start WireGuard with the given config. Blocking — run from a worker."""
    config_path = os.path.join(WG_CONFIG_DIR, config_file)
    if not os.path.exists(config_path):
        return False, f"Config file not found: {config_file}"

    _add_event("connect", f"WireGuard connect requested: {config_file}")
    stop_vpn()
    time.sleep(0.5)
    _ensure_default_route()
    _preserve_lan_routes()

    wg_private_key = _read_wg_private_key()

    os.makedirs("/etc/wireguard", exist_ok=True)
    with open(config_path) as src:
        content = src.read()
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    if wg_private_key:
        content = re.sub(
            r"^PrivateKey\s*=\s*.*$",
            f"PrivateKey = {wg_private_key}",
            content, flags=re.MULTILINE,
        )
    dns_match = re.search(r"^DNS\s*=\s*(.+)$", content, flags=re.MULTILINE)
    wg_dns_servers = []
    if dns_match:
        wg_dns_servers = [s.strip() for s in dns_match.group(1).split(",") if s.strip()]
    content = re.sub(r"^DNS\s*=.*\n?", "", content, flags=re.MULTILINE)
    if "Table" not in content:
        content = re.sub(r"(\[Interface\])", r"\1\nTable = off", content)
    with open(WG_CONF, "w") as dst:
        dst.write(content)

    with open(WG_LOG, "w") as f:
        f.write("")

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    try:
        result = subprocess.run(
            ["wg-quick", "up", WG_INTERFACE],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        _add_event("connect", "WireGuard timed out")
        return False, "WireGuard connection timed out"

    with open(WG_LOG, "a") as logf:
        logf.write(f"[{timestamp}] wg-quick up {WG_INTERFACE}\n")
        if result.stdout:
            logf.write(result.stdout)
        if result.stderr:
            logf.write(result.stderr)
        logf.write("\n")

    if result.returncode != 0:
        _add_event("connect", f"WireGuard failed: {result.stderr.strip()}")
        return False, f"WireGuard failed: {result.stderr.strip()}"

    # Manual routing: endpoint via real gateway, everything else via wg0
    try:
        route_info = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5
        )
        gw_match = re.search(r"default via (\S+)", route_info.stdout)
        if gw_match:
            gateway = gw_match.group(1)
            endpoint_info = subprocess.run(
                ["wg", "show", WG_INTERFACE, "endpoints"],
                capture_output=True, text=True, timeout=5,
            )
            ep_match = re.search(r"(\d+\.\d+\.\d+\.\d+):\d+", endpoint_info.stdout)
            if ep_match:
                endpoint_ip = ep_match.group(1)
                subprocess.run(["ip", "route", "add", endpoint_ip, "via", gateway],
                               capture_output=True, text=True, timeout=5)
                _endpoint_routes.add(endpoint_ip)
            subprocess.run(["ip", "route", "del", "default"],
                           capture_output=True, text=True, timeout=5)
            subprocess.run(["ip", "route", "add", "default", "dev", WG_INTERFACE],
                           capture_output=True, text=True, timeout=5)
            with open(WG_LOG, "a") as logf:
                logf.write(f"[{timestamp}] Routing configured via {WG_INTERFACE}\n")
    except Exception as e:
        with open(WG_LOG, "a") as logf:
            logf.write(f"[{timestamp}] Routing warning: {e}\n")

    _set_vpn_dns(wg_dns_servers)

    # WireGuard is connectionless: wg-quick succeeds even with a bad key or
    # dead server. Verify a handshake actually completes before reporting OK.
    handshake_ok = False
    probe_ip = None
    deadline = time.time() + WG_HANDSHAKE_TIMEOUT
    # A probe generates traffic, which is what triggers the handshake
    probe_ip = _probe_connectivity(timeout=4)
    while time.time() < deadline:
        try:
            hs = subprocess.run(
                ["wg", "show", WG_INTERFACE, "latest-handshakes"],
                capture_output=True, text=True, timeout=5,
            )
            for line in hs.stdout.splitlines():
                parts = line.split()
                if parts and parts[-1].isdigit() and int(parts[-1]) > 0:
                    handshake_ok = True
                    break
        except (subprocess.TimeoutExpired, OSError):
            pass
        if handshake_ok:
            break
        time.sleep(1)

    if not handshake_ok:
        _add_event("connect", f"WireGuard handshake never completed: {config_file}")
        subprocess.run(["wg-quick", "down", WG_INTERFACE],
                       capture_output=True, text=True, timeout=15)
        _restore_dns()
        return False, "WireGuard handshake failed — check your key in wireguard.txt or try another server"

    if probe_ip:
        _vpn_ip["ip"] = probe_ip
        _vpn_ip["ts"] = time.time()

    _on_connected(config_file, "wireguard")
    _add_event("connect", f"WireGuard connected: {config_file}")
    return True, "WireGuard connected successfully"


def _attempt_connect(mode, server_file):
    if mode == "wireguard":
        return start_wireguard(server_file)
    return start_vpn(server_file)


def _pick_random_failover(mode):
    pool = parse_wg_files() if mode == "wireguard" else parse_ovpn_files()
    if not pool:
        return None
    return random.choice(pool)["file"]


# ===========================================================================
# Async operation runners (everything network-heavy happens off-request)
# ===========================================================================

def request_connect(mode, server_file, source="user"):
    """Kick off a connection in the background. Returns (accepted, message)."""
    op = _get_op()
    if op["state"] in ("connecting", "disconnecting"):
        return False, f"Busy: {op['state']} {op['target'] or ''}".strip()
    if op["state"] == "reconnecting":
        if source != "user":
            return False, "Busy: auto-reconnect in progress"
        # User takes priority: ask the reconnect loop to yield
        _cancel_event.set()

    _set_op(state="connecting", target=server_file, mode=mode,
            message=f"Connecting to {server_file}...", attempt=1,
            attempts_max=1, reason=source, last_error=None)

    def worker():
        try:
            with vpn_lock:
                ok, msg = _attempt_connect(mode, server_file)
            if ok:
                _set_op(state="idle", message=msg, attempt=0, last_error=None)
            else:
                _set_op(state="idle", message=msg, attempt=0, last_error=msg)
        except Exception as e:
            _set_op(state="idle", message=str(e), attempt=0, last_error=str(e))

    threading.Thread(target=worker, daemon=True).start()
    return True, "Connection started"


def request_disconnect():
    op = _get_op()
    if op["state"] == "disconnecting":
        return False, "Already disconnecting"
    if op["state"] == "reconnecting":
        _cancel_event.set()
    _set_op(state="disconnecting", message="Disconnecting...", target=None,
            mode=None, attempt=0, reason="user")

    def worker():
        try:
            with vpn_lock:
                stop_vpn()
            _set_op(state="idle", message="Disconnected", last_error=None)
            _add_event("control", "Disconnected by user")
        except Exception as e:
            _set_op(state="idle", message=str(e), last_error=str(e))

    threading.Thread(target=worker, daemon=True).start()
    return True, "Disconnecting"


def _run_reconnect_flow(mode, server_file, reason="monitor"):
    """Retry the last server, then fail over. Runs in a background thread."""
    cfg = _load_autostart_config()
    retries = max(1, min(int(cfg.get("retry_count", 3)), 10))
    retry_delay = max(1, min(int(cfg.get("retry_delay_sec", 5)), 60))
    failover_scope = str(cfg.get("failover_scope", "global")).strip().lower()

    _set_op(state="reconnecting", target=server_file, mode=mode,
            message=f"Reconnecting to {server_file}...", attempt=0,
            attempts_max=retries, reason=reason)
    _add_event("reconnect", f"Reconnect started ({reason}) using {mode}:{server_file}")

    ok = False
    last_msg = "Reconnect failed"
    try:
        for attempt in range(retries):
            if _cancel_event.is_set():
                _add_event("reconnect", "Reconnect cancelled (user took over)")
                return False, "Cancelled"
            _set_op(attempt=attempt + 1,
                    message=f"Reconnect attempt {attempt + 1}/{retries} to {server_file}")
            _add_event("reconnect", f"Attempt {attempt + 1}/{retries} to {mode}:{server_file}")
            with vpn_lock:
                ok, last_msg = _attempt_connect(mode, server_file)
            if ok:
                _add_event("reconnect", f"Reconnect succeeded on attempt {attempt + 1}")
                _set_op(state="idle", message=last_msg, attempt=0, last_error=None)
                return True, last_msg
            _set_op(last_error=last_msg)
            # Sleep in small slices so cancellation stays responsive
            for _ in range(retry_delay * 2):
                if _cancel_event.is_set():
                    _add_event("reconnect", "Reconnect cancelled (user took over)")
                    return False, "Cancelled"
                time.sleep(0.5)

        if failover_scope == "none":
            _add_event("reconnect", "Retries exhausted; failover disabled")
            _set_op(state="idle", message=last_msg, attempt=0, last_error=last_msg)
            return False, last_msg

        failover_mode = mode if failover_scope == "same_mode" else random.choice(["openvpn", "wireguard"])
        failover_server = _pick_random_failover(failover_mode)
        if not failover_server:
            _add_event("reconnect", "Retries exhausted; no failover servers available")
            _set_op(state="idle", message=last_msg, attempt=0, last_error=last_msg)
            return False, last_msg

        _add_event("reconnect", f"Failover to {failover_mode}:{failover_server}")
        _set_op(target=failover_server, mode=failover_mode,
                message=f"Failover: connecting to {failover_server}...")
        with vpn_lock:
            ok, last_msg = _attempt_connect(failover_mode, failover_server)
        if ok:
            _add_event("reconnect", "Failover succeeded")
            _set_op(state="idle", message=last_msg, attempt=0, last_error=None)
            return True, last_msg
        _add_event("reconnect", f"Failover failed: {last_msg}")
        _set_op(state="idle", message=last_msg, attempt=0, last_error=last_msg)
        return False, last_msg
    finally:
        _cancel_event.clear()
        op = _get_op()
        if op["state"] == "reconnecting":  # safety net
            _set_op(state="idle", attempt=0)


def request_reconnect(mode, server_file, reason):
    """Run the reconnect flow in the background. Returns (accepted, message)."""
    op = _get_op()
    if op["state"] != "idle":
        return False, f"Busy: {op['state']}"
    threading.Thread(
        target=_run_reconnect_flow, args=(mode, server_file, reason), daemon=True
    ).start()
    return True, "Reconnect started"


# ===========================================================================
# Background threads
# ===========================================================================

def _health_monitor():
    """Supervise the tunnel AND the proxies.

    - interface gone           -> reconnect immediately
    - interface up, no traffic -> reconnect after N failed probes
    - proxy died               -> restart it
    """
    consecutive_probe_fails = 0
    last_probe = 0.0
    while True:
        time.sleep(5)
        try:
            if not AUTO_RECONNECT or _op_busy():
                continue

            vpn_mode = _read_mode_file()
            if not vpn_mode:
                consecutive_probe_fails = 0
                continue

            iface = WG_INTERFACE if vpn_mode == "wireguard" else "tun0"
            if not _interface_alive(iface):
                if _last_server_file and _last_vpn_mode:
                    _add_event("monitor", f"Interface {iface} is down — reconnecting")
                    request_reconnect(_last_vpn_mode, _last_server_file, "interface_down")
                continue

            # Interface is up: keep the proxies alive
            _ensure_proxies()

            # Deep probe: does traffic actually flow through the tunnel?
            now = time.time()
            if now - last_probe >= HEALTH_PROBE_INTERVAL:
                last_probe = now
                ip = _probe_connectivity()
                if ip:
                    consecutive_probe_fails = 0
                    _vpn_ip["ip"] = ip
                    _vpn_ip["ts"] = now
                else:
                    consecutive_probe_fails += 1
                    _add_event("monitor",
                               f"Connectivity probe failed ({consecutive_probe_fails}/{HEALTH_PROBE_FAILS})")
                    if consecutive_probe_fails >= HEALTH_PROBE_FAILS:
                        consecutive_probe_fails = 0
                        if _last_server_file and _last_vpn_mode:
                            _add_event("monitor", "Tunnel is dead (interface up, no traffic) — reconnecting")
                            request_reconnect(_last_vpn_mode, _last_server_file, "connectivity_lost")
        except Exception as e:
            _add_event("monitor", f"Health monitor error: {e}")


def _boot_autostart():
    global _last_server_file, _last_vpn_mode
    time.sleep(2)

    cfg = _load_autostart_config()
    if not cfg.get("enabled"):
        _add_event("autostart", "Autostart is disabled")
        return

    preferred_server = cfg.get("preferred_server")
    preferred_mode = cfg.get("preferred_mode")
    target_server = None
    target_mode = None

    if preferred_server and preferred_mode and _mode_and_server_valid(preferred_mode, preferred_server):
        target_server = preferred_server
        target_mode = preferred_mode
    else:
        last = _load_last_success()
        if last:
            ls_server = str(last.get("server"))
            ls_mode = str(last.get("vpn_mode"))
            if _mode_and_server_valid(ls_mode, ls_server):
                target_server = ls_server
                target_mode = ls_mode

    if not target_server or not target_mode:
        _add_event("autostart", "Autostart enabled but no valid target is available")
        return

    _last_server_file = target_server
    _last_vpn_mode = target_mode
    _add_event("autostart", f"Boot autostart target: {target_mode}:{target_server}")
    _run_reconnect_flow(target_mode, target_server, reason="container_boot")


def _bandwidth_monitor():
    global _bw
    while True:
        time.sleep(2)
        vpn_mode = _read_mode_file()
        if not vpn_mode:
            _bw["rx_speed"] = _bw["tx_speed"] = 0
            continue

        iface = WG_INTERFACE if vpn_mode == "wireguard" else "tun0"
        try:
            with open(f"/sys/class/net/{iface}/statistics/rx_bytes") as f:
                rx = int(f.read().strip())
            with open(f"/sys/class/net/{iface}/statistics/tx_bytes") as f:
                tx = int(f.read().strip())
        except (OSError, ValueError):
            _bw["rx_speed"] = _bw["tx_speed"] = 0
            continue

        now = time.time()
        dt = now - _bw["last_time"] if _bw["last_time"] else 0

        if dt > 0 and _bw["last_rx"] > 0:
            _bw["rx_speed"] = max(0, (rx - _bw["last_rx"]) / dt)
            _bw["tx_speed"] = max(0, (tx - _bw["last_tx"]) / dt)
            _bw["rx_total"] += max(0, rx - _bw["last_rx"])
            _bw["tx_total"] += max(0, tx - _bw["last_tx"])

        _bw["last_rx"] = rx
        _bw["last_tx"] = tx
        _bw["last_time"] = now


# ===========================================================================
# Ping helpers
# ===========================================================================

def _ping_host(host):
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            m = re.search(r"time[=<](\d+(?:\.\d+)?)\s*ms", r.stdout)
            if m:
                return round(float(m.group(1)), 1)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def _resolve_server_host(filename):
    if filename.endswith(".ovpn"):
        return filename.replace(".ovpn", "").replace("_tcp", "").replace("_udp", "")
    if filename.endswith(".conf"):
        stem = filename.replace(".conf", "")
        return f"{stem}.prod.surfshark.com"
    return None


def _ping_all_servers():
    """Ping every known server host concurrently and refresh the cache."""
    import concurrent.futures
    servers = parse_ovpn_files() + parse_wg_files()
    host_map = {}
    for s in servers:
        host = _resolve_server_host(s["file"])
        if host:
            host_map.setdefault(host, []).append(s["file"])

    now = time.time()

    def ping_one(host):
        return host, _ping_host(host)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(ping_one, h): h for h in host_map}
        for fut in concurrent.futures.as_completed(futures):
            try:
                host, latency = fut.result()
                entry = {"host": host, "latency_ms": latency,
                         "reachable": latency is not None, "timestamp": now}
                for sf in host_map[host]:
                    _ping_cache[sf] = entry
            except Exception:
                pass


def _ping_refresher():
    """Initial sweep at startup, then refresh every 15 minutes."""
    while True:
        try:
            _ping_all_servers()
        except Exception:
            pass
        time.sleep(900)


# ===========================================================================
# Flask routes
# ===========================================================================

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/status")
def api_status():
    return jsonify(get_vpn_status())


@app.route("/api/servers")
def api_servers():
    return jsonify({"servers": parse_ovpn_files()})


@app.route("/api/wg/servers")
def api_wg_servers():
    return jsonify({"servers": parse_wg_files()})


@app.route("/api/connect", methods=["POST"])
def api_connect():
    data = request.get_json(silent=True) or {}
    server_file = data.get("server", "")
    if not FILENAME_RE.match(server_file):
        return jsonify({"ok": False, "error": "Invalid server file"}), 400
    accepted, msg = request_connect("openvpn", server_file)
    if not accepted:
        return jsonify({"ok": False, "error": msg}), 409
    return jsonify({"ok": True, "message": msg, "async": True})


@app.route("/api/wg/connect", methods=["POST"])
def api_wg_connect():
    data = request.get_json(silent=True) or {}
    server_file = data.get("server", "")
    if not WG_FILENAME_RE.match(server_file):
        return jsonify({"ok": False, "error": "Invalid server file"}), 400
    accepted, msg = request_connect("wireguard", server_file)
    if not accepted:
        return jsonify({"ok": False, "error": msg}), 409
    return jsonify({"ok": True, "message": msg, "async": True})


@app.route("/api/disconnect", methods=["POST"])
def api_disconnect():
    accepted, msg = request_disconnect()
    if not accepted:
        return jsonify({"ok": False, "error": msg}), 409
    return jsonify({"ok": True, "message": msg, "async": True})


@app.route("/api/connect/random", methods=["POST"])
def api_connect_random():
    data = request.get_json(silent=True) or {}
    mode = data.get("vpn_mode", "openvpn")
    protocol = str(data.get("protocol", "udp")).upper()
    if mode == "wireguard":
        servers = parse_wg_files()
    else:
        servers = [s for s in parse_ovpn_files() if s["protocol"] == protocol]
    # Prefer servers we know are reachable, if we have ping data
    reachable = [s for s in servers if _ping_cache.get(s["file"], {}).get("reachable")]
    pool = reachable or servers
    if not pool:
        return jsonify({"ok": False, "error": "No servers available"}), 404
    pick = random.choice(pool)
    accepted, msg = request_connect(mode, pick["file"])
    if not accepted:
        return jsonify({"ok": False, "error": msg}), 409
    return jsonify({"ok": True, "message": msg, "server": pick["file"], "async": True})


@app.route("/api/reconnect-now", methods=["POST"])
def api_reconnect_now():
    global _last_server_file, _last_vpn_mode
    data = request.get_json(silent=True) or {}
    mode = data.get("vpn_mode")
    server = data.get("server")

    if mode and mode not in ("openvpn", "wireguard"):
        return jsonify({"ok": False, "error": "Invalid vpn_mode"}), 400

    if mode and server:
        if not _mode_and_server_valid(mode, server):
            return jsonify({"ok": False, "error": "Invalid server for vpn_mode"}), 400
        _last_vpn_mode = mode
        _last_server_file = server

    if not _last_server_file or not _last_vpn_mode:
        last = _load_last_success()
        if last:
            _last_server_file = str(last.get("server"))
            _last_vpn_mode = str(last.get("vpn_mode"))

    if not _last_server_file or not _last_vpn_mode:
        return jsonify({"ok": False, "error": "No reconnect target available"}), 400

    _add_event("control", f"Manual reconnect requested for {_last_vpn_mode}:{_last_server_file}")
    accepted, msg = request_reconnect(_last_vpn_mode, _last_server_file, "manual")
    if not accepted:
        return jsonify({"ok": False, "error": msg}), 409
    return jsonify({"ok": True, "message": msg, "server": _last_server_file,
                    "vpn_mode": _last_vpn_mode, "async": True})


@app.route("/api/logs")
def api_logs():
    lines = request.args.get("lines", 100, type=int)
    lines = min(lines, 500)
    vpn_mode = _read_mode_file() or "openvpn"
    if vpn_mode == "wireguard":
        return jsonify({"log": read_wg_log(lines)})
    return jsonify({"log": read_log(lines)})


@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    return jsonify({
        "socks_port": SOCKS_PORT,
        "socks_bind": SOCKS_BIND,
        "http_proxy_enabled": HTTP_PROXY_ENABLED,
        "http_proxy_port": HTTP_PROXY_PORT,
        "http_proxy_bind": HTTP_PROXY_BIND,
        "auto_reconnect": AUTO_RECONNECT,
    })


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    global SOCKS_PORT, SOCKS_BIND, HTTP_PROXY_ENABLED, HTTP_PROXY_PORT, HTTP_PROXY_BIND, AUTO_RECONNECT
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "No data provided"}), 400

    socks_changed = False
    http_changed = False

    new_port = data.get("socks_port")
    new_bind = data.get("socks_bind")
    if new_port is not None:
        try:
            new_port = int(new_port)
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "Invalid SOCKS port"}), 400
        if not (1024 <= new_port <= 65535):
            return jsonify({"ok": False, "error": "Port must be between 1024 and 65535"}), 400
        if new_port != SOCKS_PORT:
            SOCKS_PORT = new_port
            socks_changed = True
    if new_bind is not None:
        new_bind = str(new_bind).strip()
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", new_bind):
            return jsonify({"ok": False, "error": "Invalid bind IP address"}), 400
        if new_bind != SOCKS_BIND:
            SOCKS_BIND = new_bind
            socks_changed = True

    http_enabled = data.get("http_proxy_enabled")
    if http_enabled is not None and bool(http_enabled) != HTTP_PROXY_ENABLED:
        HTTP_PROXY_ENABLED = bool(http_enabled)
        http_changed = True
    http_port = data.get("http_proxy_port")
    if http_port is not None:
        try:
            http_port = int(http_port)
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "Invalid HTTP proxy port"}), 400
        if not (1024 <= http_port <= 65535):
            return jsonify({"ok": False, "error": "HTTP port must be between 1024 and 65535"}), 400
        if http_port != HTTP_PROXY_PORT:
            HTTP_PROXY_PORT = http_port
            http_changed = True
    http_bind = data.get("http_proxy_bind")
    if http_bind is not None:
        http_bind = str(http_bind).strip()
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", http_bind):
            return jsonify({"ok": False, "error": "Invalid HTTP bind IP"}), 400
        if http_bind != HTTP_PROXY_BIND:
            HTTP_PROXY_BIND = http_bind
            http_changed = True

    ar = data.get("auto_reconnect")
    if ar is not None:
        AUTO_RECONNECT = bool(ar)

    # Restart proxies with new settings only if a tunnel should be carrying them
    if socks_changed and _socks_running():
        stop_socks()
        start_socks()
        _add_event("proxy", "Restarted microsocks after settings update")

    if http_changed:
        if HTTP_PROXY_ENABLED and _read_mode_file():
            stop_tinyproxy()
            start_tinyproxy()
            _add_event("proxy", "Restarted tinyproxy after settings update")
        elif not HTTP_PROXY_ENABLED:
            stop_tinyproxy()
            _add_event("proxy", "Stopped tinyproxy after settings update")

    return jsonify({
        "ok": True,
        "socks_port": SOCKS_PORT,
        "socks_bind": SOCKS_BIND,
        "http_proxy_enabled": HTTP_PROXY_ENABLED,
        "http_proxy_port": HTTP_PROXY_PORT,
        "http_proxy_bind": HTTP_PROXY_BIND,
        "auto_reconnect": AUTO_RECONNECT,
    })


@app.route("/api/autostart", methods=["GET"])
def api_autostart_get():
    cfg = _load_autostart_config()
    last = _load_last_success()
    return jsonify({"ok": True, "config": cfg, "last_success": last})


@app.route("/api/autostart", methods=["POST"])
def api_autostart_post():
    data = request.get_json(silent=True) or {}
    cfg = _load_autostart_config()

    if "enabled" in data:
        cfg["enabled"] = bool(data.get("enabled"))

    if "preferred_mode" in data:
        mode = data.get("preferred_mode")
        if mode not in (None, "openvpn", "wireguard"):
            return jsonify({"ok": False, "error": "Invalid preferred_mode"}), 400
        cfg["preferred_mode"] = mode

    if "preferred_server" in data:
        server = data.get("preferred_server")
        if server is not None:
            server = str(server)
        cfg["preferred_server"] = server

    if cfg.get("preferred_server") and cfg.get("preferred_mode"):
        if not _mode_and_server_valid(cfg.get("preferred_mode"), cfg.get("preferred_server")):
            return jsonify({"ok": False, "error": "preferred_server does not match preferred_mode"}), 400

    if "retry_count" in data:
        try:
            retry_count = int(data.get("retry_count"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Invalid retry_count"}), 400
        if not (1 <= retry_count <= 10):
            return jsonify({"ok": False, "error": "retry_count must be between 1 and 10"}), 400
        cfg["retry_count"] = retry_count

    if "retry_delay_sec" in data:
        try:
            retry_delay = int(data.get("retry_delay_sec"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Invalid retry_delay_sec"}), 400
        if not (1 <= retry_delay <= 60):
            return jsonify({"ok": False, "error": "retry_delay_sec must be between 1 and 60"}), 400
        cfg["retry_delay_sec"] = retry_delay

    if "failover_scope" in data:
        failover_scope = str(data.get("failover_scope")).strip().lower()
        if failover_scope not in ("global", "same_mode", "none"):
            return jsonify({"ok": False, "error": "Invalid failover_scope"}), 400
        cfg["failover_scope"] = failover_scope

    _save_autostart_config(cfg)
    _add_event("autostart", "Autostart preferences updated")
    return jsonify({"ok": True, "config": cfg})


@app.route("/api/events", methods=["GET"])
def api_events():
    lines = request.args.get("lines", 200, type=int)
    lines = max(1, min(lines, 500))
    return jsonify({"ok": True, "events": _get_events(lines)})


@app.route("/api/bandwidth")
def api_bandwidth():
    return jsonify({
        "rx_speed": round(_bw["rx_speed"], 1),
        "tx_speed": round(_bw["tx_speed"], 1),
        "rx_total": _bw["rx_total"],
        "tx_total": _bw["tx_total"],
    })


@app.route("/api/ping", methods=["GET"])
def api_ping_cached():
    results = []
    for sf, entry in list(_ping_cache.items()):
        results.append({"file": sf, "host": entry["host"],
                        "latency_ms": entry["latency_ms"],
                        "reachable": entry["reachable"]})
    return jsonify({"ok": True, "results": results})


@app.route("/api/ping", methods=["POST"])
def api_ping():
    data = request.get_json(silent=True)
    if not data or "servers" not in data:
        return jsonify({"ok": False, "error": "No servers specified"}), 400
    servers = data["servers"]
    if not isinstance(servers, list) or not servers or len(servers) > 20:
        return jsonify({"ok": False, "error": "Provide 1-20 servers"}), 400

    import concurrent.futures
    now = time.time()
    results = []

    def ping_entry(sf):
        sf = str(sf)
        host = _resolve_server_host(sf)
        if not host:
            return {"file": sf, "host": None, "latency_ms": None, "reachable": False}
        latency = _ping_host(host)
        _ping_cache[sf] = {"host": host, "latency_ms": latency,
                           "reachable": latency is not None, "timestamp": now}
        return {"file": sf, "host": host, "latency_ms": latency,
                "reachable": latency is not None}

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(ping_entry, servers))
    return jsonify({"ok": True, "results": results})


@app.route("/api/favorites", methods=["GET"])
def api_favorites_get():
    return jsonify({"favorites": load_json("favorites.json", [])})


@app.route("/api/favorites", methods=["POST"])
def api_favorites_add():
    data = request.get_json(silent=True)
    if not data or "server" not in data:
        return jsonify({"ok": False, "error": "No server specified"}), 400
    sf = str(data["server"])
    if not FILENAME_RE.match(sf) and not WG_FILENAME_RE.match(sf):
        return jsonify({"ok": False, "error": "Invalid server file"}), 400
    favs = load_json("favorites.json", [])
    if sf not in favs:
        favs.append(sf)
        save_json("favorites.json", favs)
    return jsonify({"ok": True, "favorites": favs})


@app.route("/api/favorites", methods=["DELETE"])
def api_favorites_remove():
    data = request.get_json(silent=True)
    if not data or "server" not in data:
        return jsonify({"ok": False, "error": "No server specified"}), 400
    sf = str(data["server"])
    favs = load_json("favorites.json", [])
    favs = [f for f in favs if f != sf]
    save_json("favorites.json", favs)
    return jsonify({"ok": True, "favorites": favs})


@app.route("/api/recent")
def api_recent():
    return jsonify({"recent": load_json("recent.json", [])})


@app.route("/api/profiles", methods=["GET"])
def api_profiles_get():
    return jsonify({"profiles": load_json("profiles.json", [])})


@app.route("/api/profiles", methods=["POST"])
def api_profiles_create():
    data = request.get_json(silent=True)
    if not data or "name" not in data or "server" not in data:
        return jsonify({"ok": False, "error": "name and server required"}), 400
    name = str(data["name"]).strip()[:50]
    sf = str(data["server"])
    if not FILENAME_RE.match(sf) and not WG_FILENAME_RE.match(sf):
        return jsonify({"ok": False, "error": "Invalid server file"}), 400
    profiles = load_json("profiles.json", [])
    if len(profiles) >= 20:
        return jsonify({"ok": False, "error": "Maximum 20 profiles"}), 400
    if any(p["name"] == name for p in profiles):
        return jsonify({"ok": False, "error": "Profile name already exists"}), 400
    profile = {
        "name": name,
        "server": sf,
        "vpn_mode": data.get("vpn_mode", "openvpn"),
        "protocol": data.get("protocol", "UDP"),
        "socks_port": data.get("socks_port", SOCKS_PORT),
        "http_port": data.get("http_port", HTTP_PROXY_PORT),
    }
    profiles.append(profile)
    save_json("profiles.json", profiles)
    return jsonify({"ok": True, "profile": profile})


@app.route("/api/profiles", methods=["PUT"])
def api_profiles_update():
    data = request.get_json(silent=True)
    if not data or "name" not in data:
        return jsonify({"ok": False, "error": "name required"}), 400
    name = str(data["name"]).strip()
    profiles = load_json("profiles.json", [])
    for p in profiles:
        if p["name"] == name:
            if "server" in data:
                sf = str(data["server"])
                if not FILENAME_RE.match(sf) and not WG_FILENAME_RE.match(sf):
                    return jsonify({"ok": False, "error": "Invalid server file"}), 400
                p["server"] = sf
            for key in ("vpn_mode", "protocol", "socks_port", "http_port"):
                if key in data:
                    p[key] = data[key]
            save_json("profiles.json", profiles)
            return jsonify({"ok": True, "profile": p})
    return jsonify({"ok": False, "error": "Profile not found"}), 404


@app.route("/api/profiles", methods=["DELETE"])
def api_profiles_delete():
    data = request.get_json(silent=True)
    if not data or "name" not in data:
        return jsonify({"ok": False, "error": "name required"}), 400
    name = str(data["name"]).strip()
    profiles = load_json("profiles.json", [])
    profiles = [p for p in profiles if p["name"] != name]
    save_json("profiles.json", profiles)
    return jsonify({"ok": True})


@app.route("/api/profiles/activate", methods=["POST"])
def api_profiles_activate():
    global SOCKS_PORT, HTTP_PROXY_PORT
    data = request.get_json(silent=True)
    if not data or "name" not in data:
        return jsonify({"ok": False, "error": "name required"}), 400
    name = str(data["name"]).strip()
    profiles = load_json("profiles.json", [])
    profile = next((p for p in profiles if p["name"] == name), None)
    if not profile:
        return jsonify({"ok": False, "error": "Profile not found"}), 404
    try:
        if "socks_port" in profile:
            SOCKS_PORT = int(profile["socks_port"])
        if "http_port" in profile:
            HTTP_PROXY_PORT = int(profile["http_port"])
    except (TypeError, ValueError):
        pass
    mode = "wireguard" if profile.get("vpn_mode") == "wireguard" else "openvpn"
    accepted, msg = request_connect(mode, profile["server"])
    if not accepted:
        return jsonify({"ok": False, "error": msg}), 409
    return jsonify({"ok": True, "message": msg, "async": True})


@app.route("/api/geoip")
def api_geoip():
    ip = _vpn_ip["ip"]
    if not ip:
        return jsonify({"ok": False, "error": "No VPN IP available"}), 404
    cached = _geoip_cache.get(ip)
    if cached and time.time() - cached.get("_ts", 0) < 600:
        return jsonify({"ok": True, **{k: v for k, v in cached.items() if k != "_ts"}})
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "5", f"http://ip-api.com/json/{ip}"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            geo = json.loads(r.stdout)
            result = {
                "ip": ip,
                "country": geo.get("country", ""),
                "city": geo.get("city", ""),
                "isp": geo.get("isp", ""),
                "org": geo.get("org", ""),
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
            }
            _geoip_cache[ip] = {**result, "_ts": time.time()}
            return jsonify({"ok": True, **result})
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        pass
    return jsonify({"ok": False, "error": "GeoIP lookup failed"}), 502


@app.route("/api/dnstest")
def api_dnstest():
    try:
        r = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", "whoami.akamai.net", "@ns1-1.akamaitech.net"],
            capture_output=True, text=True, timeout=10,
        )
        resolver_ip = r.stdout.strip() if r.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        resolver_ip = None

    if not resolver_ip:
        return jsonify({"ok": True, "status": "unknown", "message": "Could not determine DNS resolver", "resolver_ip": None})

    leak = False
    message = f"DNS resolver: {resolver_ip}"
    try:
        r2 = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", "-x", resolver_ip],
            capture_output=True, text=True, timeout=5,
        )
        ptr = r2.stdout.strip().lower()
        if any(kw in ptr for kw in ["surfshark", "cloudflare", "google"]):
            message = f"DNS: No leak detected (resolver: {resolver_ip}, {ptr})"
        else:
            leak = True
            message = f"DNS: Possible leak (resolver: {resolver_ip}, {ptr or 'unknown'})"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        message = f"DNS resolver: {resolver_ip} (could not verify)"

    return jsonify({"ok": True, "status": "leak" if leak else "secure", "message": message, "resolver_ip": resolver_ip})


# ===========================================================================
# Start background threads & run
# ===========================================================================

def _start_background_threads():
    threading.Thread(target=_health_monitor, daemon=True).start()
    threading.Thread(target=_bandwidth_monitor, daemon=True).start()
    threading.Thread(target=_ping_refresher, daemon=True).start()
    threading.Thread(target=_boot_autostart, daemon=True).start()


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    _record_original_gateway()
    _save_autostart_config(_load_autostart_config())
    last = _load_last_success()
    if last:
        _last_server_file = str(last.get("server"))
        _last_vpn_mode = str(last.get("vpn_mode"))
    _start_background_threads()
    try:
        from waitress import serve
        serve(app, host="0.0.0.0", port=8000, threads=12)
    except ImportError:
        app.run(host="0.0.0.0", port=8000, threaded=True)
