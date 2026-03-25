import json
import os
import random
import re
import signal
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

# ---------------------------------------------------------------------------
# Runtime state (guarded by vpn_lock)
# ---------------------------------------------------------------------------
SOCKS_PORT = int(os.environ.get("SOCKS_PORT", "1080"))
SOCKS_BIND = os.environ.get("SOCKS_BIND", "0.0.0.0")
HTTP_PROXY_ENABLED = True
HTTP_PROXY_PORT = int(os.environ.get("HTTP_PORT", "8888"))
HTTP_PROXY_BIND = os.environ.get("HTTP_BIND", "0.0.0.0")
AUTO_RECONNECT = True

vpn_lock = threading.Lock()
connected_since = None  # epoch timestamp when VPN connected
_reconnecting = False
_reconnect_attempts = 0
_last_server_file = None  # last connected server filename
_last_vpn_mode = None  # "openvpn" or "wireguard"

# Bandwidth tracking
_bw = {
    "rx_speed": 0, "tx_speed": 0,
    "rx_total": 0, "tx_total": 0,
    "last_rx": 0, "last_tx": 0,
    "last_time": 0,
}

# Ping cache: {filename: {latency_ms, reachable, timestamp}}
_ping_cache = {}

# Geo-IP cache: {ip: {data..., timestamp}}
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
# Persistent JSON helpers
# ===========================================================================

def _json_path(name):
    return os.path.join(DATA_DIR, name)


def load_json(name, default=None):
    path = _json_path(name)
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default if default is not None else []


def save_json(name, data):
    os.makedirs(DATA_DIR, exist_ok=True)
    path = _json_path(name)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# ===========================================================================
# Process helpers
# ===========================================================================

def get_openvpn_pid():
    try:
        with open(OPENVPN_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return pid
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        return None


def get_microsocks_pid():
    try:
        result = subprocess.run(
            ["pgrep", "-x", "microsocks"], capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return int(result.stdout.strip().split("\n")[0])
    except (subprocess.TimeoutExpired, ValueError):
        pass
    return None


def get_tinyproxy_pid():
    try:
        result = subprocess.run(
            ["pgrep", "-x", "tinyproxy"], capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return int(result.stdout.strip().split("\n")[0])
    except (subprocess.TimeoutExpired, ValueError):
        pass
    return None


def _interface_alive(iface):
    try:
        r = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


# ===========================================================================
# Tinyproxy management
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


def start_tinyproxy():
    if not HTTP_PROXY_ENABLED:
        return
    stop_tinyproxy()
    _write_tinyproxy_conf()
    subprocess.Popen(
        ["tinyproxy", "-c", TINYPROXY_CONF],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def stop_tinyproxy():
    pid = get_tinyproxy_pid()
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.3)
        except ProcessLookupError:
            pass


# ===========================================================================
# VPN status
# ===========================================================================

def get_vpn_status():
    vpn_mode = "openvpn"
    try:
        with open(VPN_MODE_FILE) as f:
            vpn_mode = f.read().strip() or "openvpn"
    except FileNotFoundError:
        pass

    connected = False
    current_server = None
    vpn_ip = None

    if vpn_mode == "wireguard":
        if _interface_alive(WG_INTERFACE):
            connected = True
        if connected:
            try:
                result = subprocess.run(
                    ["curl", "-s", "--max-time", "5", "https://api.ipify.org"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    vpn_ip = result.stdout.strip()
            except subprocess.TimeoutExpired:
                pass
        if os.path.exists(WG_CONF):
            try:
                with open(WG_CONF) as f:
                    for line in f:
                        if line.strip().startswith("Endpoint"):
                            parts = line.split("=", 1)
                            if len(parts) == 2:
                                current_server = parts[1].strip().split(":")[0]
                            break
            except OSError:
                pass
    else:
        pid = get_openvpn_pid()
        if pid and _interface_alive("tun0"):
            connected = True
            try:
                result = subprocess.run(
                    ["curl", "-s", "--max-time", "5", "https://api.ipify.org"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    vpn_ip = result.stdout.strip()
            except subprocess.TimeoutExpired:
                pass
        if os.path.exists(ACTIVE_OVPN):
            try:
                with open(ACTIVE_OVPN) as f:
                    for line in f:
                        if line.startswith("remote "):
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                current_server = parts[1]
                            break
            except OSError:
                pass

    return {
        "connected": connected,
        "vpn_mode": vpn_mode,
        "openvpn_running": get_openvpn_pid() is not None,
        "socks_running": get_microsocks_pid() is not None,
        "current_server": current_server,
        "vpn_ip": vpn_ip,
        "socks_port": SOCKS_PORT,
        "socks_bind": SOCKS_BIND,
        "http_proxy_enabled": HTTP_PROXY_ENABLED,
        "http_proxy_port": HTTP_PROXY_PORT,
        "http_proxy_bind": HTTP_PROXY_BIND,
        "http_proxy_running": get_tinyproxy_pid() is not None,
        "auto_reconnect": AUTO_RECONNECT,
        "reconnecting": _reconnecting,
        "reconnect_attempts": _reconnect_attempts,
        "connected_since": connected_since,
    }


def read_log(lines=50):
    """Read last N lines of the OpenVPN log."""
    try:
        with open(OPENVPN_LOG) as f:
            all_lines = f.readlines()
            return "".join(all_lines[-lines:])
    except FileNotFoundError:
        return "No log file yet."


def stop_vpn():
    """Stop OpenVPN, WireGuard, tinyproxy and microsocks."""
    global connected_since
    pid = get_openvpn_pid()
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(10):
                try:
                    os.kill(pid, 0)
                    time.sleep(0.5)
                except ProcessLookupError:
                    break
        except ProcessLookupError:
            pass

    # Stop WireGuard
    try:
        route_info = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True
        )
        if WG_INTERFACE in route_info.stdout:
            all_routes = subprocess.run(
                ["ip", "route"], capture_output=True, text=True
            )
            for line in all_routes.stdout.splitlines():
                if "via" in line and WG_INTERFACE not in line:
                    m = re.search(r"via (\S+)", line)
                    if m:
                        gateway = m.group(1)
                        subprocess.run(["ip", "route", "del", "default"],
                                       capture_output=True, text=True)
                        subprocess.run(["ip", "route", "add", "default", "via", gateway],
                                       capture_output=True, text=True)
                        break
        subprocess.run(
            ["wg-quick", "down", WG_INTERFACE],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Stop proxies
    socks_pid = get_microsocks_pid()
    if socks_pid:
        try:
            os.kill(socks_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    stop_tinyproxy()

    connected_since = None
    for fpath in [OPENVPN_PID, VPN_MODE_FILE]:
        try:
            os.remove(fpath)
        except FileNotFoundError:
            pass


def _start_proxies():
    """Start SOCKS5 and HTTP proxies if not already running."""
    if not get_microsocks_pid():
        subprocess.Popen(
            ["microsocks", "-i", SOCKS_BIND, "-p", str(SOCKS_PORT)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    if HTTP_PROXY_ENABLED and not get_tinyproxy_pid():
        start_tinyproxy()


def _add_recent(server_file, vpn_mode, vpn_ip=None):
    """Log a successful connection to recent.json."""
    recent = load_json("recent.json", [])
    entry = {
        "file": server_file,
        "vpn_mode": vpn_mode,
        "vpn_ip": vpn_ip,
        "timestamp": time.time(),
    }
    recent = [r for r in recent if r.get("file") != server_file]
    recent.insert(0, entry)
    recent = recent[:20]
    save_json("recent.json", recent)


def start_vpn(config_file):
    """Start OpenVPN with the given config file and proxies."""
    global connected_since, _last_server_file, _last_vpn_mode
    config_path = os.path.join(CONFIG_DIR, config_file)
    if not os.path.exists(config_path):
        return False, f"Config file not found: {config_file}"
    if not os.path.exists(AUTH_FILE):
        return False, "Credentials file (auth.txt) not found"

    stop_vpn()
    time.sleep(1)

    # Fix auth.txt permissions so OpenVPN doesn't warn/reject
    try:
        os.chmod(AUTH_FILE, 0o600)
    except OSError:
        pass

    with open(config_path) as src:
        content = src.read()
    content = re.sub(r"^auth-user-pass.*$", f"auth-user-pass {AUTH_FILE}", content, flags=re.MULTILINE)
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
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    # Wait up to 120s: TLS negotiation can take multiple 60s retry cycles
    for _ in range(120):
        if _interface_alive("tun0"):
            with open(VPN_MODE_FILE, "w") as f:
                f.write("openvpn")
            connected_since = time.time()
            _last_server_file = config_file
            _last_vpn_mode = "openvpn"
            _start_proxies()
            _add_recent(config_file, "openvpn")
            return True, "VPN connected successfully"
        # Fast-fail if openvpn process died
        if proc.poll() is not None:
            return False, "OpenVPN process exited unexpectedly. Check logs."
        time.sleep(1)

    return False, "VPN tunnel failed to establish within 120 seconds. Check logs."


def start_wireguard(config_file):
    """Start WireGuard with the given config file and proxies."""
    global connected_since, _last_server_file, _last_vpn_mode
    config_path = os.path.join(WG_CONFIG_DIR, config_file)
    if not os.path.exists(config_path):
        return False, f"Config file not found: {config_file}"

    stop_vpn()
    time.sleep(1)

    wg_private_key = None
    if os.path.exists(WG_KEY_FILE):
        try:
            with open(WG_KEY_FILE) as f:
                lines = f.read().strip().splitlines()
                if len(lines) >= 2:
                    wg_private_key = lines[1].strip()
        except OSError:
            pass

    os.makedirs("/etc/wireguard", exist_ok=True)
    with open(config_path) as src:
        content = src.read()
    if wg_private_key:
        content = re.sub(
            r"^PrivateKey\s*=\s*.*$",
            f"PrivateKey = {wg_private_key}",
            content, flags=re.MULTILINE,
        )
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
        return False, "WireGuard connection timed out"

    with open(WG_LOG, "a") as logf:
        logf.write(f"[{timestamp}] wg-quick up {WG_INTERFACE}\n")
        if result.stdout:
            logf.write(result.stdout)
        if result.stderr:
            logf.write(result.stderr)
        logf.write("\n")

    if result.returncode != 0:
        return False, f"WireGuard failed: {result.stderr.strip()}"

    # Manual routing
    try:
        route_info = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True
        )
        gw_match = re.search(r"default via (\S+)", route_info.stdout)
        if gw_match:
            gateway = gw_match.group(1)
            endpoint_info = subprocess.run(
                ["wg", "show", WG_INTERFACE, "endpoints"],
                capture_output=True, text=True,
            )
            ep_match = re.search(r"(\d+\.\d+\.\d+\.\d+):\d+", endpoint_info.stdout)
            if ep_match:
                endpoint_ip = ep_match.group(1)
                subprocess.run(["ip", "route", "add", endpoint_ip, "via", gateway],
                               capture_output=True, text=True)
            subprocess.run(["ip", "route", "del", "default"],
                           capture_output=True, text=True)
            subprocess.run(["ip", "route", "add", "default", "dev", WG_INTERFACE],
                           capture_output=True, text=True)
            with open(WG_LOG, "a") as logf:
                logf.write(f"[{timestamp}] Routing configured via {WG_INTERFACE}\n")
    except Exception as e:
        with open(WG_LOG, "a") as logf:
            logf.write(f"[{timestamp}] Routing warning: {e}\n")

    with open(VPN_MODE_FILE, "w") as f:
        f.write("wireguard")
    connected_since = time.time()
    _last_server_file = config_file
    _last_vpn_mode = "wireguard"
    _start_proxies()
    _add_recent(config_file, "wireguard")
    return True, "WireGuard connected successfully"


def read_wg_log(lines=50):
    """Read WireGuard log and append live interface status."""
    log_content = ""
    try:
        with open(WG_LOG) as f:
            all_lines = f.readlines()
            log_content = "".join(all_lines[-lines:])
    except FileNotFoundError:
        log_content = "No WireGuard log yet.\n"

    try:
        result = subprocess.run(
            ["wg", "show"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            log_content += "\n--- WireGuard Interface Status ---\n"
            log_content += result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return log_content


# ===========================================================================
# Background threads
# ===========================================================================

def _health_monitor():
    """Check VPN interface every 10s; auto-reconnect on drop."""
    global _reconnecting, _reconnect_attempts, connected_since
    while True:
        time.sleep(10)
        if not AUTO_RECONNECT or _reconnecting:
            continue

        vpn_mode = None
        try:
            with open(VPN_MODE_FILE) as f:
                vpn_mode = f.read().strip()
        except FileNotFoundError:
            continue

        iface = WG_INTERFACE if vpn_mode == "wireguard" else "tun0"
        if _interface_alive(iface):
            # Interface up — make sure proxies are running
            if not get_microsocks_pid():
                _start_proxies()
            continue

        if not _last_server_file or not _last_vpn_mode:
            continue

        _reconnecting = True
        _reconnect_attempts = 0

        for attempt in range(3):
            _reconnect_attempts = attempt + 1
            with vpn_lock:
                if _last_vpn_mode == "wireguard":
                    ok, _ = start_wireguard(_last_server_file)
                else:
                    ok, _ = start_vpn(_last_server_file)
            if ok:
                _reconnecting = False
                _reconnect_attempts = 0
                break
            time.sleep(5)
        else:
            # Failover: pick a random server of same type
            if _last_vpn_mode == "wireguard":
                servers = parse_wg_files()
            else:
                servers = parse_ovpn_files()
            if servers:
                pick = random.choice(servers)
                with vpn_lock:
                    if _last_vpn_mode == "wireguard":
                        start_wireguard(pick["file"])
                    else:
                        start_vpn(pick["file"])

        _reconnecting = False
        _reconnect_attempts = 0


def _bandwidth_monitor():
    """Poll interface stats every 2s to calculate speed."""
    global _bw
    while True:
        time.sleep(2)
        vpn_mode = None
        try:
            with open(VPN_MODE_FILE) as f:
                vpn_mode = f.read().strip()
        except FileNotFoundError:
            _bw["rx_speed"] = _bw["tx_speed"] = 0
            continue

        iface = WG_INTERFACE if vpn_mode == "wireguard" else "tun0"
        rx_path = f"/sys/class/net/{iface}/statistics/rx_bytes"
        tx_path = f"/sys/class/net/{iface}/statistics/tx_bytes"

        try:
            with open(rx_path) as f:
                rx = int(f.read().strip())
            with open(tx_path) as f:
                tx = int(f.read().strip())
        except (FileNotFoundError, ValueError):
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
# Ping helper
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
    except subprocess.TimeoutExpired:
        pass
    return None


def _resolve_server_host(filename):
    if filename.endswith(".ovpn"):
        return filename.replace(".ovpn", "").replace("_tcp", "").replace("_udp", "")
    if filename.endswith(".conf"):
        stem = filename.replace(".conf", "")
        return f"{stem}.prod.surfshark.com"
    return None


def _startup_ping():
    """Ping all servers once at startup and populate the cache."""
    import concurrent.futures
    servers = parse_ovpn_files() + parse_wg_files()
    # Deduplicate by host to avoid pinging the same host twice (TCP+UDP)
    host_map = {}  # host -> [filenames]
    for s in servers:
        host = _resolve_server_host(s["file"])
        if host:
            host_map.setdefault(host, []).append(s["file"])

    now = time.time()
    def ping_one(host):
        latency = _ping_host(host)
        return host, latency

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
    data = request.get_json()
    if not data or "server" not in data:
        return jsonify({"ok": False, "error": "No server specified"}), 400
    server_file = data["server"]
    if not FILENAME_RE.match(server_file):
        return jsonify({"ok": False, "error": "Invalid server file"}), 400
    with vpn_lock:
        ok, msg = start_vpn(server_file)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/wg/connect", methods=["POST"])
def api_wg_connect():
    data = request.get_json()
    if not data or "server" not in data:
        return jsonify({"ok": False, "error": "No server specified"}), 400
    server_file = data["server"]
    if not WG_FILENAME_RE.match(server_file):
        return jsonify({"ok": False, "error": "Invalid server file"}), 400
    with vpn_lock:
        ok, msg = start_wireguard(server_file)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/disconnect", methods=["POST"])
def api_disconnect():
    with vpn_lock:
        stop_vpn()
    return jsonify({"ok": True, "message": "VPN disconnected"})


@app.route("/api/connect/random", methods=["POST"])
def api_connect_random():
    data = request.get_json() or {}
    mode = data.get("vpn_mode", "openvpn")
    protocol = data.get("protocol", "udp").upper()
    if mode == "wireguard":
        servers = parse_wg_files()
    else:
        servers = [s for s in parse_ovpn_files() if s["protocol"] == protocol]
    if not servers:
        return jsonify({"ok": False, "error": "No servers available"}), 404
    pick = random.choice(servers)
    with vpn_lock:
        if mode == "wireguard":
            ok, msg = start_wireguard(pick["file"])
        else:
            ok, msg = start_vpn(pick["file"])
    return jsonify({"ok": ok, "message": msg, "server": pick["file"]})


@app.route("/api/logs")
def api_logs():
    lines = request.args.get("lines", 100, type=int)
    lines = min(lines, 500)
    vpn_mode = "openvpn"
    try:
        with open(VPN_MODE_FILE) as f:
            vpn_mode = f.read().strip() or "openvpn"
    except FileNotFoundError:
        pass
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
    data = request.get_json()
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
    if http_enabled is not None:
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

    if socks_changed:
        pid = get_microsocks_pid()
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.5)
            except ProcessLookupError:
                pass
            subprocess.Popen(
                ["microsocks", "-i", SOCKS_BIND, "-p", str(SOCKS_PORT)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

    if http_changed:
        if HTTP_PROXY_ENABLED and get_tinyproxy_pid():
            stop_tinyproxy()
            start_tinyproxy()
        elif not HTTP_PROXY_ENABLED:
            stop_tinyproxy()

    return jsonify({
        "ok": True,
        "socks_port": SOCKS_PORT,
        "socks_bind": SOCKS_BIND,
        "http_proxy_enabled": HTTP_PROXY_ENABLED,
        "http_proxy_port": HTTP_PROXY_PORT,
        "http_proxy_bind": HTTP_PROXY_BIND,
        "auto_reconnect": AUTO_RECONNECT,
    })


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
    """Return all cached ping results."""
    results = []
    for sf, entry in _ping_cache.items():
        results.append({"file": sf, "host": entry["host"],
                        "latency_ms": entry["latency_ms"],
                        "reachable": entry["reachable"]})
    return jsonify({"ok": True, "results": results})


@app.route("/api/ping", methods=["POST"])
def api_ping():
    data = request.get_json()
    if not data or "servers" not in data:
        return jsonify({"ok": False, "error": "No servers specified"}), 400
    servers = data["servers"]
    if not isinstance(servers, list) or len(servers) > 20:
        return jsonify({"ok": False, "error": "Provide 1-20 servers"}), 400

    now = time.time()
    results = []
    for sf in servers:
        sf = str(sf)
        host = _resolve_server_host(sf)
        if not host:
            results.append({"file": sf, "host": None, "latency_ms": None, "reachable": False})
            continue
        latency = _ping_host(host)
        entry = {"host": host, "latency_ms": latency, "reachable": latency is not None, "timestamp": now}
        _ping_cache[sf] = entry
        results.append({"file": sf, "host": host, "latency_ms": latency, "reachable": latency is not None})
    return jsonify({"ok": True, "results": results})


@app.route("/api/favorites", methods=["GET"])
def api_favorites_get():
    return jsonify({"favorites": load_json("favorites.json", [])})


@app.route("/api/favorites", methods=["POST"])
def api_favorites_add():
    data = request.get_json()
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
    data = request.get_json()
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
    data = request.get_json()
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
    data = request.get_json()
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
    data = request.get_json()
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
    data = request.get_json()
    if not data or "name" not in data:
        return jsonify({"ok": False, "error": "name required"}), 400
    name = str(data["name"]).strip()
    profiles = load_json("profiles.json", [])
    profile = next((p for p in profiles if p["name"] == name), None)
    if not profile:
        return jsonify({"ok": False, "error": "Profile not found"}), 404
    if "socks_port" in profile:
        SOCKS_PORT = int(profile["socks_port"])
    if "http_port" in profile:
        HTTP_PROXY_PORT = int(profile["http_port"])
    sf = profile["server"]
    with vpn_lock:
        if profile.get("vpn_mode") == "wireguard":
            ok, msg = start_wireguard(sf)
        else:
            ok, msg = start_vpn(sf)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/geoip")
def api_geoip():
    status = get_vpn_status()
    ip = status.get("vpn_ip")
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
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return jsonify({"ok": False, "error": "GeoIP lookup failed"}), 502


@app.route("/api/dnstest")
def api_dnstest():
    try:
        r = subprocess.run(
            ["dig", "+short", "whoami.akamai.net", "@ns1-1.akamaitech.net"],
            capture_output=True, text=True, timeout=10,
        )
        resolver_ip = r.stdout.strip() if r.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        resolver_ip = None

    if not resolver_ip:
        return jsonify({"ok": True, "status": "unknown", "message": "Could not determine DNS resolver", "resolver_ip": None})

    leak = False
    message = f"DNS resolver: {resolver_ip}"
    try:
        r2 = subprocess.run(
            ["dig", "+short", "-x", resolver_ip],
            capture_output=True, text=True, timeout=5,
        )
        ptr = r2.stdout.strip().lower()
        if any(kw in ptr for kw in ["surfshark", "cloudflare", "google"]):
            message = f"DNS: No leak detected (resolver: {resolver_ip}, {ptr})"
        else:
            leak = True
            message = f"DNS: Possible leak (resolver: {resolver_ip}, {ptr or 'unknown'})"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        message = f"DNS resolver: {resolver_ip} (could not verify)"

    return jsonify({"ok": True, "status": "leak" if leak else "secure", "message": message, "resolver_ip": resolver_ip})


# ===========================================================================
# Start background threads & run
# ===========================================================================

if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    threading.Thread(target=_health_monitor, daemon=True).start()
    threading.Thread(target=_bandwidth_monitor, daemon=True).start()
    threading.Thread(target=_startup_ping, daemon=True).start()
    app.run(host="0.0.0.0", port=8080)
