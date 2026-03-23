import os
import re
import signal
import subprocess
import time
from pathlib import Path

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

CONFIG_DIR = "/vpn/config"
AUTH_FILE = "/vpn/auth.txt"
ACTIVE_OVPN = "/tmp/active.ovpn"
OPENVPN_LOG = "/var/log/openvpn.log"
OPENVPN_PID = "/var/run/openvpn.pid"
SOCKS_PORT = int(os.environ.get("SOCKS_PORT", "1080"))
SOCKS_BIND = os.environ.get("SOCKS_BIND", "0.0.0.0")

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
    "nyt": "Naypyidaw", "oma": "Omaha", "opo": "Porto", "osl": "Oslo",
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
    """Parse all .ovpn files and return structured server list."""
    servers = []
    config_path = Path(CONFIG_DIR)
    if not config_path.exists():
        return servers

    for f in sorted(config_path.glob("*.ovpn")):
        name = f.stem  # e.g. "pk-khi.prod.surfshark.com_tcp"
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


def get_openvpn_pid():
    """Get the running OpenVPN PID, or None."""
    try:
        with open(OPENVPN_PID) as f:
            pid = int(f.read().strip())
        # Check process exists
        os.kill(pid, 0)
        return pid
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        return None


def get_microsocks_pid():
    """Get the running microsocks PID, or None."""
    try:
        result = subprocess.run(
            ["pgrep", "-x", "microsocks"], capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            return int(result.stdout.strip().split("\n")[0])
    except (subprocess.TimeoutExpired, ValueError):
        pass
    return None


def get_vpn_status():
    """Get current VPN connection status."""
    pid = get_openvpn_pid()
    connected = False
    tun_up = False
    current_server = None
    vpn_ip = None

    if pid:
        # Check if tun0 exists
        try:
            result = subprocess.run(
                ["ip", "link", "show", "tun0"],
                capture_output=True, text=True, timeout=5
            )
            tun_up = result.returncode == 0
        except subprocess.TimeoutExpired:
            pass

        connected = tun_up

        if connected:
            try:
                result = subprocess.run(
                    ["curl", "-s", "--max-time", "5", "https://api.ipify.org"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    vpn_ip = result.stdout.strip()
            except subprocess.TimeoutExpired:
                pass

    # Read current active config
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

    socks_pid = get_microsocks_pid()

    return {
        "connected": connected,
        "openvpn_running": pid is not None,
        "socks_running": socks_pid is not None,
        "current_server": current_server,
        "vpn_ip": vpn_ip,
        "socks_port": SOCKS_PORT,
        "socks_bind": SOCKS_BIND,
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
    """Stop OpenVPN and microsocks."""
    pid = get_openvpn_pid()
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            # Wait for process to die
            for _ in range(10):
                try:
                    os.kill(pid, 0)
                    time.sleep(0.5)
                except ProcessLookupError:
                    break
        except ProcessLookupError:
            pass

    socks_pid = get_microsocks_pid()
    if socks_pid:
        try:
            os.kill(socks_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    # Clean up PID file
    try:
        os.remove(OPENVPN_PID)
    except FileNotFoundError:
        pass


def start_vpn(config_file):
    """Start OpenVPN with the given config file and microsocks."""
    config_path = os.path.join(CONFIG_DIR, config_file)
    if not os.path.exists(config_path):
        return False, f"Config file not found: {config_file}"

    if not os.path.exists(AUTH_FILE):
        return False, "Credentials file (auth.txt) not found"

    # Stop any running instance first
    stop_vpn()
    time.sleep(1)

    # Prepare config
    with open(config_path) as src:
        content = src.read()
    content = re.sub(r"^auth-user-pass.*$", f"auth-user-pass {AUTH_FILE}", content, flags=re.MULTILINE)
    with open(ACTIVE_OVPN, "w") as dst:
        dst.write(content)

    # Clear old log
    with open(OPENVPN_LOG, "w") as f:
        f.write("")

    # Start OpenVPN
    subprocess.Popen(
        ["openvpn", "--config", ACTIVE_OVPN, "--log", OPENVPN_LOG, "--writepid", OPENVPN_PID],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    # Wait for tunnel
    for i in range(30):
        try:
            result = subprocess.run(
                ["ip", "link", "show", "tun0"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Start microsocks
                socks_pid = get_microsocks_pid()
                if not socks_pid:
                    subprocess.Popen(
                        ["microsocks", "-i", SOCKS_BIND, "-p", str(SOCKS_PORT)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                return True, "VPN connected successfully"
        except subprocess.TimeoutExpired:
            pass
        time.sleep(1)

    return False, "VPN tunnel failed to establish within 30 seconds. Check logs."


# --- Routes ---

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/status")
def api_status():
    return jsonify(get_vpn_status())


@app.route("/api/servers")
def api_servers():
    return jsonify(parse_ovpn_files())


@app.route("/api/connect", methods=["POST"])
def api_connect():
    data = request.get_json()
    if not data or "server" not in data:
        return jsonify({"ok": False, "error": "No server specified"}), 400

    server_file = data["server"]
    # Validate filename format to prevent path traversal
    if not re.match(r"^[a-z]{2}-[a-z]{3}\.prod\.surfshark\.com_(tcp|udp)\.ovpn$", server_file):
        return jsonify({"ok": False, "error": "Invalid server file"}), 400

    ok, msg = start_vpn(server_file)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/disconnect", methods=["POST"])
def api_disconnect():
    stop_vpn()
    return jsonify({"ok": True, "message": "VPN disconnected"})


@app.route("/api/logs")
def api_logs():
    lines = request.args.get("lines", 100, type=int)
    lines = min(lines, 500)
    return jsonify({"log": read_log(lines)})


@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    return jsonify({"socks_port": SOCKS_PORT, "socks_bind": SOCKS_BIND})


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    global SOCKS_PORT, SOCKS_BIND
    data = request.get_json()
    if not data:
        return jsonify({"ok": False, "error": "No data provided"}), 400

    new_port = data.get("socks_port")
    new_bind = data.get("socks_bind")
    changed = False

    if new_port is not None:
        try:
            new_port = int(new_port)
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "Invalid port number"}), 400
        if not (1024 <= new_port <= 65535):
            return jsonify({"ok": False, "error": "Port must be between 1024 and 65535"}), 400
        if new_port != SOCKS_PORT:
            SOCKS_PORT = new_port
            changed = True

    if new_bind is not None:
        new_bind = str(new_bind).strip()
        # Basic IP validation
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", new_bind):
            return jsonify({"ok": False, "error": "Invalid bind IP address"}), 400
        if new_bind != SOCKS_BIND:
            SOCKS_BIND = new_bind
            changed = True

    if changed:
        # Restart microsocks with new settings if it's running
        socks_pid = get_microsocks_pid()
        if socks_pid:
            try:
                os.kill(socks_pid, signal.SIGTERM)
                time.sleep(0.5)
            except ProcessLookupError:
                pass
            subprocess.Popen(
                ["microsocks", "-i", SOCKS_BIND, "-p", str(SOCKS_PORT)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

    return jsonify({"ok": True, "socks_port": SOCKS_PORT, "socks_bind": SOCKS_BIND})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
