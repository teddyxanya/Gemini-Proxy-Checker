#!/usr/bin/env python3
"""
Standalone Gemini Web Stub Checker
Verifies proxy nodes specifically against gemini.google.com Web UI,
detecting Google's regional unavailability stub ("isn't supported in your country / region")
via response inspection and WIZ_global_data vXmutd geo-tagging.
"""

import os
import sys
import re
import json
import base64
import time
import socket
import logging
import tempfile
import subprocess
import urllib.parse
from pathlib import Path
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("gemini-web-checker")

BLOCKED_COUNTRIES = {"RU", "BY", "CN", "IR", "KP", "CU", "SY"}

STUB_KEYWORDS = [
    "isn't supported in your country",
    "not supported in your country",
    "is not supported in your country",
    "не поддерживается в вашей стране",
    "не доступен в вашей стране",
    "недоступен в вашей стране",
    "unavailable in your country",
    "not available in your country"
]


def load_env_file(env_path: Path):
    if not env_path.exists():
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


def parse_node_xray(uri: str):
    parsed = urllib.parse.urlparse(uri)
    scheme = parsed.scheme.lower()
    tag = urllib.parse.unquote(parsed.fragment) or "Unnamed"

    if scheme == "vless":
        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        qs = urllib.parse.parse_qs(parsed.query)

        security = qs.get("security", ["none"])[0].lower()
        net = qs.get("type", ["tcp"])[0].lower()
        sni = qs.get("sni", [host])[0]
        fp = qs.get("fp", ["chrome"])[0]
        flow = qs.get("flow", [""])[0]

        stream_settings = {"network": net}

        if security == "reality":
            pbk = qs.get("pbk", [""])[0]
            sid = qs.get("sid", [""])[0]
            spx = qs.get("spx", ["/"])[0]
            stream_settings["security"] = "reality"
            stream_settings["realitySettings"] = {
                "serverName": sni,
                "fingerprint": fp,
                "publicKey": pbk,
                "shortId": sid,
                "spiderX": spx
            }
        elif security == "tls":
            stream_settings["security"] = "tls"
            stream_settings["tlsSettings"] = {
                "serverName": sni,
                "fingerprint": fp
            }

        if net in ("xhttp", "splithttp"):
            path = qs.get("path", ["/"])[0]
            host_header = qs.get("host", [""])[0]
            mode = qs.get("mode", ["auto"])[0]
            stream_settings["xhttpSettings"] = {
                "path": path,
                "host": host_header,
                "mode": mode
            }
        elif net == "ws":
            path = qs.get("path", ["/"])[0]
            host_header = qs.get("host", [""])[0]
            stream_settings["wsSettings"] = {
                "path": path,
                "headers": {"Host": host_header} if host_header else {}
            }

        stream_settings["sockopt"] = {"dialerProxy": "fragment-out"}

        outbound = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "encryption": "none",
                        "flow": flow
                    }]
                }]
            },
            "streamSettings": stream_settings
        }

        fragment_outbound = {
            "tag": "fragment-out",
            "protocol": "freedom",
            "settings": {
                "fragment": {
                    "packets": "tlshello",
                    "length": "50-100",
                    "interval": "10-20"
                }
            }
        }

        return tag, [outbound, fragment_outbound, {"tag": "direct", "protocol": "freedom", "settings": {}}]

    elif scheme == "trojan":
        password = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        qs = urllib.parse.parse_qs(parsed.query)
        sni = qs.get("sni", [host])[0]
        net = qs.get("type", ["tcp"])[0].lower()
        fp = qs.get("fp", ["chrome"])[0]

        stream_settings = {
            "network": net,
            "security": "tls",
            "tlsSettings": {
                "serverName": sni,
                "fingerprint": fp
            }
        }
        if net == "ws":
            path = qs.get("path", ["/"])[0]
            host_header = qs.get("host", [""])[0]
            stream_settings["wsSettings"] = {
                "path": path,
                "headers": {"Host": host_header} if host_header else {}
            }

        outbound = {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "password": password
                }]
            },
            "streamSettings": stream_settings
        }
        return tag, [outbound, {"tag": "direct", "protocol": "freedom", "settings": {}}]

    elif scheme == "ss":
        user_info = parsed.netloc.split("@")[0]
        server_info = parsed.netloc.split("@")[1] if "@" in parsed.netloc else ""
        if not server_info:
            try:
                padded = user_info + "=" * (-len(user_info) % 4)
                decoded = base64.urlsafe_b64decode(padded.encode()).decode()
                if "@" in decoded:
                    user_info, server_info = decoded.split("@", 1)
            except Exception:
                return None, None

        if not server_info and parsed.hostname:
            host = parsed.hostname
            port = parsed.port
        else:
            host, port_str = server_info.split(":", 1)
            port = int(port_str.split("/")[0])

        if ":" in user_info:
            method, password = user_info.split(":", 1)
        else:
            try:
                padded = user_info + "=" * (-len(user_info) % 4)
                decoded = base64.urlsafe_b64decode(padded.encode()).decode()
                method, password = decoded.split(":", 1)
            except Exception:
                return None, None

        outbound = {
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": password
                }]
            }
        }
        return tag, [outbound, {"tag": "direct", "protocol": "freedom", "settings": {}}]

    return None, None


def check_web_stub(proxies: dict, timeout: int = 8) -> tuple[bool, str]:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7'
    }
    try:
        # Pre-check: Verify egress IP location via Cloudflare trace to prevent Russian leaks
        cf_country = None
        try:
            cf_r = requests.get('https://cloudflare.com/cdn-cgi/trace', proxies=proxies, timeout=min(timeout, 4))
            m_cf = re.search(r'loc=([A-Z]{2})', cf_r.text)
            if m_cf:
                cf_country = m_cf.group(1).upper()
                if cf_country in BLOCKED_COUNTRIES:
                    return False, f"Egress blocked ({cf_country})"
        except Exception:
            pass

        t0 = __import__("time").time()
        r = requests.get('https://gemini.google.com/app', headers=headers, proxies=proxies, timeout=timeout, allow_redirects=True)
        elapsed = __import__("time").time() - t0
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        if elapsed > 6.0:
            return False, f"Too slow ({elapsed:.1f}s > 6s threshold)"

        if "unavailable" in r.url.lower():
            return False, f"Redirect: {r.url}"

        text_lower = r.text.lower()
        for kw in STUB_KEYWORDS:
            if kw in text_lower:
                return False, f"Stub: '{kw}'"

        # PRIMARY CHECK: Google locale field (most reliable - reflects Google's VPN detection)
        # Format: tm.LANG.HASH.BUILD.O","LOCALE","UI_LANG" where LOCALE is google domain suffix
        # locale=ru means Google flagged this IP as Russian VPN → "Gemini not available"
        locale_match = re.search(r'tm\.[\w]+\.[\w]+\.\d+\.O","(\w+)","(\w+)"', r.text)
        if locale_match:
            google_locale = locale_match.group(1)
            BLOCKED_LOCALES = {"ru", "by", "cn", "ir", "kp", "cu", "sy"}
            if google_locale.lower() in BLOCKED_LOCALES:
                return False, f"Google VPN-blocked (locale={google_locale})"

        country = None
        m = re.search(r'window\.WIZ_global_data\s*=\s*(\{.+?\});', r.text)
        if m:
            try:
                wiz = json.loads(m.group(1))
                raw_geo = wiz.get("vXmutd", "")
                geo_match = re.search(r'"([A-Z]{2})"', str(raw_geo))
                if geo_match:
                    country = geo_match.group(1)
            except Exception:
                pass

        if not country:
            fallback_match = re.search(r'vXmutd["\']?\s*[:=]\s*["\']?%\.@\.["\']([A-Z]{2})["\']', r.text)
            if fallback_match:
                country = fallback_match.group(1)

        if country:
            if country in BLOCKED_COUNTRIES:
                return False, f"Geo-blocked: {country}"
            return True, f"Geo: {country}"

        if "BardChatUi" in r.text or "assistant-bard" in r.text:
            if cf_country and cf_country not in BLOCKED_COUNTRIES:
                return True, f"Bundle OK (CF: {cf_country})"
            return False, "Bundle unverified (unknown country)"

        return False, "Unverified response"
    except Exception as e:
        return False, f"Web error: {type(e).__name__}"

def test_node_web(outbounds: list, timeout: int = 10) -> tuple[bool, str]:
    xray_bin = os.getenv("XRAY_BIN", "/usr/local/bin/xray")
    if not os.path.exists(xray_bin):
        return False, "xray not found"

    port = get_free_port()
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="xray_web_", suffix=".json")
    os.close(tmp_fd)

    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False}
        }],
        "outbounds": outbounds
    }

    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(config, f)

    proc = None
    try:
        proc = subprocess.Popen(
            [xray_bin, "run", "-c", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1.2)
        proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
        return check_web_stub(proxies, timeout=timeout)
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def fetch_subscription(sub_url: str) -> list:
    headers = {"User-Agent": "Shadowrocket/2.2.35"}
    resp = requests.get(sub_url, headers=headers, timeout=15)
    resp.raise_for_status()
    raw = resp.text.strip()
    try:
        padded = raw + "=" * (-len(raw) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        decoded = raw
    return [line.strip() for line in decoded.splitlines() if line.strip()]


def main():
    base_dir = Path(__file__).resolve().parent
    env_file = base_dir / ".env"
    load_env_file(env_file)

    sub_url = os.getenv("SUB_URL")
    if not sub_url:
        logger.error("SUB_URL is not set!")
        sys.exit(1)

    logger.info("Fetching subscription nodes...")
    raw_nodes = fetch_subscription(sub_url)
    logger.info(f"Loaded {len(raw_nodes)} nodes. Starting Gemini Web stub verification...")

    passed = []
    for idx, uri in enumerate(raw_nodes, 1):
        tag, outbounds = parse_node_xray(uri)
        if not outbounds:
            continue

        ok, details = test_node_web(outbounds)
        status = "PASSED" if ok else "BLOCKED/FAILED"
        logger.info(f"[{idx}/{len(raw_nodes)}] {tag} -> {status} ({details})")
        if ok:
            passed.append(tag)

    logger.info(f"\n==========================================")
    logger.info(f"Summary: {len(passed)}/{len(raw_nodes)} nodes passed Gemini Web check.")
    for t in passed:
        logger.info(f"  + {t}")
    logger.info(f"==========================================")


if __name__ == "__main__":
    main()
