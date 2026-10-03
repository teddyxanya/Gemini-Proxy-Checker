#!/usr/bin/env python3
"""
Gemini Proxy Checker (Dual Web & API Edition with Xray-core)
Tests subscription proxy nodes simultaneously against:
1. Google Gemini Web UI (gemini.google.com) - verifying absence of regional block stubs & vXmutd geo-blocking.
2. Google AI Studio API (generativelanguage.googleapis.com) - verifying generateContent with 15 RPM rate limiting.

Generates and updates shadowrocket.conf:
- GEMINI: nodes verified for API access.
- GEMINI2 / gemeni2: nodes verified for Web UI (no regional stub).
"""

import os
import sys
import re
import json
import base64
import time
import socket
import logging

import requests
import tempfile
import subprocess
import urllib.parse
from pathlib import Path

# Base template matching user's latest github shadowrocket.conf
DEFAULT_TEMPLATE = """# Shadowrocket: 2026-09-24 22:49:04
[General]
bypass-system = true
skip-proxy = ::1, 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com, *.ru, *.su, *.рф
bypass-tun = ::1/128, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32
# update-url настроен на ваш репозиторий с автообновлением узлов
update-url = https://raw.githubusercontent.com/teddyxanya/Gemini-Proxy-Checker/main/shadowrocket.conf
# оригинальный авторский update-url: https://raw.githubusercontent.com/Simonerrror/ShadowRocket/main/shadowrocket.conf
dns-server = https://dns.google/dns-query, https://1.1.1.1/dns-query, 8.8.8.8, 1.1.1.1
direct-dns-server = 77.88.8.8, 77.88.8.1
fallback-dns-server = https://dns.google/dns-query, 1.1.1.1
ipv6 = false
prefer-ipv6 = false
dns-direct-system = false
icmp-auto-reply = true
always-reject-url-rewrite = false
private-ip-answer = true
dns-direct-fallback-proxy = true
hijack-dns = 8.8.8.8:53, 8.8.4.4:53

[Proxy Group]
# 0. Группа проверенных узлов для Gemini API (Google AI Studio)
GEMINI = fallback,policy-regex-filter=^(PLACEHOLDER)$,interval=180,tolerance=50,url=https://www.gstatic.com/generate_204,timeout=3
# 0.1 Группа проверенных узлов для Gemini Web (gemini.google.com без региональной заглушки)
GEMINI2 = fallback,policy-regex-filter=^(PLACEHOLDER)$,interval=180,tolerance=50,url=https://www.gstatic.com/generate_204,timeout=3
# 1. Ручной выбор узла без WL и SS
MANUAL-PROXY = select,policy-regex-filter=(?i)^(?!.*\\bWL\\b)(?!.*\\bSS\\b).*$
# 2. Авто-скорость: быстрый узел вне RU/BY/UA (убран жесткий дефолт)
AUTO-SPEED = url-test,interval=180,tolerance=100,url=https://abs.twimg.com/favicon.ico,timeout=7,policy-regex-filter=(?i)^(?!.*(?:Russia|Belarus|Ukraine))(?!.*\\bWL\\b).*\\b(?:VLESS|TT|Naive|NV|MR|AWG(?:2|3\\.1)?)\\b.*$
# 3. Авто-стабильность: первый живой узел
AUTO-STABILITY = fallback,policy-regex-filter=(?i)^(?!.*(?:Russia|Belarus|Ukraine))(?!.*\\bWL\\b).*\\b(?:VLESS|TT|Naive|NV|MR|AWG(?:2|3\\.1)?)\\b.*$,interval=240,url=https://abs.twimg.com/favicon.ico,timeout=3
# 4. Отдельная группа WL
WL = select,policy-regex-filter=(?i)\\bWL\\b
# 5. Главный переключатель (сохраняет ваш выбор между мануалом и автоматом)
PROXY = select,AUTO-STABILITY,AUTO-SPEED,MANUAL-PROXY,WL,GEMINI,GEMINI2

[Rule]
# --- Gemini Web (GEMINI2: проверено на отсутствие региональной заглушки на gemini.google.com) ---
DOMAIN-SUFFIX,gemini.google.com,GEMINI2,force-remote-dns
DOMAIN-SUFFIX,bard.google.com,GEMINI2,force-remote-dns
DOMAIN-KEYWORD,gemini,GEMINI2,force-remote-dns

# --- Gemini API & Google AI (GEMINI: проверено через Google AI Studio API) ---
DOMAIN-SUFFIX,generativelanguage.googleapis.com,GEMINI,force-remote-dns
DOMAIN-SUFFIX,aistudio.google.com,GEMINI,force-remote-dns
DOMAIN-SUFFIX,alkalimakersuite-pa.clients6.google.com,GEMINI,force-remote-dns
DOMAIN-SUFFIX,proactivebackend-pa.googleapis.com,GEMINI,force-remote-dns
DOMAIN-SUFFIX,deepmind.google,GEMINI,force-remote-dns
DOMAIN-SUFFIX,deepmind.com,GEMINI,force-remote-dns
DOMAIN-SUFFIX,googleapis.com,GEMINI,force-remote-dns
DOMAIN-KEYWORD,google,GEMINI2,force-remote-dns

# --- Другие нейросети (ChatGPT / Claude) ---
DOMAIN-SUFFIX,oaistatic.com,PROXY,force-remote-dns
DOMAIN-SUFFIX,oaiusercontent.com,PROXY,force-remote-dns
DOMAIN-SUFFIX,openai.com,PROXY,force-remote-dns
DOMAIN-SUFFIX,chatgpt.com,PROXY,force-remote-dns
DOMAIN-SUFFIX,claude.ai,PROXY,force-remote-dns
DOMAIN-SUFFIX,anthropic.com,PROXY,force-remote-dns

# Списки автора
RULE-SET,https://raw.githubusercontent.com/Simonerrror/ShadowRocket/main/rules/whitelist_direct.list,DIRECT
RULE-SET,https://raw.githubusercontent.com/Simonerrror/ShadowRocket/main/rules/greylist_proxy.list,PROXY,force-remote-dns
RULE-SET,https://raw.githubusercontent.com/Simonerrror/ShadowRocket/main/rules/microsoft.list,PROXY,force-remote-dns
RULE-SET,https://raw.githubusercontent.com/Simonerrror/ShadowRocket/main/rules/domains_community.list,PROXY

# Direct для RU сегмента и сервисов
DOMAIN-SUFFIX,ru,DIRECT
DOMAIN-SUFFIX,рф,DIRECT
DOMAIN-SUFFIX,su,DIRECT
DOMAIN-SUFFIX,xn--p1ai,DIRECT
DOMAIN-KEYWORD,sberbank,DIRECT
DOMAIN-KEYWORD,tinkoff,DIRECT
DOMAIN-KEYWORD,tbank,DIRECT
DOMAIN-KEYWORD,gosuslugi,DIRECT
GEOIP,RU,DIRECT

# Все остальное зарубежное
FINAL,PROXY
"""

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("gemini-proxy-checker")


def send_telegram_alert(message: str):
    """Отправляет HTML-сообщение в Telegram через Bot API."""
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        requests.post(url, json={"chat_id": chat_id, "text": message,
                                 "parse_mode": "HTML", "disable_web_page_preview": True},
                      timeout=10)
    except Exception as e:
        logger.error(f"Telegram alert error: {e}")

RATE_LIMIT_DELAY = 4.2  # Ensures <= 15 RPM
BLOCKED_COUNTRIES = {"RU", "BY", "CN", "IR", "KP", "CU", "SY"}
BLOCKED_LOCALES = {"ru", "by", "cn", "ir", "kp", "cu", "sy"}

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


def fetch_subscription(sub_url: str) -> list:
    logger.info(f"Fetching subscription from: {sub_url[:35]}...")
    headers = {"User-Agent": "Shadowrocket/2.2.35"}
    resp = None
    for attempt in range(4):
        try:
            resp = requests.get(sub_url, headers=headers, timeout=15)
            if resp.status_code == 200:
                break
            time.sleep(2)
        except Exception:
            if attempt == 3:
                raise
            time.sleep(2)
    if resp is not None:
        resp.raise_for_status()

    raw = resp.text.strip()
    try:
        padded = raw + "=" * (-len(raw) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        decoded = raw

    nodes = [line.strip() for line in decoded.splitlines() if line.strip()]
    logger.info(f"Loaded {len(nodes)} proxy nodes from subscription.")
    return nodes


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


def check_web_stub(proxies: dict, timeout: int = 15) -> tuple[bool, str]:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7'
    }
    
    last_err = ""
    for attempt in range(2):
        try:
            cf_country = None
            try:
                cf_r = requests.get('https://cloudflare.com/cdn-cgi/trace', proxies=proxies, timeout=min(timeout, 5))
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
                last_err = f"HTTP {r.status_code}"
                __import__("time").sleep(1)
                continue
                
            if elapsed > 12.0:
                last_err = f"Too slow ({elapsed:.1f}s > 12s)"
                __import__("time").sleep(1)
                continue

            if "unavailable" in r.url.lower():
                return False, f"Redirect: {r.url}"

            text_lower = r.text.lower()
            for kw in STUB_KEYWORDS:
                if kw in text_lower:
                    return False, f"Stub: '{kw}'"

            locale_match = re.search(r'tm\.[\w]+\.[\w]+\.\d+\.O","(\w+)","(\w+)"', r.text)
            if locale_match:
                google_locale = locale_match.group(1)
                if google_locale.lower() in BLOCKED_LOCALES:
                    return False, f"Google VPN-blocked (locale={google_locale})"

            country = None
            m = re.search(r'window\.WIZ_global_data\s*=\s*(\{.+?\});', r.text)
            if m:
                try:
                    import json
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
                
            return True, "Geo: UNKNOWN (but passed)"
            
        except requests.exceptions.RequestException as e:
            last_err = f"Web error: {type(e).__name__}"
            __import__("time").sleep(1)
            
    return False, last_err

def check_api_inference(proxies: dict, gemini_key: str, timeout: int = 8) -> tuple[bool, str]:
    test_models = ["gemma-4-26b-a4b-it", "gemini-flash-lite-latest"]
    payload = {"contents": [{"parts": [{"text": "Hi"}]}]}

    for model in test_models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}"
        for attempt in range(2):
            try:
                resp = requests.post(url, json=payload, proxies=proxies, timeout=timeout)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "candidates" in data and len(data["candidates"]) > 0:
                            return True, f"200 OK ({model})"
                    except Exception:
                        return False, "Invalid JSON"
                    return False, "No candidates"
                elif resp.status_code in (400, 403):
                    body = resp.text
                    if "User location is not supported" in body or "FAILED_PRECONDITION" in body:
                        return False, "API Geo-blocked"
                    return False, f"HTTP {resp.status_code}"
                elif resp.status_code == 429:
                    logger.warning("Rate limit 429 on API. Backing off 10s...")
                    time.sleep(10.0)
                    continue
                elif resp.status_code == 503:
                    time.sleep(1.0)
                    break
            except requests.exceptions.RequestException as e:
                if attempt == 0:
                    time.sleep(1.0)
                    continue
                return False, f"ReqErr: {type(e).__name__}"
    return False, "API Failed"


def test_node_dual(outbounds: list, gemini_key: str, timeout: int = 8) -> tuple[bool, bool, str]:
    """
    Spawns ephemeral Xray instance and tests both Gemini Web and Gemini API.
    Returns (web_ok, api_ok, details_str).
    """
    xray_bin = os.getenv("XRAY_BIN", "/usr/local/bin/xray")
    if not os.path.exists(xray_bin):
        logger.error(f"Xray binary not found at {xray_bin}!")
        return False, False, "Xray binary missing"

    port = get_free_port()
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="xray_chk_", suffix=".json")
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

        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}"
        }

        # 1. Test Web
        web_ok, web_desc = check_web_stub(proxies, timeout=timeout)

        # 2. Test API
        api_ok, api_desc = check_api_inference(proxies, gemini_key, timeout=timeout)

        details = f"Web: {web_desc} | API: {api_desc}"
        return web_ok, api_ok, details
    except Exception as e:
        return False, False, f"Dual test error: {e}"
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


def make_regex(tags: list) -> str:
    if not tags:
        return "^(NONE)$"
    escaped_tags = [re.sub(r'([()[\]{}.*+?^$|\\])', r'\\\1', t) for t in tags]
    return "^(" + "|".join(escaped_tags) + ")$"


def update_shadowrocket_conf(conf_path: Path, passed_api_tags: list, passed_web_tags: list):
    """
    Updates GEMINI (API), GEMINI2 (Web), and gemeni2 (alias) in shadowrocket.conf.
    Preserves all other sections and user rules.
    """
    if not conf_path.exists():
        logger.info(f"{conf_path} not found. Creating from base template...")
        conf_path.parent.mkdir(parents=True, exist_ok=True)
        content = DEFAULT_TEMPLATE
    else:
        with open(conf_path, "r", encoding="utf-8") as f:
            content = f.read()

    # Ensure GEMINI2 proxy group exists
    if "GEMINI2 =" not in content and "[Proxy Group]" in content:
        gemini2_line = (
            "\n# 0.1 Группа проверенных узлов для Gemini Web (gemini.google.com без региональной заглушки)\n"
            "GEMINI2 = fallback,policy-regex-filter=^(PLACEHOLDER)$,interval=180,tolerance=50,url=https://www.gstatic.com/generate_204,timeout=3"
        )
        content = re.sub(r'(\[Proxy Group\]\n)', r'\1' + gemini2_line + '\n', content)

    # Ensure GEMINI2 is in PROXY select group
    if re.search(r'^(PROXY\s*=\s*select,)(?!.*GEMINI2)(.*)$', content, flags=re.MULTILINE):
        content = re.sub(r'^(PROXY\s*=\s*select,.*?)(GEMINI)(.*)$', r'\1GEMINI,GEMINI2\3', content, flags=re.MULTILINE)

    # Direct Web Gemini rules to GEMINI2 in [Rule]
    content = re.sub(r'^(DOMAIN-SUFFIX,gemini\.google\.com,)GEMINI(,.*)?$', r'\1GEMINI2\2', content, flags=re.MULTILINE)
    content = re.sub(r'^(DOMAIN-SUFFIX,bard\.google\.com,)GEMINI(,.*)?$', r'\1GEMINI2\2', content, flags=re.MULTILINE)
    content = re.sub(r'^(DOMAIN-KEYWORD,gemini,)GEMINI(,.*)?$', r'\1GEMINI2\2', content, flags=re.MULTILINE)
    content = re.sub(r'^(DOMAIN-KEYWORD,google,)GEMINI(,.*)?$', r'\1GEMINI2\2', content, flags=re.MULTILINE)

    # Remove any leftover gemeni2 duplicate lines
    content = re.sub(r'^gemeni2\s*=.*$\n?', '', content, flags=re.MULTILINE)

    # Update regexes
    api_regex = make_regex(passed_api_tags) if passed_api_tags else None
    web_regex = make_regex(passed_web_tags) if passed_web_tags else None

    if api_regex:
        content, c1 = re.subn(
            r'^(GEMINI\s*=\s*(?:fallback|url-test|select),policy-regex-filter=)[^,]+(.*)$',
            lambda m: f"{m.group(1)}{api_regex}{m.group(2)}",
            content,
            flags=re.MULTILINE
        )
        logger.info(f"Updated GEMINI (API) group with {len(passed_api_tags)} nodes.")

    if web_regex:
        content, c2 = re.subn(
            r'^(GEMINI2\s*=\s*(?:fallback|url-test|select),policy-regex-filter=)[^,]+(.*)$',
            lambda m: f"{m.group(1)}{web_regex}{m.group(2)}",
            content,
            flags=re.MULTILINE
        )
        logger.info(f"Updated GEMINI2 (Web) group with {len(passed_web_tags)} nodes.")

    tmp_file = conf_path.with_suffix(".tmp")
    with open(tmp_file, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp_file, conf_path)
    logger.info(f"Successfully saved updated {conf_path}.")
    return True


def main():
    base_dir = Path(__file__).resolve().parent
    env_file = base_dir / ".env"
    load_env_file(env_file)

    sub_url = os.getenv("SUB_URL")
    gemini_key = os.getenv("GEMINI_API_KEY")
    conf_path_str = os.getenv("CONF_PATH", str(base_dir / "shadowrocket.conf"))
    conf_path = Path(conf_path_str)

    if not sub_url:
        logger.error("SUB_URL is not set in environment or .env file!")
        sys.exit(1)
    if not gemini_key:
        logger.error("GEMINI_API_KEY is not set in environment or .env file!")
        sys.exit(1)

    try:
        raw_nodes = fetch_subscription(sub_url)
    except Exception as e:
        logger.error(f"Failed to fetch subscription: {e}")
        sys.exit(1)

    quick_check = os.getenv("QUICK_CHECK") == "1"
    quick_nodes = set(os.getenv("QUICK_NODES", "").split(",")) if quick_check else set()
    
    if quick_check and quick_nodes:
        filtered_nodes = []
        for uri in raw_nodes:
            tag, _ = parse_node_xray(uri)
            if tag in quick_nodes:
                filtered_nodes.append(uri)
        raw_nodes = filtered_nodes
        if not raw_nodes:
            logger.info("Quick check nodes not found in subscription!")
            sys.exit(0)
        logger.info(f"Running QUICK CHECK for {len(raw_nodes)} nodes...")

    passed_api_nodes = []
    passed_web_nodes = []
    total = len(raw_nodes)

    logger.info(f"Starting dual Gemini Web & API verification on {total} nodes via Xray (15 RPM rate limit)...")
    for idx, node_uri in enumerate(raw_nodes, 1):
        tag, outbounds = parse_node_xray(node_uri)
        if not outbounds:
            continue

        web_ok, api_ok, details = test_node_dual(outbounds, gemini_key)
        
        status_web = "WEB:OK" if web_ok else "WEB:FAIL"
        status_api = "API:OK" if api_ok else "API:FAIL"
        logger.info(f"[{idx}/{total}] {tag} -> [{status_web}] [{status_api}] ({details})")

        if web_ok:
            passed_web_nodes.append(tag)
        if api_ok:
            passed_api_nodes.append(tag)

        # Enforce rate limit delay between nodes
        if idx < total:
            time.sleep(RATE_LIMIT_DELAY)

    logger.info(f"==========================================")
    logger.info(f"Results Summary:")
    logger.info(f"  Web UI (gemini.google.com without stub): {len(passed_web_nodes)}/{total} nodes")
    logger.info(f"  API (generateContent):                   {len(passed_api_nodes)}/{total} nodes")
    logger.info(f"==========================================")

    passed_both_nodes = [t for t in passed_web_nodes if t in passed_api_nodes]
    logger.info(f"Nodes passing BOTH web and API (GEMINI2): {len(passed_both_nodes)}/{total}")
    update_shadowrocket_conf(conf_path, passed_api_nodes, passed_both_nodes)
    
    # ------------------ STATE & NOTIFICATION LOGIC ------------------
    state_file = Path(__file__).resolve().parent / "checker_state.json"
    old_state = {"api": [], "web": [], "history": []}
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as sf:
                old_state = json.load(sf)
        except Exception:
            pass

    old_web = set(old_state.get("web", []))
    new_web = set(passed_both_nodes)
    
    import datetime
    now_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    quick_check = os.getenv("QUICK_CHECK") == "1"
    
    if quick_check:
        quick_expected = set(os.getenv("QUICK_NODES", "").split(","))
        lost_in_quick = quick_expected - new_web
        if lost_in_quick:
            logger.error(f"Quick check failed! Lost nodes: {lost_in_quick}")
            sys.exit(1) # Triggers full check via bash
        else:
            logger.info("Quick check passed. Updating timestamp.")
            old_state["last_check"] = now_ts
            with open(state_file, "w") as sf:
                json.dump(old_state, sf)
            sys.exit(0)

    # FULL CHECK LOGIC
    added_web = new_web - old_web
    lost_web = old_web - new_web

    if added_web or lost_web:
        lines = ["🤖 <b>Gemini Proxy Checker (Авто-Отчёт)</b>\n"]
        lines.append(f"<b>Всего серверов (Web + API):</b> {len(new_web)}")
        if added_web:
            lines.append("\n✅ <b>Новые рабочие серверы:</b>")
            for w in added_web:
                lines.append(f"  • <code>{w}</code>")
        if lost_web:
            lines.append("\n❌ <b>Отвалившиеся серверы:</b>")
            for w in lost_web:
                lines.append(f"  • <code>{w}</code>")
        
        send_telegram_alert("\n".join(lines))

    # UPDATE HISTORY
    history = old_state.get("history", [])
    history.insert(0, {
        "ts": now_ts,
        "web": passed_both_nodes,
        "api": passed_api_nodes
    })
    history = history[:48] # Keep 48 entries

    new_state = {
        "api": passed_api_nodes,
        "web": passed_both_nodes,
        "last_check": now_ts,
        "history": history
    }

    try:
        with open(state_file, "w") as sf:
            json.dump(new_state, sf)
    except Exception as e:
        logger.error(f"Failed to save state: {e}")

    logger.info("Dual checker run finished successfully.")


if __name__ == "__main__":
    main()
