#!/usr/bin/env python3
"""
e0f.cx Private Multi-Profile Telegram-Managed Subscription Daemon
- Serves additional protocols (AWG 2.0 & 3.1, Mieru, TrustTunnel) to Shadowrocket.
- Multi-profile management via Telegram Bot (@podpisici_bot):
    - /newprofile <name>  -> creates separate AWG configs on e0f + gives subscription link
    - /delprofile <name>  -> deletes that profile's AWG configs on e0f to free slots
    - /profiles           -> lists all profiles and their subscription links
    - /status             -> status of all servers, slots, and profiles
    - /sync               -> force refresh from e0f API
- AmneziaWG configs are strictly isolated: each profile only uses its own configs.
- Slot limit monitoring: notifies in Telegram if any server runs out of slots.
- Shared protocols (TrustTunnel, Mieru) are automatically included across all profiles.
"""

import os
import sys
import json
import base64
import time
import logging
import threading
import secrets
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import shutil
import requests

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("e0f-daemon")

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"
PROFILES_FILE = BASE_DIR / "profiles.json"
STATE_FILE = BASE_DIR / "protocols_state.json"
CHECKER_STATE_FILE = BASE_DIR / "checker_state.json"


def get_vps_base_url() -> str:
    """Returns base HTTPS URL using VPS_IP from env, fallback to localhost"""
    vps_ip = os.getenv("VPS_IP", "127.0.0.1")
    return f"http://{vps_ip}:8081"
API_BASE = "https://e0f.cx/api"

# Cache: { sub_token: { "b64": str, "name": str, "awg_count": int, "total_count": int } }
profile_cache = {}
last_sync_time = 0
sync_lock = threading.Lock()


def load_profile_cache_from_disk():
    """Populates profile_cache from local sub_cache_*.txt files so subscriptions never drop to 0 if e0f API is down."""
    global profile_cache
    profiles = load_profiles()
    for p_id, p_data in profiles.items():
        p_name = p_data["name"]
        p_sub = p_data["sub_token"]
        p_cache_file = BASE_DIR / f"sub_cache_{p_name}.txt"
        if p_cache_file.exists():
            try:
                b64 = p_cache_file.read_text(encoding="utf-8").strip()
                if b64:
                    padded = b64 + "=" * (-len(b64) % 4)
                    decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                    lines = [l.strip() for l in decoded.splitlines() if l.strip()]
                    awg_count = sum(1 for l in lines if l.startswith("wg://"))
                    profile_cache[p_sub] = {
                        "b64": b64,
                        "name": p_name,
                        "awg_count": awg_count,
                        "total_count": len(lines)
                    }
                    logger.info(f"Loaded disk cache for profile '{p_name}': {len(lines)} nodes (AWG: {awg_count})")
            except Exception as e:
                logger.error(f"Error loading disk cache for '{p_name}': {e}")


AWG_KEY_MAP = {
    'headerprotectionkey': 'header_protection_key',
    'contentpaddingaddition': 'content_padding_addition',
    'randomtrailers': 'random_trailers'
}


def load_env() -> dict:
    env_vars = {}
    if ENV_FILE.exists():
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                env_vars[k] = v
                if k not in os.environ:
                    os.environ[k] = v
    return env_vars


def save_env_var(key: str, value: str):
    load_env()
    lines = []
    found = False
    if ENV_FILE.exists():
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith(f"{key}=") or stripped.startswith(f"{key} ="):
                    lines.append(f'{key}="{value}"\n')
                    found = True
                else:
                    lines.append(line)
    if not found:
        lines.append(f'{key}="{value}"\n')
    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)
    os.environ[key] = value


def load_profiles() -> dict:
    """Loads profiles from JSON, initializes default profile 'Xan' if empty"""
    if PROFILES_FILE.exists():
        try:
            with open(PROFILES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading {PROFILES_FILE}: {e}")

    # Initialize default profile Xan
    env_vars = load_env()
    default_sub = env_vars.get("SECRET_TOKEN", "default_secret")
    initial = {
        "Xan": {
            "name": "Xan",
            "sub_token": default_sub,
            "created_at": int(time.time())
        }
    }
    save_profiles(initial)
    return initial


def save_profiles(profiles: dict):
    with open(PROFILES_FILE, "w", encoding="utf-8") as f:
        json.dump(profiles, f, indent=2, ensure_ascii=False)


def get_flag(country_code: str) -> str:
    if len(country_code) == 2:
        return chr(127397 + ord(country_code[0].upper())) + chr(127397 + ord(country_code[1].upper())) + " "
    return ""


# =====================================================================
# TrustTunnel DeepLink Encoder (TLV + Varint binary format)
# =====================================================================
def varint_encode(val: int) -> bytes:
    if val < 0:
        raise ValueError("Invalid varint")
    if val <= 63:
        return bytes([val & 63])
    elif val <= 16383:
        return bytes([(val >> 8 & 63) | 64, val & 255])
    elif val <= 1073741823:
        return bytes([
            (val >> 24 & 63) | 128,
            val >> 16 & 255,
            val >> 8 & 255,
            val & 255
        ])
    else:
        res = bytearray(8)
        for i in range(7, -1, -1):
            res[i] = (val >> ((7 - i) * 8)) & 255
        res[0] = (res[0] & 63) | 192
        return bytes(res)


def tlv_bytes(tag: int, data: bytes) -> bytes:
    return varint_encode(tag) + varint_encode(len(data)) + data


def tlv_str(tag: int, val: str) -> bytes:
    return tlv_bytes(tag, val.encode('utf-8'))


def tlv_varint(tag: int, val: int) -> bytes:
    return tlv_bytes(tag, varint_encode(val))


def generate_tt_link(hostname: str, addresses: list, username: str, password: str,
                     custom_sni: str = "", name: str = "", version: int = 1) -> str:
    chunks = []
    if version > 0:
        chunks.append(tlv_varint(0, version))
    chunks.append(tlv_str(1, hostname))
    for addr in addresses:
        chunks.append(tlv_str(2, addr))
    chunks.append(tlv_str(5, username))
    chunks.append(tlv_str(6, password))
    if custom_sni:
        chunks.append(tlv_str(3, custom_sni))
    if name:
        chunks.append(tlv_str(12, name))
        
    payload = b"".join(chunks)
    b64 = base64.b64encode(payload).decode('ascii').replace('+', '-').replace('/', '_').rstrip('=')
    return f"tt://?{b64}"


# =====================================================================
# INI Parsing & AmneziaWG URI Formatting
# =====================================================================
def parse_ini(text: str) -> dict:
    data = {}
    section = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1].lower()
            data[section] = {}
        elif '=' in line and section:
            k, v = line.split('=', 1)
            data[section][k.strip().lower()] = v.strip()
    return data


def config_to_wireguard_node(conf_text: str, server_name: str, country_code: str = "",
                             server_id: str = "", profile_name: str = "") -> dict:
    d = parse_ini(conf_text)
    iface = d.get('interface', {})
    peer = d.get('peer', {})

    endpoint = peer.get('endpoint', '')
    pubkey = peer.get('publickey', '')
    privkey = iface.get('privatekey', '')
    psk = peer.get('presharedkey', '')
    ip = iface.get('address', '').replace('/32', '')
    mtu = iface.get('mtu', '1280')
    dns = iface.get('dns', '77.88.8.1').replace(' ', '')

    obfs_dict = {}
    standard_keys = {'privatekey', 'address', 'dns', 'mtu'}
    has_obfs = False

    for k, v in iface.items():
        if k not in standard_keys and v:
            has_obfs = True
            clean_k = AWG_KEY_MAP.get(k, k)
            val = str(v)
            if clean_k == 'random_trailers':
                val = 'true' if val.lower() in ('on', 'true', '1', 'yes') else 'false'
            obfs_dict[clean_k] = val

    flag = get_flag(country_code)

    base_name = server_name
    if server_id == '62' or (country_code.upper() == 'RU' and has_obfs):
        base_name = "Russia SPB (AWG)"
    elif server_id == '61' or (country_code.upper() == 'RU' and not has_obfs):
        base_name = "Russia SPB (WG)"

    p_prefix = f"[{profile_name}] " if profile_name else ""
    tag = f"{flag}{p_prefix}{base_name}"

    params = {
        'publicKey': pubkey,
        'privateKey': privkey,
    }
    if psk:
        params['presharedKey'] = psk
    params['ip'] = ip
    params['mtu'] = mtu
    params['dns'] = dns
    params['udp'] = '1'

    if obfs_dict:
        params['obfs'] = 'amneziawg'
        params['obfsParam'] = json.dumps(obfs_dict, separators=(',', ':'))

    if country_code:
        params['flag'] = country_code.upper()

    query = urllib.parse.urlencode(params)
    clean_uri = f"wg://{endpoint}?{query}#{urllib.parse.quote(tag)}"

    return {
        'clean_uri': clean_uri,
        'tag': tag,
        'has_obfs': has_obfs,
        'endpoint': endpoint,
        'server_id': server_id
    }


def send_telegram_alert(bot_token: str, chat_id: str, message: str):
    if not bot_token or not chat_id:
        return
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        logger.warning(f"Telegram alert error: {e}")


# =====================================================================
# Shared Protocol Fetching (Mieru & TrustTunnel)
# =====================================================================
def fetch_mieru_nodes(headers: dict) -> list:
    nodes = []
    try:
        r = requests.get(f"{API_BASE}/mieru/config", headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            username = data.get('username')
            password = data.get('password')
            servers = data.get('servers', [])
            for s in servers:
                name = s.get('name', 'Server')
                ip = s.get('ip')
                port = s.get('port', 2090)
                profile_name = f"EOFVPN+{name}"
                query = urllib.parse.urlencode({
                    'udp': '1',
                    'port': str(port),
                    'profile': profile_name
                })
                flag = get_flag(s.get('countryCode', ''))
                tag = f"{flag}EOFVPN {name} (Mieru)"
                link = f"mierus://{username}:{password}@{ip}?{query}#{urllib.parse.quote(tag)}"
                nodes.append(link)
    except Exception as e:
        logger.error(f"Error fetching Mieru: {e}")
    return nodes


def fetch_trusttunnel_nodes(headers: dict) -> list:
    nodes = []
    try:
        r = requests.get(f"{API_BASE}/trusttunnel/config", headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            username = data.get('username')
            password = data.get('password')
            servers = data.get('servers', [])
            for s in servers:
                name = s.get('name', 'Server')
                ip = s.get('ip')
                port = s.get('port', 443)
                domain = s.get('domain', '')
                flag = get_flag(s.get('countryCode', ''))
                tt_name = f"{flag}EOFVPN {name} (TrustTunnel)"
                link = generate_tt_link(
                    hostname=ip,
                    addresses=[f"{ip}:{port}"],
                    username=username,
                    password=password,
                    custom_sni=domain,
                    name=tt_name,
                    version=1
                )
                nodes.append(link)
    except Exception as e:
        logger.error(f"Error fetching TrustTunnel: {e}")
    return nodes


def fetch_hysteria2_nodes(headers: dict) -> list:
    nodes = []
    try:
        r = requests.get(f"{API_BASE}/hysteria2/subscription", headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            country_flags = {
                "Czech": "🇨🇿",
                "Germany": "🇩🇪",
                "Israel": "🇮🇱",
                "USA": "🇺🇸"
            }
            for link in data.get('links', []):
                if '#' in link:
                    base_part, raw_tag = link.split('#', 1)
                    tag_name = urllib.parse.unquote(raw_tag)
                    flag = ""
                    for k, f in country_flags.items():
                        if k.lower() in tag_name.lower():
                            flag = f + " "
                            break
                    new_tag = f"{flag}EOFVPN {tag_name} (Hysteria2)"
                    nodes.append(f"{base_part}#{urllib.parse.quote(new_tag)}")
                else:
                    nodes.append(link)
    except Exception as e:
        logger.error(f"Error fetching Hysteria2: {e}")
    return nodes


# =====================================================================
# Profile AWG Synchronization (Single Account - Multi Config Names)
# =====================================================================
def sync_profile_awg(headers: dict, profile_name: str, awg_servers: list, all_configs: list,
                     create_missing: bool = True, tg_token: str = None, tg_chat: str = None) -> tuple:
    """
    Returns (uris, created_count, warnings).
    Matches ONLY configs where name == profile_name.
    NEVER deletes any configs.
    """
    profile_configs = [c for c in all_configs if c.get('name') == profile_name]
    config_by_server = {}
    for c in profile_configs:
        config_by_server[str(c.get('serverId'))] = c

    uris = []
    created_count = 0
    warnings = []

    for s in awg_servers:
        sid = str(s['id'])
        sname = s.get('name', f"Server {sid}")
        country_code = s.get('countryCode', '')

        conf_to_use = None
        if sid in config_by_server:
            c = config_by_server[sid]
            conf_to_use = c.get('config') or c.get('configLegacy')
        elif create_missing:
            used = s.get('userCreationsUsed', 0)
            lim = s.get('userCreationsLimit', 5)
            if used < lim:
                logger.info(f"[{profile_name}] Creating AWG config on '{sname}' ({sid})...")
                try:
                    res = requests.post(
                        f"{API_BASE}/wireguard/configs",
                        headers=headers,
                        json={"serverId": sid, "name": profile_name},
                        timeout=10
                    )
                    if res.status_code in (200, 201):
                        new_c = res.json()
                        conf_to_use = new_c.get('config') or new_c.get('configLegacy')
                        created_count += 1
                        all_configs.append(new_c)
                        config_by_server[sid] = new_c
                        # Update slot tracking
                        s['userCreationsUsed'] = used + 1
                        logger.info(f"[{profile_name}] Config created on '{sname}'")
                    else:
                        logger.warning(f"[{profile_name}] Creation failed on '{sname}': {res.text}")
                except Exception as ex:
                    logger.error(f"[{profile_name}] Creation error on '{sname}': {ex}")
            else:
                warn_msg = f"⚠️ Для профиля <b>{profile_name}</b> на сервере <b>{sname}</b> нет свободных слотов ({used}/{lim})."
                warnings.append(warn_msg)
                logger.warning(f"[{profile_name}] {warn_msg}")
                if tg_token and tg_chat:
                    send_telegram_alert(tg_token, tg_chat, warn_msg)

        if conf_to_use:
            node = config_to_wireguard_node(conf_to_use, sname, country_code, sid, profile_name=profile_name)
            if node['has_obfs']:
                uris.append(node['clean_uri'])

    return uris, created_count, warnings


def do_sync() -> dict:
    global profile_cache, last_sync_time
    with sync_lock:
        env_vars = load_env()
        token = env_vars.get("EOF_TOKEN") or env_vars.get("PROFILE_1_EOF_TOKEN")
        tg_token = env_vars.get("TELEGRAM_BOT_TOKEN")
        tg_chat = env_vars.get("TELEGRAM_CHAT_ID")

        if not token:
            logger.error("EOF_TOKEN not configured!")
            load_profile_cache_from_disk()
            return {"error": "EOF_TOKEN not configured"}

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        # 1. Fetch servers and user configs
        try:
            r_srv = requests.get(f"{API_BASE}/wireguard/servers", headers=headers, timeout=15)
            r_srv.raise_for_status()
            servers = r_srv.json()
        except Exception as e:
            logger.error(f"Failed fetching servers: {e}")
            load_profile_cache_from_disk()
            return {"error": f"Failed fetching servers: {e}"}

        try:
            r_cfg = requests.get(f"{API_BASE}/wireguard/configs", headers=headers, timeout=15)
            r_cfg.raise_for_status()
            configs = r_cfg.json()
        except Exception as e:
            logger.error(f"Failed fetching configs: {e}")
            load_profile_cache_from_disk()
            return {"error": f"Failed fetching configs: {e}"}

        # Filter active AWG servers (exclude plain WG and unavailable)
        awg_servers = [
            s for s in servers
            if not s.get('unavailable', False) and str(s['id']) not in ('105', '61')
        ]

        # 2. Shared protocols
        mieru_uris = fetch_mieru_nodes(headers)
        tt_uris = fetch_trusttunnel_nodes(headers)
        hy2_uris = fetch_hysteria2_nodes(headers)

        # 3. Process each profile from profiles.json
        profiles = load_profiles()
        new_cache = {}
        all_warnings = []
        report_details = []

        for p_id, p_data in profiles.items():
            p_name = p_data["name"]
            p_sub = p_data["sub_token"]

            awg_uris, created_cnt, p_warns = sync_profile_awg(headers, p_name, awg_servers, configs, create_missing=True)
            if p_warns:
                all_warnings.extend([f"[{p_name}] {w}" for w in p_warns])

            combined_uris = awg_uris + mieru_uris + tt_uris + hy2_uris
            sub_b64 = base64.b64encode("\n".join(combined_uris).encode('utf-8')).decode('ascii')

            p_cache_file = BASE_DIR / f"sub_cache_{p_name}.txt"
            try:
                p_cache_file.write_text(sub_b64, encoding="utf-8")
            except Exception:
                pass

            new_cache[p_sub] = {
                "b64": sub_b64,
                "name": p_name,
                "awg_count": len(awg_uris),
                "total_count": len(combined_uris)
            }

            report_details.append(
                f"👤 <b>{p_name}</b>: {len(awg_uris)} AWG + {len(mieru_uris)} Mieru + {len(tt_uris)} TT + {len(hy2_uris)} Hy2 = <b>{len(combined_uris)} узлов</b>"
            )

        # Maintain backward compatible default cache
        default_sub = env_vars.get("SECRET_TOKEN", "default_secret")
        if default_sub in new_cache:
            try:
                (BASE_DIR / "awg_sub_cache_working.txt").write_text(new_cache[default_sub]["b64"], encoding="utf-8")
            except Exception:
                pass

        profile_cache = new_cache
        last_sync_time = time.time()

        # Check server diff for Telegram notification
        curr_map = {str(s['id']): s.get('name') for s in servers if not s.get('unavailable', False)}
        prev_map = {}
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    prev_map = json.load(f)
            except Exception:
                pass

        new_servers = [name for sid, name in curr_map.items() if sid not in prev_map]
        lost_servers = [name for sid, name in prev_map.items() if sid not in curr_map]

        if (new_servers or lost_servers or all_warnings) and tg_token and tg_chat:
            msg_lines = ["<b>⚡ e0f.cx: Обновление протоколов</b>\n"]
            if new_servers:
                msg_lines.append("<b>➕ Добавлены серверы:</b>")
                for n in new_servers:
                    msg_lines.append(f"  • {n}")
            if lost_servers:
                msg_lines.append("\n<b>➖ Удалены серверы:</b>")
                for n in lost_servers:
                    msg_lines.append(f"  • {n}")
            if all_warnings:
                msg_lines.append("\n<b>⚠️ Предупреждения по слотам:</b>")
                for w in all_warnings:
                    msg_lines.append(f"  • {w}")
            msg_lines.append("\n<b>Текущие подписки:</b>")
            msg_lines.extend(report_details)
            send_telegram_alert(tg_token, tg_chat, "\n".join(msg_lines))

        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(curr_map, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

        logger.info(f"Sync complete. Active profiles: {len(profiles)}.")
        return {
            "status": "ok",
            "profiles": [
                {"name": v["name"], "nodes": v["total_count"], "awg": v["awg_count"]}
                for v in new_cache.values()
            ],
            "warnings": all_warnings,
            "timestamp": int(last_sync_time)
        }


# =====================================================================
# Profile Management Functions (Called via Telegram Bot)
# =====================================================================
def add_new_profile_via_telegram(name: str) -> dict:
    """Creates a new profile, allocates AWG configs with profile tag, returns sub url"""
    clean_name = name.strip().replace(" ", "_")
    if not clean_name:
        return {"error": "Имя профиля не может быть пустым."}

    profiles = load_profiles()
    # Check if exists
    for p_id, p_info in profiles.items():
        if p_info["name"].lower() == clean_name.lower():
            return {"error": f"Профиль с именем «{p_info['name']}» уже существует."}

    # Generate unique subscription token
    sub_token = f"sub_{clean_name.lower()}_{secrets.token_hex(4)}"

    profiles[clean_name] = {
        "name": clean_name,
        "sub_token": sub_token,
        "created_at": int(time.time())
    }
    save_profiles(profiles)

    # Trigger sync to create configs on e0f and build cache
    sync_res = do_sync()
    warnings = sync_res.get("warnings", [])

    matched = [p for p in sync_res.get("profiles", []) if p["name"] == clean_name]
    nodes_count = matched[0]["nodes"] if matched else 0
    awg_count = matched[0]["awg"] if matched else 0

    return {
        "ok": True,
        "name": clean_name,
        "sub_token": sub_token,
        "awg_count": awg_count,
        "total_nodes": nodes_count,
        "warnings": warnings
    }


def delete_profile_via_telegram(name: str) -> dict:
    """Deletes profile and frees up AWG configs on e0f for that profile"""
    clean_name = name.strip()
    profiles = load_profiles()

    target_key = None
    for k, v in profiles.items():
        if v["name"].lower() == clean_name.lower():
            target_key = k
            break

    if not target_key:
        return {"error": f"Профиль «{clean_name}» не найден."}

    real_name = profiles[target_key]["name"]
    del profiles[target_key]
    save_profiles(profiles)

    # Delete configs belonging to this profile from e0f to free slots
    env_vars = load_env()
    token = env_vars.get("EOF_TOKEN") or env_vars.get("PROFILE_1_EOF_TOKEN")
    freed_count = 0

    if token:
        headers = {"Authorization": f"Bearer {token}"}
        try:
            r_cfg = requests.get(f"{API_BASE}/wireguard/configs", headers=headers, timeout=15)
            if r_cfg.status_code == 200:
                for c in r_cfg.json():
                    if c.get('name') == real_name:
                        cid = c.get('id')
                        try:
                            requests.delete(f"{API_BASE}/wireguard/configs/{cid}", headers=headers, timeout=10)
                            freed_count += 1
                        except Exception:
                            pass
        except Exception as e:
            logger.error(f"Error cleaning configs for '{real_name}': {e}")

    # Remove cache file
    p_cache_file = BASE_DIR / f"sub_cache_{real_name}.txt"
    if p_cache_file.exists():
        try:
            p_cache_file.unlink()
        except Exception:
            pass

    do_sync()

    return {
        "ok": True,
        "name": real_name,
        "freed_slots": freed_count
    }


# =====================================================================
# Telegram Bot Worker (Long-polling + Profile Commands)
# =====================================================================

# =====================================================================
# Music & Shazam Pipeline with Interactive Confirmation
# =====================================================================

PENDING_MUSIC_DIR = BASE_DIR / "music_pending"
PENDING_MUSIC_DIR.mkdir(parents=True, exist_ok=True)


def cleanup_old_pending_music(max_age_seconds: int = 7200):
    """Removes pending download folders older than max_age_seconds (default 2 hours)."""
    try:
        now = time.time()
        for p in PENDING_MUSIC_DIR.glob("*"):
            if p.is_dir() and (now - p.stat().st_mtime) > max_age_seconds:
                shutil.rmtree(p, ignore_errors=True)
    except Exception as e:
        logger.debug(f"Pending music cleanup error: {e}")


def search_and_prepare_music(query: str, reply_chat_id: str = None, reply_msg_id: int = None):
    """
    Searches track via yt-dlp, downloads 320k mp3 with artwork to PENDING_MUSIC_DIR,
    and sends audio file to user PM with [✅ Закинуть в канал] and [❌ Отмена] buttons.
    """
    import glob, yt_dlp, secrets

    clean_query = query.strip()
    if not clean_query:
        return

    cleanup_old_pending_music()

    env_vars = load_env()
    tg_token = env_vars.get("TELEGRAM_BOT_TOKEN")
    if not tg_token:
        logger.error("TELEGRAM_BOT_TOKEN not found for music upload")
        return

    if not reply_chat_id:
        reply_chat_id = env_vars.get("TELEGRAM_CHAT_ID") or env_vars.get("TELEGRAM_OWNER_ID")

    status_msg_id = None
    if reply_chat_id:
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{tg_token}/sendMessage",
                json={
                    "chat_id": reply_chat_id,
                    "text": f"🔎 <b>Ищу и скачиваю трек:</b>\n<code>{clean_query}</code>...",
                    "parse_mode": "HTML",
                    "reply_to_message_id": reply_msg_id
                },
                timeout=10
            ).json()
            if r.get("ok"):
                status_msg_id = r["result"]["message_id"]
        except Exception as e:
            logger.warning(f"Failed to send search ack: {e}")

    track_id = secrets.token_hex(4)
    track_dir = PENDING_MUSIC_DIR / track_id
    track_dir.mkdir(parents=True, exist_ok=True)

    try:
        ydl_opts = {
            'format': 'bestaudio/best',
            'outtmpl': str(track_dir / '%(title)s.%(ext)s'),
            'postprocessors': [
                {'key': 'FFmpegExtractAudio', 'preferredcodec': 'mp3', 'preferredquality': '320'},
                {'key': 'EmbedThumbnail'},
                {'key': 'FFmpegMetadata'},
            ],
            'writethumbnail': True,
            'noplaylist': True,
            'default_search': 'ytsearch1',
            'quiet': True,
            'no_warnings': True,
        }

        logger.info(f"Searching and downloading audio for: {clean_query} (id: {track_id})")
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(f"ytsearch1:{clean_query}", download=True)
            if 'entries' in info and info['entries']:
                entry = info['entries'][0]
            else:
                entry = info

        title = entry.get('track') or entry.get('title') or clean_query
        artist = entry.get('artist') or entry.get('uploader') or 'Музыка'
        duration = int(entry.get('duration') or 0)

        mp3_files = list(track_dir.glob("*.mp3"))
        if not mp3_files:
            raise Exception("MP3 файл не найден после конвертации")
        mp3_path = mp3_files[0]

        thumb_files = [f for f in track_dir.glob("*.*") if f.suffix.lower() in ('.jpg', '.jpeg', '.png', '.webp') and f.suffix.lower() != '.mp3']
        thumb_path = thumb_files[0] if thumb_files else None

        # Save metadata for callback handler
        meta = {
            "id": track_id,
            "query": clean_query,
            "title": title,
            "artist": artist,
            "duration": duration,
            "mp3_path": str(mp3_path),
            "thumb_path": str(thumb_path) if thumb_path else None,
            "chat_id": reply_chat_id,
            "status_msg_id": status_msg_id,
            "created_at": time.time()
        }
        (track_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

        m, s = divmod(duration, 60)
        dur_str = f"{m}:{s:02d}"

        # Send preview audio with inline confirmation buttons
        if reply_chat_id:
            caption = (
                f"🎧 <b>Найден трек:</b>\n"
                f"🎵 <b>{artist} — {title}</b>\n"
                f"⏱ Длительность: <code>{dur_str}</code>\n\n"
                f"Опубликовать в канале «Свалка треков»?"
            )
            reply_markup = {
                "inline_keyboard": [
                    [
                        {"text": "✅ Закинуть в канал", "callback_data": f"pub:{track_id}"},
                        {"text": "❌ Отмена", "callback_data": f"del:{track_id}"}
                    ]
                ]
            }

            url = f"https://api.telegram.org/bot{tg_token}/sendAudio"
            with open(mp3_path, 'rb') as audio_file:
                files = {'audio': (mp3_path.name, audio_file, 'audio/mpeg')}
                thumb_file = open(thumb_path, 'rb') if thumb_path and thumb_path.exists() else None
                if thumb_file:
                    files['thumbnail'] = (thumb_path.name, thumb_file, 'image/jpeg')

                data = {
                    'chat_id': str(reply_chat_id),
                    'title': title,
                    'performer': artist,
                    'duration': duration,
                    'caption': caption,
                    'parse_mode': 'HTML',
                    'reply_markup': json.dumps(reply_markup)
                }
                res = requests.post(url, data=data, files=files, timeout=90).json()
                if thumb_file:
                    thumb_file.close()

            # Delete the "searching..." message if preview sent
            if status_msg_id:
                try:
                    requests.post(
                        f"https://api.telegram.org/bot{tg_token}/deleteMessage",
                        json={"chat_id": reply_chat_id, "message_id": status_msg_id},
                        timeout=5
                    )
                except Exception:
                    pass

    except Exception as e:
        logger.error(f"Error searching/downloading music for '{clean_query}': {e}")
        shutil.rmtree(track_dir, ignore_errors=True)
        if reply_chat_id:
            fail_text = f"❌ Не удалось найти или скачать трек: <i>{clean_query}</i>\nОшибка: {e}"
            if status_msg_id:
                requests.post(
                    f"https://api.telegram.org/bot{tg_token}/editMessageText",
                    json={
                        "chat_id": reply_chat_id,
                        "message_id": status_msg_id,
                        "text": fail_text,
                        "parse_mode": "HTML"
                    },
                    timeout=10
                )
            else:
                send_telegram_alert(tg_token, reply_chat_id, fail_text)


def handle_telegram_callback(cb: dict, tg_token: str, env_vars: dict):
    """Handles inline button clicks: pub:<id> or del:<id>."""
    cb_id = cb["id"]
    cb_data = cb.get("data", "")
    from_user = str(cb.get("from", {}).get("id", ""))
    msg = cb.get("message", {})
    chat_id = str(msg.get("chat", {}).get("id", ""))
    msg_id = msg.get("message_id")

    if not cb_data or ":" not in cb_data:
        return

    action, track_id = cb_data.split(":", 1)
    track_dir = PENDING_MUSIC_DIR / track_id
    meta_path = track_dir / "meta.json"

    if action == "del":
        requests.post(
            f"https://api.telegram.org/bot{tg_token}/answerCallbackQuery",
            json={"callback_query_id": cb_id, "text": "❌ Добавление отменено"},
            timeout=5
        )
        title = "трек"
        artist = ""
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                title = meta.get("title", "")
                artist = meta.get("artist", "")
            except Exception:
                pass
        shutil.rmtree(track_dir, ignore_errors=True)

        name_str = f"{artist} — {title}" if artist else title
        requests.post(
            f"https://api.telegram.org/bot{tg_token}/editMessageCaption",
            json={
                "chat_id": chat_id,
                "message_id": msg_id,
                "caption": f"❌ <b>Отменено:</b> <s>{name_str}</s>",
                "parse_mode": "HTML",
                "reply_markup": {"inline_keyboard": []}
            },
            timeout=10
        )
        return

    if action == "pub":
        if not meta_path.exists():
            requests.post(
                f"https://api.telegram.org/bot{tg_token}/answerCallbackQuery",
                json={"callback_query_id": cb_id, "text": "⚠️ Файл устарел или уже опубликован", "show_alert": True},
                timeout=5
            )
            requests.post(
                f"https://api.telegram.org/bot{tg_token}/editMessageCaption",
                json={
                    "chat_id": chat_id,
                    "message_id": msg_id,
                    "caption": "⚠️ <b>Срок ожидания истёк или трек уже удалён.</b>",
                    "parse_mode": "HTML",
                    "reply_markup": {"inline_keyboard": []}
                },
                timeout=10
            )
            return

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            title = meta["title"]
            artist = meta["artist"]
            duration = meta.get("duration", 0)
            mp3_path = Path(meta["mp3_path"])
            thumb_path = Path(meta["thumb_path"]) if meta.get("thumb_path") else None

            channel_id_val = env_vars.get("MUSIC_CHANNEL_ID")
            if not channel_id_val:
                raise Exception("MUSIC_CHANNEL_ID is not configured in .env")
            channel_id = int(channel_id_val)

            requests.post(
                f"https://api.telegram.org/bot{tg_token}/answerCallbackQuery",
                json={"callback_query_id": cb_id, "text": "🚀 Публикую в канал..."},
                timeout=5
            )

            # Upload to music channel
            url = f"https://api.telegram.org/bot{tg_token}/sendAudio"
            with open(mp3_path, 'rb') as audio_file:
                files = {'audio': (mp3_path.name, audio_file, 'audio/mpeg')}
                thumb_file = open(thumb_path, 'rb') if thumb_path and thumb_path.exists() else None
                if thumb_file:
                    files['thumbnail'] = (thumb_path.name, thumb_file, 'image/jpeg')

                caption = f"🎵 <b>{artist} — {title}</b>\n\n#музыка"
                data = {
                    'chat_id': channel_id,
                    'title': title,
                    'performer': artist,
                    'duration': duration,
                    'caption': caption,
                    'parse_mode': 'HTML'
                }
                res = requests.post(url, data=data, files=files, timeout=90).json()
                if thumb_file:
                    thumb_file.close()

            if not res.get("ok"):
                raise Exception(res.get("description", "Unknown Telegram error"))

            channel_msg_id = res['result']['message_id']
            chat_obj = res['result'].get('chat', {})
            chat_uname = chat_obj.get('username')
            if chat_uname:
                channel_link = f"https://t.me/{chat_uname}/{channel_msg_id}"
            else:
                c_id_clean = str(channel_id).replace("-100", "").replace("-", "")
                channel_link = f"https://t.me/c/{c_id_clean}/{channel_msg_id}"

            # Edit preview message in user PM
            requests.post(
                f"https://api.telegram.org/bot{tg_token}/editMessageCaption",
                json={
                    "chat_id": chat_id,
                    "message_id": msg_id,
                    "caption": (
                        f"✅ <b>Опубликовано в «Свалка треков»!</b>\n\n"
                        f"🎵 <b>{artist} — {title}</b>\n"
                        f"🔗 <a href=\"{channel_link}\">Перейти к треку в канале</a>"
                    ),
                    "parse_mode": "HTML",
                    "reply_markup": {"inline_keyboard": []}
                },
                timeout=10
            )

            shutil.rmtree(track_dir, ignore_errors=True)
            logger.info(f"Published track {artist} - {title} to channel {channel_id}")

        except Exception as e:
            logger.error(f"Error publishing track: {e}")
            requests.post(
                f"https://api.telegram.org/bot{tg_token}/answerCallbackQuery",
                json={"callback_query_id": cb_id, "text": f"❌ Ошибка: {e}", "show_alert": True},
                timeout=5
            )

def telegram_bot_worker():
    logger.info("Telegram Bot worker started.")
    offset = 0

    # Ensure webhook is cleared so getUpdates works
    try:
        env_vars = load_env()
        tg_tok = env_vars.get("TELEGRAM_BOT_TOKEN")
        if tg_tok:
            requests.post(f"https://api.telegram.org/bot{tg_tok}/deleteWebhook", timeout=10)
    except Exception:
        pass

    while True:
        try:
            env_vars = load_env()
            tg_token = env_vars.get("TELEGRAM_BOT_TOKEN")
            current_chat_id = env_vars.get("TELEGRAM_CHAT_ID")

            if not tg_token:
                time.sleep(10)
                continue

            url = f"https://api.telegram.org/bot{tg_token}/getUpdates?offset={offset}&timeout=25"
            r = requests.get(url, timeout=30)
            if r.status_code == 409:
                logger.warning("Telegram 409 Conflict (webhook active). Deleting webhook...")
                try:
                    requests.post(f"https://api.telegram.org/bot{tg_token}/deleteWebhook", timeout=10)
                except Exception:
                    pass
                time.sleep(3)
                continue

            if r.status_code == 200:
                data = r.json()
                for update in data.get("result", []):
                    offset = update["update_id"] + 1

                    cb = update.get("callback_query")
                    if cb:
                        handle_telegram_callback(cb, tg_token, env_vars)
                        continue

                    msg = update.get("message")
                    if not msg:
                        continue

                    chat_id = str(msg["chat"]["id"])
                    raw_text = msg.get("text", "").strip()

                    # Auto-bind chat ID and owner user_id (first ever sender becomes owner)
                    sender_user_id = str(msg.get("from", {}).get("id", ""))
                    owner_user_id = env_vars.get("TELEGRAM_OWNER_ID", "")
                    if not chat_id.startswith("-"):
                        if not current_chat_id or current_chat_id != chat_id:
                            save_env_var("TELEGRAM_CHAT_ID", chat_id)
                            current_chat_id = chat_id
                            logger.info(f"Auto-bound Telegram Chat ID: {chat_id}")
                    if not owner_user_id and sender_user_id:
                        save_env_var("TELEGRAM_OWNER_ID", sender_user_id)
                        owner_user_id = sender_user_id
                        logger.info(f"Auto-bound Telegram Owner user_id: {sender_user_id}")

                    # Commands handling
                    parts = raw_text.split()
                    cmd = parts[0].lower() if parts else ""
                    args = parts[1:] if len(parts) > 1 else []

                    # 1. /start, /help
                    if cmd in ("/start", "/help"):
                        help_msg = (
                            "🤖 <b>e0f Protocol Subscription Manager</b>\n\n"
                            "<b>Управление профилями:</b>\n"
                            "➕ <code>/newprofile &lt;имя&gt;</code> — Создать новый профиль (выделит свои AWG серверы и выдаст ссылку)\n"
                            "➖ <code>/delprofile &lt;имя&gt;</code> — Удалить профиль и освободить слоты на e0f\n"
                            "📋 <code>/profiles</code> — Список всех профилей и ссылки подписок\n\n"
                            "<b>Серверы и синхронизация:</b>\n"
                            "📊 <code>/status</code> — Статус серверов и слотов\n"
                            "🔄 <code>/sync</code> — Принудительно обновить серверы\n"
                            "🔎 <code>/check</code> — Тест Gemini серверов\n\n"
                            "🎵 <b>Поиск музыки:</b>\n"
                            "Отправьте боту любое название трека (или <code>/music &lt;название&gt;</code>) — он найдёт его, скачает в MP3 (320 kbps) и отправит в группу «Свалка треков»!"
                        )
                        send_telegram_alert(tg_token, chat_id, help_msg)

                    # 2. /newprofile or /add
                    elif cmd in ("/newprofile", "/add", "/create"):
                        if not args:
                            send_telegram_alert(tg_token, chat_id, "⚠️ Укажите имя профиля, например:\n<code>/newprofile Work</code>")
                        else:
                            p_name = args[0]
                            send_telegram_alert(tg_token, chat_id, f"⏳ Создаю профиль <b>«{p_name}»</b> и выделяю AWG-серверы...")
                            res = add_new_profile_via_telegram(p_name)
                            if "error" in res:
                                send_telegram_alert(tg_token, chat_id, f"❌ Ошибка: {res['error']}")
                            else:
                                sub_url = f"{get_vps_base_url()}/sub?token={res['sub_token']}"
                                lines = [
                                    f"✅ <b>Профиль «{res['name']}» успешно создан!</b>\n",
                                    "🔗 <b>Ссылка подписки для Shadowrocket:</b>",
                                    f"<code>{sub_url}</code>\n",
                                    f"⚡ <b>AmneziaWG:</b> {res['awg_count']} серверов (с тегом [{res['name']}])",
                                    f"🛡 <b>Доп. протоколы:</b> {res['total_nodes'] - res['awg_count']} (Mieru, TrustTunnel, Hysteria2)",
                                    f"Всего в подписке: <b>{res['total_nodes']} узлов</b>"
                                ]
                                if res.get("warnings"):
                                    lines.append("\n⚠️ <b>Предупреждения по слотам:</b>")
                                    for w in res["warnings"]:
                                        lines.append(f"  • {w}")
                                send_telegram_alert(tg_token, chat_id, "\n".join(lines))

                    # 3. /delprofile or /delete
                    elif cmd in ("/delprofile", "/delete", "/del"):
                        if not args:
                            send_telegram_alert(tg_token, chat_id, "⚠️ Укажите имя профиля для удаления, например:\n<code>/delprofile Work</code>")
                        else:
                            p_name = args[0]
                            res = delete_profile_via_telegram(p_name)
                            if "error" in res:
                                send_telegram_alert(tg_token, chat_id, f"❌ Ошибка: {res['error']}")
                            else:
                                send_telegram_alert(
                                    tg_token, chat_id,
                                    f"🗑 <b>Профиль «{res['name']}» удалён!</b>\n"
                                    f"Освобождено слотов на e0f.cx: <b>{res['freed_slots']}</b>."
                                )

                    # 4. /profiles or /list
                    elif cmd in ("/profiles", "/list"):
                        profiles = load_profiles()
                        lines = ["📋 <b>Активные профили подписок:</b>\n"]
                        for k, p in profiles.items():
                            p_name = p["name"]
                            sub_url = f"{get_vps_base_url()}/sub?token={p['sub_token']}"
                            info = profile_cache.get(p["sub_token"], {})
                            total = info.get("total_count", 0)
                            awg = info.get("awg_count", 0)
                            lines.append(f"👤 <b>Профиль: {p_name}</b> ({total} узлов, AWG: {awg})")
                            lines.append(f"🔗 <code>{sub_url}</code>\n")
                        send_telegram_alert(tg_token, chat_id, "\n".join(lines))

                    # 5. /status
                    elif cmd == "/status":
                        lines = ["📊 <b>Статус Gemini Checker</b>\n"]
                        # Gemini checker state
                        checker_state = {}
                        if CHECKER_STATE_FILE.exists():
                            try:
                                with open(CHECKER_STATE_FILE, "r") as csf:
                                    checker_state = json.load(csf)
                            except Exception:
                                pass
                        gemini_nodes = checker_state.get("web", [])
                        last_check_str = checker_state.get("last_check", "")
                        if gemini_nodes:
                            lines.append(f"✅ <b>Рабочие серверы (Web+API): {len(gemini_nodes)}</b>")
                            for node in gemini_nodes[:10]:
                                lines.append(f"  • {node}")
                            if len(gemini_nodes) > 10:
                                lines.append(f"  ... и ещё {len(gemini_nodes) - 10}")
                        else:
                            lines.append("❌ <b>Нет рабочих Gemini серверов</b>")
                        if last_check_str:
                            lines.append(f"\n⏱ Последняя проверка: {last_check_str}")
                        # Calculate next cron run (every 3 hours from midnight UTC)
                        import datetime as _dt
                        now_utc = _dt.datetime.utcnow()
                        hour = now_utc.hour
                        next_h = ((hour // 3) + 1) * 3
                        if next_h >= 24:
                            next_check = now_utc.replace(hour=0, minute=0, second=0, microsecond=0) + _dt.timedelta(days=1)
                        else:
                            next_check = now_utc.replace(hour=next_h, minute=0, second=0, microsecond=0)
                        delta = next_check - now_utc
                        mins_left = int(delta.total_seconds() // 60)
                        h_left, m_left = divmod(mins_left, 60)
                        if h_left > 0:
                            eta_str = f"{h_left}ч {m_left}мин"
                        else:
                            eta_str = f"{m_left}мин"
                        lines.append(f"🕐 Следующая проверка: через {eta_str}")
                        # Subscriptions
                        if not profile_cache:
                            load_profile_cache_from_disk()
                        profiles = load_profiles()
                        lines.append("\n📦 <b>Подписки:</b>")
                        for k, p in profiles.items():
                            p_name = p["name"]
                            info = profile_cache.get(p["sub_token"], {})
                            total = info.get("total_count", 0)
                            awg = info.get("awg_count", 0)
                            lines.append(f"  👤 {p_name}: {total} серверов (AWG: {awg})")
                        if last_sync_time:
                            lines.append(f"\n⏱ Последняя синхронизация e0f: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_sync_time))}")
                        send_telegram_alert(tg_token, chat_id, "\n".join(lines))

                    # 6. /sync
                    elif cmd == "/check":
                        # Защита: только владелец бота может запускать проверку
                        if owner_user_id and sender_user_id != owner_user_id:
                            send_telegram_alert(tg_token, chat_id, "⛔ Команда /check доступна только владельцу бота.")
                        else:
                            send_telegram_alert(tg_token, chat_id, "⏳ Запущена полная проверка прокси-серверов (Web + API).\nЭто займёт около 15-20 минут. Отчёт придёт автоматически по завершении!")
                            import subprocess
                            subprocess.Popen(["bash", "/opt/gemini-proxy-checker/run.sh"], cwd="/opt/gemini-proxy-checker")

                    # 7. /sync
                    elif cmd == "/sync":
                        send_telegram_alert(tg_token, chat_id, "⏳ Синхронизация всех профилей...")
                        res = do_sync()
                        summary = ", ".join([f"{p['name']}: {p['nodes']}" for p in res.get('profiles', [])])
                        send_telegram_alert(tg_token, chat_id, f"✅ Синхронизация завершена!\n{summary}")

                    # 8. /music, /song, /track
                    elif cmd in ("/music", "/song", "/track", "/m"):
                        query = " ".join(args).strip()
                        if not query:
                            send_telegram_alert(tg_token, chat_id, "⚠️ Укажите название трека, например:\n<code>/music The Weeknd Blinding Lights</code>")
                        else:
                            threading.Thread(target=search_and_prepare_music, args=(query, chat_id, msg.get("message_id")), daemon=True).start()

                    # 9. Plain text message in private chat -> search music
                    elif not cmd.startswith("/") and not chat_id.startswith("-"):
                        query = raw_text.strip()
                        if query:
                            threading.Thread(target=search_and_prepare_music, args=(query, chat_id, msg.get("message_id")), daemon=True).start()

        except Exception as e:
            logger.debug(f"Telegram polling exception: {e}")
            time.sleep(5)


# =====================================================================
# Web Status Page Builder
# =====================================================================
def build_status_page() -> str:
    """Builds a public HTML status page with Gemini node health and subscription info."""
    import datetime as _dt
    checker_state = {}
    if CHECKER_STATE_FILE.exists():
        try:
            with open(CHECKER_STATE_FILE, "r", encoding="utf-8") as f:
                checker_state = json.load(f)
        except Exception:
            pass

    gemini_web = checker_state.get("web", [])
    gemini_api = checker_state.get("api", [])
    last_check = checker_state.get("last_check", "Нет данных")
    history = checker_state.get("history", [])

    # Profiles count (no tokens exposed)
    profiles = load_profiles()
    profile_info = []
    for p_id, p in profiles.items():
        info = profile_cache.get(p["sub_token"], {})
        profile_info.append({
            "name": p["name"],
            "total": info.get("total_count", 0),
            "awg": info.get("awg_count", 0)
        })

    # Next cron
    now_utc = _dt.datetime.utcnow()
    hour = now_utc.hour
    next_h = ((hour // 3) + 1) * 3
    if next_h >= 24:
        next_check_dt = now_utc.replace(hour=0, minute=0, second=0, microsecond=0) + _dt.timedelta(days=1)
    else:
        next_check_dt = now_utc.replace(hour=next_h, minute=0, second=0, microsecond=0)
    delta = next_check_dt - now_utc
    mins_left = int(delta.total_seconds() // 60)
    h_left, m_left = divmod(mins_left, 60)
    next_check_str = f"{next_h:02d}:00 UTC (через {h_left}ч {m_left}мин)" if h_left > 0 else f"{next_h:02d}:00 UTC (через {m_left}мин)"

    # Build node rows
    all_nodes = sorted(set(gemini_web + gemini_api))
    node_rows = ""
    for node in all_nodes:
        web_ok = node in gemini_web
        api_ok = node in gemini_api
        web_dot = '<span class="dot green" title="Web OK">●</span>' if web_ok else '<span class="dot red" title="Web FAIL">●</span>'
        api_dot = '<span class="dot green" title="API OK">●</span>' if api_ok else '<span class="dot red" title="API FAIL">●</span>'
        node_rows += f'<tr><td class="node-name">{node}</td><td>{web_dot} Web</td><td>{api_dot} API</td></tr>\n'

    if not node_rows:
        node_rows = '<tr><td colspan="3" style="text-align:center;color:#888">Нет данных о нодах</td></tr>'

    # Profile rows
    prof_rows = ""
    for p in profile_info:
        prof_rows += f'<tr><td>👤 {p["name"]}</td><td>{p["total"]} серверов</td><td>AWG: {p["awg"]}</td></tr>\n'

    # History table (last 5)
    hist_rows = ""
    for entry in history[:5]:
        ts = entry.get("ts", "")
        w = len(entry.get("web", []))
        a = len(entry.get("api", []))
        hist_rows += f'<tr><td>{ts}</td><td>{w}</td><td>{a}</td></tr>\n'

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="60">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gemini Proxy Checker — Статус</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }}
  h1 {{ color: #58a6ff; font-size: 1.5em; margin-bottom: 8px; }}
  h2 {{ color: #8b949e; font-size: 1em; margin: 20px 0 8px; text-transform: uppercase; letter-spacing: 1px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
  .meta {{ color: #8b949e; font-size: 0.85em; margin-bottom: 16px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
  th {{ color: #8b949e; text-align: left; padding: 6px 10px; border-bottom: 1px solid #30363d; font-weight: normal; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid #21262d; }}
  tr:last-child td {{ border-bottom: none; }}
  .node-name {{ font-family: monospace; }}
  .dot {{ font-size: 1.2em; }}
  .dot.green {{ color: #3fb950; }}
  .dot.red {{ color: #f85149; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; font-weight: bold; }}
  .badge.ok {{ background: #1a4731; color: #3fb950; }}
  .badge.warn {{ background: #3d2f00; color: #e3b341; }}
  .footer {{ color: #484f58; font-size: 0.75em; margin-top: 20px; text-align: center; }}
  .summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 16px; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 20px; text-align: center; }}
  .stat .num {{ font-size: 2em; font-weight: bold; color: #3fb950; }}
  .stat .label {{ font-size: 0.8em; color: #8b949e; margin-top: 4px; }}
</style>
</head>
<body>
<h1>🤖 Gemini Proxy Checker</h1>
<p class="meta">Последняя проверка: <b>{last_check}</b> &nbsp;|&nbsp; Следующая: <b>{next_check_str}</b> &nbsp;|&nbsp; <span style="color:#484f58">Обновляется каждые 60 сек</span></p>

<div class="summary">
  <div class="stat"><div class="num">{len(gemini_web)}</div><div class="label">Web ноды</div></div>
  <div class="stat"><div class="num">{len(gemini_api)}</div><div class="label">API ноды</div></div>
  <div class="stat"><div class="num">{sum(p["total"] for p in profile_info)}</div><div class="label">Серверов в подписках</div></div>
</div>

<div class="card">
<h2>Gemini Ноды</h2>
<table>
<tr><th>Нода</th><th>Web</th><th>API</th></tr>
{node_rows}
</table>
</div>

<div class="card">
<h2>Подписки</h2>
<table>
<tr><th>Профиль</th><th>Серверов</th><th>AWG</th></tr>
{prof_rows}
</table>
</div>

{'<div class="card"><h2>История проверок</h2><table><tr><th>Время</th><th>Web нод</th><th>API нод</th></tr>' + hist_rows + '</table></div>' if hist_rows else ''}

<p class="footer">gemini-proxy-checker &nbsp;•&nbsp; {now_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
</body>
</html>"""
    return html


# =====================================================================
# HTTP Request Handler
# =====================================================================
class SubscriptionHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.info(f"{self.client_address[0]} - {args[0]} {args[1]}")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        req_token = qs.get("token", [""])[0]

        # 1. Health check
        if path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "service": "e0f-telegram-sub"}).encode())
            return

        # 2. Trigger sync
        if path in ("/trigger", "/sync"):
            profiles = load_profiles()
            valid_tokens = [p["sub_token"] for p in profiles.values()]
            if req_token not in valid_tokens:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"403 Forbidden")
                return
            result = do_sync()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(result, indent=2, ensure_ascii=False).encode('utf-8'))
            return

        # 3. Subscription endpoint: /sub, /awg, /
        if path in ("/sub", "/awg", "/"):
            global profile_cache
            if not profile_cache or req_token not in profile_cache:
                do_sync()

            matched_profile = profile_cache.get(req_token)
            if not matched_profile:
                self.send_response(403)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"403 Forbidden: Invalid subscription token.\n")
                return

            sub_b64 = matched_profile["b64"]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Subscription-Userinfo", f"upload=0; download=0; total=1073741824000; expire=2148091000")
            self.send_header("Profile-Update-Interval", "12")
            self.end_headers()
            self.wfile.write(sub_b64.encode('ascii'))
            return

        # 4. Web status page (public)
        if path == "/status":
            html = build_status_page()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        # 5. Music / Shazam webhook GET
        if path in ("/shazam", "/music"):
            env_vars = load_env()
            shazam_secret = env_vars.get("SHAZAM_SECRET_TOKEN", "")
            req_token = (
                qs.get("token", [""])[0] or
                qs.get("key", [""])[0] or
                self.headers.get("X-Auth-Token", "") or
                self.headers.get("Authorization", "").replace("Bearer ", "").strip()
            )

            if shazam_secret and req_token != shazam_secret:
                logger.warning(f"Unauthorized /shazam attempt from {self.client_address[0]}")
                self.send_response(403)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "error": "Forbidden: invalid or missing token"}).encode('utf-8'))
                return

            q = qs.get("q", [""])[0] or qs.get("track", [""])[0] or qs.get("query", [""])[0]
            if q:
                current_chat_id = env_vars.get("TELEGRAM_CHAT_ID") or env_vars.get("TELEGRAM_OWNER_ID")
                threading.Thread(target=search_and_prepare_music, args=(q, current_chat_id), daemon=True).start()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "ok": True,
                    "status": "waiting_confirmation",
                    "query": q,
                    "message": "Track downloaded and sent to Telegram for confirmation"
                }, ensure_ascii=False).encode('utf-8'))
                return
            else:
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "error": "Missing ?q= parameter"}).encode('utf-8'))
                return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not Found")



    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path in ("/shazam", "/music"):
            env_vars = load_env()
            shazam_secret = env_vars.get("SHAZAM_SECRET_TOKEN", "")

            content_len = int(self.headers.get('Content-Length', 0))
            post_body = self.rfile.read(content_len).decode('utf-8', errors='ignore')
            q = ""
            req_token = (
                self.headers.get("X-Auth-Token", "") or
                self.headers.get("Authorization", "").replace("Bearer ", "").strip()
            )
            try:
                body_json = json.loads(post_body)
                q = body_json.get("query") or body_json.get("track") or body_json.get("title") or body_json.get("q")
                if not req_token:
                    req_token = body_json.get("token") or body_json.get("key")
            except Exception:
                qs = urllib.parse.parse_qs(post_body)
                q = qs.get("q", [""])[0] or qs.get("track", [""])[0] or post_body.strip()
                if not req_token:
                    req_token = qs.get("token", [""])[0]

            if shazam_secret and req_token != shazam_secret:
                logger.warning(f"Unauthorized POST /shazam attempt from {self.client_address[0]}")
                self.send_response(403)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "error": "Forbidden: invalid or missing token"}).encode('utf-8'))
                return

            if q:
                current_chat_id = env_vars.get("TELEGRAM_CHAT_ID") or env_vars.get("TELEGRAM_OWNER_ID")
                threading.Thread(target=search_and_prepare_music, args=(q, current_chat_id), daemon=True).start()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "ok": True,
                    "status": "waiting_confirmation",
                    "query": q,
                    "message": "Track downloaded and sent to Telegram for confirmation"
                }, ensure_ascii=False).encode('utf-8'))
                return
            else:
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "error": "Missing query in body"}).encode('utf-8'))
                return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not Found")

def background_scheduler(interval_seconds: int = 1800):
    logger.info(f"Background sync worker started (interval: {interval_seconds}s).")
    while True:
        try:
            do_sync()
        except Exception as e:
            logger.error(f"Error in background sync: {e}")
        time.sleep(interval_seconds)


def run_server(port: int = 8088):
    env_vars = load_env()
    bot_token = env_vars.get("TELEGRAM_BOT_TOKEN") or ""
    save_env_var("TELEGRAM_BOT_TOKEN", bot_token)

    # Load cached profiles from disk first so service is ready immediately
    load_profile_cache_from_disk()

    # Initial sync
    do_sync()

    # Start background scheduler
    t_sync = threading.Thread(target=background_scheduler, args=(1800,), daemon=True)
    t_sync.start()

    # Start Telegram Bot worker
    t_tg = threading.Thread(target=telegram_bot_worker, daemon=True)
    t_tg.start()

    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, SubscriptionHandler)
    logger.info("=" * 60)
    logger.info(f"e0f Telegram Subscription Service running on port {port}")
    profiles = load_profiles()
    for p_id, p in profiles.items():
        logger.info(f"Profile '{p['name']}': http://<VPS_IP>:{port}/sub?token={p['sub_token']}")
    logger.info("=" * 60)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        httpd.server_close()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8088))
    run_server(port)
