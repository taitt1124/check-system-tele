#!/usr/bin/env python

import sys
import json
import requests
import os
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
from dateutil import parser

# ======= CONFIG =======
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "-4725661475")
CACHE_FILE = "/tmp/post_request_cache.json"

# ======= UTILITY FUNCTIONS =======
def load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_cache(data):
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Lỗi ghi cache: {e}", file=sys.stderr)

def send_telegram(message: str, hook_url: str):
    msg_data = {
        'chat_id': CHAT_ID,
        'text': message
    }
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    response = requests.post(hook_url, headers=headers, data=json.dumps(msg_data))
    if not response.ok:
        print(f"Telegram send error: {response.text}", file=sys.stderr)

def resolve_device(target_user, target_domain, default_device):
    if default_device != "N/A":
        return default_device
    if target_user.endswith("$"):
        return target_user.rstrip("$")
    if target_domain not in ["N/A", "ESUHAI.LOCAL", "esuhai.local"]:
        return target_domain
    return "N/A"

# ======= MAIN ENTRY =======
if len(sys.argv) < 4:
    print("Usage: script.py <alert_json_file> <unused> <telegram_webhook>", file=sys.stderr)
    sys.exit(1)

alert_path = sys.argv[1]
hook_url = sys.argv[3]

with open(alert_path, 'r') as f:
    alert_json = json.load(f)

# ======= Extract Fields =======
alert_level = alert_json.get('rule', {}).get('level', "N/A")
description = alert_json.get('rule', {}).get('description', "N/A")
agent = alert_json.get('agent', {}).get('name', "N/A")
target_user = alert_json.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName", "N/A")
ip_addr = alert_json.get("data", {}).get("win", {}).get("eventdata", {}).get("ipAddress", "N/A")
target_domain = alert_json.get("data", {}).get("win", {}).get("eventdata", {}).get("targetDomainName", "N/A")
src_ip = alert_json.get("data", {}).get("srcip", "N/A")
url_post = alert_json.get("data", {}).get("url", "N/A")
protocol = alert_json.get("data", {}).get("protocol", "N/A")
time_send = alert_json.get("timestamp", "N/A")

dt_utc = parser.isoparse(time_send)
dt_vn = dt_utc + timedelta(hours=7)
time_format = dt_vn.strftime("%Y-%m-%d %H:%M:%S")

device = resolve_device(target_user, target_domain, alert_json.get("data", {}).get("win", {}).get("eventdata", {}).get("workstationName", "N/A"))

# ======= Skip unwanted alerts =======
if description.strip().lower() == "multiple web server 400 error codes from same source ip.":
    sys.exit(0)

# ======= Alert Handlers =======
def handle_audit_failure():
    msg = f"""
❌ **CẢNH BÁO ĐĂNG NHẬP THẤT BẠI** ❌
📝 Mô tả: {description}
🖥  Agent: {agent}
⚡ Cấp độ: {alert_level}
👤 **Người dùng:** {target_user}
🌍 **IP:** {ip_addr}
💻 **Thiết bị:** {device}
"""
    send_telegram(msg, hook_url)
    sys.exit(0)

def handle_system_alert():
    msg = f"""
🚨 **CẢNH BÁO HỆ THỐNG** 🚨
📝 Mô tả: {description}
🖥  Agent: {agent}
⚡ Cấp độ: {alert_level}
👤 **Người dùng:** {target_user}
🌍 **IP:** {ip_addr}
💻 **Thiết bị:** {device}
"""
    send_telegram(msg, hook_url)
    sys.exit(0)

def handle_post_request():
   msg = f"""
⚠️**CẢNH BÁO POST REQUEST** ⚠️
📝 Mô tả: {description}
🖥  Agent: {agent}
⚡️ Cấp độ: {alert_level}
👤 **Người dùng:** {target_user}
🌍 **IP:** {src_ip}
💻 **Thiết bị:** {device}
🕒 **Thời gian:** {time_format}
📌 **URL**:
{url_post}
"""
   send_telegram(msg, hook_url)
   sys.exit(0)

# ======= MAIN ROUTING =======
desc_lower = description.lower()
if protocol.upper() == "POST":
    handle_post_request()
elif "multiple login errors" in description.lower():
    handle_system_alert()
else:
    handle_audit_failure()


    
# test