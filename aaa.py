from osint_routes import (
    get_ip_geolocation, get_domain_info, check_ip_reputation,
    extract_ip_from_headers, extract_device_from_headers, calculate_risk_score
)

from flask import Flask, render_template, request, jsonify, redirect, session, make_response
import auth  # Импортируем модуль аутентификации
from functools import wraps


app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  # ВАЖНО: замените на случайную строку

# Инициализация аутентификации
auth.init_auth()

# Декоратор для защиты маршрутов
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session_token')
        if not session_token:
            return redirect('/login')
        
        email = auth.verify_session(session_token)
        if not email:
            return redirect('/login')
        
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session_token')
        if not session_token:
            return jsonify({'success': False, 'error': 'Требуется авторизация'}), 401
        email = auth.verify_session(session_token)
        if not email or not auth.is_admin(email):
            return jsonify({'success': False, 'error': 'Доступ запрещён'}), 403
        return f(*args, **kwargs)
    return decorated_function

from flask import Flask, render_template, request, jsonify
import smtplib
import imaplib
import email
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import policy
from email.parser import BytesParser
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import os
import re
import json
import time
import threading
from datetime import datetime
from werkzeug.utils import secure_filename
import osint_routes
import pickle
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64
import sys


# === КЛАСС ДЕТЕКТОРА ===
class PhishingDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1500, ngram_range=(1, 2))
        self.model = None
        self.feature_names = ['Срочность', 'Деньги/Призы', 'Пароль/Аккаунт', 'Ссылки', 'КАПС']

    def extract_features(self, text):
        f = []
        if not text: text = ""
        f.append(sum(1 for w in ['срочно', 'сейчас', 'внимание', 'быстро', 'urgent', 'now'] if w in text.lower()))
        f.append(sum(1 for w in ['деньги', 'выиграл', 'приз', 'карта', 'счет', 'money', 'prize', 'win'] if w in text.lower()))
        f.append(sum(1 for w in ['пароль', 'логин', 'аккаунт', 'взломан', 'войти', 'password', 'login', 'account'] if w in text.lower()))
        f.append(len(re.findall(r'http', text.lower())))
        f.append(sum(1 for c in text if c.isupper()) / len(text) if len(text) > 0 else 0)
        return np.array(f)

    def predict(self, text):
        X_t = self.vectorizer.transform([text])
        X_e = self.extract_features(text)
        X_final = np.hstack([X_t.toarray(), [X_e]])
        prediction = self.model.predict(X_final)[0]
        probability = self.model.predict_proba(X_final)[0]
        return {
            'is_phishing': bool(prediction),
            'phishing_probability': float(probability[1]),
            'safe_probability': float(probability[0]),
            'features': X_e
        }

def generate_visual_report(prob, features):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
    risk_color = 'red' if prob > 0.5 else 'green'
    ax1.barh(['УРОВЕНЬ УГРОЗЫ'], [prob * 100], color=risk_color, edgecolor='black')
    ax1.set_xlim(0, 100)
    ax1.set_title(f"АНАЛИЗ РИСКОВ: {prob:.1%}")
    feature_names = ['Срочность', 'Деньги', 'Аккаунт', 'Ссылки', 'КАПС']
    ax2.bar(feature_names, features, color='teal', alpha=0.7)
    ax2.set_title("ВЫЯВЛЕННЫЕ АНОМАЛИИ")
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    img_base64 = base64.b64encode(buf.read()).decode('utf-8')
    plt.close(fig)
    return img_base64

app = Flask(__name__)

# Настройки SMTP
SMTP_HOST = os.getenv('SMTP_HOST', 'mailhog')
SMTP_PORT = int(os.getenv('SMTP_PORT', '1025'))

# Gmail настройки
GMAIL_SMTP = "smtp.gmail.com"
GMAIL_IMAP = "imap.gmail.com"
GMAIL_PORT = 587
GMAIL_USER = "rymtaianel05@gmail.com"
GMAIL_PASS = "tixz mvnk bxxs igak"

# Папки
if getattr(sys, 'frozen', False):
    PROJECT_ROOT = os.path.dirname(sys.executable)
else:
    PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

os.chdir(PROJECT_ROOT)

WATCH_FOLDER = os.path.join(PROJECT_ROOT, 'incoming_eml')
ANALYZED_FOLDER = os.path.join(PROJECT_ROOT, 'analyzed')
UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, 'uploads')
MODEL_FOLDER = os.path.join(PROJECT_ROOT, 'model')
ALLOWED_EXTENSIONS = {'eml'}

for folder in [UPLOAD_FOLDER, WATCH_FOLDER, ANALYZED_FOLDER, MODEL_FOLDER]:
    os.makedirs(folder, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Хранилище писем
analyzed_emails = []
received_emails = []  # НОВОЕ: письма из Gmail
monitoring_active = False
gmail_monitoring_active = False  # НОВОЕ

print("="*50)
print(f"КОРЕНЬ ПРОЕКТА: {PROJECT_ROOT}")
print(f" МОНИТОРИНГ: {WATCH_FOLDER}")
print(f" РЕЗУЛЬТАТЫ: {ANALYZED_FOLDER}")
print("="*50)

# Загрузка ML модели
DETECTOR_PATH = os.path.join(MODEL_FOLDER, 'phishing_detector.pkl')
ml_detector = None

try:
    with open(DETECTOR_PATH, 'rb') as f:
        ml_detector = pickle.load(f)
    print("ML детектор загружен успешно")
except Exception as e:
    print(f" ML детектор не найден: {e}")

# ========== НОВАЯ ФУНКЦИЯ: ПОЛУЧЕНИЕ ПИСЕМ ИЗ GMAIL ==========
def fetch_emails_from_gmail(max_emails=10):
    """Получение писем из Gmail через IMAP"""
    try:
        mail = imaplib.IMAP4_SSL(GMAIL_IMAP)
        mail.login(GMAIL_USER, GMAIL_PASS)
        mail.select('inbox')
        
        # Получаем последние письма
        status, messages = mail.search(None, 'ALL')
        email_ids = messages[0].split()
        email_ids = email_ids[-max_emails:]
        
        emails_fetched = []
        
        for email_id in email_ids:
            status, msg_data = mail.fetch(email_id, '(RFC822)')
            
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    # Декодируем тему
                    subject = ""
                    if msg["Subject"]:
                        subject_decoded = decode_header(msg["Subject"])[0]
                        if isinstance(subject_decoded[0], bytes):
                            subject = subject_decoded[0].decode(subject_decoded[1] or 'utf-8')
                        else:
                            subject = subject_decoded[0]
                    
                    from_email = msg.get("From", "Unknown")
                    date = msg.get("Date", "")
                    
                    # Получаем тело письма
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                try:
                                    body = part.get_payload(decode=True).decode()
                                except:
                                    body = str(part.get_payload())
                    else:
                        try:
                            body = msg.get_payload(decode=True).decode()
                        except:
                            body = str(msg.get_payload())
                    
                    # Анализируем на фишинг
                    score, reasons, links, verdict, risk_level = detect_phishing(subject, body, from_email)
                    
                    # Генерируем график
                    prob = score / 100.0
                    features_for_chart = [0, 0, 0, 0, 0]
                    if ml_detector:
                        try:
                            features_for_chart = ml_detector.extract_features(subject + " " + body)
                        except:
                            pass
                    visual_chart_data = generate_visual_report(prob, features_for_chart)
                    
                    email_data = {
                        "id": email_id.decode(),
                        "source": "gmail",  # НОВОЕ: помечаем источник
                        "from": from_email,
                        "subject": subject,
                        "date": date,
                        "body_preview": body[:300] if body else "",
                        "body_full": body,
                        "score": score,
                        "verdict": verdict,
                        "risk_level": risk_level,
                        "reasons": reasons,
                        "links": links,
                        "visual_chart": visual_chart_data,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    emails_fetched.append(email_data)
                    print(f" Gmail: {subject[:50]}... - {verdict}")
        
        mail.close()
        mail.logout()
        return emails_fetched
    
    except Exception as e:
        print(f"Ошибка получения Gmail: {e}")
        return []

# ========== НОВАЯ ФУНКЦИЯ: МОНИТОРИНГ GMAIL ==========
def monitor_gmail_inbox():
    """Фоновый мониторинг Gmail"""
    global gmail_monitoring_active, received_emails
    
    print(f" Мониторинг Gmail: {GMAIL_USER}")
    
    while gmail_monitoring_active:
        try:
            new_emails = fetch_emails_from_gmail(max_emails=5)
            
            for email_data in new_emails:
                if not any(e.get('id') == email_data['id'] for e in received_emails):
                    received_emails.insert(0, email_data)
                    print(f" Новое письмо: {email_data['subject'][:50]}...")
            
            if len(received_emails) > 100:
                received_emails = received_emails[:100]
            
            time.sleep(30)  # Проверяем каждые 30 секунд
            
        except Exception as e:
            print(f"Ошибка мониторинга Gmail: {e}")
            time.sleep(60)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def detect_phishing(subject, body, from_email=''):
    score = 0
    reasons = []
    text = (subject or "") + "\n" + (body or "")
    text_l = text.lower()
    
    ml_result = None
    if ml_detector is not None:
        try:
            ml_result = ml_detector.predict(text)
            score = int(ml_result['phishing_probability'] * 100)
            reasons.insert(0, f'ML модель: вероятность фишинга {ml_result["phishing_probability"]:.1%}')
            
            features = ml_result['features']
            feature_names = ['срочные слова', 'деньги/призы', 'пароли/аккаунты', 'ссылки', 'КАПС']
            for i, (name, value) in enumerate(zip(feature_names, features)):
                if value > 0:
                    reasons.append(f'   {name}: {int(value) if i < 4 else f"{value:.1%}"}')
        except Exception as e:
            print(f"Ошибка ML: {e}")
            reasons.append(f'Ошибка ML: {str(e)}')
    else:
        reasons.append('ML модель не загружена')
    
    keyword_score = 0
    link_score = 0
    
    keywords = {
        'срочно': 10, 'пароль': 15, 'подтвердите': 15, 'verify': 15,
        'login': 10, 'bank': 20, 'pay': 15, 'action required': 15,
        'аккаунт': 10, 'заблокирован': 20, 'безопасность': 10,
        'prize': 15, 'winner': 15, 'congratulations': 10,
        'urgent': 15, 'suspended': 20, 'unusual activity': 20
    }
    
    for keyword, points in keywords.items():
        if keyword in text_l:
            keyword_score += points
            reasons.append(f'Подозрительное слово: "{keyword}"')
    
    links = re.findall(r'https?://[^\s\'"<>]+', body or "")
    suspicious_domains = ['bit.ly', 'tinyurl', 'goo.gl', 'shortened', 'click']
    
    for link in links:
        link_score += 5
        reasons.append(f'Ссылка: {link[:50]}...')
        for domain in suspicious_domains:
            if domain in link.lower():
                link_score += 15
                reasons.append(f'Короткий URL: {domain}')
    
    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', body or ''):
        link_score += 20
        reasons.append('Ссылка на IP-адрес')
    
    if from_email and links:
        from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
        for link in links:
            link_domain = re.search(r'://([^/]+)', link)
            if link_domain and from_domain and from_domain not in link_domain.group(1).lower():
                link_score += 10
                reasons.append(f'Домен не совпадает')
                break
    
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if caps_ratio > 0.3:
        keyword_score += 10
        reasons.append('Много заглавных букв')
    
    if ml_result is not None:
        rule_score = min(keyword_score + link_score, 100)
        score = int(score * 0.8 + rule_score * 0.2)
    else:
        score = min(keyword_score + link_score, 100)
    
    score = min(score, 100)
    
    if score >= 70:
        verdict = "ВЫСОКИЙ РИСК"
        risk_level = "high"
    elif score >= 40:
        verdict = "СРЕДНИЙ РИСК"
        risk_level = "medium"
    elif score >= 20:
        verdict = "НИЗКИЙ РИСК"
        risk_level = "low"
    else:
        verdict = "БЕЗОПАСНО"
        risk_level = "safe"
    
    return score, reasons, links, verdict, risk_level

def check_spf_dkim_dmarc(domain):
    try:
        import dns.resolver
        results = {'spf': False, 'dkim': False, 'dmarc': False, 'spf_record': None, 'dmarc_policy': None}
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                if 'v=spf1' in str(rdata):
                    results['spf'] = True
                    results['spf_record'] = str(rdata)
                    break
        except:
            pass
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                if 'v=DMARC1' in str(rdata):
                    results['dmarc'] = True
                    if 'p=reject' in str(rdata):
                        results['dmarc_policy'] = 'reject'
                    elif 'p=quarantine' in str(rdata):
                        results['dmarc_policy'] = 'quarantine'
                    else:
                        results['dmarc_policy'] = 'none'
                    break
        except:
            pass
        selectors = ['default', 'google', 'mail', 'k1', 'selector1']
        for selector in selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    if 'v=DKIM1' in str(rdata) or 'k=' in str(rdata):
                        results['dkim'] = True
                        break
                if results['dkim']:
                    break
            except:
                continue
        return results
    except:
        return {'spf': False, 'dkim': False, 'dmarc': False}

def analyze_eml_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        subject = str(msg['subject']) if msg['subject'] else 'Без темы'
        frm = str(msg['from']) if msg['from'] else 'Неизвестно'
        to = str(msg['to']) if msg['to'] else 'Неизвестно'
        date = str(msg['date']) if msg['date'] else datetime.now().isoformat()
        
        body_part = msg.get_body(preferencelist=('plain', 'html'))
        body = body_part.get_content() if body_part else ''
        
        score, reasons, links, verdict, risk_level = detect_phishing(subject, body, frm)
        
        prob = score / 100.0
        features_for_chart = [0, 0, 0, 0, 0]
        if ml_detector:
            try:
                features_for_chart = ml_detector.extract_features(subject + " " + body)
            except:
                pass
        visual_chart_data = generate_visual_report(prob, features_for_chart)
        
        domain = frm.split('@')[-1] if '@' in frm else ''
        domain = domain.strip('<> ')
        dns_check = check_spf_dkim_dmarc(domain) if domain else {}
        
        result = {
            "success": True,
            "source": "eml_file",  # НОВОЕ: помечаем источник
            "filename": os.path.basename(filepath),
            "from": frm,
            "to": to,
            "subject": subject,
            "date": date,
            "body_preview": body[:300] if body else "",
            "score": score,
            "verdict": verdict,
            "risk_level": risk_level,
            "reasons": reasons,
            "links": links,
            "dns_check": dns_check,
            "visual_chart": visual_chart_data,
            "timestamp": datetime.now().isoformat()
        }
        
        analyzed_emails.insert(0, result)
        
        json_path = os.path.join(ANALYZED_FOLDER, os.path.basename(filepath) + '.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"success": False, "error": str(e)}

def monitor_eml_folder():
    global monitoring_active
    processed = set()
    print(f"Мониторинг папки: {os.path.abspath(WATCH_FOLDER)}")
    
    while monitoring_active:
        try:
            files = [f for f in os.listdir(WATCH_FOLDER) if f.lower().endswith('.eml')]
            for fn in files:
                if fn in processed:
                    continue
                full_path = os.path.join(WATCH_FOLDER, fn)
                print(f"📧 Обнаружен файл: {fn}")
                result = analyze_eml_file(full_path)
                if result['success']:
                    print(f"Проанализирован: {fn} - {result['verdict']}")
                processed.add(fn)
            time.sleep(3)
        except Exception as e:
            print(f"Ошибка мониторинга: {e}")
            time.sleep(3)

# ========== API МАРШРУТЫ ==========

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/emails')
@login_required
def get_emails():
    current_email = request.cookies.get('session_token')
    current_email = auth.verify_session(current_email)
    if auth.is_admin(current_email):
        emails_to_show = analyzed_emails
    else:
        # Обычный пользователь видит только свои письма (загруженные через EML)
        emails_to_show = [e for e in analyzed_emails if e.get('user_email') == current_email]
    result = []
    for e in emails_to_show[:50]:
        result.append({
            'from': e.get('from', ''),
            'subject': e.get('subject', ''),
            'date': e.get('date', ''),
            'score': e.get('score', 0),
            'verdict': e.get('verdict', ''),
            'risk_level': e.get('risk_level', 'safe'),
            'reasons': e.get('reasons', []),
            'dns_check': e.get('dns_check', {}),
            'chart_base64': e.get('visual_chart', ''),
            'user_email': e.get('user_email', '') if auth.is_admin(current_email) else ''
        })
    return jsonify({'success': True, 'emails': result})
# ========== НОВЫЕ API ДЛЯ GMAIL ==========

@app.route('/api/received-emails')
@login_required
def get_received_emails():
    """Письма из Gmail"""
    return jsonify({'success': True, 'emails': received_emails, 'total': len(received_emails)})

@app.route('/api/all-emails')
@login_required
def get_all_emails():
    """Все письма (EML + Gmail)"""
    all_emails = analyzed_emails + received_emails
    all_emails.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return jsonify({'success': True, 'emails': all_emails, 'total': len(all_emails)})

@app.route('/api/fetch-gmail', methods=['POST'])
@login_required
def fetch_gmail_now():
    """Принудительно получить новые письма"""
    try:
        new_emails = fetch_emails_from_gmail(max_emails=10)
        for email_data in new_emails:
            if not any(e.get('id') == email_data['id'] for e in received_emails):
                received_emails.insert(0, email_data)
        return jsonify({'success': True, 'message': f'Получено {len(new_emails)} писем', 'new_count': len(new_emails)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/gmail-monitoring/start', methods=['POST'])
@login_required
def start_gmail_monitoring():
    global gmail_monitoring_active
    if not gmail_monitoring_active:
        gmail_monitoring_active = True
        thread = threading.Thread(target=monitor_gmail_inbox, daemon=True)
        thread.start()
        return jsonify({'success': True, 'message': 'Gmail мониторинг запущен'})
    return jsonify({'success': False, 'message': 'Мониторинг уже активен'})

@app.route('/api/gmail-monitoring/stop', methods=['POST'])
@login_required
def stop_gmail_monitoring():
    global gmail_monitoring_active
    gmail_monitoring_active = False
    return jsonify({'success': True, 'message': 'Gmail мониторинг остановлен'})

@app.route('/api/gmail-monitoring/status')
@login_required
def gmail_monitoring_status():
    return jsonify({
        'active': gmail_monitoring_active,
        'email': GMAIL_USER,
        'received_count': len(received_emails)
    })

# ========== ОСТАЛЬНЫЕ API (БЕЗ ИЗМЕНЕНИЙ) ==========

@app.route('/api/ml-info')
@login_required
def ml_info():
    if ml_detector is None:
        return jsonify({'success': False, 'loaded': False, 'message': 'ML модель не загружена'})
    return jsonify({
        'success': True,
        'loaded': True,
        'model_type': type(ml_detector.model).__name__,
        'vectorizer_type': type(ml_detector.vectorizer).__name__,
        'feature_names': ml_detector.feature_names
    })

@app.route('/api/analyze-text', methods=['POST'])
@login_required
def analyze_text():
    try:
        data = request.json
        subject = data.get('subject', '')
        body = data.get('body', '')
        text = subject + " " + body
        if ml_detector:
            res = ml_detector.predict(text)
            prob = res['phishing_probability']
            features = res['features']
            visual_data = generate_visual_report(prob, features)
            return jsonify({
                'success': True,
                'score': int(prob * 100),
                'verdict': "ФИШИНГ" if prob > 0.5 else "БЕЗОПАСНО",
                'risk_level': "high" if prob > 0.5 else "safe",
                'reasons': [f"Вероятность фишинга: {prob:.1%}"],
                'visual_chart': visual_data
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/monitoring/start', methods=['POST'])
@login_required
def start_monitoring():
    global monitoring_active
    if not monitoring_active:
        monitoring_active = True
        thread = threading.Thread(target=monitor_eml_folder, daemon=True)
        thread.start()
        return jsonify({'success': True, 'message': 'Мониторинг запущен'})
    return jsonify({'success': False, 'message': 'Мониторинг уже активен'})

@app.route('/api/monitoring/stop', methods=['POST'])
@login_required
def stop_monitoring():
    global monitoring_active
    monitoring_active = False
    return jsonify({'success': True, 'message': 'Мониторинг остановлен'})

@app.route('/api/monitoring/status')
@login_required
def monitoring_status():
    return jsonify({
        'active': monitoring_active,
        'watch_folder': os.path.abspath(WATCH_FOLDER),
        'ml_loaded': ml_detector is not None
    })

@app.route('/upload-eml', methods=['POST'])
@login_required
def upload_eml():
    try:
        session_token = request.cookies.get('session_token')
        current_user_email = auth.verify_session(session_token)

        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'Файл не найден'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Файл не выбран'}), 400
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'Разрешены только .eml файлы'}), 400
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        result = analyze_eml_file(filepath)
        # Привязываем письмо к пользователю
        if result.get('success') and current_user_email:
            result['user_email'] = current_user_email
            # Обновляем запись в analyzed_emails
            for e in analyzed_emails:
                if e.get('filename') == result.get('filename') and not e.get('user_email'):
                    e['user_email'] = current_user_email
                    break
        os.remove(filepath)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/send-email', methods=['POST'])
@login_required
def send_email():
    try:
        data = request.json
        msg = MIMEMultipart()
        msg['From'] = data.get('from_email', 'sender@example.local')
        msg['To'] = data.get('to_email', 'recipient@example.local')
        msg['Subject'] = data.get('subject', 'Тест')
        msg.attach(MIMEText(data.get('body', ''), 'plain', 'utf-8'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.send_message(msg)
        return jsonify({'success': True, 'message': 'Письмо отправлено!', 'mailhog_url': 'http://localhost:8025'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/send-gmail', methods=['POST'])
@login_required
def send_gmail():
    try:
        data = request.json
        msg = MIMEText(data.get('body', ''), "plain", "utf-8")
        msg['Subject'] = data.get('subject', 'Тест')
        msg['From'] = GMAIL_USER
        msg['To'] = data.get('to_email')
        with smtplib.SMTP(GMAIL_SMTP, GMAIL_PORT) as server:
            server.starttls()
            server.login(GMAIL_USER, GMAIL_PASS)
            server.send_message(msg)
        return jsonify({'success': True, 'message': 'Письмо отправлено через Gmail!'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/send-phishing', methods=['POST'])
@login_required
def send_phishing():
    try:
        data = request.json
        msg = MIMEMultipart()
        msg['From'] = 'security@bank.com'
        msg['To'] = data.get('to_email', 'victim@example.local')
        msg['Subject'] = 'СРОЧНО: Подтвердите вашу учетную запись'
        body = """
Уважаемый клиент,
Мы обнаружили подозрительную активность в вашем аккаунте.
Пожалуйста, СРОЧНО подтвердите свои данные по ссылке:
http://fake-bank-login.com/verify
Если вы не подтвердите данные в течение 24 часов, ваш аккаунт будет ЗАБЛОКИРОВАН.
С уважением, Служба безопасности банка
        """
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.send_message(msg)
        return jsonify({'success': True, 'message': 'Фишинговое письмо отправлено', 'mailhog_url': 'http://localhost:8025'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/check-spf', methods=['POST'])
@login_required
def check_spf():
    try:
        import dns.resolver
        domain = request.json.get('domain')
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            spf_records = [str(r) for r in answers if 'v=spf1' in str(r)]
            if spf_records:
                return jsonify({'success': True, 'has_spf': True, 'records': spf_records})
            else:
                return jsonify({'success': True, 'has_spf': False, 'message': 'SPF не найден'})
        except dns.resolver.NXDOMAIN:
            return jsonify({'success': False, 'error': 'Домен не найден'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/check-dkim', methods=['POST'])
@login_required
def check_dkim():
    try:
        import dns.resolver
        domain = request.json.get('domain')
        selector = request.json.get('selector', 'default')
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            dkim_records = [str(r) for r in answers if 'v=DKIM1' in str(r) or 'k=' in str(r)]
            if dkim_records:
                return jsonify({'success': True, 'has_dkim': True, 'records': dkim_records, 'selector': selector})
            else:
                return jsonify({'success': True, 'has_dkim': False, 'message': f'DKIM не найден'})
        except:
            return jsonify({'success': True, 'has_dkim': False, 'message': 'DKIM не найден'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/check-dmarc', methods=['POST'])
@login_required
def check_dmarc():
    try:
        import dns.resolver
        domain = request.json.get('domain')
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_records = [str(r) for r in answers if 'v=DMARC1' in str(r)]
            if dmarc_records:
                policy = 'unknown'
                if 'p=reject' in dmarc_records[0]:
                    policy = 'reject'
                elif 'p=quarantine' in dmarc_records[0]:
                    policy = 'quarantine'
                else:
                    policy = 'none'
                return jsonify({'success': True, 'has_dmarc': True, 'records': dmarc_records, 'policy': policy})
            else:
                return jsonify({'success': True, 'has_dmarc': False, 'message': 'DMARC не найден'})
        except:
            return jsonify({'success': True, 'has_dmarc': False, 'message': 'DMARC не найден'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# OSINT API (без изменений)
@app.route('/api/osint/employees')
@login_required
def get_employees():
    employees = osint_routes.get_all_employees()
    return jsonify({'success': True, 'employees': employees, 'total': len(employees)})

@app.route('/api/osint/employee/<int:emp_id>')
@login_required
def get_employee(emp_id):
    employee = osint_routes.get_employee_by_id(emp_id)
    if employee:
        return jsonify({'success': True, 'employee': employee})
    return jsonify({'success': False, 'error': 'Сотрудник не найден'}), 404

@app.route('/api/osint/report/<int:emp_id>')
@login_required
def get_osint_report(emp_id):
    employee = osint_routes.get_employee_by_id(emp_id)
    if not employee:
        return jsonify({'success': False, 'error': 'Сотрудник не найден'}), 404
    report = osint_routes.generate_osint_report(employee)
    return jsonify({'success': True, 'report': report})

@app.route('/api/osint/company-risk')
@login_required
def get_company_risk():
    risk_data = osint_routes.calculate_company_risk_score()
    return jsonify({'success': True, 'risk_data': risk_data})

@app.route('/api/osint/generate-phishing/<int:emp_id>', methods=['POST'])
@login_required
def generate_phishing_for_employee(emp_id):
    employee = osint_routes.get_employee_by_id(emp_id)
    if not employee:
        return jsonify({'success': False, 'error': 'Сотрудник не найден'}), 404
    data = request.json or {}
    attack_type = data.get('attack_type', 'BEC')
    phishing_email = osint_routes.generate_targeted_phishing_email(employee, attack_type)
    return jsonify({'success': True, 'email': phishing_email})

@app.route('/api/osint/send-targeted-phishing/<int:emp_id>', methods=['POST'])
@login_required
def send_targeted_phishing(emp_id):
    employee = osint_routes.get_employee_by_id(emp_id)
    if not employee:
        return jsonify({'success': False, 'error': 'Сотрудник не найден'}), 404
    try:
        data = request.json or {}
        attack_type = data.get('attack_type', 'BEC')
        phishing_email = osint_routes.generate_targeted_phishing_email(employee, attack_type)
        msg = MIMEMultipart()
        msg['From'] = phishing_email['from']
        msg['To'] = phishing_email['to']
        msg['Subject'] = phishing_email['subject']
        msg.attach(MIMEText(phishing_email['body'], 'plain', 'utf-8'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.send_message(msg)
        return jsonify({
            'success': True,
            'message': f'Таргетированное письмо отправлено на {employee["email"]}',
            'email': phishing_email,
            'mailhog_url': 'http://localhost:8025'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/check-url', methods=['POST'])
@login_required
def check_url():
    """Проверка URL на фишинг"""
    try:
        data = request.json
        url = data.get('url', '')
        
        if not url:
            return jsonify({'success': False, 'error': 'URL не указан'}), 400
        
        # Анализируем URL
        score = 0
        reasons = []
        risk_level = 'safe'
        
        url_lower = url.lower()
        
        # 1. Проверка на IP адрес
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            score += 40
            reasons.append('URL содержит IP-адрес вместо доменного имени')
        
        # 2. Короткие URL
        short_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'cli.gs', 'pic.gd', 'DwarfURL.com', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'bitly.com', 'cur.lv', 'tinyurl.com', 'ow.ly', 'bit.ly', 'ity.im', 'q.gs', 'is.gd', 'po.st', 'bc.vc', 'twitthis.com', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org', 'x.co', 'prettylinkpro.com', 'scrnch.me', 'filoops.info', 'vzturl.com', 'qr.net', '1url.com', 'tweez.me', 'v.gd', 'tr.im', 'link.zip.net']
        for domain in short_domains:
            if domain in url_lower:
                score += 35
                reasons.append(f'Используется сервис сокращения ссылок: {domain}')
                break
        
        # 3. Подозрительные слова в URL
        suspicious_words = ['login', 'verify', 'account', 'update', 'secure', 'banking', 'confirm', 'suspended', 'locked', 'urgent', 'signin', 'password', 'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook']
        found_suspicious = []
        for word in suspicious_words:
            if word in url_lower:
                found_suspicious.append(word)
        
        if found_suspicious:
            score += len(found_suspicious) * 10
            reasons.append(f'Подозрительные слова в URL: {", ".join(found_suspicious)}')
        
        # 4. Проверка на наличие @ (попытка скрыть реальный домен)
        if '@' in url:
            score += 50
            reasons.append('URL содержит символ @ (возможная подмена домена)')
        
        # 5. Много дефисов или точек
        domain_part = url.split('/')[2] if len(url.split('/')) > 2 else url
        if domain_part.count('-') > 3:
            score += 20
            reasons.append('Слишком много дефисов в доменном имени')
        
        if domain_part.count('.') > 4:
            score += 20
            reasons.append('Слишком много точек в доменном имени')
        
        # 6. Проверка на подозрительные ТЛД
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link', '.download', '.stream', '.review', '.country', '.kim', '.cricket', '.science', '.party']
        for tld in suspicious_tlds:
            if url_lower.endswith(tld) or tld + '/' in url_lower:
                score += 25
                reasons.append(f'Подозрительное доменное расширение: {tld}')
                break
        
        # 7. Очень длинный URL
        if len(url) > 100:
            score += 15
            reasons.append('Очень длинный URL (возможна попытка скрыть реальный адрес)')
        
        # 8. Проверка на наличие HTTPS
        if not url.startswith('https://'):
            score += 20
            reasons.append('Отсутствует HTTPS (незащищенное соединение)')
        
        # Ограничиваем score
        score = min(score, 100)
        
        # Определяем уровень риска
        if score >= 70:
            verdict = "ВЫСОКИЙ РИСК"
            risk_level = "high"
        elif score >= 40:
            verdict = "СРЕДНИЙ РИСК"
            risk_level = "medium"
        elif score >= 20:
            verdict = "НИЗКИЙ РИСК"
            risk_level = "low"
        else:
            verdict = "БЕЗОПАСНО"
            risk_level = "safe"
        
        return jsonify({
            'success': True,
            'url': url,
            'score': score,
            'verdict': verdict,
            'risk_level': risk_level,
            'reasons': reasons
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== АУТЕНТИФИКАЦИЯ ==========

@app.route('/login')
def login_page():
    """Страница входа"""
    return render_template('login.html')

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Регистрация нового пользователя"""
    data = request.json
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    
    if not email or not password or not name:
        return jsonify({'success': False, 'error': 'Заполните все поля'}), 400
    
    result = auth.create_user(email, password, name)
    return jsonify(result)

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Вход пользователя"""
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'success': False, 'error': 'Заполните все поля'}), 400
    
    result = auth.verify_user(email, password)
    
    if result['success']:
        # Создаём сессию
        session_token = auth.create_session(email)
        
        response = make_response(jsonify({
            'success': True,
            'message': 'Успешный вход',
            'user': result['user']
        }))
        
        # Устанавливаем cookie на 7 дней
        response.set_cookie('session_token', session_token, max_age=7*24*60*60, httponly=True)
        return response
    
    return jsonify(result), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Выход пользователя"""
    session_token = request.cookies.get('session_token')
    if session_token:
        auth.delete_session(session_token)
    
    response = make_response(jsonify({'success': True, 'message': 'Вы вышли'}))
    response.set_cookie('session_token', '', expires=0)
    return response

@app.route('/api/auth/me')
@login_required
def get_current_user():
    session_token = request.cookies.get('session_token')
    email = auth.verify_session(session_token)
    user = auth.get_user(email)
    return jsonify({
        'success': True,
        'user': {
            'email': email,
            'name': user.get('name', 'Пользователь'),
            'role': user.get('role', 'user')
        }
    })
@app.route('/api/emails/my')
@login_required
def get_my_emails():
    current_email = auth.verify_session(request.cookies.get('session_token'))
    emails_to_show = [e for e in analyzed_emails if e.get('user_email') == current_email]
    result = [{'from': e.get('from',''), 'subject': e.get('subject',''), 'score': e.get('score',0),
               'verdict': e.get('verdict',''), 'risk_level': e.get('risk_level','safe'),
               'reasons': e.get('reasons',[]), 'dns_check': e.get('dns_check',{}),
               'chart_base64': e.get('visual_chart','')} for e in emails_to_show[:50]]
    return jsonify({'success': True, 'emails': result})

@app.route('/api/admin/users')
@admin_required
def get_users():
    return jsonify({'success': True, 'users': auth.get_all_users()})

@app.route('/api/admin/users/create', methods=['POST'])
@admin_required
def admin_create_user():
    data = request.json
    result = auth.create_user(data.get('email'), data.get('password'), data.get('name'), data.get('role', 'user'))
    return jsonify(result)

@app.route('/api/admin/users/delete', methods=['POST'])
@admin_required
def admin_delete_user():
    data = request.json
    email_to_delete = data.get('email')
    current_email = auth.verify_session(request.cookies.get('session_token'))
    if email_to_delete == current_email:
        return jsonify({'success': False, 'error': 'Нельзя удалить себя'}), 400
    try:
        with open(auth.USERS_FILE, 'r', encoding='utf-8') as f:
            users = json.load(f)
        if email_to_delete not in users:
            return jsonify({'success': False, 'error': 'Пользователь не найден'}), 404
        del users[email_to_delete]
        with open(auth.USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
        return jsonify({'success': True, 'message': 'Пользователь удалён'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/gmail/start', methods=['POST'])
@admin_required
def start_gmail():
    global gmail_monitoring_active
    if not gmail_monitoring_active:
        gmail_monitoring_active = True
        import threading
        threading.Thread(target=monitor_gmail_inbox, daemon=True).start()
    return jsonify({'success': True, 'message': 'Gmail мониторинг запущен'})

@app.route('/api/gmail/stop', methods=['POST'])
@admin_required
def stop_gmail():
    global gmail_monitoring_active
    gmail_monitoring_active = False
    return jsonify({'success': True, 'message': 'Gmail мониторинг остановлен'})

@app.route('/api/osint/domain', methods=['POST'])
@login_required
def osint_domain():
    """OSINT анализ домена"""
    try:
        data = request.json
        domain = data.get('domain', '')
        
        if not domain:
            return jsonify({'success': False, 'error': 'Домен не указан'}), 400
        
        # Получаем информацию о домене
        domain_info = get_domain_info(domain)
        
        # Проверяем DNS
        dns_check = check_spf_dkim_dmarc(domain)
        
        # Рассчитываем риск
        risk_score = calculate_risk_score({
            'domain': domain,
            'domain_info': domain_info,
            'dns': dns_check
        })
        
        result = {
            'success': True,
            'domain': domain,
            'domain_info': domain_info,
            'dns_check': dns_check,
            'risk_score': risk_score,
            'risk_level': 'high' if risk_score >= 70 else 'medium' if risk_score >= 40 else 'low'
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Маршрут для OSINT по Email

@app.route('/api/osint/email', methods=['POST'])
@login_required
def osint_email():
    """OSINT анализ по email адресу - РЕАЛЬНЫЕ ДАННЫЕ"""
    try:
        data = request.json
        email_address = data.get('email', '')
        
        if not email_address:
            return jsonify({'success': False, 'error': 'Email не указан'}), 400
        
        # Извлекаем домен из email
        domain = email_address.split('@')[-1] if '@' in email_address else ''
        
        if not domain:
            return jsonify({'success': False, 'error': 'Неверный формат email'}), 400
        
        print(f"\n OSINT анализ email: {email_address}")
        print(f"   Домен: {domain}")
        
        # Получаем РЕАЛЬНУЮ информацию о домене
        domain_info = get_domain_info(domain)
        print(f"   Информация о домене получена: {domain_info.get('resolved')}")
        
        # Проверяем DNS записи
        dns_check = check_spf_dkim_dmarc(domain)
        print(f"   DNS проверка: SPF={dns_check.get('spf')}, DKIM={dns_check.get('dkim')}, DMARC={dns_check.get('dmarc')}")
        
        # Если домен разрешен, получаем геолокацию IP
        geolocation = None
        if domain_info.get('ip_address') and domain_info['ip_address'] != 'Не разрешен':
            geolocation = get_ip_geolocation(domain_info['ip_address'])
            print(f"   Геолокация IP: {geolocation.get('country', 'Неизвестно')}")
        
        # Рассчитываем риск
        risk_data = {
            'domain': domain,
            'dns': dns_check,
            'domain_info': domain_info,
            'geolocation': geolocation
        }
        risk_score = calculate_risk_score(risk_data)
        
        result = {
            'success': True,
            'email': email_address,
            'domain': domain,
            'domain_info': domain_info,
            'dns_check': dns_check,
            'geolocation': geolocation,
            'risk_score': risk_score,
            'risk_level': 'high' if risk_score >= 70 else 'medium' if risk_score >= 40 else 'low'
        }
        
        print(f"   ✅ Анализ завершен: риск = {risk_score}%\n")
        return jsonify(result)
        
    except Exception as e:
        print(f"   ❌ Ошибка: {e}\n")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/osint/ip', methods=['POST'])
@login_required
def osint_ip():
   
    try:
        data = request.json
        ip_address = data.get('ip', '')
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP адрес не указан'}), 400
        
        print(f"\n OSINT анализ IP: {ip_address}")
        
        # Получаем РЕАЛЬНУЮ геолокацию IP
        geo_info = get_ip_geolocation(ip_address)
        print(f"   Геолокация: {geo_info.get('country', 'Неизвестно')}, {geo_info.get('city', 'Неизвестно')}")
        
        # Проверяем репутацию IP
        reputation = check_ip_reputation(ip_address)
        print(f"   Репутация: {reputation.get('risk', 'Неизвестно')}")
        
        # Рассчитываем риск
        risk_data = {
            'ip': ip_address,
            'geolocation': geo_info,
            'reputation': reputation
        }
        
        risk_score = calculate_risk_score(risk_data)
        
        result = {
            'success': True,
            'ip': ip_address,
            'geolocation': geo_info,
            'reputation': reputation,
            'risk_score': risk_score,
            'risk_level': 'high' if risk_score >= 70 else 'medium' if risk_score >= 40 else 'low'
        }
        
        print(f"   ✅ Анализ завершен: риск = {risk_score}%\n")
        return jsonify(result)
        
    except Exception as e:
        print(f"   ❌ Ошибка: {e}\n")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/monitoring/my-activity')
@login_required
def get_my_monitoring():
    token = request.cookies.get('session_token')
    user_email = auth.verify_session(token)
    
    # Загружаем все логи
    all_logs = load_all_logs() # Ваша функция чтения из файла/БД
    
    if auth.is_admin(user_email):
        return jsonify(all_logs) # Админ видит ВСЁ
    else:
        # Фильтруем: оставляем только то, что искал этот пользователь
        user_logs = [log for log in all_logs if log.get('user') == user_email]
        return jsonify(user_logs)


if __name__ == '__main__':
    # Запуск обоих мониторингов
    monitoring_active = True
    monitor_thread = threading.Thread(target=monitor_eml_folder, daemon=True)
    monitor_thread.start()
    
    gmail_monitoring_active = True
    gmail_thread = threading.Thread(target=monitor_gmail_inbox, daemon=True)
    gmail_thread.start()
    
    print("\n" + "="*60)
    print(" PHISHING DETECTION SYSTEM")
    print("="*60)
    if ml_detector:
        print("ML модель: ЗАГРУЖЕНА")
        print(f"   Тип: {type(ml_detector.model).__name__}")
    else:
        print("ML модель: НЕ ЗАГРУЖЕНА")
    print(f"Gmail мониторинг: {GMAIL_USER}")
    print(f"EML мониторинг: {WATCH_FOLDER}")
    print("="*60)
    print("Сервер: http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)