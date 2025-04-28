import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from datetime import datetime
import threading
import time
import requests
import re
import random
import string
from functools import wraps
import logging
import os
from PIL import Image, ImageDraw, ImageFont
import io

# Flask setup
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management

# Constants and global variables
traffic_log = []  # List to store traffic data
ddos_threshold = 50  # Example threshold requests per second per IP
blocked_ips_file = 'blocked_ips.txt'  # File to store blocked IPs
DJANGO_APP_URL = "http://127.0.0.1:8000"  # Replace with Django app's URL
admin_password = "admin123"  # Use plain credentials directly in the code
blocked_ips = set()  # Cached blocked IPs

# Email settings (directly in the code)
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USER = "nasirhussainclg@gmail.com"  # Your email address
EMAIL_PASSWORD = "xzem ufph ubdi fcui"  # Your Gmail app password (not the regular Gmail password)
EMAIL_RECIPIENT = "nasirmaggi65@gmail.com"  # Recipient email address

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Ensure blocked IPs file exists
if not os.path.exists(blocked_ips_file):
    open(blocked_ips_file, 'w').close()

def load_blocked_ips():
    """Load blocked IPs from the file."""
    try:
        with open(blocked_ips_file, 'r') as file:
            return set(line.strip() for line in file.readlines())
    except FileNotFoundError:
        return set()

def save_blocked_ips(blocked_ips):
    """Save blocked IPs to the file."""
    with open(blocked_ips_file, 'w') as file:
        for ip in blocked_ips:
            file.write(f"{ip}\n")

def is_valid_ip(ip):
    """Validate IP address format."""
    pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    return pattern.match(ip)

# Load initial blocked IPs
blocked_ips = load_blocked_ips()

def admin_auth(func):
    """Decorator to enforce simple password authentication for admin routes."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.args.get('auth')
        if auth != admin_password:
            return jsonify({"error": "Unauthorized access"}), 401
        return func(*args, **kwargs)
    return wrapper

def generate_captcha():
    """Generate a CAPTCHA image with random characters."""
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = captcha_text  # Store captcha text in session

    # Create a new image
    img = Image.new('RGB', (200, 50), color='darkblue')
    font = ImageFont.load_default()
    draw = ImageDraw.Draw(img)
    draw.text((50, 10), captcha_text, font=font, fill='white')

    # Save image to a byte buffer
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)

    return img_io

def send_email(subject, body):
    """Send an email notification with timeout and improved error handling."""
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = EMAIL_RECIPIENT
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=30) as server:  # Set SMTP timeout to 30 seconds
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USER, EMAIL_RECIPIENT, msg.as_string())
        logging.info("Email sent successfully.")
    except smtplib.SMTPAuthenticationError:
        logging.error("Failed to authenticate with Gmail SMTP. Check your username/password or app password settings.")
    except smtplib.SMTPConnectError:
        logging.error("Failed to connect to Gmail SMTP server. Check your network connection or Gmail settings.")
    except smtplib.SMTPException as e:
        logging.error(f"SMTP error occurred: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

@app.route('/', methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])  # Allow all paths
def firewall(path=None):
    ip_address = request.remote_addr
    current_time = datetime.now()

    # Log traffic with timestamp
    traffic_log.append((ip_address, current_time))

    # Clean up traffic log for requests older than 1 second
    traffic_log[:] = [req for req in traffic_log if (current_time - req[1]).seconds < 1]

    # Count requests from this IP in the last second
    ip_count = sum(1 for req in traffic_log if req[0] == ip_address)

    if ip_count > ddos_threshold:
        blocked_ips.add(ip_address)
        save_blocked_ips(blocked_ips)
        logging.warning(f"Blocked IP {ip_address} due to DDoS suspicion.")

        # Send email notification
        send_email("DDoS Suspicion - IP Blocked", f"IP {ip_address} has been blocked due to suspected DDoS activity.")
        
        return jsonify({"error": "Blocked due to suspected DDoS"}), 403

    if ip_address in blocked_ips:
        logging.info(f"Blocked request from {ip_address}.")
        return redirect(url_for('captcha_verification'))

    # Forward request to Django app for any path
    try:
        target_url = f"{DJANGO_APP_URL}/{path}" if path else DJANGO_APP_URL
        headers = {key: value for key, value in request.headers if key != 'Host'}
        cookies = request.cookies

        if request.method == 'GET':
            response = requests.get(target_url, headers=headers, params=request.args, cookies=cookies)
        elif request.method == 'POST':
            post_data = request.form.copy()
            response = requests.post(target_url, headers=headers, data=post_data, cookies=request.cookies)

        # Handle redirects from Django
        if response.status_code == 302:
            return redirect(response.headers['Location'])

        return (response.content, response.status_code, response.headers.items())
    except requests.ConnectionError:
        logging.error("Failed to connect to Django application.")
        return jsonify({"error": "Django application is unreachable"}), 502

@app.route('/captcha', methods=['GET'])
def captcha_verification():
    """Generate CAPTCHA image and render the verification page."""
    captcha_image = generate_captcha()
    captcha_path = os.path.join(app.static_folder, 'captcha.png')
    with open(captcha_path, 'wb') as f:
        f.write(captcha_image.read())
    return render_template('captcha.html', captcha_image='captcha.png')

@app.route('/verify_captcha', methods=['POST'])
def verify_captcha():
    """Verify the CAPTCHA entered by the user."""
    user_input = request.form.get('captcha_input')
    
    # Log both the user input and the stored session CAPTCHA for debugging
    logging.info(f"User input: {user_input}, Session captcha: {session.get('captcha')}")

    if user_input.upper() == session.get('captcha'):
        ip_address = request.remote_addr
        blocked_ips.discard(ip_address)
        save_blocked_ips(blocked_ips)
        logging.info(f"IP {ip_address} passed CAPTCHA verification.")

        captcha_path = os.path.join(app.static_folder, 'captcha.png')
        if os.path.exists(captcha_path):
            os.remove(captcha_path)

        return redirect(url_for('firewall'))
    else:
        return render_template('captcha.html', error="Incorrect CAPTCHA, please try again.")

@app.route('/admin', methods=['GET', 'POST'])
@admin_auth
def admin_panel():
    """Admin panel for managing IPs."""
    if request.method == 'POST':
        ip_to_block = request.form.get('ip_to_block')
        ip_to_unblock = request.form.get('ip_to_unblock')

        if ip_to_block and is_valid_ip(ip_to_block):
            blocked_ips.add(ip_to_block)
            save_blocked_ips(blocked_ips)
            logging.info(f"Manually blocked IP: {ip_to_block}")

        if ip_to_unblock and is_valid_ip(ip_to_unblock):
            blocked_ips.discard(ip_to_unblock)
            save_blocked_ips(blocked_ips)
            logging.info(f"Manually unblocked IP: {ip_to_unblock}")

        return redirect(url_for('admin_panel', auth=admin_password))

    # Prepare data for admin panel
    ip_stats = {ip: sum(1 for req in traffic_log if req[0] == ip) for ip, _ in traffic_log}
    recent_logs = [f"{ip} at {timestamp.strftime('%Y-%m-%d %H:%M:%S')}" for ip, timestamp in traffic_log[-10:]]
    return render_template('admin.html', ip_stats=ip_stats, recent_logs=recent_logs, blocked_ips=blocked_ips)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
