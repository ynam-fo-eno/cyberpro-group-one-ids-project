import smtplib
from email.message import EmailMessage
import datetime
import os # To read environment variables
from dotenv import load_dotenv # To load the .env file
from config.config import config

# Load environment variables at the very start
load_dotenv()

class AlertLogger:
    def __init__(self):
        self.alert_file = config.ALERT_LOG
        self.last_alert_times = {}

    def log_alert(self, message: str, ip: str = None, severity: str ='HIGH'):
        """Print alert to console, save to file, and trigger email"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Console output
        color = "\033[91m" if severity == "HIGH" else "\033[93m"
        reset = "\033[0m"
        full_message = f"{color}[{severity} ALERT]{reset} {timestamp} | {message}"
        print(full_message)

        # Save to file [cite: 24]
        with open(self.alert_file, 'a') as f:
            file_msg = f"[{severity}] {timestamp} | {message}"
            if ip:
                file_msg += f" | IP: {ip}"
            f.write(file_msg + "\n")

        # Send Email Alert
        subject = f"Security Incident: {severity} Priority"
        self.send_email_alert("Security Alert", message, severity, ip=ip)

    def send_email_alert(self, subject, body, severity, ip = None):
        if not config.ENABLE_EMAIL_ALERTS:
            return

        #To keep us from getting a million emails over the same attack
        # RATE LIMITER: Only email about the same IP once every 10 minutes
        if ip:
            now = datetime.datetime.now()
            last_time = self.last_alert_times.get(ip)
            if last_time and (now - last_time) < datetime.timedelta(minutes=10):
                return # Skip the email, we already sent one recently!
            self.last_alert_times[ip] = now

        # Fetch secrets from environment (Hardening!) [cite: 230]
        sender = os.getenv("SENDER_EMAIL")
        password = os.getenv("EMAIL_PASS")

        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = f"[{severity} ALERT] {subject}"
        msg['From'] = sender
        msg['To'] = "1202dtim@gmail.com"

        try:
            # Use TLS for encryption in transit [cite: 351, 468]
            with smtplib.SMTP('smtp.gmail.com', 587) as s:
                s.starttls() 
                s.login(sender, password)
                s.send_message(msg)
        except Exception as e:
            print(f"Email failed: {e}")

    def clear_log(self):
        with open(self.alert_file, 'w') as f:
            f.write("=== IDS Alert Log Started ===\n\n")

alert_logger = AlertLogger()