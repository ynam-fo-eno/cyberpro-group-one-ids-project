import smtplib
from email.message import EmailMessage
import datetime
#Assists in reading environemn variables
import os 
 # To load the .env file
from dotenv import load_dotenv
from config.config import config

# Load environment variables at the very start.
# Saving them this way over hardcoding them is safer,
#provided in the .gitignore we add .env, which is done.
load_dotenv()

class AlertLogger:
    def __init__(self):
        # This variable writes the logs from our config in one central place.
        # Using the alert_log we made in config.
        self.alert_file = config.ALERT_LOG
        #We use this empty dictionary to 
        #track the last time an email was sent to the party
        #concerned so that instead of several emails to the same person
        # over the same attack it is consolidated to one. More on this
        # in our send email method.
        self.last_alert_times = {}

    def log_alert(self, message: str, ip: str = None, severity: str ='HIGH'):
        #Prints alert to console, save to file, and trigger email
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # --- CONSOLE OUTPUT ---
        # We use ANSI escape codes to color-code our terminal output.
        # Red (\033[91m) for HIGH severity makes threats immediately visible.
        color = "\033[91m" if severity == "HIGH" else "\033[93m"
        reset = "\033[0m"
        full_message = f"{color}[{severity} ALERT]{reset} {timestamp} | {message}"
        print(full_message)

        # 
        with open(self.alert_file, 'a') as f:
            file_msg = f"[{severity}] {timestamp} | {message}"
            if ip:
                file_msg += f" | IP: {ip}"
            f.write(file_msg + "\n")

        # Send Email Alert
        subject = f"Security Incident: {severity} Priority"
        self.send_email_alert(subject,  message,  severity, ip=ip)

    #More comments at the bottom kuhusu how email was setup outside the code itself.
    def send_email_alert(self, subject, body, severity, ip = None):
        if not config.ENABLE_EMAIL_ALERTS:
            return

        #To keep us from getting a million emails over the same attack
        # RATE LIMITER: Only email about the same IP once every 10 minutes
        if ip:
            now = datetime.datetime.now()
            last_time = self.last_alert_times.get(ip)
            if last_time and (now - last_time) < datetime.timedelta(minutes=10):
                # Skip the email, we already sent one recently!
                return
            self.last_alert_times[ip] = now

        # Fetch secrets from environment without hardcoding them
        sender = os.getenv("SENDER_EMAIL")
        password = os.getenv("EMAIL_PASS")

        #This is what controls how and to whom the email is sent
        #including an object of the EmailMessage we imported
        msg = EmailMessage()
        # Compare this to how it looks in your email of choice
        msg.set_content(body)
        msg['Subject'] = f"[{severity} ALERT] {subject}"
        msg['From'] = sender
        msg['To'] = "1202dtim@gmail.com"

        try:
            # ENCRYPTION IN TRANSIT: Use TLS (Transport Layer Security) 
            # to encrypt the email credentials and content while they 
            # travel across the internet.
            with smtplib.SMTP('smtp.gmail.com', 587) as s:
                s.starttls() 
                s.login(sender, password)
                s.send_message(msg)
        except Exception as e:
            print(f"Email failed: {e}")

    def clear_log(self):
        with open(self.alert_file, 'w') as f:
            f.write("=== IDS Alert Log Started ===\n\n")

#This initalizes the logger object that will be used in all the modules
alert_logger = AlertLogger()


"""
This is more explanation on how the email was setup:
    1. In addition to the code seen above, the email address and password* was
        saved as environment variables in our .env file (which won't be visible
        to people who receive zip as it'll be removed manually before compression
        and GitHub coz of the .gitignore) bolstering the security of those very
        sensitive credentials). 
    2.*The password is NOT the one you'd normally login with. If using Google,
        for example, you'll go to its security settings section and enter "App 
        Password".You'll then be asked to write the name of our app, and when 
        you do you get a 16 character string that will be your password.
        You'll see it with spaces but put without in your .env.
        Example: abcdefghijklmnop
"""