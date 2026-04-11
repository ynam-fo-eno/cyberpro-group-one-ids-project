# detectors/brute_force.py
# This is our first detection rule - Brute Force Login Attempts
# Made modular so we can add more detectors later (port scan, etc.)

from collections import deque
from datetime import timedelta
from config.config import config
from utils.logger import alert_logger

class BruteForceDetector:
    def __init__(self):
        self.max_failed = config.BRUTE_FORCE_MAX_FAILED
        self.time_window = config.BRUTE_FORCE_TIME_WINDOW 

        # We use a dictionary: IP → deque of timestamps (only failed attempts)
        # deque is very efficient for sliding windows
        self.ip_failed_attempts = {}

    def check(self, timestamp, status: str, ip: str) -> bool:
        """Check if this login attempt trigers a brute force attack alert"""
        is_failed = "failed" in status.lower()

        if not is_failed:
            return False    #Only care about failed attempts for brute force
        
        #Initialize deque for this IP if its the first time
        if ip not in self.ip_failed_attempts:
            self.ip_failed_attempts[ip] = deque()

        #Add current timestamps to the window
        self.ip_failed_attempts[ip].append(timestamp)

        #Remove old attempts outside the time window (sliding window)
        while self.ip_failed_attempts[ip] and self.ip_failed_attempts[ip][0] < timestamp - self.time_window:
            self.ip_failed_attempts[ip].popleft()

        #Check if we crossed the threshold
        if len(self.ip_failed_attempts[ip]) >= self.max_failed:
            alert_msg = (f"Possible Brute-Force Attack detected from {ip}! "
                         f"{len(self.ip_failed_attempts[ip])} failed attempts in Last "
                         f"{self.time_window.total_seconds()/60:.0f} minutes. ")
            
            alert_logger.log_alert(alert_msg, ip=ip, severity= "HIGH")
            return True
        
        return False
    
    def get_failed_count(self, ip: str) -> int:
        """Helper for final reporting"""
        if ip in self.ip_failed_attempts:
            return len(self.ip_failed_attempts[ip])
        return 0