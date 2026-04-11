from config.config import config

class SuspiciousActivityDetector:
    def __init__(self):
        self.ip_connection_counts = {}
        self.threshold = 50 # Example: 50 connections from one IP is "suspicious"

    def check(self, ip):
        self.ip_connection_counts[ip] = self.ip_connection_counts.get(ip, 0) + 1
        if self.ip_connection_counts[ip] > self.threshold:
            return True
        return False