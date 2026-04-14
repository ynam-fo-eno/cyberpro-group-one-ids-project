from config.config import config


# detectors/suspect_activity.py
# This complements the Brute Force detector by looking for 'High Volume' activity.
# Even if a user is logging in successfully, 50+ connections in a short time 
# could indicate a DDoS attack or an automated scraper[cite: 10].
class SuspiciousActivityDetector:
    def __init__(self):
        # Feature 3: IP Tracking. This dictionary stores the total count 
        # of every connection made by an IP address
        self.ip_connection_counts = {}
        # We pull the threshold (50) from our centralized config file
        self.threshold = 50 

    def check(self, ip):
        #Simply increments the counter for the IP and flags it if it 
        #exceeds our 'High Volume' limit[cite: 10, 23].
        
        
        # Get current count (defaulting to 0) and add 1.
        self.ip_connection_counts[ip] = self.ip_connection_counts.get(ip, 0) + 1
        # If they cross the line, we return True so the engine can alert the user.
        if self.ip_connection_counts[ip] > self.threshold:
            return True
        return False