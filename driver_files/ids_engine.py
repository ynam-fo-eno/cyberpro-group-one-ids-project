# Main Engine of the Advanced Python IDS
# This is where all modules connect together

from datetime import timedelta, datetime
import os
from config.config import config
from utils.logger import alert_logger
from detectors.brute_force import BruteForceDetector
from detectors.suspect_activity import SuspiciousActivityDetector

class IntrusionDetectionSystem:
    def __init__(self):
        self.detector = BruteForceDetector()
        self.sus_detector = SuspiciousActivityDetector()
        self.total_attacks_detected = 0
        self.total_logs_processed = 0
        self.ip_total_attempts = {}     # For final reporting: total attempts per IP

    def parse_log_line(self, line: str):
        """Convert raw log line into usable data (timestamp, status, ip)"""
        try:
            # Our log format: 2026-04-10 14:30:25 - Failed - 192.168.1.100
            parts = line.strip().split(" - ")
            if len(parts) != 3:
                return None
            
            timestamp_str, status, ip = parts
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            return timestamp, status.strip(), ip.strip()
        
        except Exception as e:
            # Silently skip bad lines (robustness) mwahahahah! aint i clever
            return None
        
    def run(self):
        """Main method that runs the entire IDS"""
        if not os.path.exists(config.LOG_FILE):
            print(f"ERROR! ERROR!!: {config.LOG_FILE} not found!!!")
            print("TRY FIRST =>>    Please run 'python log_generator.py' first.")
            return
        
        #Clear old eleart for a clean run
        alert_logger.clear_log()

        print(" ========== STARTING PYTHON IDS ==========")
        print("=" * 70 + "\n\n")
        print(f"Moitoring of File : {config.LOG_FILE}")
        print(f"Brute-Force Threshold : {config.BRUTE_FORCE_MAX_FAILED} failed attempts in {config.BRUTE_FORCE_TIME_WINDOW}")
        print("=" * 70 + "\n\n")
        
        with open(config.LOG_FILE, 'r') as f:
            for line in f:
                self.total_logs_processed += 1

                parsed = self.parse_log_line(line)
                if not parsed: 
                    continue

                timestamp, status, ip = parsed

                #Track total time per ip for reporting
                if ip not in self.ip_total_attempts:
                    self.ip_total_attempts[ip] = 0
                self.ip_total_attempts[ip] += 1

                #Send to detection engine the brute force and suspicious activity ones...
                is_brute = self.detector.check(timestamp, status, ip)
                is_suspect = self.sus_detector.check(ip)

                # If either detector flags a threat, increment the total attack count
                if is_brute or is_suspect:
                    self.total_attacks_detected += 1
                    alert_logger.log_alert(f"Threat detected from {ip}", ip=ip, severity="HIGH")

               

        # Show final profesional report
        self.generate_report()

    def generate_report(self):
        """Generate a professional timestamped report including ALL detectors"""
        report_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_filename = f"IDS_Report_{report_time}.txt"

        report_content = [
            "=" * 70,
            "📊 ADVANCED IDS FINAL REPORT",
            "=" * 70,
            f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total log entries processed: {self.total_logs_processed}",
            f"Total suspicious incidents: {self.total_attacks_detected}",
            "\nTop Offending IPs (Ranked by Total Activity):",
            "-" * 50
        ]

        # Get stats for the report
        ip_stats = []
        for ip in self.ip_total_attempts:
            # 1. Get failed attempts from Brute Force detector
            failed = self.detector.get_failed_count(ip)
            
            # 2. Get total volume (from our engine's tracker)
            total = self.ip_total_attempts[ip]
            
            # 3. Check if Suspicious Activity detector flagged high volume
            is_high_volume = total > config.SUSPICIOUS_IP_THRESHOLD
            
            # Label the threat type for better communication
            threat_type = "NONE"
            if failed >= config.BRUTE_FORCE_MAX_FAILED and is_high_volume:
                threat_type = "BRUTE + VOLUME"
            elif failed >= config.BRUTE_FORCE_MAX_FAILED:
                threat_type = "BRUTE-FORCE"
            elif is_high_volume:
                threat_type = "HIGH VOLUME"

            # Add to report if it hit any threshold
            if failed > 0 or is_high_volume:
                ip_stats.append((ip, failed, total, threat_type))
        
        # Sort by total connection volume (most active first)
        ip_stats.sort(key=lambda x: x[2], reverse=True)

        for rank, (ip, failed, total, threat) in enumerate(ip_stats[:config.TOP_OFFENDING_IPS], 1):
            report_content.append(
                f"{rank:2d}. {ip:15} | Total: {total:3} | Failed: {failed:2} | Type: {threat}"
            )

        # Save to file
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write("\n".join(report_content))

        print(f"\n[+] Professional report generated: {report_filename}")
