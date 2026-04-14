# Main Engine of the Advanced Python IDS:
# This is where all modules connect together and do their collective jobs and
#not only alert the user on the suspect IP addresses, but also sends them an
#email to that effect.

from datetime import datetime
import os
from config.config import config
from utils.logger import alert_logger
from detectors.brute_force import BruteForceDetector
from detectors.suspect_activity import SuspiciousActivityDetector

class IntrusionDetectionSystem:
    def __init__(self):
        #We initialize our detector objects from brute_force. and 
        # suspect_activity.py, which will dynamically change based on
        # logs found as we shall shortly see within this program. 
        self.detector = BruteForceDetector()
        self.sus_detector = SuspiciousActivityDetector()
        self.total_attacks_detected = 0
        self.total_logs_processed = 0
        #This last one reports total # of attempts from 1 IP, mostly our 
        #offensive one in this case.
        self.ip_total_attempts = {}    

    def parse_log_line(self, line: str):
        #This method converts raw log line into usable data (timestamp, status, ip) 
        # This covers our FIRST feature: which was monitoring logs - first their 
        # existence, then their format if they exist.

        try:
            # Our log format will be as follows:
            # "Template": yyyy-mm-dd hh:mm:ss  Success|Failed - <RelevantIP Address>
            # Example:    2026-04-10 14:30:25      Failed     -   192.168.1.100

            #This is what splits our raw log into 3 distinct parts and otherwise
            # the function stops and returns nothing.
            parts = line.strip().split(" - ")
            if len(parts) != 3:
                return None
            
            #Each variable is assigned the corresponding subsection
            # of the parts list- timestamp-_str gets the 1st element (with time)
            # status the 2nd element- failed/success part and ip the last element,
            # the IP address...
            timestamp_str, status, ip = parts

            #Note that strptime is for parsing raw date data to sth more readable.
            # Whereas strftime is for dealing with already parsed dates and 
            # having them as more computer readable.
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            return timestamp, status.strip(), ip.strip()
        
        except Exception as e:
            return None
        
    def run(self):
        # Main method that runs the entire IDS.
        # Starting swiftly by checking if there is a log file to read from to
        #begin with. Throwing the error seen below if there isn't but
        # doing the necessary otherwise.
        if not os.path.exists(config.LOG_FILE):
            print(f"ERROR! ERROR!!: {config.LOG_FILE} not found!!!")
            print("TRY FIRST =>>    Please run 'python log_generator.py' first.")
            return
        
        #We clear old logs for a cleaner run every time we use this IDS.
        alert_logger.clear_log()

        print(" ========== STARTING PYTHON IDS ==========")
        print("=" * 200 + "\n\n")
        print(f"Moitoring of File : {config.LOG_FILE}")
        print(f"Brute-Force Threshold : {config.BRUTE_FORCE_MAX_FAILED} failed attempts in {config.BRUTE_FORCE_TIME_WINDOW}")
        print("=" * 200 + "\n\n")
        
        #Remember the config? We use the file we made and which was saved in that object here
        
        with open(config.LOG_FILE, 'r') as f:
            for line in f:
                self.total_logs_processed += 1

                parsed = self.parse_log_line(line)
                if not parsed: 
                    continue
                # We use a similar pattern of picking the parsed list elements with
                # 3 variables like we saw in our parse_log_line() method just now.
                timestamp, status, ip = parsed

                #Track total times per ip for reporting (Core Feature #3)
                if ip not in self.ip_total_attempts:
                    self.ip_total_attempts[ip] = 0
                self.ip_total_attempts[ip] += 1

                #Send to detection engine the brute force and suspicious activity check
                # methods (feature 2 and 3)
                is_brute = self.detector.check(timestamp, status, ip)
                is_suspect = self.sus_detector.check(ip)

                # If either detector flags a threat, increment the total attack count.
                #This is what writes the red stuff we saw before. 
                #That red color in turn is made possible by settings we see in
                # logger.py shortly.
                if is_brute or is_suspect:
                    self.total_attacks_detected += 1
                    alert_logger.log_alert(f"Threat detected from {ip}", ip=ip, severity="HIGH")

               

        # Show final profesional report
        self.generate_report()

    def generate_report(self):
        #Generate a professional timestamped report including ALL detectors
        report_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_filename = f"IDS_Report_{report_time}.txt"

        #This just gives the report we're about to generate a header
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

        # Get stats for the report which include and aren't limited to:
        ip_stats = []
        for ip in self.ip_total_attempts:
            # 1. Getting the number of  failed attempts from Brute Force detector
            failed = self.detector.get_failed_count(ip)
            
            # 2. Get how often said IP address attempted.
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
        
        # RANKING: We sort the list so the most active (dangerous) IP is at the
        #  top. x[2] refers to the 'total' connections count.
        ip_stats.sort(key=lambda x: x[2], reverse=True)


        #SLICING: We only show the 'Top X' offenders defined in our config file.
        # Remember in config we set TOP_OFFENDING_IPS to 5 so this in our 
        # IDS_Report_<datetime>.txt we only see the five "worst" IP addresses.
        for rank, (ip, failed, total, threat) in enumerate(ip_stats[:config.TOP_OFFENDING_IPS], 1):
            report_content.append(
                f"{rank:2d}. {ip:15} | Total: {total:3} | Failed: {failed:2} | Type: {threat}"
            )

        # Save to file
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write("\n".join(report_content))

        print(f"\n[+] Professional report generated: {report_filename}")
