import json
from datetime import timedelta

class IDSConfig:
    def __init__(self):
        """
        Initialize IDSConfig instance.
        Currently, this constructor does not take any parameters or perform any initialization.
        """

        self.LOG_FOLDER = "logs"
        self.LOG_FILE = f"{self.LOG_FOLDER}/sample_logs.txt"
        self.ALERT_LOG = f"{self.LOG_FOLDER}/ids_alerts.log"

        #Brute force rule
        self.BRUTE_FORCE_MAX_FAILED = 5
        self.BRUTE_FORCE_TIME_WINDOW = timedelta(minutes=2)

        #Future rules can be addedher easily
        self.ENABLE_EMAIL_ALERTS = True

        #Reporting settings
        self.TOP_OFFENDING_IPS = 5

        #This will complement the recently created config file for suspicious activity...
        self.SUSPICIOUS_IP_THRESHOLD = 50


    def save(self):
        """Optional: save config to JSON """
        config_dict = {
            "brute_force_max_failed": self.BRUTE_FORCE_MAX_FAILED,
            "brute_force_time_window_minutes": 2,
         }
        with open("ids_config.json", "w") as f:
            json.dump(config_dict, f, indent=4)

#create one gloabal config object to use everywhere
config = IDSConfig()