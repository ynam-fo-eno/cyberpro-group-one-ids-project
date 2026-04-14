import json
from datetime import timedelta

class IDSConfig:
    def __init__(self):
       #This is the folder in which we store the constants we shall be using 
       # globally in the project and its modules and which won't change
       #(hence why you see their variable names written entirely in uppercase letters).
       #Most of the other files here will import from this module and use 
       # its initialization object (aptly called self as traditional in 
       # OOP programming) so that we needn't write them over and over
       #again in our code, more so since again they won't change.


       #First the constants that control the path 
       # in which our logs will be saved
        self.LOG_FOLDER = "logs"
        self.LOG_FILE = f"{self.LOG_FOLDER}/sample_logs.txt"
        self.ALERT_LOG = f"{self.LOG_FOLDER}/ids_alerts.log"

        #Then the constants we use in brute force rule
        self.BRUTE_FORCE_MAX_FAILED = 5
        self.BRUTE_FORCE_TIME_WINDOW = timedelta(minutes=2)

        # Extra settings, like permitting our code (with further setting up)
        # to send emails to recipients of our choosing
        self.ENABLE_EMAIL_ALERTS = True

        #Reporting settings
        self.TOP_OFFENDING_IPS = 5

        #This will complement the recently created detector file for suspicious activity...
        self.SUSPICIOUS_IP_THRESHOLD = 50

    #Though optional, it means other tools, including those in different languages like C or Lua, 
    #could look at the JSON file this makes and...eh, make sense of the config file for our
    #simple IDS system.
    def save(self):
        """Optional: save config to JSON """
        config_dict = {
            "brute_force_max_failed": self.BRUTE_FORCE_MAX_FAILED,
            "brute_force_time_window_minutes": 2,
         }
        with open("ids_config.json", "w") as f:
            json.dump(config_dict, f, indent=4)

#create one gloabal config object to use everywhere, which is constructed with 
#all the necessary constants
config = IDSConfig()