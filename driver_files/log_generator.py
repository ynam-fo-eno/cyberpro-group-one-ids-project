from datetime import datetime, timedelta
from config.config import config
import random

# We set the limit of logs we'll show per run to 200 in our default value here.
def generate_sample_logs(num_entries=200):
    #This is a list of the IP addresses whose logs we shall check for... 
    ips = ['192.168.1.100', '192.168.1.101', '10.0.0.5', '172.16.0.1', '203.0.113.45','192.168.0.21']
    # ...including our "bad guy"
    attacker_ip = '192.168.0.21'   

    start_time = datetime.now()
    current_time = start_time

    #Worth noting - our 2nd argument could be:
    #-> "w" (write)- each run of this file overwrites previous logs
    # ->"a" (append) - each run of this file adds the latest logs to what
    # sample_logs.txt will already have had by then.
    # -> "r"(read) - Only allows you to see a file not add to or overwrite
    #it and would thrown an error if there isn't a file to read from.
    # -> "r+"(read & write) - Allows reading and writing simultaneously.



    # SIMULATION LOGIC:
        # We don't just want random noise; we want 'Attacker Bursts'.
        # 'i % 15 < 7' creates a pattern where every 15 logs, the first 7 are 
        # likely to be the attacker. This guarantees the '5 failed attempts' 
        # rule will be broken for the IDS to catch .
    with open(config.LOG_FILE, 'w') as f:
        for i in range(num_entries):
            # 30% of the time we simulate brute-force from attacker
            if i %15 < 7 and random.random() < 0.85:
                ip =attacker_ip
                status = "Failed"
            else:
                ip = random.choice(ips)
                status = random.choice(["Failed", "Success"])

            line = f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} - {status} - {ip}\n"
            f.write(line)

            #random delay between log entries (maks it realistic)
            current_time += timedelta(seconds=random.randint(3, 40))

        print(f"Generated {num_entries} realistic logs -> {config.LOG_FILE}")
        print(f"Attacker {attacker_ip} is enacting brute force bursts!")

#This initializes so that when main is called and only when ids_engine later
#  calls it is when it runs.
if __name__ == "__main__":
    generate_sample_logs()