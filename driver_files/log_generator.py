from datetime import datetime, timedelta
from config.config import config
import random

def generate_sample_logs(num_entries=200):
    
    ips = ['192.168.1.100', '192.168.1.101', '10.0.0.5', '172.16.0.1', '203.0.113.45','192.168.0.21']
    attacker_ip = '192.168.0.21'   # our "bad guy"

    start_time = datetime.now()
    current_time = start_time

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

            #random delay between log entries (maks it ralistic)
            current_time += timedelta(seconds=random.randint(3, 40))

        print(f"Generated {num_entries} relistic logs -> {config.LOG_FILE}")
        print(f"Attacker {attacker_ip} is enacting brute force bursts!")


if __name__ == "__main__":
    generate_sample_logs()