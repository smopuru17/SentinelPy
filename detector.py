from collections import defaultdict
from datetime import datetime, timedelta

def detect_brute_force(events):

    failed_attempts = defaultdict(list)
    alerts = []

    # Collecting failed login attempts
    for event in events:

        if event["status"] == "Failed":

            ip = event["ip_address"]
            timestamp = datetime.fromisoformat(
                event["timestamp"]
            )

            failed_attempts[ip].append(timestamp)

    # Analyze attempts from each IP
    for ip, timestamps in failed_attempts.items():

        timestamps.sort()

        # Check groups of 5 attempts
        for i in range(len(timestamps) - 4):

            window = timestamps[i:i + 5]

            time_difference = window[-1] - window[0]

            if time_difference <= timedelta(seconds=60):

                alerts.append({
                    "ip_address": ip,
                    "attack_type": "SSH Brute Force",
                    "severity": "HIGH",
                    "timestamp": window[-1].isoformat(),
                    "mitre_attack": "T1110"
                })

                break
    
    return alerts
