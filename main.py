import re 
from datetime import datetime
from detector import detect_brute_force
from database import initialize_db, save_alerts, get_alerts

LOG_FILE = "logs/sample_auth.log"

def parse_log(line):

    pattern = (
    r"^(\S+) (Failed|Accepted) password "
    r"for (\S+) from (\S+)$"

    )

    match = re.match(pattern, line.strip())

    if match:
        timestamp, status, username, ip = match.groups()


    return {
        "timestamp": timestamp,
        "status": status,
        "username": username,
        "ip_address": ip
    }

    return None
    

def main():

    initialize_db()

    failed_count = 0
    success_count = 0
    events = []

    with open(LOG_FILE, "r") as file:

        for line in file:

            event = parse_log(line)

            if event:
                print(event)

                events.append(event)

                if event["status"] == "Failed":
                    failed_count += 1

                elif event["status"] == "Accepted":
                    success_count += 1

    print("\n--- Authentication Summary ---")
    print("Failed Logins:", failed_count)
    print("Successful Logins:", success_count)
    print("Total Events:", failed_count + success_count)


    # Run the threat detection engine 
    alerts = detect_brute_force(events)

    print("\n--- New Detection Results ---")
    print("Alerts detected:", len(alerts))

    # Save alerts into DB
    save_alerts(alerts)

    stored_alerts = get_alerts()
    
    print("\n--- Stored Security Alerts ---")

    for alert in stored_alerts:

        print("Alert ID:", alert["id"])
        print("Threat:", alert["attack_type"])
        print("Source IP:", alert["ip_address"])
        print("Severity:", alert["severity"])
        print("Timestamp:", alert["timestamp"])
        print("MITRE ATT&CK:", alert["mitre_attack"])
        print("----------------------------")

if __name__ == "__main__":
    main()