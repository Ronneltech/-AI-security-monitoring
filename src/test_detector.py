from log_collector import load_logs
from detector import detect_threats


events = load_logs("logs/sample_security.log")
alerts = detect_threats(events)

print("Alerts detected:", len(alerts))

for alert in alerts:
    print(alert)
