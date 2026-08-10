from src.log_collector import load_logs
from src.detector import detect_threats
from src.ai_analyzer import analyze_alerts


events = load_logs("logs/sample_security.log")
alerts = detect_threats(events)
analyses = analyze_alerts(alerts)

print("Alerts analyzed:", len(analyses))

for item in analyses:
    alert = item["alert"]
    analysis = item["analysis"]

    print("\n--- Security Alert ---")
    print("Type:", alert["type"])
    print("Severity:", alert["severity"])
    print("Classification:", analysis["classification"])
    print("Risk:", analysis["risk"])
    print("Explanation:", analysis["explanation"])

    print("Recommendations:")

    for recommendation in analysis["recommendations"]:
        print("-", recommendation)
