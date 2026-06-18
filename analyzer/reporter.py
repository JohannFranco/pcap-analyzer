import json
from datetime import datetime

def generate_report(connections, alerts):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"output/report_{timestamp}.json"
    
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_packets": len(connections),
        "total_alerts": len(alerts),
        "alerts": alerts
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report saved to {output_path}")

    print("\n===== PCAP ANALYZER REPORT =====")
    print(f"Packets analyzed : {report['total_packets']}")
    print(f"Alerts generated : {report['total_alerts']}")
    print("================================")
    for alert in alerts:
        severity = alert.get("severity", "INFO")
        print(f"[{severity}] {alert['type']} — {alert}")
    print("================================\n")