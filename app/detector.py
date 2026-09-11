from typing import Any, Dict, List

SENSITIVE_PORTS = {21, 22, 23, 3389, 445, 5900}
SUSPICIOUS_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
}


def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score > 0:
        return "low"
    return "informational"


def analyze_event(event: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    alerts: List[str] = []
    recommendations: List[str] = []

    failed_attempts = int(event.get("failed_attempts") or 0)
    if event.get("event_type") == "login" and event.get("success") is False and failed_attempts >= 5:
        score += min(40, 15 + failed_attempts * 2)
        alerts.append("Possible brute-force login activity")
        recommendations.append(
            "Temporarily block the source IP and inspect authentication logs."
        )

    destination_port = event.get("destination_port")
    if destination_port in SENSITIVE_PORTS:
        score += 20
        alerts.append("Connection to a sensitive service port")
        recommendations.append(
            "Verify whether this service exposure is expected and restrict access if unnecessary."
        )

    process_name = (event.get("process_name") or "").lower()
    if process_name in SUSPICIOUS_PROCESSES:
        score += 25
        alerts.append("Suspicious process observed")
        recommendations.append(
            "Inspect the process command line, parent process, user context, and recent activity."
        )

    bytes_sent = int(event.get("bytes_sent") or 0)
    if bytes_sent >= 50_000_000:
        score += 30
        alerts.append("Large outbound data transfer")
        recommendations.append(
            "Review the destination and validate whether the transfer is legitimate."
        )

    score = min(score, 100)

    if not alerts:
        recommendations.append("No high-confidence rule fired. Continue monitoring the event context.")

    return {
        "risk_score": score,
        "severity": _severity(score),
        "alerts": alerts,
        "recommendations": recommendations,
        "event_summary": {
            "event_type": event.get("event_type"),
            "source_ip": event.get("source_ip"),
            "destination_ip": event.get("destination_ip"),
        },
    }
