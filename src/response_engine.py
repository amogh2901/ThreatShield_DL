"""
ThreatShield Adaptive Response Engine
-------------------------------------
Generates recommended security actions based on threat severity.
This module does not block requests automatically.
It only recommends appropriate security responses.
"""


def response_action(severity):
    severity = severity.upper()

    responses = {

        "CRITICAL": {
            "status": "BLOCKED",
            "message": "Critical threat detected. Immediately block the request and isolate the source.",
            "firewall": "Enabled",
            "admin_alert": "Sent",
            "log_status": "Recorded",
            "recommended_action": "Block request, isolate source IP, investigate immediately."
        },

        "HIGH": {
            "status": "WARNING",
            "message": "High-risk attack detected. Block the request and investigate.",
            "firewall": "Enabled",
            "admin_alert": "Sent",
            "log_status": "Recorded",
            "recommended_action": "Block request and review server logs."
        },

        "MEDIUM": {
            "status": "MONITOR",
            "message": "Suspicious activity detected. Continue monitoring.",
            "firewall": "Monitoring Only",
            "admin_alert": "Not Required",
            "log_status": "Recorded",
            "recommended_action": "Monitor future requests from this source."
        },

        "LOW": {
            "status": "SAFE",
            "message": "No immediate threat detected.",
            "firewall": "No Action",
            "admin_alert": "Not Required",
            "log_status": "Recorded",
            "recommended_action": "Allow request and continue normal monitoring."
        }

    }

    return responses.get(
        severity,
        {
            "status": "UNKNOWN",
            "message": "Unknown threat level detected.",
            "firewall": "Monitoring Only",
            "admin_alert": "Review Required",
            "log_status": "Recorded",
            "recommended_action": "Review the request manually."
        }
    )