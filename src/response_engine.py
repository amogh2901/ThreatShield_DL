def response_action(severity):
    severity_upper = severity.upper()

    if severity_upper == "CRITICAL":
        return {
            "status": "BLOCKED",
            "message": "Critical threat detected. Block the request, isolate the source, and generate a security alert."
        }
    elif severity_upper == "HIGH":
        return {
            "status": "WARNING",
            "message": "Potential attack detected. Apply rate limiting and investigate."
        }
    elif severity_upper == "MEDIUM":
        return {
            "status": "MONITOR",
            "message": "Suspicious activity detected. Request is being monitored."
        }
    elif severity_upper == "LOW":
        return {
            "status": "SAFE",
            "message": "No immediate action required. Continue monitoring."
        }
    else:
        # For unknown severity levels
        return {
            "status": "MONITOR",
            "message": "Unknown threat level. Continue monitoring."
        }