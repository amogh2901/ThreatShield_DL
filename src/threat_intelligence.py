def get_threat_info(attack_type):
    threats = {
        "Normal": {
            "severity": "LOW",
            "description": "Normal request.",
            "action": "Allow request."
        },
        "SQL Injection": {
            "severity": "CRITICAL",
            "description": "SQL Injection attack detected.",
            "action": "Block attacker IP and sanitize database queries."
        },
        "Cross Site Scripting": {
            "severity": "HIGH",
            "description": "Cross Site Scripting attack detected.",
            "action": "Sanitize input and enable output encoding."
        },
        "Path Traversal": {
            "severity": "HIGH",
            "description": "Directory traversal attempt detected.",
            "action": "Restrict file system access."
        },
        "Phishing URL": {
            "severity": "HIGH",
            "description": "Suspicious or phishing URL detected.",
            "action": "Block URL and warn user."
        }
    }
    # Return the threat info if found, otherwise provide a default response
    return threats.get(attack_type, {
        "severity": "MEDIUM",
        "description": "Unknown attack pattern detected.",
        "action": "Monitor request and investigate."
    })