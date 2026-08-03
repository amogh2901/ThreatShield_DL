"""
ThreatShield Threat Intelligence Module
---------------------------------------
Provides threat severity, description, recommended action,
MITRE ATT&CK mapping, CVSS score and security recommendations.
"""


THREAT_DATABASE = {

    "Normal": {
        "severity": "LOW",
        "description": "The request appears legitimate. No malicious behavior detected.",
        "action": "Allow the request and continue monitoring.",
        "mitre": "N/A",
        "cvss": 0.0,
        "recommendation": "No action required."
    },

    "SQL Injection": {
        "severity": "CRITICAL",
        "description": "SQL Injection attack attempting to manipulate backend database queries.",
        "action": "Block the request immediately and sanitize database inputs.",
        "mitre": "T1190 - Exploit Public-Facing Application",
        "cvss": 9.8,
        "recommendation": "Use parameterized queries, prepared statements and input validation."
    },

    "Cross Site Scripting": {
        "severity": "HIGH",
        "description": "Cross Site Scripting (XSS) attack detected. The request may execute malicious JavaScript.",
        "action": "Reject the request and sanitize user input.",
        "mitre": "T1059.007 - JavaScript",
        "cvss": 8.2,
        "recommendation": "Apply output encoding, Content Security Policy (CSP) and input sanitization."
    },

    "Path Traversal": {
        "severity": "HIGH",
        "description": "Directory Traversal attempt detected. The request may access restricted files.",
        "action": "Block file access and validate file paths.",
        "mitre": "T1006 - Path Traversal",
        "cvss": 8.6,
        "recommendation": "Restrict file system permissions and normalize file paths."
    },

    "Phishing URL": {
        "severity": "HIGH",
        "description": "Potential phishing website detected based on suspicious URL characteristics.",
        "action": "Block access and warn the user.",
        "mitre": "T1583 - Acquire Infrastructure",
        "cvss": 7.8,
        "recommendation": "Verify the URL, enable Safe Browsing and educate users about phishing."
    }

}


def get_threat_info(attack_type):
    """
    Returns threat intelligence information for the detected attack.
    """

    return THREAT_DATABASE.get(
        attack_type,
        {
            "severity": "MEDIUM",
            "description": "Unknown attack pattern detected.",
            "action": "Monitor the request and investigate manually.",
            "mitre": "Unknown",
            "cvss": 5.0,
            "recommendation": "Perform manual security analysis."
        }
    )