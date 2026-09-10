severity_map = {
    "benign": "Low",
    "port-scan": "Medium",
    "ddos": "High",
    "brute-force": "High",
    "credential-stuffing": "High",
    "sql-injection": "Critical",
    "xss": "Critical",
    "command-injection": "Critical",
    "exploit-attempt": "Critical",
    "c2": "Critical"
}

recommendation_map = {
    "port-scan": "Monitor suspicious network scanning activity.",
    "ddos": "Enable rate limiting and traffic filtering.",
    "brute-force": "Enable MFA and account lockout policies.",
    "credential-stuffing": "Monitor login attempts and enforce MFA.",
    "sql-injection": "Validate inputs and use parameterized queries.",
    "xss": "Sanitize user input and implement CSP.",
    "command-injection": "Validate system commands and restrict privileges.",
    "exploit-attempt": "Patch vulnerable services immediately.",
    "c2": "Investigate compromised hosts and isolate systems."
}