"""Define methods for the API endpoints."""


def get_all_subtypes():
    """Get subtypes for alerts and events."""
    return {
        "alerts": {
            "anomaly": "anomaly",
            "Compromised Credential": "compromisedcredential",
            "policy": "policy",
            "Legal Hold": "legalhold",
            "malsite": "malsite",
            "Malware": "malware",
            "DLP": "dlp",
            "Security Assessment": "securityassessment",
            "watchlist": "watchlist",
            "quarantine": "quarantine",
            "Remediation": "remediation",
            "uba": "uba",
            "ctep": "ctep",
            "ips": "ips",
            "c2": "c2"
        },
        "events": {
            "Page": "page",
            "Application": "application",
            "Audit": "audit",
            "Infrastructure": "infrastructure",
            "Network": "network",
            "Incident": "incident",
            "Endpoint": "endpoint",
        }
    }
