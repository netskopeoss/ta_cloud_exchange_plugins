"""Define methods for the API endpoints."""


def get_all_subtypes():
    """Get subtypes for alerts and events."""
    return {
        "events": {
            "Audit": "audit",
            "Authentication": "authentication",
            "Client": "client",
            "Gateway": "gateway",
            "System": "system"
        }
    }
