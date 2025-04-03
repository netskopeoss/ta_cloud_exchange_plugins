"""Define methods for the API endpoints."""


def get_all_subtypes():
    """Get subtypes for alerts and events."""
    return {
        "events": {
            "BWAN_Audit": "bwan_audit",
            "BWAN_Authentication": "bwan_authentication",
            "BWAN_Client": "bwan_client",
            "BWAN_Gateway": "bwan_gateway",
            "BWAN_System": "bwan_system"
        }
    }
