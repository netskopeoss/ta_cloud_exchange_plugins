"""ThreatConnect Plugin constants."""

from netskope.integrations.cte.models import SeverityType

INDICATOR_TYPES = ["File", "URL", "Host", "Address"]

RATING_TO_SEVERITY = {
    0: SeverityType.UNKNOWN,
    1: SeverityType.LOW,
    2: SeverityType.LOW,
    3: SeverityType.MEDIUM,
    4: SeverityType.HIGH,
    5: SeverityType.CRITICAL,
}

SEVERITY_TO_RATING = {
    SeverityType.UNKNOWN: 0,
    SeverityType.LOW: 1,
    SeverityType.MEDIUM: 3,
    SeverityType.HIGH: 4,
    SeverityType.CRITICAL: 5,
}

LIMIT = 1000  # Maximum Response LIMIT at Time.
PAGE_LIMIT = 100
MAX_RETRY = 3
TAG_NAME = "Netskope CE"
MODULE_NAME = "CTE"
PLUGIN_NAME = "ThreatConnect"
PLATFORM_NAME = "ThreatConnect"
PLUGIN_VERSION = "1.2.1"
DATE_FORMAT = r"%Y-%m-%dT%H:%M:%SZ"
# Default Confidence value
DEFAULT_CONFIDENCE = 50

DEFAULT_WAIT_TIME = 60
MAX_WAIT_TIME = 300
THREAT_CONNECT_URLS = {
    "owners": "/api/v3/security/owners",
    "owners_mine": "/api/v2/owners/mine",
    "indicators": "/api/v3/indicators",
    "groups": "/api/v3/groups/",
    "update_indicators": "/api/v3/indicators/{value}",
}
INTEGER_THRESHOLD = 4611686018427387904
# Response Messages
PUSH_INDICATOR_FAILURE = "contained on a system-wide exclusion list"
BIFURCATE_INDICATOR_TYPES = {"url", "domain", "ipv4", "ipv6", "hostname"}
