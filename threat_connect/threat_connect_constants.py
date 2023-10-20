"""ThreatConnect Plugin constants."""

from netskope.integrations.cte.models import (
    IndicatorType,
    SeverityType,
)

INDICATOR_TYPES = [
    "File",
    "URL",
    "Host",
    "Address"
]

THREATCONNECT_TO_INTERNAL_TYPE = {
    "sha256": IndicatorType.SHA256,
    "md5": IndicatorType.MD5,
    "url": IndicatorType.URL,
}

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
PLATFORM_NAME = "ThreatConnect"
MODULE_NAME = "CTE"
PLUGIN_VERSION = "1.1.1"
