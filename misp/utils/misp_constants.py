"""MISP Contstants."""

TYPES = {
    "md5": "md5",
    "sha256": "sha256",
    "ip-src": "url",
    "url": "url",
    "domain": "url",
}

ATTRIBUTE_TYPES = ["md5", "sha256", "ip-src", "url", "domain"]


ATTRIBUTE_CATEGORIES = [
    "Internal reference",
    "Targeting data",
    "Antivirus detection",
    "Payload delivery",
    "Artifacts dropped",
    "Payload installation",
    "Persistence mechanism",
    "Network activity",
    "Payload type",
    "Attribution",
    "External analysis",
    "Financial fraud",
    "Support Tool",
    "Social network",
    "Person",
    "Other",
]
