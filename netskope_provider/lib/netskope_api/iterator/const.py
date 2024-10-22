"""
Define the const used across all components.

Only put built-in imports in this module to make this really Const.
Use var.py for variable definitions.

"""

class Const(object):

    """
    Constant definition for iterator
    """
    NSKP_TOKEN = "TOKEN"
    NSKP_ITERATOR_NAME = "ITERATOR_NAME"
    NSKP_EVENT_TYPE = "EVENT_TYPE"
    NSKP_ALERT_TYPE = "ALERT_TYPE"
    NSKP_TENANT_HOSTNAME = "TENANT_HOSTNAME"
    NSKP_PROXIES = "PROXIES_DICT"
    NSKP_USER_AGENT = "USER_AGENT"
    SUCCESS_OK_CODE = 200


    # *************************#
    # Rate limiting constants #
    #*************************#

    # Rate limit remaining
    RATELIMIT_REMAINING = "ratelimit-remaining"
    # Rate limit RESET value is in seconds
    RATELIMIT_RESET = "ratelimit-reset"
    # Ratelimit
    RATELIMIT_LIMIT = "ratelimit-limit"

    # *************************#
    # Alert Type constants     #
    # *************************#

    ALERT_TYPE_DLP = "dlp"
    ALERT_TYPE_WATCHLIST = "watchlist"
    ALERT_TYPE_CTEP = "ctep"
    ALERT_TYPE_COMPROMISEDC_CREDENTIALS = "compromisedcredential"
    ALERT_TYPE_MALSITE = "malsite"
    ALERT_TYPE_MALWARE = "malware"
    ALERT_TYPE_POLICY = "policy"
    ALERT_TYPE_REMEDIATION = "remediation"
    ALERT_TYPE_QUARANTINE = "quarantine"
    ALERT_TYPE_SECURITY_ASSESSMENT = "securityassessment"
    ALERT_TYPE_UBA = "uba"

    # *************************#
    # Event Type constants     #
    # *************************#
    EVENT_TYPE_ALERT = "alert"
    EVENT_TYPE_PAGE = "page"
    EVENT_TYPE_APPLICATION = "application"
    EVENT_TYPE_INCIDENT = "incident"
    EVENT_TYPE_AUDIT = "audit"
    EVENT_TYPE_INFRASTRUCTURE = "infrastructure"
    EVENT_TYPE_NETWORK = "network"




