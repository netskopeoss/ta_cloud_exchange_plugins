"""Netskope CRE plugin Constants."""

MAX_RETRY_COUNT = 4
DEFAULT_WAIT_TIME = 60
PAGE_SIZE = 100
MAX_HOSTS_PER_PRIVATE_APP = 500
USERS_BATCH_SIZE = 512
APPLICATIONS_BATCH_SIZE = 100
REGEX_HOST = (
    r"^(?!:\/\/)([a-z0-9-]{1,63}\.)?[a-z0-9-]{1,63}(?:\.[a-z]{2,})?$|"
    r"^(?:(?:25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)$"
)
REGEX_EMAIL = r"[^@]+@[^@]+\.[^@]+"
MODULE_NAME = "CRE"
PLUGIN = "Netskope Risk Exchange"
PLUGIN_VERSION = "1.3.0"
URLS = {
    "V2_PRIVATE_APP": "/api/v2/steering/apps/private",
    "V2_PRIVATE_APP_PATCH": "/api/v2/steering/apps/private/{}",
    "V2_PUBLISHER": "/api/v2/infrastructure/publishers",
    "V2_CCI_TAG_CREATE": "/api/v2/services/cci/tags",
    "V2_CCI_TAG_UPDATE": "/api/v2/services/cci/tags/{}",
    "V1_APP_INSTANCE": "/api/v1/app_instances",
    "V2_SCIM_GROUPS": "/api/v2/scim/Groups",
    "V2_SCIM_USERS": "/api/v2/scim/Users",
    "V2_UCI_RESET": "/api/v2/incidents/users/uci/reset",
    "V2_CCI_APP": "/api/v2/services/cci/app",
    "V2_CCI_DOMAINS": "/api/v2/services/cci/domain",
    "V2_CCI_TAGS": "/api/v2/services/cci/tags",
    "V2_UCI_IMPACT": "/api/v2/incidents/user/uciimpact",
    "V2_GET_UCI": "/api/v2/incidents/uba/getuci",
}
ERROR_TAG_EXISTS = (
    "Tag provided is already present. Hence use PATCH method to add "
    "existing tag to the list of apps/ids"
)
ERROR_APP_DOES_NOT_EXIST = "No records matched"
SUCCESS = "Success"
TAG_NOT_FOUND = "Tag provided is not present"
TAG_EXISTS = "Tag provided is already present"
# Bulk actions batch size
ADD_REMOVE_USER_BATCH_SIZE = 5000
APP_INSTANCE_BATCH_SIZE = 500
TAG_APP_BATCH_SIZE = 100
TAG_APP_TAG_LENGTH = 75
