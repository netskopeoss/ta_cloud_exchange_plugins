"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

CRE Cisco ISE Plugin constants.
"""

MODULE_NAME = "CRE"
PLATFORM_NAME = "Cisco ISE"
PLUGIN_VERSION = "1.0.0"
PLUGIN_NAME = "Cisco ISE"

HOST_ENTITY_NAME = "Hosts"

# Configuration keys.
ISE_HOST_KEY = "ise_host"
ERS_USERNAME_KEY = "ers_username"
ERS_PASSWORD_KEY = "ers_password"
SGT_IP_MAPPING_SOURCE = "sgt_ip_mapping_source"
SOURCE_PXGRID = "pxgrid"
SOURCE_ERS = "ers"
SUPPORTED_SOURCES = [SOURCE_PXGRID, SOURCE_ERS]

SOURCE_LABEL_PXGRID = "Live Sessions"
SOURCE_LABEL_ERS = "IP SGT Static Mapping"

SGT_NAME_FILTER = "sgt_name_filter"

# Plugin-level SSL validation controls (independent of Cloud
# Exchange's own per-configuration 'Enable SSL Certificate
# Validation' checkbox) - lets a customer keep validation on while
# trusting Cisco ISE's own certificate (typically self-signed).
SSL_VALIDATION_MODE = "ssl_validation_mode"
SSL_VALIDATION_DISABLE = "disable"
SSL_VALIDATION_SYSTEM_DEFAULT = "system_default"
SSL_VALIDATION_CUSTOM_CERT = "custom_cert"
SUPPORTED_SSL_VALIDATION_MODES = [
    SSL_VALIDATION_DISABLE,
    SSL_VALIDATION_SYSTEM_DEFAULT,
    SSL_VALIDATION_CUSTOM_CERT,
]
# Single certificate field: the user concatenates the ERS and (if
# 'Live Sessions' is selected) pxGrid certificates into one textarea.
# Cloud Exchange does not support dynamic field rendering driven by
# more than one configuration field, so a single always-shown field
# gated only on SSL_VALIDATION_MODE is used instead of two fields
# whose visibility also depended on SGT_IP_MAPPING_SOURCE.
CERTIFICATE_KEY = "certificate"

# Storage keys caching the on-disk custom SSL certificate file written
# by CiscoISEPlugin._get_or_create_ssl_cert_file(), so it's written
# once per distinct certificate value rather than on every
# validate()/fetch_records() call. Removed by cleanup() on delete.
SSL_CERT_FILE_KEY = "ssl_cert_file_path"
SSL_CERT_HASH_KEY = "ssl_cert_hash"

# ERS filter syntax (query param 'filter'): '<attribute>.<OPERATOR>.<value>'.
ERS_SGT_NAME_FILTER_TEMPLATE = "sgtName.EQ.{sgt_name}"
# pxGrid getSessions filter expression (request body 'filter' field).
PXGRID_SGT_FILTER_TEMPLATE = "ctsSecurityGroup == '{sgt_name}'"

# Retry and timeout constants
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
MAX_WAIT_TIME = 300
DEFAULT_REQUEST_TIMEOUT = 300

# Port constants
ERS_PORT = 9060
PXGRID_PORT = 8910

# Page size for ERS pagination (max allowed by API)
ERS_PAGE_SIZE = 100

# pxGrid service name for session directory
PXGRID_SERVICE_NAME = "com.cisco.ise.session"

# Storage key constants for pxGrid credential persistence
PXGRID_NODE_NAME_KEY = "pxgrid_node_name"
PXGRID_PASSWORD_KEY = "pxgrid_password"
PXGRID_SECRET_KEY = "pxgrid_secret"
PXGRID_REST_BASE_URL_KEY = "pxgrid_rest_base_url"
PXGRID_PROVIDER_NODE_KEY = "pxgrid_provider_node_name"

# ERS/pxGrid URL templates. 'ise_host' is expected to already include
# its 'https://' scheme (configured that way by the user - see
# manifest.json's 'ISE Primary Admin Node Base URL' field), so none of
# these templates add one.
ERS_BASE_URL = "{ise_host}:{port}/ers/config"
ERS_SGMAPPING_ENDPOINT = (
    "{ise_host}:{port}/ers/config/sgmapping"
)
ERS_SGT_ENDPOINT = (
    "{ise_host}:{port}/ers/config/sgt"
)

# pxGrid control URL templates
PXGRID_CONTROL_BASE_URL = (
    "{ise_host}:{port}/pxgrid/control"
)
PXGRID_ACCOUNT_CREATE_ENDPOINT = (
    "{ise_host}:{port}/pxgrid/control/AccountCreate"
)
PXGRID_ACCOUNT_ACTIVATE_ENDPOINT = (
    "{ise_host}:{port}/pxgrid/control/AccountActivate"
)
PXGRID_SERVICE_LOOKUP_ENDPOINT = (
    "{ise_host}:{port}/pxgrid/control/ServiceLookup"
)
PXGRID_ACCESS_SECRET_ENDPOINT = (
    "{ise_host}:{port}/pxgrid/control/AccessSecret"
)

# pxGrid data-plane endpoint for getSessions. Called directly against
# the configured ISE host on the pxGrid control port - NOT against the
# 'restBaseUrl' returned by ServiceLookup, which can point at an
# internal hostname that isn't reachable from the Cloud Exchange host
# (confirmed against a live ISE instance). ServiceLookup is still
# required beforehand, but only to obtain the peer node name needed by
# AccessSecret.
PXGRID_GET_SESSIONS_PATH = "/getSessions"
PXGRID_GET_SESSIONS_ENDPOINT = (
    "{ise_host}:{port}/pxgrid/mnt/sd" + PXGRID_GET_SESSIONS_PATH
)


# ERS required headers
ERS_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}

# pxGrid control headers
PXGRID_CONTROL_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# Field mapping for the merged 'Hosts' entity's pxGrid-sourced fields.
# Maps entity field name -> API response key path (dot notation for nesting).
# 'Security Group Tag', 'IP Address(es)', 'Security Group Tag Value',
# 'User Name', 'Secondary Security Groups', 'Authorization Profiles' and
# 'Last Seen' need custom handling and are built directly in main.py.
SESSION_FIELD_MAPPING = {
    "MAC Address": {
        "key": "macAddress",
        "default": None,
    },
    "Session State": {
        "key": "state",
        "default": None,
    },
    "NAS IP Address": {
        "key": "nasIpAddress",
        "default": None,
    },
}

# Account state values returned by AccountActivate
PXGRID_STATE_ENABLED = "ENABLED"
PXGRID_STATE_PENDING = "PENDING"
PXGRID_STATE_DISABLED = "DISABLED"
