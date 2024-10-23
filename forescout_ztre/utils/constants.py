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

CRE Forescout Constants module.
"""

PLUGIN_NAME = "Forescout"
PLATFORM_NAME = "Forescout"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "CRE"
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
MAX_RETRY_AFTER_IN_MIN = 5
INTEGER_THRESHOLD = 4611686018427387904
HOST_MAPPING = {
    "Host ID": {"key": "host.id"},
    "Host Mac Address": {"key": "host.mac"},
    "OT Security Risk": {
        "key": "host.fields.otsm_details_security_risk.value",
        "transformation": "float",
    },
    "OT Criticality": {
        "key": "host.fields.otsm_details_criticality.value",
        "transformation": "integer",
    },
    "OT Operational Risk": {
        "key": "host.fields.otsm_details_operational_risk.value",
        "transformation": "float",
    },
    "CYSIV Risk Severity": {"key": "host.fields.cysiv_risk_severity.value"},
    "CYSIV Risk Device Criticality": {
        "key": "host.fields.cysiv_risk_device_criticality.value"
    },
    "Model Classification Score": {
        "key": "host.fields.model_classification_score.value",
        "transformation": "integer",
    },
    "OS Discovery Score": {
        "key": "host.fields.os_discovery_score.value",
        "transformation": "integer",
    },
    "Prim Discovery Score": {
        "key": "host.fields.prim_discovery_score.value",
        "transformation": "integer",
    },
    "Vendor Classification Score": {
        "key": "host.fields.vendor_classification_score.value",
        "transformation": "integer",
    },
    "Classification Score": {
        "key": "host.fields.classification_score.value",
        "transformation": "integer",
    },
    "Firmware Classification Score": {
        "key": "host.fields.firmware_classification_score.value",
        "transformation": "integer",
    },
    "Discovery Score": {
        "key": "host.fields.discovery_score.value",
        "transformation": "integer",
    },
    "CYSIV Risk Score": {
        "key": "host.fields.cysiv_risk_score.value",
        "transformation": "float",
    },
}
