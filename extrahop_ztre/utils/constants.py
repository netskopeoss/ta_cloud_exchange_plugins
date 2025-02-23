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

CRE ExtraHop Reveal(x) 360 plugin constants.
"""

PLATFORM_NAME = "ExtraHop Reveal(x) 360"
MODULE_NAME = "CRE"
PLUGIN_VERSION = "1.0.0"
DEFAULT_WAIT_TIME = 60
MAX_API_CALLS = 4
PAGE_LIMIT = 10000
DEVICE_BATCH_LIMIT = 10000
INTEGER_THRESHOLD = 4611686018427387904
ENTITY_NAME = "Cloud Workloads (Devices)"
DETECTION_FIELD_MAPPING = {
    "Detection ID": {"key": "id", "transformation": "integer"},
    "Detection Title": {"key": "title"},
    "Detection Risk Score": {
        "key": "risk_score",
        "transformation": "integer",
    },
    "Detection Type": {"key": "type"},
    "Detection Status": {"key": "status"},
    "URL": {"key": "url"},
}

DEVICE_FIELD_MAPPING = {
    "Device ID": {"key": "id", "transformation": "integer"},
    "VPC ID": {"key": "vpc_id"},
    "Default Name": {"key": "default_name"},
    "Subnet ID": {"key": "subnet_id"},
    "DHCP Name": {"key": "dhcp_name"},
    "VLAN ID": {"key": "vlanid", "transformation": "integer"},
    "Vendor": {"key": "vendor"},
    "MAC Address": {"key": "macaddr"},
    "DNS Name": {"key": "dns_name"},
    "IPv4 Address": {"key": "ipaddr4"},
    "IPv6 Address": {"key": "ipaddr6"},
    "Custom Type": {"key": "custom_type"},
    "Custom Name": {"key": "custom_name"},
    "Display Name": {"key": "display_name"},
    "Critical": {"key": "critical", "transformation": "string"},
    "Discovery ID": {"key": "discovery_id"},
    "ExtraHop ID": {"key": "extrahop_id"},
    "Cloud Instance Name": {"key": "cloud_instance_name"},
    "Cloud Instance Type": {"key": "cloud_instance_type"},
    "Cloud Instance ID": {"key": "cloud_instance_id"},
    "Cloud Account": {"key": "cloud_account"},
    "NetBIOS Name": {"key": "netbios_name"},
    "Device Class": {"key": "device_class"},
    "Analysis": {"key": "analysis"},
    "Analysis Level": {"key": "analysis_level"},
}
