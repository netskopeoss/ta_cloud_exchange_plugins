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

CRE JAMF Plugin constants.
"""

PLATFORM_NAME = "Jamf"
MODULE_NAME = "CRE"
PLUGIN_VERSION = "1.0.0"
MAX_API_CALLS = 4
ACTION_ENDPOINT = "risk/v1/override"
DEVICE_ENDPOINT = "risk/v2/devices"
LOGIN_ENDPOINT = "v1/login"
DEFAULT_RETRY_AFTER_TIME = 60000
PAGE_SIZE = 99
DEVICE_FIELD_MAPPING = {
    "Device ID": {"key": "guid"},
    "User Name": {"key": "user.name"},
    "User Email": {"key": "user.email"},
    "Device Name": {"key": "info.device.deviceName"},
    "Device System Version": {"key": "info.device.deviceSystemVersion"},
    "App Name": {"key": "info.app.name"},
    "App Version": {"key": "info.app.version"},
    "OS Type": {"key": "info.device.osType"},
    "Device Platform": {"key": "info.device.platform"},
    "Device Risk Category": {"key": "riskCategory"},
}
