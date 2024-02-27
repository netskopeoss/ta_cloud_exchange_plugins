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

CTE Commvault Plugin's Constant file.
"""
import re
from netskope.integrations.cte.models import SeverityType

MODULE_NAME = "CTE"
PLUGIN_NAME = "Commvault"
PLATFORM_NAME = "Commvault"
PLUGIN_VERSION = "1.0.0"
COMMVAULT_TO_NETSCOPE_SEVERITY = {
    -1: SeverityType.UNKNOWN,
    0: SeverityType.LOW,
    1: SeverityType.LOW,
    2: SeverityType.LOW,
    3: SeverityType.LOW,
    4: SeverityType.HIGH,
    5: SeverityType.HIGH,
    6: SeverityType.HIGH,
    7: SeverityType.HIGH,
    8: SeverityType.CRITICAL,
    9: SeverityType.CRITICAL,
    10: SeverityType.CRITICAL,
}
MAX_PAGE_SIZE = 100
MAX_PULL_PAGE_SIZE = 2000
MAX_API_CALLS = 4
MAX_INDICATOR_THRESHOLD = 100000
BATCH_SIZE = 1000
DEFAULT_WAIT_TIME = 30
TOKEN_VALIDITY_DAYS = 7
TOKEN_EXPIRY_BUFFER_SECONDS = 2 * 24 * 60 * 60  # 2 days
RE_DEL_HTML = re.compile(r"(<span[^>]*>(.+?)</span>)|(<.*?>)")
RE_GET_LINK = re.compile(r"<a[^>]*href=(.+?)>.+?</a>")
ACCESS_TOKEN_NAME = "netskope-access-token"
ANOMALOUS_EVENTCODE_STRINGS = {
    "7:333": {"comments": RE_DEL_HTML, "extended_info": RE_GET_LINK},
    "14:336": {"comments": RE_DEL_HTML, "extended_info": RE_GET_LINK},
    "14:337": {"comments": RE_DEL_HTML, "extended_info": RE_GET_LINK},
    "69:59": {"comments": RE_DEL_HTML, "extended_info": RE_GET_LINK},
    "69:60": {"comments": RE_DEL_HTML, "extended_info": RE_GET_LINK},
}
