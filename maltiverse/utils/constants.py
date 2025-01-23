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

CTE Maltiverse Plugin constants.
"""

MODULE_NAME = "CTE"
PLATFORM_NAME = "Maltiverse"
PLUGIN_VERSION = "1.0.0"
MAX_API_CALLS = 4
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFAULT_WAIT_TIME = 60
BASE_URL = "https://api.maltiverse.com"
CLASSIFICATIONS = ["malicious", "suspicious", "neutral"]
FEEDS = {
    'RbSs1YUBYAdeK0KL3rUf': 'Advanced Persistent Threats', 
    'xXPAOoUBqd_8q-E2ZH4Z': 'Cobalt Strike', 
    'VdhZV34B4jHUXfKt_gDi': 'Command and Controls', 
    '04xeknEB8jmkCY9eOoUv': 'Cybercrime', 
    'kskDSoEB4jHUXfKtb4IZ': 'Emotet', 
    'VFveEXsBGb1u75L8tCaY': 'Industrial Control Systems', 
    '3DyIvYAB4jHUXfKt9SQL': 'IoT', 
    'QthpV34B4jHUXfKtOw--': 'Known Attackers', 
    'xKWKangBN4Q8MD8oRYd-': 'Malicious Hostvalues', 
    'uYxZknEB8jmkCY9eQoUJ': 'Malicious IP', 
    'H4yrknEB8jmkCY9eb4aN': 'Malicious URL', 
    'WZ0XJHIB8jmkCY9eLpr0': 'Malware', 
    'ZtjCV34B4jHUXfKtjWdD': 'Malware Distribution', 
    'EIAO4HAB8jmkCY9e8HoL': 'Phishing', 
    'Ryjs1n0BGb1u75L8KpjZ': 'TOR Nodes'
}
