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

CTE Imperva Plugin constants.
"""

MODULE_NAME = "CTE"
PLATFORM_NAME = "Imperva"
PLUGIN_VERSION = "1.0.0"
MAXIMUM_CE_VERSION = "5.1.2"
MAX_API_CALLS = 4
RETRACTION = "Retraction"
DEFAULT_SLEEP_TIME = 60
INTEGER_THRESHOLD = 1800
IMPERVA_API_BASE_URL = "https://api.imperva.com"
IMPERVA_INCIDENT_URL = (
   "https://management.service.imperva.com/attack-analytics/"
   "incident-details/{incident_id}"
)
IMPERVA_INCIDENT_ENDPOINT = (
   f"{IMPERVA_API_BASE_URL}/analytics/v1/incidents"
)
ENABLE_TAGGING_VALUES = {"Yes": "yes", "No": "no"}
CHUNK_HOURS = 24
