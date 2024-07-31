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

URE CrowdStrike Constants module.
"""

PAGE_SIZE = 5000
BATCH_SIZE = 1000
MAC_PUT_DIR = r"/Library/Application Support/Netskope/STAgent"
WINDOWS_PUT_DIR = r"C:\Program Files (x86)\Netskope\STAgent"  # noqa
PLUGIN_NAME = "CrowdStrike"
PLATFORM_NAME = "CrowdStrike"
PLUGIN_VERSION = "1.3.1"
MODULE_NAME = "URE"
MAX_API_CALLS = 3
DEFAULT_WAIT_TIME = 60
MAX_RETRY_AFTER_IN_MIN = 5
CROWDSTRIKE_DATE_FORMAT = r"%Y-%m-%dT%H:%M:%SZ"
COMMAND_TIMEOUT = 60
COMMAND_WAIT = 6
SCORE_NORMALIZE_MULTIPLIER = 10
SCRIPT_PERMISSION_TYPE = "public"
SCORE_TO_FILE_MAPPING = {
    "1_25": "crwd_zta_1_25.txt",
    "26_50": "crwd_zta_26_50.txt",
    "51_75": "crwd_zta_51_75.txt",
    "76_100": "crwd_zta_76_100.txt",
}
WINDOWS_REMOVE_FILE_SCRIPT_NAME = "Windows Score File Removal Script"
MAC_REMOVE_FILE_SCRIPT_NAME = "Mac Score File Removal Script"
BASE_URLS = [
    "https://api.crowdstrike.com",
    "https://api.us-2.crowdstrike.com",
    "https://api.laggar.gcw.crowdstrike.com",
    "https://api.eu-1.crowdstrike.com",
]
