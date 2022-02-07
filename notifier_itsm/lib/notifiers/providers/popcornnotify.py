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
"""

from ..core import Provider, Response
from ..utils import requests
from ..utils.schema.helpers import one_or_more, list_to_commas


class PopcornNotify(Provider):
    """Send PopcornNotify notifications"""

    base_url = "https://popcornnotify.com/notify"
    site_url = "https://popcornnotify.com/"
    name = "popcornnotify"
    path_to_errors = ("error",)

    _required = {"required": ["message", "api_key", "recipients"]}

    _schema = {
        "type": "object",
        "properties": {
            "message": {"type": "string", "title": "The message to send"},
            "api_key": {"type": "string", "title": "The API key"},
            "recipients": one_or_more(
                {
                    "type": "string",
                    "format": "email",
                    "title": "The recipient email address or phone number. Or an array of\
                        email addresses and phone numbers",
                }
            ),
            "subject": {
                "type": "string",
                "title": "The subject of the email. It will not be included in text messages.",
            },
        },
    }

    def _prepare_data(self, data: dict) -> dict:
        if isinstance(data["recipients"], str):
            data["recipients"] = [data["recipients"]]
        data["recipients"] = list_to_commas(data["recipients"])
        return data

    def _send_notification(self, data: dict) -> Response:
        response, errors = requests.post(
            url=self.base_url, json=data, path_to_errors=self.path_to_errors
        )
        return self.create_response(data, response, errors)
