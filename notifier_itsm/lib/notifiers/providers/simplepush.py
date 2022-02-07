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


class SimplePush(Provider):
    """Send SimplePush notifications"""

    base_url = "https://api.simplepush.io/send"
    site_url = "https://simplepush.io/"
    name = "simplepush"

    _required = {"required": ["key", "message"]}
    _schema = {
        "type": "object",
        "properties": {
            "key": {"type": "string", "title": "your user key"},
            "message": {"type": "string", "title": "your message"},
            "title": {"type": "string", "title": "message title"},
            "event": {"type": "string", "title": "Event ID"},
        },
        "additionalProperties": False,
    }

    def _prepare_data(self, data: dict) -> dict:
        data["msg"] = data.pop("message")
        return data

    def _send_notification(self, data: dict) -> Response:
        path_to_errors = ("message",)
        response, errors = requests.post(
            self.base_url, data=data, path_to_errors=path_to_errors
        )
        return self.create_response(data, response, errors)
