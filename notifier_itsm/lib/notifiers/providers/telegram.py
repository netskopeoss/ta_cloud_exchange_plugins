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

from ..core import Provider, Response, ProviderResource
from ..exceptions import ResourceError
from ..utils import requests


class TelegramMixin:
    """Shared resources between :class:`TelegramUpdates` and :class:`Telegram`"""

    base_url = "https://api.telegram.org/bot{token}"
    name = "telegram"
    path_to_errors = ("description",)


class TelegramUpdates(TelegramMixin, ProviderResource):
    """Return Telegram bot updates, correlating to the `getUpdates` method. Returns chat IDs needed to notifications"""

    resource_name = "updates"
    updates_endpoint = "/getUpdates"

    _required = {"required": ["token"]}

    _schema = {
        "type": "object",
        "properties": {"token": {"type": "string", "title": "Bot token"}},
        "additionalProperties": False,
    }

    def _get_resource(self, data: dict) -> list:
        url = self.base_url.format(token=data["token"]) + self.updates_endpoint
        response, errors = requests.get(url, path_to_errors=self.path_to_errors)
        if errors:
            raise ResourceError(
                errors=errors,
                resource=self.resource_name,
                provider=self.name,
                data=data,
                response=response,
            )
        return response.json()["result"]


class Telegram(TelegramMixin, Provider):
    """Send Telegram notifications"""

    site_url = "https://core.telegram.org/"
    push_endpoint = "/sendMessage"

    _resources = {"updates": TelegramUpdates()}

    _required = {"required": ["message", "chat_id", "token"]}
    _schema = {
        "type": "object",
        "properties": {
            "message": {"type": "string", "title": "Text of the message to be sent"},
            "token": {"type": "string", "title": "Bot token"},
            "chat_id": {
                "oneOf": [{"type": "string"}, {"type": "integer"}],
                "title": "Unique identifier for the target chat or username of the target channel "
                "(in the format @channelusername)",
            },
            "parse_mode": {
                "type": "string",
                "title": "Send Markdown or HTML, if you want Telegram apps to show bold, italic,"
                " fixed-width text or inline URLs in your bot's message.",
                "enum": ["markdown", "html"],
            },
            "disable_web_page_preview": {
                "type": "boolean",
                "title": "Disables link previews for links in this message",
            },
            "disable_notification": {
                "type": "boolean",
                "title": "Sends the message silently. Users will receive a notification with no sound.",
            },
            "reply_to_message_id": {
                "type": "integer",
                "title": "If the message is a reply, ID of the original message",
            },
        },
        "additionalProperties": False,
    }

    def _prepare_data(self, data: dict) -> dict:
        data["text"] = data.pop("message")
        return data

    def _send_notification(self, data: dict) -> Response:
        token = data.pop("token")
        url = self.base_url.format(token=token) + self.push_endpoint
        response, errors = requests.post(
            url, json=data, path_to_errors=self.path_to_errors
        )
        return self.create_response(data, response, errors)
