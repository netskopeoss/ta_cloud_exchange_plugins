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


class GitterMixin:
    """Shared attributes between :class:`~notifiers.providers.gitter.GitterRooms` and
    :class:`~notifiers.providers.gitter.Gitter`"""

    name = "gitter"
    path_to_errors = "errors", "error"
    base_url = "https://api.gitter.im/v1/rooms"

    def _get_headers(self, token: str) -> dict:
        """
        Builds Gitter requests header bases on the token provided

        :param token: App token
        :return: Authentication header dict
        """
        return {"Authorization": f"Bearer {token}"}


class GitterRooms(GitterMixin, ProviderResource):
    """Returns a list of Gitter rooms via token"""

    resource_name = "rooms"

    _required = {"required": ["token"]}

    _schema = {
        "type": "object",
        "properties": {
            "token": {"type": "string", "title": "access token"},
            "filter": {"type": "string", "title": "Filter results"},
        },
        "additionalProperties": False,
    }

    def _get_resource(self, data: dict) -> list:
        headers = self._get_headers(data["token"])
        filter_ = data.get("filter")
        params = {"q": filter_} if filter_ else {}
        response, errors = requests.get(
            self.base_url,
            headers=headers,
            params=params,
            path_to_errors=self.path_to_errors,
        )
        if errors:
            raise ResourceError(
                errors=errors,
                resource=self.resource_name,
                provider=self.name,
                data=data,
                response=response,
            )
        rsp = response.json()
        return rsp["results"] if filter_ else rsp


class Gitter(GitterMixin, Provider):
    """Send Gitter notifications"""

    message_url = "/{room_id}/chatMessages"
    site_url = "https://gitter.im"

    _resources = {"rooms": GitterRooms()}

    _required = {"required": ["message", "token", "room_id"]}
    _schema = {
        "type": "object",
        "properties": {
            "message": {"type": "string", "title": "Body of the message"},
            "token": {"type": "string", "title": "access token"},
            "room_id": {
                "type": "string",
                "title": "ID of the room to send the notification to",
            },
        },
        "additionalProperties": False,
    }

    def _prepare_data(self, data: dict) -> dict:
        data["text"] = data.pop("message")
        return data

    @property
    def metadata(self) -> dict:
        metadata = super().metadata
        metadata["message_url"] = self.message_url
        return metadata

    def _send_notification(self, data: dict) -> Response:
        room_id = data.pop("room_id")
        url = self.base_url + self.message_url.format(room_id=room_id)

        headers = self._get_headers(data.pop("token"))
        response, errors = requests.post(
            url, json=data, headers=headers, path_to_errors=self.path_to_errors
        )
        return self.create_response(data, response, errors)
