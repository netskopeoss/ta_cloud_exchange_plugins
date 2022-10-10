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

"""Notifier CTO plugin."""


import uuid
from typing import List, Dict
from functools import partial
import requests

from netskope.integrations.itsm.plugin_base import (
    PluginBase,
    ValidationResult,
    MappingField,
)
from netskope.integrations.itsm.models import (
    FieldMapping,
    Queue,
    Task,
    Alert,
    TaskStatus,
)

from .lib.notifiers import get_notifier
from .lib.notifiers.exceptions import BadArguments
from .lib.notifiers.utils import requests as notifier_requests


MAPPED_FIELDS = {
    "email": ["message", "subject", "to_"],
    "gitter": ["message"],
    "gmail": ["message", "subject", "to_"],
    "hipchat": ["message"],
    "join": ["message", "clipboard", "title"],
    "mailgun": ["message", "html", "subject"],
    "pagerduty": ["message"],
    "popcornnotify": ["message", "subject"],
    "pushbullet": ["message", "title", "url"],
    "pushover": ["message", "title", "url", "url_title"],
    "simplepush": ["message", "title"],
    "slack": ["message"],
    "statuspage": ["message", "body"],
    "telegram": ["message"],
    "twilio": ["message"],
    "zulip": ["message", "subject"],
}


PASSWORD_FIELDS = {
    "email": ["password"],
    "gitter": ["token"],
    "gmail": ["password"],
    "hipchat": ["token"],
    "join": ["apikey"],
    "mailgun": ["api_key"],
    "pagerduty": ["routing_key"],
    "popcornnotify": ["api_key"],
    "pushbullet": ["token"],
    "pushover": ["token"],
    "simplepush": ["key"],
    "slack": [],
    "statuspage": ["api_key"],
    "telegram": ["token"],
    "twilio": ["auth_token"],
    "zulip": ["api_key"],
}

EXCLUDED_FIELDS = {
    "email": ["attachments"],
    "gitter": [],
    "gmail": ["attachments"],
    "hipchat": [],
    "join": [],
    "mailgun": ["attachment"],
    "pagerduty": [],
    "popcornnotify": [],
    "pushbullet": ["type_"],
    "pushover": ["attachment"],
    "simplepush": [],
    "slack": [],
    "statuspage": [],
    "telegram": [],
    "twilio": [],
    "zulip": [],
}


class NotifierPlugin(PluginBase):
    """Jira plugin implementation."""

    def _get_notifier(self, configuration):
        """Get notifier object from configuration."""
        platform = configuration.get("platform").get("name")
        notifier = get_notifier(platform)
        if notifier is None:
            raise ValueError("Notifier not found.")
        return notifier

    def _remove_empties(self, data):
        """Remove empty values from dictionary."""
        new_dict = {}
        for key, value in data.items():
            if type(value) is str:
                if value.strip() != "":
                    new_dict[key] = value
            elif type(value) in [int, bool]:
                new_dict[key] = value
        return new_dict

    def create_task(self, alert: Alert, mappings: Dict, queue: Queue) -> Task:
        """Create an issue/ticket on Jira platform."""
        notifier = self._get_notifier(self.configuration)
        params = {**self.configuration.get("params"), **mappings}
        filtered_args = self._get_args_from_params(params)
        notifier_requests.get = partial(
            notifier_requests.get, proxies=self.proxy
        )
        notifier_requests.post = partial(
            notifier_requests.post, proxies=self.proxy
        )
        requests.get = partial(requests.get, proxies=self.proxy)
        requests.post = partial(requests.post, proxies=self.proxy)
        response = notifier.notify(**filtered_args)
        response.raise_on_errors()
        if response.ok:
            return Task(id=uuid.uuid4().hex, status=TaskStatus.NOTIFICATION)

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync all task states."""
        return tasks

    def update_task(
        self, task: Task, alert: Alert, mappings: Dict, queue: Queue
    ) -> Task:
        """Add a comment in existing Jira issue."""
        return task

    def _get_args_from_params(self, params: dict) -> dict:
        """Get dictionary that can be unpacked and used as argument."""
        new_dict = {}
        for key, value in params.items():
            if value == "boolean_true":
                new_dict[key] = True
            elif value == "boolean_false":
                new_dict[key] = False
            else:
                new_dict[key] = value
        return self._remove_empties(new_dict)

    def validate_step(
        self, name: str, configuration: dict
    ) -> ValidationResult:
        """Validate a given configuration step."""
        if name != "params":
            return ValidationResult(
                success=True, message="Validation successful."
            )
        platform = configuration.get("platform").get("name")
        notifier = self._get_notifier(configuration)
        mapped_fields = {key: "" for key in MAPPED_FIELDS.get(platform, [])}
        args = self._get_args_from_params(configuration.get("params", {}))
        args = {**args, **mapped_fields}
        try:
            notifier._validate_data(args)
        except BadArguments as ex:
            return ValidationResult(success=False, message=ex.message)
        return ValidationResult(success=True, message="Validation successful.")

    def get_available_fields(self, configuration: dict) -> List[MappingField]:
        """Get list of all the mappable fields."""
        platform = configuration.get("platform").get("name")
        notifier = self._get_notifier(configuration)
        args = notifier.arguments
        fields = []
        keys = set()
        for key, val in args.items():
            if val.get("duplicate", False):
                continue
            if key in keys:
                continue
            if key not in MAPPED_FIELDS.get(platform, []):
                continue
            keys.add(key)
            fields.append(
                MappingField(label=" ".join(key.split("_")).title(), value=key)
            )
        return fields

    def get_default_mappings(
        self, configuration: dict
    ) -> Dict[str, List[FieldMapping]]:
        """Get default mappings."""
        platform = configuration.get("platform").get("name")
        return {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    custom_message="$user",
                    destination_field=field,
                )
                if field == "to_"
                else FieldMapping(
                    extracted_field="custom_message",
                    custom_message="",
                    destination_field=field,
                )
                for field in MAPPED_FIELDS.get(platform, [])
            ],
            "dedup": [],
        }

    def get_fields(self, name: str, configuration: dict):
        """Get available fields."""
        if name == "params":
            platform = configuration.get("platform").get("name")
            notifier = self._get_notifier(configuration)
            args = notifier.arguments
            fields = []
            keys = set()
            for key, val in args.items():
                if val.get("duplicate", False):
                    continue
                if key in keys:
                    continue
                if key in MAPPED_FIELDS.get(
                    platform, []
                    ) or key in EXCLUDED_FIELDS.get(platform, []):
                    continue
                keys.add(key)
                if val.get("type") == "string":
                    if "enum" in val:
                        field = {
                            "label": " ".join(key.split("_")).title(),
                            "key": key,
                            "type": "choice",
                            "description": f"({key}) {val.get('title', '')}",
                            "choices": [
                                {"key": key.title(), "value": key}
                                for key in val.get("enum", [])
                            ],
                            "default": val.get("enum")[0]
                            if val.get("enum", [])
                            else "",
                        }
                    else:
                        field = {
                            "label": " ".join(key.split("_")).title(),
                            "key": key,
                            "type": "password"
                            if key in PASSWORD_FIELDS.get(platform, [])
                            else "text",
                            "description": f"({key}) {val.get('title', '')}",
                        }
                    fields.append(field)
                elif val.get("type") == "integer":
                    field = {
                        "label": " ".join(key.split("_")).title(),
                        "key": key,
                        "type": "number",
                        "description": f"({key}) {val.get('title', '')}",
                    }
                    fields.append(field)
                elif val.get("oneOf") is not None:
                    string_fields = list(
                        filter(
                            lambda x: x.get("type") == "string",
                            val.get("oneOf", []),
                        )
                    )
                    if not string_fields:
                        continue
                    string_field = string_fields.pop()
                    fields.append(
                        {
                            "label": " ".join(key.split("_")).title(),
                            "key": key,
                            "type": "text",
                            "description": f"({key}) {string_field.get('title', '')}",
                        }
                    )
                elif val.get("type") == "boolean":
                    field = {
                        "label": " ".join(key.split("_")).title(),
                        "key": key,
                        "type": "choice",
                        "choices": [
                            {"key": "Yes", "value": "boolean_true"},
                            {"key": "No", "value": "boolean_false"},
                        ],
                        "default": "boolean_true",
                        "description": f"({key}) {val.get('title', '')}",
                    }
                    fields.append(field)
            return fields
        else:
            raise NotImplementedError()

    def get_queues(self) -> List[Queue]:
        """Get list of Jira projects as queues."""
        return [Queue(label="Notification", value="notification")]
