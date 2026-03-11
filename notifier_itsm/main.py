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

Notifier CTO plugin."""

import uuid
import time
import traceback
import json
import hmac
import hashlib
from typing import List, Dict, Tuple
from fastapi import HTTPException
from functools import partial
import requests
import urllib.parse

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
    Severity,
    UpdatedTaskValues,
)
from netskope.integrations.itsm.utils import get_task_from_query

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

MODULE_NAME = "CTO"
PLATFORM_NAME = "Notifier"
PLUGIN_VERSION = "1.2.0"
DYNAMIC_FIELDS = ["status", "severity", "assignee"]
WEBHOOK_FIELDS = ["webhook_id", "enable_webhook", "token", "signing_secret"]


class NotifierPlugin(PluginBase):
    """Notifier plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Notifier plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = NotifierPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

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
            else:
                new_dict[key] = value
        return new_dict

    def normalize_value(self, value: str) -> str:
        """Normalize a string by converting to lowercase
        and replacing spaces with underscores.

        Args:
            value (str): String to normalize.

        Returns:
            str: Normalized string.
        """
        if not isinstance(value, str):
            return value
        return value.strip().lower().replace(" ", "_")

    def prepare_block(self, field_name: str, current_value: str):
        """Prepare json payload for dynamic fields.

        Args:
            field_name (str): Field name.
            current_value (str): Current value of the field.

        Returns:
            dict: Json payload for dynamic fields.
        """

        normalized_current_value = current_value
        if field_name == "status" or field_name == "severity":
            normalized_current_value = self.normalize_value(current_value)
            available_options = (
                [
                    x.value
                    for x in TaskStatus
                    if x not in [TaskStatus.NOTIFICATION, TaskStatus.FAILED]
                ]
                if field_name == "status"
                else [x.value for x in Severity]
            )
            default_option = (
                TaskStatus.OTHER.value
                if field_name == "status"
                else Severity.OTHER.value
            )
            block = {
                "type": "section",
                "block_id": f"block_{field_name}",
                "text": {
                    "type": "plain_text",
                    "text": f"Alert/Event {field_name.capitalize()}",
                },
                "accessory": {
                    "action_id": f"change_{field_name}",
                    "type": "static_select",
                    "initial_option": {
                        "text": {
                            "type": "plain_text",
                            "text": (
                                normalized_current_value
                                if normalized_current_value
                                in available_options
                                else default_option
                            ),
                        },
                        "value": (
                            normalized_current_value
                            if normalized_current_value in available_options
                            else default_option
                        ),
                    },
                    "placeholder": {
                        "type": "plain_text",
                        "text": "Select an item",
                    },
                    "options": [
                        {
                            "text": {"type": "plain_text", "text": option},
                            "value": option,
                        }
                        for option in available_options
                    ],
                },
            }
            return block
        elif field_name == "assignee":
            block = {
                "type": "input",
                "block_id": f"block_{field_name}",
                "label": {
                    "type": "plain_text",
                    "text": f"Alert/Event {field_name.capitalize()}",
                },
                "dispatch_action": True,
                "element": {
                    "type": "plain_text_input",
                    "dispatch_action_config": {
                        "trigger_actions_on": ["on_enter_pressed"]
                    },
                    "initial_value": (
                        normalized_current_value
                        if normalized_current_value
                        else ""
                    ),
                    "action_id": f"change_{field_name}",
                    "placeholder": {
                        "type": "plain_text",
                        "text": "Enter an assignee",
                    },
                },
            }
            return block

    def _check_status_severity_from_queue_mapping(
        self, mappings: Dict
    ) -> Tuple[str, str]:
        """
        Check if status and severity are valid.

        Args:
            status_mapping (str): Status mapping.
            severity_mapping (str): Severity mapping.
        """
        severity = self.normalize_value(mappings.get("severity"))
        state = self.normalize_value(mappings.get("status"))
        status_available_options = [
            x.value
            for x in TaskStatus
            if x not in [TaskStatus.NOTIFICATION, TaskStatus.FAILED]
        ]
        severity_available_options = [x.value for x in Severity]

        if severity not in severity_available_options:
            severity = Severity.OTHER.value

        if state not in status_available_options:
            state = TaskStatus.OTHER.value

        return state, severity

    def create_task(self, alert: Alert, mappings: Dict, queue: Queue) -> Task:
        """Create an issue/ticket on Jira platform.
        Args:
            alert (Alert): Alert object.
            mappings (Dict): Mappings object.
            queue (Queue): Queue object.

        Returns:
            Task: Task object.
        """

        notifier = self._get_notifier(self.configuration)
        additional_payload = {}
        mapping_copy = mappings.copy()
        if self.configuration.get("platform").get("name") == "slack":
            additional_payload = {
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": mappings.get("message"),
                        },
                    },
                ]
            }
            for field in DYNAMIC_FIELDS:
                additional_payload["blocks"].append(
                    self.prepare_block(field, mappings.get(field))
                )
                mappings.pop(field, None)

        params = {**self.configuration.get("params"), **mappings}

        # Generate notification id.
        notification_id = uuid.uuid4().hex

        if additional_payload:
            params["message"] = notification_id
            params.update(additional_payload)

        filtered_args = self._get_args_from_params(
            params, self.configuration.get("platform", {}).get("name")
        )

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
            if self.configuration.get("platform").get("name") == "slack":
                assignee = mapping_copy.get("assignee")
                (
                    state,
                    severity,
                ) = self._check_status_severity_from_queue_mapping(mapping_copy)

                task = Task(
                    id=notification_id,
                    status=state,
                    severity=severity,
                    dataItem=alert,
                )

                task = self.update_task_details(
                    task,
                    {
                        "severity": severity,
                        "status": state,
                        "assignee": assignee,
                    },
                    "severity",
                    "status",
                    "assignee",
                )
                return task
            else:
                return Task(id=notification_id, status=TaskStatus.NOTIFICATION)

    def extract_information(self, data):
        """Extract dynamic fields and changes along with ticket id from
         parsed data"""
        parsed_data = json.loads(
            urllib.parse.parse_qs(data).get(b"payload", ["{}"])[0]
        )

        token = self.configuration.get("params", {}).get("token")
        if parsed_data.get("token") != token:
            return None, {}, False
        notification_id = parsed_data.get("message", {}).get("text", None)
        field_values = {}
        for field in DYNAMIC_FIELDS:
            field_payload_value = None
            is_value_exists = False
            if (
                field_data := parsed_data.get("state", {})
                .get("values", {})
                .get(f"block_{field}", {})
                .get(f"change_{field}", {})
            ):
                if field_data.get("type", None) == "static_select":
                    is_value_exists = True
                    field_payload_value = field_data.get(
                        "selected_option", {}
                    ).get("value", None)
                elif field_data.get("type", None) == "plain_text_input":
                    is_value_exists = True
                    field_payload_value = field_data.get("value", None)
            if is_value_exists:
                field_values[field] = field_payload_value
        return notification_id, field_values, True

    def update_task_details(
        self,
        task: dict,
        slack_data: dict,
        severity_field,
        status_field,
        assignee_field,
    ):
        """Update task fields with ServiceNow data.

        Args:
            task (Task): CE task.
            slack_data (dict): Updated data from servicenow.
            severity_field (str): Severity field based on table.
            status_field (str): Status field based on table.
            assignee_field (str): Assignee field based on table.
        """
        if task.dataItem and task.dataItem.rawData:
            old_status = task.dataItem.rawData.get("status", TaskStatus.OTHER)
            old_severity = task.dataItem.rawData.get(
                "severity", Severity.OTHER
            )

            old_severity = self.normalize_value(old_severity)
            old_status = self.normalize_value(old_status)

            if task.updatedValues:
                task.updatedValues.oldSeverity = (
                    old_severity
                    if old_severity.upper() in Severity.__members__
                    else Severity.OTHER
                )
                task.updatedValues.oldStatus = (
                    old_status
                    if old_status.upper() in TaskStatus.__members__
                    else TaskStatus.OTHER
                )
                task.updatedValues.oldAssignee = task.dataItem.rawData.get(
                    "assignee", None
                )
            else:
                task.updatedValues = UpdatedTaskValues(
                    status=None,
                    oldStatus=(
                        old_status
                        if old_status.upper() in TaskStatus.__members__
                        else TaskStatus.OTHER
                    ),
                    assignee=None,
                    oldAssignee=task.dataItem.rawData.get("assignee", None),
                    severity=None,
                    oldSeverity=(
                        old_severity
                        if old_severity.upper() in Severity.__members__
                        else Severity.OTHER
                    ),
                )

        if slack_data.get(status_field):
            task.updatedValues.status = (
                slack_data.get(status_field)
                if slack_data.get(status_field, "").upper()
                in TaskStatus.__members__
                else TaskStatus.OTHER
            )

        if slack_data.get(severity_field):
            task.updatedValues.severity = (
                slack_data.get(severity_field)
                if slack_data.get(severity_field, "").upper()
                in Severity.__members__
                else Severity.OTHER
            )

        task.updatedValues.assignee = slack_data.get(assignee_field, None)

        task.status = (
            slack_data.get(status_field)
            if slack_data.get(status_field, "")
            in [x.value for x in TaskStatus]
            else TaskStatus.OTHER
        )
        task.severity = (
            slack_data.get(severity_field)
            if slack_data.get(severity_field, "")
            in [s.value for s in Severity]
            else Severity.OTHER
        )
        return task

    def process_webhooks(self, query_params: dict, headers: dict, body: bytes):
        """Process incoming webhooks."""
        if (
            self.configuration.get("params", {}).get("enable_webhook", "no")
            != "yes"
        ):
            self.logger.info(
                f"{self.log_prefix}: CE Incoming Webhook is not enabled, "
                "skipping incoming request for this configuration."
            )
            raise HTTPException(
                status_code=400, detail="Webhook is not enabled."
            )

        signing_secret = self.configuration.get("params", {}).get(
            "signing_secret"
        )

        timestamp = headers.get("X-Slack-Request-Timestamp")
        slack_signature = headers.get("X-Slack-Signature")

        if not timestamp or not slack_signature:
            self.logger.error(
                f"{self.log_prefix}: Discarding the incoming webhook request"
                " because either the X-Slack-Request-Timestamp"
                " or X-Slack-Signature header is missing."
            )
            raise HTTPException(
                status_code=400,
                detail="Either the X-Slack-Request-Timestamp or "
                "X-Slack-Signature header is missing from the "
                "incoming webhook request.",
            )

        if abs(time.time() - int(timestamp)) > 60 * 5:
            self.logger.error(
                f"{self.log_prefix}: Discarding the incoming webhook request"
                " because the Slack request timestamp header "
                "(X-Slack-Request-Timestamp) is older than 1 hour."
            )
            raise HTTPException(
                status_code=400,
                detail="Slack request timestamp header is too old.",
            )

        body_base = f"v0:{timestamp}:{body.decode('utf-8')}"
        my_signature = (
            "v0="
            + hmac.new(
                signing_secret.encode(), body_base.encode(), hashlib.sha256
            ).hexdigest()
        )
        if not hmac.compare_digest(my_signature, slack_signature):
            self.logger.error(
                f"{self.log_prefix}: Discarding the incoming webhook request"
                " because an invalid payload was detected while verifying"
                " with the signing secret."
            )
            raise HTTPException(
                status_code=403, detail="Invalid Slack signature."
            )

        notification_id, field_values, is_valid_token = (
            self.extract_information(body)
        )
        if not is_valid_token:
            self.logger.error(
                f"{self.log_prefix}: Discarding the incoming webhook request"
                " because an invalid verification token was received"
                " in the payload."
            )
            raise HTTPException(
                status_code=403, detail="Invalid Verification Token."
            )
        if notification_id:
            tasks = get_task_from_query({"id": notification_id})
            for task in tasks:
                if task.id == notification_id:
                    task = self.update_task_details(
                        task, field_values, "severity", "status", "assignee"
                    )
                else:
                    if (
                        task.updatedValues.status
                        and task.updatedValues.status != TaskStatus.DELETED
                    ):
                        (
                            task.updatedValues.oldStatus,
                            task.updatedValues.status,
                        ) = (task.updatedValues.status, TaskStatus.DELETED)
                    else:
                        (
                            task.updatedValues.oldStatus,
                            task.updatedValues.status,
                        ) = (TaskStatus.DELETED, TaskStatus.DELETED)
                    task.status = TaskStatus.DELETED
            self.logger.info(
                f"{self.log_prefix}: Successfully processed incoming"
                f" webhook request, {len(tasks)} task(s) has been updated."
            )
            return tasks, {"success": True}
        return [], {"success": False}

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync all task states."""
        return tasks

    def update_task(
        self, task: Task, alert: Alert, mappings: Dict, queue: Queue
    ) -> Task:
        """Add a comment in existing Jira issue."""
        return task

    def _get_args_from_params(
        self, params: dict, platform: str = None
    ) -> dict:
        """Get dictionary that can be unpacked and used as argument."""
        new_dict = {}
        for key, value in params.items():
            if value == "boolean_true":
                new_dict[key] = True
            elif value == "boolean_false":
                new_dict[key] = False
            elif platform == "slack" and key in WEBHOOK_FIELDS:
                continue
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
        args = self._get_args_from_params(
            configuration.get("params", {}), platform
        )
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
        if platform == "slack":
            fields.extend(
                [
                    MappingField(label=x.capitalize(), value=x)
                    for x in DYNAMIC_FIELDS
                ]
            )

        return fields

    def get_default_mappings(
        self, configuration: dict
    ) -> Dict[str, List[FieldMapping]]:
        """Get default mappings."""
        platform = configuration.get("platform").get("name")
        return {
            "mappings": [
                (
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
                            "default": (
                                val.get("enum")[0]
                                if val.get("enum", [])
                                else ""
                            ),
                        }
                    else:
                        field = {
                            "label": " ".join(key.split("_")).title(),
                            "key": key,
                            "type": (
                                "password"
                                if key in PASSWORD_FIELDS.get(platform, [])
                                else "text"
                            ),
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
                            "description": (
                                f"({key}) {string_field.get('title', '')}"
                            ),
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
            if platform == "slack":
                fields.extend(
                    [
                        {
                            "label": "Enable CE Incoming Webhook",
                            "key": "enable_webhook",
                            "type": "choice",
                            "choices": [
                                {"key": "Yes", "value": "yes"},
                                {"key": "No", "value": "no"},
                            ],
                            "default": "no",
                            "description": (
                                "Enable/Disable CE Incoming Webhook."
                            ),
                        },
                        {
                            "label": "CE Incoming Webhook URL",
                            "key": "webhook_id",
                            "type": "text_copy",
                            "description": (
                                "CE Incoming Webhook URL to accept incoming"
                                " request from the Slack platform."
                            ),
                            "disabled": True,
                            "condition": {
                                "key": "enable_webhook",
                                "values": ["yes"],
                            },
                        },
                        {
                            "label": "Signing Secret",
                            "key": "signing_secret",
                            "type": "password",
                            "description": (
                                "Used to verify incoming webhook "
                                "request's payload from the Slack platform."
                            ),
                            "mandatory": True,
                            "condition": {
                                "key": "enable_webhook",
                                "values": ["yes"],
                            },
                        },
                        {
                            "label": "Verification Token",
                            "key": "token",
                            "type": "password",
                            "description": (
                                "Used to verify incoming webhook "
                                "request from the Slack platform."
                            ),
                            "mandatory": True,
                            "condition": {
                                "key": "enable_webhook",
                                "values": ["yes"],
                            },
                        },
                    ]
                )
            return fields
        else:
            raise NotImplementedError()

    def get_queues(self) -> List[Queue]:
        """Get list of Jira projects as queues."""
        return [Queue(label="Notification", value="notification")]
