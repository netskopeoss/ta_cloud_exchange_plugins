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

CRE ExtraHop Plugin.
"""

import json
import traceback
import urllib
from datetime import datetime, timedelta
from typing import List

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    DETECTION_FIELD_MAPPING,
    DEVICE_BATCH_LIMIT,
    DEVICE_FIELD_MAPPING,
    ENTITY_NAME,
    INTEGER_THRESHOLD,
    MODULE_NAME,
    PAGE_LIMIT,
    PLATFORM_NAME,
    PLUGIN_VERSION,
)
from .utils.helper import ExtraHopPluginException, ExtraHopPluginHelper


class ExtraHopPlugin(PluginBase):
    """ExtraHop plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init method.

        Args:
            name (str): Configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.extrahop_helper = ExtraHopPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = ExtraHopPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            (list): Returns a list of details for UI to display group

        """
        if action.value == "generate":
            return []

    def execute_action(self, action: Action):
        """Execute action on the users.

        Args:
            action (Action): Action that needs to be perform on users.

        Returns:
            None
        """
        action_label = action.label

        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate ExtraHop action configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_value = action.value
        if action_value not in ["generate"]:
            self.logger.error(
                f'{self.log_prefix}: Unsupported action "{action_value}" '
                "provided in the action configuration."
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        log_msg = (
            "Successfully validated "
            f"action configuration for '{action.label}'."
        )
        self.logger.debug(
            f"{self.log_prefix}: Successfully validated "
            f"action configuration for '{action.label}'."
        )
        return ValidationResult(success=True, message=log_msg)

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urllib.parse.urlparse(url)
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """
        validation_err_msg = "Validation error occurred,"
        # Validate Base URL
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(base_url, str) or not self._validate_url(
            base_url
        ):
            err_msg = (
                "Invalid Base URL value provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                "Base URL should be an non-empty string."
            )
            return ValidationResult(success=False, message=err_msg)

        # Client ID
        client_id = configuration.get("client_id", "").strip()
        if "client_id" not in configuration or not client_id:
            err_msg = "Client ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = (
                "Invalid Client ID provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Client Secret
        client_secret = configuration.get("client_secret")
        if "client_secret" not in configuration or not client_secret:
            err_msg = "Client Secret is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = (
                "Invalid Client Secret provided in "
                "configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Initial Range
        initial_range = configuration.get("days", 0)
        if initial_range is None:
            err_msg = (
                "Initial Range (in days) is a required configuration"
                " parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(initial_range, int):
            err_msg = (
                "Invalid value provided in Initial Range (in days) "
                "in configuration parameter. Initial Range (in days) "
                "should be positive integer value."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif initial_range <= 0 or initial_range > INTEGER_THRESHOLD:
            err_msg = (
                "Invalid value for Initial Range (in days) provided. "
                "Select a value between 1 to 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate auth credentials.
        return self.validate_auth_params(base_url, client_id, client_secret)

    def validate_auth_params(self, base_url, client_id, client_secret):
        """Validate the authentication params with ExtraHop platform.

        Args: configuration (dict).

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            auth_token = self.extrahop_helper.generate_auth_token(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
                logger_msg=(
                    "generating auth token for authenticating credentials"
                ),
            )

            endpoint = f"{base_url}/api/v1/detections/search"
            json_body = {"limit": 1}
            headers = {"Authorization": f"Bearer {auth_token}"}
            self.extrahop_helper.api_helper(
                url=endpoint,
                method="POST",
                headers=headers,
                json=json_body,
                is_handle_error_required=True,
                logger_msg="pulling indicators for authenticating credentials",
                regenerate_auth_token=False,
            )
            log_msg = (
                f"Validation successful for {MODULE_NAME} "
                f"{PLATFORM_NAME} plugin."
            )
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(
                success=True,
                message=log_msg,
            )
        except ExtraHopPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def add_field(
        self,
        fields_dict: dict,
        field_name: str,
        value,
        transformation: str = None,
    ):
        """Function to add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        if transformation and transformation == "string":
            value = str(value)
        elif isinstance(value, int):
            value = value
        elif isinstance(value, str) and value:
            value = value
        fields_dict[field_name] = value

    def _extract_field_from_event(
        self, key: str, event: dict, default, transformation=None
    ):
        """Extract field from event.

        Args:
            key (str): Key to fetch.
            event (dict): Event dictionary.
            default (str,None): Default value to set.
            transformation (str, None, optional): Transformation
                to perform on key. Defaults to None.

        Returns:
            Any: Value of the key from event.
        """
        keys = key.split(".")
        while keys:
            k = keys.pop(0)
            if k not in event and default is not None:
                return default
            event = event.get(k, {})
        if transformation and transformation == "string":
            return str(event)
        elif transformation and transformation == "integer":
            return int(event)
        elif transformation and transformation == "float":
            return float(event)
        return event

    def _extract_device_fields(self, device: dict) -> dict:
        """Extract Device Fields.

        Args:
            device (dict): Device dictionary.

        Returns:
            dict: Extracted fields dictionary.
        """
        extracted_fields = {}
        for field_name, field_value in DEVICE_FIELD_MAPPING.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, device, default, transformation
                ),
            )
        return extracted_fields

    def _extract_detection_fields(
        self,
        detection: dict,
        participant: dict,
    ) -> dict:
        """Extract user fields.

        Args:
            event (dict): Event payload.
            participant (dict): Participant dictionary.

        Returns:
            dict: Extracted fields dictionary.
        """
        extracted_fields = {}
        for field_name, field_value in DETECTION_FIELD_MAPPING.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, detection, default, transformation
                ),
            )

        self.add_field(
            extracted_fields,
            "Role",
            participant.get("role"),
        )
        self.add_field(
            extracted_fields,
            "Is External",
            participant.get("external"),
            "string",
        )
        self.add_field(
            extracted_fields,
            "Hostname",
            participant.get("hostname"),
        )
        if detection.get("usernames") and isinstance(
            detection.get("usernames"), list
        ):
            self.add_field(
                extracted_fields,
                "usernames",
                participant.get("usernames"),
            )

        return extracted_fields

    def fetch_devices(
        self,
        detection_records: dict,
        base_url: str,
        headers: dict,
        auth_creds: dict,
        is_update: bool = False,
    ) -> List[dict]:
        """Fetch and extract list of devices/Cloud Workloads from ExtraHop.

        Args:
            detection_records (dict): Detection Records.
            base_url (str): Base URL.
            headers (dict): Headers.
            auth_creds (dict);: Authentication credentials dictionary.
            is_update (bool, optional): Update flag. Defaults to False.

        Returns:
            List[dict]: List of devices.
        """
        endpoint = f"{base_url}/api/v1/devices/search"
        total_device_count = 0
        batch_number = 1
        page_count = 1
        final_records = []
        log_msg = "updated" if is_update else "fetched"
        msg = f"Fetching details of devices from {PLATFORM_NAME} platform"
        entity_name = ENTITY_NAME.lower()
        if is_update:
            msg += " to update the records."
        else:
            msg += " to pull the records."
        self.logger.info(f"{self.log_prefix}: {msg}")
        for batch in range(0, len(detection_records), DEVICE_BATCH_LIMIT):
            detection_device_ids = list(detection_records.keys())[
                batch : batch + DEVICE_BATCH_LIMIT  # noqa
            ]
            device_ids = [record[1] for record in detection_device_ids]
            payload = {
                "filter": {
                    "field": "id",
                    "operand": device_ids,
                    "operator": "in",
                },
                "limit": DEVICE_BATCH_LIMIT,
                "offset": 0,
            }
            device_page_count = 1
            device_count = 0
            while True:
                logger_msg = (
                    f"fetching details of devices for page "
                    f"{device_page_count} and batch {batch_number} "
                    "using Device ID"
                )
                if is_update:
                    logger_msg += " to update the records"
                resp_json = self.extrahop_helper.api_helper(
                    url=endpoint,
                    method="POST",
                    headers=headers,
                    data=json.dumps(payload),
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=logger_msg,
                    auth_creds=auth_creds,
                    show_data=False,
                )
                device_map = {
                    device.get("id"): device
                    for device in resp_json
                    if device.get("id")
                }
                for detection_id, device_id in detection_records.keys():
                    try:
                        if device_id in device_map:
                            extracted_fields = self._extract_device_fields(
                                device_map[device_id]
                            )
                            if extracted_fields:
                                detection_records[
                                    (detection_id, device_id)
                                ].update(extracted_fields)
                                final_records.append(
                                    detection_records[
                                        (detection_id, device_id)
                                    ]
                                )
                                device_count += 1
                                total_device_count += 1
                    except ExtraHopPluginException as exp:
                        err_msg = (
                            f"{self.log_prefix}: Unable to fetch details for "
                            f"Device ID: {device_id}. Hence skipping this"
                            f" record"
                        )
                        if is_update:
                            err_msg += f" for update. Error: {exp}"
                        else:
                            err_msg += f". Error: {exp}"
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=traceback.format_exc(),
                        )

                if not resp_json or len(resp_json) < PAGE_LIMIT:
                    break

                self.logger.info(
                    f"{self.log_prefix}: Successfully {log_msg} "
                    f"{device_count} device(s) details in page "
                    f"{page_count} and batch {batch_number} of Device "
                    f"Ids. Total {entity_name} {log_msg}:"
                    f" {total_device_count}"
                )
                device_page_count += 1
                payload["offset"] += PAGE_LIMIT

            self.logger.info(
                f"{self.log_prefix}: Successfully {log_msg}"
                f" {device_count} {entity_name} record(s) in batch "
                f"{batch_number} of Device Ids. Total {entity_name} record(s)"
                f" {log_msg}: {total_device_count}"
            )
            batch_number += 1

        self.logger.info(
            f"{self.log_prefix}: Successfully {log_msg} {len(final_records)}"
            f" {entity_name} record(s) from {PLATFORM_NAME}."
        )
        return final_records

    def fetch_records(self, entity: str) -> List:
        """Pull Records from ExtraHop.

        Returns:
            List: List of records to be stored on the platform.
        """
        entity_name = entity.lower()
        if entity != ENTITY_NAME:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{ENTITY_NAME} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ExtraHopPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} from "
            f"{PLATFORM_NAME} platform."
        )
        checkpoint = None
        if self.last_run_at:
            checkpoint = self.last_run_at
        else:
            checkpoint = datetime.now() - timedelta(
                days=self.configuration.get("days")
            )
        checkpoint = int(checkpoint.timestamp() * 1000)
        auth_creds = self.extrahop_helper.get_credentials(
            configuration=self.configuration
        )
        base_url = auth_creds.get("base_url")
        client_id = auth_creds.get("client_id")
        client_secret = auth_creds.get("client_secret")

        endpoint = f"{base_url}/api/v1/detections/search"
        json_body = {
            "limit": PAGE_LIMIT,
            "offset": 0,
            "mod_time": checkpoint,
            "sort": [{"direction": "asc", "field": "mod_time"}],
        }
        page_count = 1
        skip_count = 0
        headers = {
            "Authorization": "Bearer {}".format(
                self.extrahop_helper.generate_auth_token(
                    base_url, client_id, client_secret
                )
            )
        }
        total_detections = {}
        while True:
            try:
                page_detections = 0
                resp_json = self.extrahop_helper.api_helper(
                    url=endpoint,
                    auth_creds=auth_creds,
                    method="POST",
                    headers=headers,
                    json=json_body,
                    is_handle_error_required=True,
                    logger_msg=f"pulling detections for page {page_count}",
                    regenerate_auth_token=True,
                )
                if not resp_json:
                    break
                for detection in resp_json:
                    try:
                        if detection.get("id") and detection.get(
                            "participants", []
                        ):
                            for participant in detection.get(
                                "participants", []
                            ):
                                if participant.get("object_type", "") not in [
                                    "device",
                                    "device_group",
                                    "network_locality",
                                ]:
                                    skip_count += 1
                                    continue
                                device_id = participant.get("object_id")
                                if device_id:
                                    extracted_fields = (
                                        self._extract_detection_fields(
                                            detection=detection,
                                            participant=participant,
                                        )
                                    )
                                    if extracted_fields:
                                        total_detections[
                                            (detection.get("id"), device_id)
                                        ] = extracted_fields
                                        page_detections += 1

                                else:
                                    skip_count += 1
                        else:
                            skip_count += 1
                    except ExtraHopPluginException:
                        skip_count += 1
                    except Exception as err:
                        id = detection.get("id")
                        err_msg = (
                            "Unable to extract fields from detection"
                            f' having id "{id}".'
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg}"
                                f" Error: {err}"
                            ),
                            details=f"Detection Record: {detection}",
                        )
                        skip_count += 1
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_detections} detections for page {page_count}."
                    f" Total detections fetched: {len(total_detections)}"
                )
                if len(resp_json) < PAGE_LIMIT:
                    break

                json_body["offset"] += PAGE_LIMIT
                page_count += 1

            except ExtraHopPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    f"Unexpected error occurred while fetching "
                    f"{entity_name} from {PLATFORM_NAME} platform."
                    f" Error: {exp}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )
                raise ExtraHopPluginException(err_msg)
        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count}"
                f" {entity_name} because they might not contain Device ID(id)"
                " or Detection ID(object_id) in their API response or fields"
                " could not be extracted from them."
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched "
            f"{len(total_detections)} detections for {entity_name} "
            f"from {PLATFORM_NAME} platform."
        )

        return self.fetch_devices(
            base_url=base_url,
            headers=headers,
            detection_records=total_detections,
            auth_creds=auth_creds,
        )

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update user scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        entity_name = entity.lower()

        if entity != ENTITY_NAME:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ExtraHopPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} {entity_name}"
            f" record(s) from {PLATFORM_NAME}."
        )
        update_records = {}
        id_list = set()
        for record in records:
            if record.get("Detection ID") and record.get("Device ID"):
                id_list.add(
                    (
                        record.get("Detection ID"),
                        record.get("Device ID"),
                    )
                )
                update_records.update(
                    {
                        (
                            record.get("Detection ID"),
                            record.get("Device ID"),
                        ): {
                            "Detection ID": record.get("Detection ID"),
                            "Device ID": record.get("Device ID"),
                            "Detection Risk Score": record.get(
                                "Detection Risk Score"
                            ),
                        }
                    }
                )

        log_msg = (
            f"{len(id_list)} {entity_name} record(s) will be updated out"
            f" of {len(records)} records from {PLATFORM_NAME}."
        )

        if len(records) - len(id_list) > 0:
            log_msg += (
                f" Skipped {len(records) - len(id_list)} user(s) as they"
                " do not have Detection ID or Device ID field in them."
            )

        self.logger.info(f"{self.log_prefix}: {log_msg}")

        auth_creds = self.extrahop_helper.get_credentials(
            configuration=self.configuration
        )

        auth_token = self.extrahop_helper.generate_auth_token(
            base_url=auth_creds.get("base_url"),
            client_id=auth_creds.get("client_id"),
            client_secret=auth_creds.get("client_secret"),
            logger_msg="generating auth token for authenticating credentials",
        )

        headers = {
            "Authorization": f"Bearer {auth_token}",
        }
        base_url = auth_creds.get("base_url")

        skip_count = 0
        for (detection_id, _), record in update_records.items():
            risk_score = record.get("Detection Risk Score")
            if isinstance(risk_score, int) and 1 <= risk_score <= 100:
                normalized_score = (100 - risk_score) * 10
                self.add_field(
                    record,
                    "Netskope Normalized Score",
                    normalized_score,
                )
            else:
                err_msg = (
                    f"{self.log_prefix}: Invalid "
                    f"{PLATFORM_NAME} Risk Score received "
                    f"for Detection ID: {detection_id}. "
                    "Netskope Normalized Score will not be "
                    "calculated for this Detection. "
                    "Valid Risk Score range is 0 to 100."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"Risk Score: '{risk_score}'",
                )
                skip_count += 1
        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count}"
                f" {entity_name} record(s) for Normalization as they might"
                " have invalid Detection Risk Score or there might be some"
                " issue calculating the Netskope Normalized Score."
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully Normalized Risk Score for "
            f"{len(update_records)} detection(s) for {entity_name}."
        )

        return self.fetch_devices(
            detection_records=update_records,
            is_update=True,
            base_url=base_url,
            headers=headers,
            auth_creds=auth_creds,
        )

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name=ENTITY_NAME,
                fields=[
                    EntityField(
                        name="Detection ID",
                        type=EntityFieldType.NUMBER,
                        required=True,
                    ),
                    EntityField(
                        name="Device ID",
                        type=EntityFieldType.NUMBER,
                        required=True,
                    ),
                    EntityField(
                        name="Detection Title", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Detection Risk Score",
                        type=EntityFieldType.NUMBER,
                        required=True,
                    ),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Detection Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Role",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Is External",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="User Names",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(name="Hostname", type=EntityFieldType.STRING),
                    EntityField(
                        name="Detection Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="URL",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="VPC ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Default Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Subnet ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="DHCP Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="VLAN ID",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Vendor",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="MAC Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="DNS Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="IPv4 Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="IPv6 Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Custom Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Custom Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Display Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Critical",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Discovery ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="ExtraHop ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Cloud Instance Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Cloud Instance Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Cloud Instance ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Cloud Account",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="NetBIOS Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Device Class",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Analysis",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Analysis Level",
                        type=EntityFieldType.STRING,
                    ),
                ],
            )
        ]
