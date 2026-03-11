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

CRE Palo Alto Networks Cortex XDR
"""

import traceback
from typing import Dict, Generator, List, Literal, Tuple, Union
from urllib.parse import urlparse

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    ACTION,
    ACTION_BATCH_SIZE,
    ADVANCED,
    CANCELSCAN,
    CONFIGURATION,
    ENDPOINTS,
    ENDPOINT_FIELD_MAPPING,
    FETCH_ENDPOINTS_API,
    FETCH_HOSTS_API,
    FETCH_USERS_API,
    ISOLATE,
    MODULE_NAME,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    RUNSCAN,
    STANDARD,
    UNISOLATE,
    USERS,
    USER_FIELD_MAPPING,
    VALIDATE_API,
)
from .utils.helper import (
    PaloAltoNetworksCortexXDRPluginException,
    PaloAltoNetworksCortexXDRPluginHelper,
)


class PaloAltoNetworksCortexXDRPlugin(PluginBase):
    """PaloAltoNetworksCortexXDRPlugin class having implementation all
    plugin's methods."""

    def __init__(self, name, *args, **kwargs):
        """PaloAltoCortexXDR plugin initializer.

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
        self.palo_alto_cortex_helper = PaloAltoNetworksCortexXDRPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = PaloAltoNetworksCortexXDRPlugin.metadata
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

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="No action", value="generate"),
            ActionWithoutParams(label="Isolate endpoint", value="add"),
            ActionWithoutParams(label="Un-isolate endpoint", value="remove"),
            ActionWithoutParams(label="Run scan on endpoint", value="run"),
            ActionWithoutParams(
                label="Cancel running scan on endpoint", value="cancel"
            ),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        if action.value == "generate":
            return []
        if action.value == "add":
            return [
                {
                    "label": "Endpoint ID",
                    "key": "endpoint_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "ID of endpoint to be isolated.",
                },
                {
                    "label": "Incident ID (Optional)",
                    "key": "incident_id",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "When included in the request, the Isolate"
                        " endpoint action will appear in the"
                        " Cortex XDR Incident ViewTimeline tab."
                    ),
                },
            ]
        if action.value == "remove":
            return [
                {
                    "label": "Endpoint ID",
                    "key": "endpoint_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "ID of endpoint to be un-isolated.",
                },
                {
                    "label": "Incident ID (Optional)",
                    "key": "incident_id",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "When included in the request, the Un-isolate"
                        " endpoint action will appear in the"
                        " Cortex XDR Incident View Timeline tab."
                    ),
                },
            ]
        if action.value == "run":
            return [
                {
                    "label": "Endpoint ID",
                    "key": "endpoint_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "ID of endpoint where scan will be run.",
                },
                {
                    "label": "Incident ID (Optional)",
                    "key": "incident_id",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "When included in the request, the Run scan on"
                        " endpoint action will appear in the Cortex XDR"
                        " Incident View Timeline tab."
                    ),
                },
            ]
        if action.value == "cancel":
            return [
                {
                    "label": "Endpoint ID",
                    "key": "endpoint_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "ID of endpoint where running scan will be cancelled."
                    ),
                },
                {
                    "label": "Incident ID (Optional)",
                    "key": "incident_id",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "When included in the request, the Cancel running"
                        " scan on endpoint action will appear in the"
                        " Cortex XDR Incident View Timeline tab."
                    ),
                },
            ]
        return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate HPE Central action configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_value = action.value
        incident_id = action.parameters.get("incident_id", "")
        if action_value == "generate":
            log_msg = (
                f"Successfully validated action configuration for '{action.label}'."
            )
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(success=True, message=log_msg)
        if action_value not in ["generate", "add", "remove", "run", "cancel"]:
            self.logger.error(
                f'{self.log_prefix}: Unsupported action "{action_value}" '
                "provided in the action configuration. Supported Actions"
                " are - 'Isolate endpoint', 'Un-isolate endpoint', "
                "'Run scan on endpoint', 'Cancel running scan on endpoint'."
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if incident_id and "$" in incident_id:
            err_msg = "'Incident ID' should be a static field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        if action_value in ["add", "remove", "run", "cancel"]:
            endpoint_id = action.parameters.get("endpoint_id", "")
            if validation_result := self._check_configuration_or_action_field_empty_and_type(
                field_name="Endpoint ID",
                field_value=endpoint_id,
                field_type=str,
                is_configuration=False,
            ):
                return validation_result

        self.logger.debug(
            f"{self.log_prefix}: Successfully validated "
            f"action configuration for '{action.label}'."
        )
        return ValidationResult(success=True, message="Validation successful.")

    def _create_batch_of_1000_endpoints(
        self, endpoint_id_list: List[str]
    ) -> Generator[List[str], None, None]:
        """
        Divide a list of endpoint IDs into batches of 1000.

        Args:
            endpoint_id_list (List[str]): A list of endpoint IDs.

        Yields:
            Tuple[List[str], int]: A tuple containing a list of endpoint IDs
                and the batch number.
        """
        batch_number = 0
        for i in range(0, len(endpoint_id_list), ACTION_BATCH_SIZE):
            batch_number += 1
            yield endpoint_id_list[i: i + ACTION_BATCH_SIZE], batch_number

    def _get_endpoint_action_params(
        self,
        action_name: Literal[
            "isolate",
            "un-isolate",
            "run-scan",
            "cancel-scan",
        ],
        batch_number: int,
        endpoint_id_list: List[str],
        incident_id: str,
        is_batched: bool,
    ) -> Tuple[str, str, Dict[str, Dict[str, Union[List[str], str]]], str]:
        """
        Given the action name, batch number, list of endpoint IDs, incident ID,
        and whether to execute the action in batches, this function returns a
        tuple of the API endpoint URL, a string to be used in logging, and
        the request body to be used in the API call.

        Args:
        action_name (Literal["isolate", "un-isolate", "run-scan", "cancel-scan"]):
            The name of the action to be executed.
        batch_number (int):
            The number of the batch of endpoints being processed.
        endpoint_id_list (List[str]):
            The list of endpoint IDs to be processed in the current batch.
        incident_id (str):
            The ID of the incident for which the action is being executed.
        is_batched (bool):
            Whether to execute the action in batches.

        Returns:
        Tuple[str, str, Dict[str, Dict[str, Union[List[str], str]]]]: A tuple
        containing the API endpoint URL, a string to be used in logging, and
        the request body to be used in the API call.
        """
        action_label = None
        api_endpoint = None
        request_body = None
        action_stats_msg = None
        incident_id_msg = None
        batch_number_msg = f" for batch {batch_number}"
        request_body = {
            "request_data": {
                "filters": [
                    {
                        "field": "endpoint_id_list",
                        "operator": "in",
                        "value": endpoint_id_list,
                    }
                ],
                "incident_id": incident_id,
            }
        }
        if incident_id:
            incident_id_msg = f", Incident ID {incident_id}"
        else:
            incident_id_msg = ""
            request_body["request_data"].pop("incident_id")
        if is_batched:
            action_stats_msg = (
                f"{len(endpoint_id_list)} endpoints"
                f"{incident_id_msg}{batch_number_msg}"
            )
        else:
            action_stats_msg = f"endpoint {endpoint_id_list[0]}{incident_id_msg}"
        if action_name == ISOLATE:
            action_label = "isolated"
            api_endpoint = "/public_api/v1/endpoints/isolate"
            logger_msg = f"isolating {action_stats_msg}"
        elif action_name == UNISOLATE:
            action_label = "un-isolated"
            api_endpoint = "/public_api/v1/endpoints/unisolate"
            logger_msg = f"un-isolating {action_stats_msg}"
        elif action_name == RUNSCAN:
            action_label = "run scan on"
            api_endpoint = "/public_api/v1/endpoints/scan"
            logger_msg = f"running scan on {action_stats_msg}"
        elif action_name == CANCELSCAN:
            action_label = "cancelled running scan on"
            api_endpoint = "/public_api/v1/endpoints/abort_scan"
            logger_msg = f"canceling scan on {action_stats_msg}"
        else:
            err_msg = f"Invalid action name: {action_name} provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)
        return api_endpoint, logger_msg, request_body, action_label

    def _execute_endpoint_action(
        self,
        action_name: Literal[
            "isolate",
            "un-isolate",
            "run-scan",
            "cancel-scan",
        ],
        endpoint_id_list: List[str],
        incident_id: str,
        is_batched: bool,
    ) -> Union[Tuple[int, int], Literal[True], None]:
        """
        Execute the given action on the given list of endpoint IDs.

        Args:
        action_name (Literal["isolate", "un-isolate", "run-scan", "cancel-scan"]):
            The action to be executed.
        endpoint_id_list (List[str]):
            The list of endpoint IDs to execute the action on.
        incident_id (str):
            The incident ID to associate with the action.
        is_batched (bool):
            Whether to execute the action in batches.

        Returns:
        Union[Tuple[int, int], Literal[True], None]:
            If is_batched is True, returns a tuple of two integers:
                - The first integer is the count of successful actions.
                - The second integer is the count of skipped actions.
            If is_batched is False, returns True if the action is successful, else None.
        """
        action_success_count = 0
        action_skip_count = 0
        base_url, api_key, api_key_id, auth_method = (
            self.palo_alto_cortex_helper.get_configuration_parameters(
                self.configuration
            )
        )
        headers = self.palo_alto_cortex_helper.get_auth_headers(
            api_key_id=api_key_id, api_key=api_key, auth_method=auth_method
        )
        for endpoint_batch, batch_number in self._create_batch_of_1000_endpoints(
            endpoint_id_list,
        ):
            endpoint, logger_msg, request_body, action_label = (
                self._get_endpoint_action_params(
                    action_name=action_name,
                    batch_number=batch_number,
                    endpoint_id_list=endpoint_batch,
                    incident_id=incident_id,
                    is_batched=is_batched,
                )
            )
            try:
                self.palo_alto_cortex_helper.api_helper(
                    logger_msg=logger_msg,
                    url=f"{base_url}{endpoint}",
                    method="POST",
                    headers=headers,
                    json=request_body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_validation=False,
                    is_handle_error_required=True,
                )
                action_success_count += len(endpoint_batch)
                if is_batched:
                    self.logger.info(
                        f"{self.log_prefix}: Successfully {action_label}"
                        f" {len(endpoint_batch)} endpoints for batch"
                        f" {batch_number}. Action stats: "
                        f"{action_success_count} successful, "
                        f"{action_skip_count} skipped."
                    )
            except PaloAltoNetworksCortexXDRPluginException as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while"
                        f" {logger_msg}."
                    ),
                    details=str(err),
                )
                if is_batched:
                    action_skip_count += len(endpoint_id_list)
                    continue
                else:
                    raise
            except Exception as err:
                err_msg = f"Unexpected error occurred while {logger_msg}."
                self.logger.error(
                    message=(f"{self.log_prefix}: {err_msg}"),
                    details=str(err),
                )
                if is_batched:
                    action_skip_count += len(endpoint_id_list)
                    continue
                else:
                    raise PaloAltoNetworksCortexXDRPluginException(err_msg)
        if is_batched:
            return action_success_count, action_skip_count
        else:
            return True

    def execute_action(self, action: Action):
        action_label = action.label
        action_params = action.parameters
        endpoint_id = action_params.get("endpoint_id", "")
        incident_id = action_params.get("incident_id", "")

        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return
        if action.value == "add":
            if not endpoint_id:
                self.logger.info(
                    (
                        f"{self.log_prefix}: Skipping action '{action_label}'"
                        f" for endpoint {endpoint_id} because Endpoint ID"
                        " is empty."
                    )
                )
                return
            success = self._execute_endpoint_action(
                action_name=ISOLATE,
                endpoint_id_list=[endpoint_id],
                incident_id=incident_id,
                is_batched=False,
            )
            if success:
                self.logger.info(
                    f"{self.log_prefix}: Successfully Isolated"
                    f" endpoint {endpoint_id}."
                )
            return
        if action.value == "remove":
            if not endpoint_id:
                self.logger.info(
                    (
                        f"{self.log_prefix}: Skipping action '{action_label}'"
                        f" for endpoint {endpoint_id} because Endpoint ID"
                        " is empty."
                    )
                )
                return
            success = self._execute_endpoint_action(
                action_name=UNISOLATE,
                endpoint_id_list=[endpoint_id],
                incident_id=incident_id,
                is_batched=False,
            )
            if success:
                self.logger.info(
                    f"{self.log_prefix}: Successfully Un-isolated"
                    f" endpoint {endpoint_id}."
                )
            return
        if action.value == "run":
            if not endpoint_id:
                self.logger.info(
                    (
                        f"{self.log_prefix}: Skipping action '{action_label}'"
                        f" for endpoint {endpoint_id} because Endpoint ID"
                        " is empty."
                    )
                )
                return
            success = self._execute_endpoint_action(
                action_name=RUNSCAN,
                endpoint_id_list=[endpoint_id],
                incident_id=incident_id,
                is_batched=False,
            )
            if success:
                self.logger.info(
                    f"{self.log_prefix}: Successfully started scan"
                    f" on endpoint {endpoint_id}."
                )
            return
        if action.value == "cancel":
            if not endpoint_id:
                self.logger.info(
                    (
                        f"{self.log_prefix}: Skipping action '{action_label}'"
                        f" for endpoint {endpoint_id} because Endpoint ID"
                        " is empty."
                    )
                )
                return
            success = self._execute_endpoint_action(
                action_name=CANCELSCAN,
                endpoint_id_list=[endpoint_id],
                incident_id=incident_id,
                is_batched=False,
            )
            if success:
                self.logger.info(
                    f"{self.log_prefix}: Successfully cancelled scan"
                    f" running on endpoint {endpoint_id}."
                )
            return

    def execute_actions(self, action: Action):
        """Execute action on the clients.

        Args:
            action (Action): Action that needs to be perform on clients.

        Returns:
            None
        """
        first_action = action[0]
        action_label = first_action.label
        action_value = first_action.value
        action_success_count = 0
        action_skip_count = 0

        if action_value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return
        endpoints_ids_list = []
        skipped_endpoints_count = 0
        incident_id = first_action.parameters.get("incident_id", "")
        for action_item in action:
            endpoint_id = action_item.parameters.get("endpoint_id", "")
            if endpoint_id:
                endpoints_ids_list.append(endpoint_id)
            else:
                skipped_endpoints_count += 1
        if skipped_endpoints_count > 0:
            self.logger.info(
                (
                    f"{self.log_prefix}: Skipping action '{action_label}'"
                    f" for {skipped_endpoints_count} endpoints as they"
                    " did not have an Endpoint ID."
                )
            )
        if action_value == "add":
            action_success_count, action_skip_count = self._execute_endpoint_action(
                action_name=ISOLATE,
                endpoint_id_list=endpoints_ids_list,
                incident_id=incident_id,
                is_batched=True,
            )
        elif action_value == "remove":
            action_success_count, action_skip_count = self._execute_endpoint_action(
                action_name=UNISOLATE,
                endpoint_id_list=endpoints_ids_list,
                incident_id=incident_id,
                is_batched=True,
            )
        elif action_value == "run":
            action_success_count, action_skip_count = self._execute_endpoint_action(
                action_name=RUNSCAN,
                endpoint_id_list=endpoints_ids_list,
                incident_id=incident_id,
                is_batched=True,
            )
        elif action_value == "cancel":
            action_success_count, action_skip_count = self._execute_endpoint_action(
                action_name=CANCELSCAN,
                endpoint_id_list=endpoints_ids_list,
                incident_id=incident_id,
                is_batched=True,
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully executed '{action_label}'"
            f" action for {action_success_count} endpoints and skipped"
            f" {action_skip_count} endpoints."
        )
        return

    def add_field(self, fields_dict: dict, field_name: str, value):
        """Add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        if isinstance(value, int) or isinstance(value, float):
            fields_dict[field_name] = value
            return
        if value:
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
        return event

    def _extract_entity_fields(
        self, event: dict, entity_field_mapping: Dict[str, Dict[str, str]]
    ) -> dict:
        """
        Extracts the required entity fields from the event payload as
        per the mapping provided.

        Args:
            event (dict): Event payload.
            entity_field_mapping (Dict): Mapping of entity fields to
                their corresponding keys in the event payload and
                default values.

        Returns:
            dict: Dictionary containing the extracted entity fields.
        """
        extracted_fields = {}
        for field_name, field_value in entity_field_mapping.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key,
                    event,
                    default,
                    transformation,
                ),
            )
        return extracted_fields

    def _fetch_users(
        self,
        base_url: str,
        headers: Dict,
    ) -> List[Dict]:
        """
        Fetch users from Palo Alto Cortex XDR.

        Args:
            base_url (str): API Base URL for Palo Alto Cortex XDR
            headers (Dict): Headers with API key

        Returns:
            List[Dict]: List of users
        """
        try:
            total_users_fetched = 0
            skip_count = 0
            users_records = []
            # The API does not support pagination
            response = self.palo_alto_cortex_helper.api_helper(
                logger_msg=f"fetching users from {PLATFORM_NAME} platform",
                url=f"{base_url}{FETCH_USERS_API}",
                method="POST",
                headers=headers,
                json={},
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=False,
                is_handle_error_required=True,
            )
            for user in response.get("reply", []):
                try:
                    extracted_data = self._extract_entity_fields(
                        user,
                        USER_FIELD_MAPPING,
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error while extracting user"
                            f" details. {err}"
                        ),
                        details=traceback.format_exc(),
                    )
                    skip_count += 1
                    continue
                if extracted_data:
                    users_records.append(extracted_data)
                    total_users_fetched += 1
                else:
                    skip_count += 1
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{total_users_fetched} user record(s) and"
                f" skipped {skip_count} user record(s)"
                f" from {PLATFORM_NAME} platform.",
            )
        except PaloAltoNetworksCortexXDRPluginException:
            raise
        except Exception as err:
            err_msg = "Unexpected error occurred while fetching users."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                details=traceback.format_exc(),
            )
        return users_records

    def _fetch_hosts(
        self,
        base_url: str,
        headers: Dict,
    ) -> Dict:
        """
        Fetch hosts from Palo Alto Cortex XDR.

        Args:
            base_url (str): API Base URL of Cortex XDR.
            headers (dict): Headers with API key.

        Returns:
            Dict: Dictionary containing the extracted host fields.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching risk score details for"
            f" endpoints from {PLATFORM_NAME} platform."
        )
        try:
            hosts_dict = {}
            response = self.palo_alto_cortex_helper.api_helper(
                logger_msg=(
                    "fetching risk score details for endpoints"
                    f" from {PLATFORM_NAME} platform"
                ),
                url=f"{base_url}{FETCH_HOSTS_API}",
                method="POST",
                headers=headers,
                json={},
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=False,
                is_handle_error_required=True,
            )
            for host in response.get("reply", []):
                host_id = host.get("id", "").lower()
                hosts_dict[host_id] = {
                    "Risk Score": host.get("score"),
                    "Normalized Risk Score": host.get("norm_risk_score"),
                    "Risk Level": host.get("risk_level"),
                }
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched risk score"
                f" details for {len(hosts_dict)} endpoint record(s)."
            )
        except PaloAltoNetworksCortexXDRPluginException:
            raise
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while fetching risk score"
                " details for endpoints."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                details=traceback.format_exc(),
            )
        return hosts_dict

    def _fetch_endpoints(
        self,
        base_url: str,
        headers: Dict,
    ) -> List[Dict]:
        """
        Fetch Endpoints from Palo Alto Cortex XDR

        Args:
            base_url (str): API Base URL for Palo Alto Cortex XDR
            headers (Dict): Headers with API key

        Returns:
            List[Dict]: List of Endpoints
        """
        try:
            total_endpoint_fetched = 0
            endpoints_records = []
            search_from = 0
            page_number = 1
            total_skipped = 0
            while True:
                self.logger.info(
                    f"{self.log_prefix}: Fetching endpoints for page "
                    f"{page_number} from {PLATFORM_NAME} platform."
                )
                response = self.palo_alto_cortex_helper.api_helper(
                    logger_msg=(
                        f"fetching endpoints for page {page_number}"
                        f" from {PLATFORM_NAME} platform"
                    ),
                    url=f"{base_url}{FETCH_ENDPOINTS_API}",
                    method="POST",
                    headers=headers,
                    json={
                        "request_data": {
                            "search_from": search_from,
                            "search_to": search_from + PAGE_SIZE,
                        }
                    },
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_validation=False,
                    is_handle_error_required=True,
                )
                successful_fetch_count = 0
                skip_count = 0
                for endpoint in response.get("reply", {}).get("endpoints", []):
                    try:
                        extracted_data = self._extract_entity_fields(
                            endpoint, ENDPOINT_FIELD_MAPPING
                        )
                    except Exception as err:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Error while extracting"
                                f" endpoint details. {err}"
                            ),
                            details=traceback.format_exc(),
                        )
                        skip_count += 1
                        continue
                    if extracted_data:
                        endpoints_records.append(extracted_data)
                        successful_fetch_count += 1
                    else:
                        skip_count += 1
                total_endpoint_fetched += successful_fetch_count
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{successful_fetch_count} endpoint record(s),"
                    f" Skipped {skip_count} endpoint record(s) "
                    f"for page  {page_number}."
                    f" Total endpoints fetched: {total_endpoint_fetched}."
                )
                search_from += PAGE_SIZE
                page_number += 1
                total_skipped += skip_count
                if response.get("reply", {}).get("result_count", 0) < PAGE_SIZE:
                    break
        except PaloAltoNetworksCortexXDRPluginException:
            raise
        except Exception as err:
            err_msg = "Unexpected error occurred while fetching endpoints."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                details=traceback.format_exc(),
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched "
            f"{len(endpoints_records)} endpoint record(s)"
            f" from {PLATFORM_NAME} platform."
        )
        if total_skipped > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {total_skipped} "
                f"endpoint record(s) from {PLATFORM_NAME} platform."
            )
        return endpoints_records

    def _combine_endpoint_and_host_data(
        self, endpoints_list: List[Dict], hosts_dict: Dict
    ) -> List[Dict]:
        """
        Combine the endpoint and host data.

        This function combines the endpoint and host data by populating the
        Score, Normalized Risk Score and Risk Level fields in the endpoint data
        from the host data. It also adds the remaining host data as new
        endpoint records.

        Args:
            endpoints_list (List[Dict]): The list of endpoint records.
            hosts_dict (Dict): The dictionary of host records.

        Returns:
            List[Dict]: The combined list of endpoint records.
        """
        try:
            for endpoint in endpoints_list:
                endpoint_name = endpoint.get("Endpoint Name", "").lower()
                if endpoint_name in hosts_dict:
                    endpoint["Risk Score"] = hosts_dict[endpoint_name].get("Risk Score")
                    endpoint["Normalized Risk Score"] = hosts_dict[endpoint_name].get(
                        "Normalized Risk Score"
                    )
                    endpoint["Risk Level"] = hosts_dict[endpoint_name].get("Risk Level")
                    hosts_dict.pop(endpoint_name)
            for host_id, host_data in hosts_dict.items():
                host_data["Endpoint Name"] = host_id
                endpoints_list.append(host_data)
            return endpoints_list
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while combining endpoint"
                " and host data."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                details=traceback.format_exc(),
            )
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)

    def fetch_records(self, entity: str) -> List[Dict]:
        """Fetch users and endpoints records from Palo Alto Cortex XDR.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        records = []
        entity_name = entity.lower()
        base_url, api_key, api_key_id, auth_method = (
            self.palo_alto_cortex_helper.get_configuration_parameters(
                self.configuration
            )
        )
        auth_header = self.palo_alto_cortex_helper.get_auth_headers(
            api_key_id, api_key, auth_method
        )
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )
        try:
            if entity == ENDPOINTS:
                endpoints_list = self._fetch_endpoints(base_url, auth_header)
                hosts_dict = self._fetch_hosts(base_url, auth_header)
                endpoint_records = self._combine_endpoint_and_host_data(
                    endpoints_list, hosts_dict
                )
                records.extend(endpoint_records)
            elif entity == USERS:
                user_records = self._fetch_users(base_url, auth_header)
                records.extend(user_records)
            else:
                err_msg = (
                    f"Invalid entity found. {PLATFORM_NAME} plugin "
                    "only supports 'Endpoints' and 'Users' Entity."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise PaloAltoNetworksCortexXDRPluginException(err_msg)
            return records
        except PaloAltoNetworksCortexXDRPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while fetching "
                f"{entity_name} records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)

    def update_records(self, entity: str, records: list[dict]) -> List[Dict]:
        """Update records.

        Args:
            entity (str): Entity to be updated.
            records (list): Records to be updated.

        Returns:
            List: List of updated records.
        """
        entity_name = entity.lower()
        norm_score_skip_count = 0
        update_count = 0
        updated_records = []

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} "
            f"{entity_name} record(s) from {PLATFORM_NAME} platform."
        )
        try:
            if not records:
                self.logger.info(
                    "Skipped calculating Netskope normalized "
                    f"risk score for {entity} entity as there"
                    " is no risk score."
                )
                return []
            if entity == USERS:
                user_records = self._remove_unwanted_empty_fields(
                    records, USERS
                )
                update_count = 0
                for user in user_records:
                    risk_score = user.get("Risk Score", "")
                    if isinstance(risk_score, (float, int)):
                        user["Netskope Normalized Risk Score"] = (
                            self._normalize_risk_scores(risk_score)
                        )
                        update_count += 1
                        updated_records.append(user)
                    else:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Invalid "
                                f"{PLATFORM_NAME} Risk Score received"
                                f" for User ID: {user.get('User ID')}. "
                                "Netskope Normalized Score will not be"
                                " calculated for this user."
                            ),
                            details=f"Risk Score: '{risk_score}'",
                        )
                        norm_score_skip_count += 1
            elif entity == ENDPOINTS:
                endpoint_records = self._remove_unwanted_empty_fields(
                    records, ENDPOINTS
                )
                for endpoint in endpoint_records:
                    risk_score = endpoint.get("Risk Score", "")
                    if isinstance(risk_score, (float, int)):
                        endpoint["Netskope Normalized Risk Score"] = (
                            self._normalize_risk_scores(risk_score)
                        )
                        update_count += 1
                        updated_records.append(endpoint)
                    else:
                        norm_score_skip_count += 1
            else:
                err_msg = (
                    f"Invalid entity found. {PLATFORM_NAME} plugin"
                    " supports 'Users' and 'Endpoints' Entity."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise PaloAltoNetworksCortexXDRPluginException(err_msg)
        except PaloAltoNetworksCortexXDRPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while updating {entity_name}"
                f" records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)
        if norm_score_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped calculating "
                "Netskope Normalized Score for "
                f"{norm_score_skip_count} {entity_name} record(s)"
                " as invalid Risk Score value received from the"
                f" {PLATFORM_NAME} platform."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully updated"
            f" {update_count} {entity_name} record(s)"
            f" from {PLATFORM_NAME} platform."
        )
        return updated_records

    def _remove_unwanted_empty_fields(
        self,
        records: List[Dict],
        record_type: Literal["Users", "Endpoints"],
    ) -> List[Dict]:
        """
        Remove records which do not have either 'User ID' or 'Endpoint ID'
        or 'Endpoint Name' field depending on the record type.

        Args:
            records (List[Dict]): List of records to be filtered.
            record_type (str): Type of records. It can be 'Users' or
            'Endpoints'.

        Returns:
            List[Dict]: List of records which contain 'User ID' or
            'Endpoint ID' and 'Endpoint Name' field.
        """
        non_empty_records = []
        skipped_records = 0
        for record in records:
            if record_type == USERS:
                skipped_keys = "'User ID' field."
                if not record.get("User ID", ""):
                    skipped_records += 1
                else:
                    non_empty_records.append(
                        {
                            "User ID": record.get("User ID", ""),
                            "Risk Score": record.get("Risk Score", ""),
                        }
                    )
            elif record_type == ENDPOINTS:
                skipped_keys = "'Endpoint ID' and 'Endpoint Name' fields."
                if not record.get("Endpoint ID", "") and not record.get(
                    "Endpoint Name", ""
                ):
                    skipped_records += 1
                else:
                    non_empty_records.append(
                        {
                            "Endpoint ID": record.get("Endpoint ID", ""),
                            "Endpoint Name": record.get("Endpoint Name", ""),
                            "Risk Score": record.get("Risk Score", ""),
                        }
                    )
            else:
                err_msg = f"Invalid record type: '{record_type}' provided."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise PaloAltoNetworksCortexXDRPluginException(err_msg)
        log_msg = (
            f"{len(non_empty_records)} {record_type} record(s) will be"
            f" updated out of {len(records)} records."
        )
        if skipped_records > 0:
            log_msg += (
                f" {skipped_records} {record_type} record(s)"
                " will be skipped as they do not contain"
                f" {skipped_keys}"
            )
        self.logger.info(f"{self.log_prefix}: {log_msg}")
        return non_empty_records

    def _normalize_risk_scores(self, risk_score: int) -> int:
        """
        Normalize the Palo Alto Cortex XDR Risk Score.

        Args:
            risk_score (int): Palo Alto Cortex XDR Risk Score.

        Returns:
            int: Netskope normalized risk score.
        """
        if risk_score > 100:
            return 0
        netskope_normalized_score = round(1000 * (1 - (risk_score / 100)))
        return netskope_normalized_score

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed_url = urlparse(url)
        return parsed_url.scheme and parsed_url.netloc

    def _check_configuration_or_action_field_empty_and_type(
        self,
        field_name: str,
        field_value: str,
        field_type: type,
        is_configuration: True,
    ):
        empty_err_msg = "{field_name} is a required {field} parameter."
        type_err_msg = (
            "Invalid value provided for the {field} parameter '{field_name}'."
        )
        if isinstance(field_value, str):
            field_value = field_value.strip()
        if is_configuration:
            empty_err_msg = empty_err_msg.format(
                field_name=field_name,
                field=CONFIGURATION,
            )
            type_err_msg = type_err_msg.format(
                field=CONFIGURATION,
                field_name=field_name,
            )
            validation_err_msg = "Validation error occurred."
            logger_msg_empty = f"{validation_err_msg} {empty_err_msg}"
            logger_msg_type = f"{validation_err_msg} {type_err_msg}"
        else:
            logger_msg_empty = empty_err_msg.format(
                field_name=field_name,
                field=ACTION,
            )
            logger_msg_type = type_err_msg.format(
                field=ACTION,
                field_name=field_name,
            )
        if not field_value:
            self.logger.error(f"{self.log_prefix}: {logger_msg_empty}")
            return ValidationResult(success=False, message=logger_msg_empty)
        if not isinstance(field_value, field_type):
            self.logger.error(
                message=(f"{self.log_prefix}: {logger_msg_type}"),
                details=(
                    f"{(CONFIGURATION if is_configuration else ACTION).capitalize()}"
                    f" parameter '{field_name}' should be of type"
                    f" '{field_type.__name__}.'"
                ),
            )
            return ValidationResult(success=False, message=logger_msg_type)

    def _validate_connectivity(
        self,
        base_url: str,
        api_key_id: str,
        api_key: str,
        auth_method: Literal["standard", "advanced"],
    ) -> ValidationResult:
        self.logger.debug(
            f"{self.log_prefix}: Validating connectivity with"
            f" {PLATFORM_NAME} server."
        )
        try:
            headers = self.palo_alto_cortex_helper.get_auth_headers(
                api_key_id, api_key, auth_method
            )
            self.palo_alto_cortex_helper.api_helper(
                logger_msg=(
                    f"validating connectivity with {PLATFORM_NAME}"
                    " server"
                ),
                url=f"{base_url}{VALIDATE_API}",
                method="POST",
                headers=headers,
                json={},
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=True,
                is_handle_error_required=True,
            )

            log_msg = (
                f"Validation successful for {MODULE_NAME}"
                f" {PLATFORM_NAME} plugin."
            )
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(success=True, message=log_msg)
        except PaloAltoNetworksCortexXDRPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def validate(self, configuration: Dict) -> ValidationResult:
        base_url, api_key, api_key_id, auth_method = (
            self.palo_alto_cortex_helper.get_configuration_parameters(
                configuration=configuration
            )
        )

        # Base URL
        if validation_result := self._check_configuration_or_action_field_empty_and_type(
            "API Base URL", base_url, str, True
        ):
            return validation_result

        if not self._validate_url(base_url):
            err_msg = (
                "Invalid value provided for the configuration parameter"
                " 'API Base URl'."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # API Key ID
        if validation_result := self._check_configuration_or_action_field_empty_and_type(
            "API Key ID", api_key_id, str, True
        ):
            return validation_result

        # API Key
        if validation_result := self._check_configuration_or_action_field_empty_and_type(
            "API Key", api_key, str, True
        ):
            return validation_result

        # Auth Method
        if validation_result := self._check_configuration_or_action_field_empty_and_type(
            "Authentication Method", auth_method, str, True
        ):
            return validation_result

        if auth_method.lower() not in [STANDARD, ADVANCED]:
            err_msg = (
                f"Invalid Authentication Method '{auth_method}'"
                " provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return self._validate_connectivity(
            base_url,
            api_key_id,
            api_key,
            auth_method,
        )

    def get_entities(self) -> List[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name="User ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Risk Score",
                        type=EntityFieldType.NUMBER,
                        required=True,
                    ),
                    EntityField(name="Email", type=EntityFieldType.STRING),
                    EntityField(
                        name="Risk Level",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Normalized Risk Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Netskope Normalized Risk Score",
                        type=EntityFieldType.NUMBER,
                    ),
                ],
            ),
            Entity(
                name="Endpoints",
                fields=[
                    EntityField(
                        name="Endpoint ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Endpoint Name",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Risk Score",
                        type=EntityFieldType.NUMBER,
                        required=True,
                    ),
                    EntityField(
                        name="IPv4 Address",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="IPv6 Address",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Public IP Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Users",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Domain",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="MAC Address",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Risk Level",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Normalized Risk Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Netskope Normalized Risk Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Isolation Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Operational Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Scan Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Group Name",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Endpoint Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Endpoint Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Operating System Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Operating System Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Operating System Version",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Server Tags",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Endpoint Tags",
                        type=EntityFieldType.LIST,
                    ),
                ],
            ),
        ]
