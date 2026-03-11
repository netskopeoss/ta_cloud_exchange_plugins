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

CRE Microsoft Intune Plugin parser module.
"""

import json
from typing import Any, Dict, List, Tuple  # type: ignore
from urllib.parse import urlparse, parse_qs

from requests.models import Response
from netskope.integrations.crev2.models import Action

from .constants import ACTION_BATCH_SIZE, CUSTOM_SEPARATOR
from .exceptions import MicrosoftIntunePluginException


class MicrosoftIntuneParser:
    """Microsoft Intune Parser class."""

    def __init__(self, logger, log_prefix, is_ce_post_v512: bool) -> None:
        """
        MicrosoftIntuneParser initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): Log prefix.
            is_ce_post_v512 (bool): Flag to check if CE version is more
                than v5.1.2
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.partial_action_result_supported = is_ce_post_v512

    def _add_field(self, fields_dict: dict, field_name: str, value):
        """
        Add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        fields_dict[field_name] = value

    def _extract_field_from_event(
        self, key: str, event: dict, default, transformation=None
    ):
        """
        Extract field from event.

        Args:
            key (str): Key to fetch.
            event (dict): Event dictionary.
            default (str,None): Default value to set.
            transformation (str, None, optional): Transformation
                function to perform on the event value. Defaults to None.

        Returns:
            Any: Value of the key from event.
        """
        keys = key.split(".")
        while keys:
            k = keys.pop(0)
            if k not in event and default is not None:
                return default
            event = event.get(k, {})
        if transformation:
            transformation_func = getattr(self, transformation)
            return transformation_func(event)
        return event

    def extract_entity_fields(
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
            self._add_field(
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

    def parse_response(
        self,
        response: Response,
        logger_msg: str,
        is_validation: bool,
    ):
        """
        Parse API Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received "
                f"from API while {logger_msg}. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify API Base URL provided in the "
                    "configuration parameters. Check logs"
                    " for more details."
                )
            raise MicrosoftIntunePluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing "
                f"json response while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify API Base URL provided in the "
                    "configuration parameters. Check logs"
                    " for more details."
                )
            raise MicrosoftIntunePluginException(err_msg)

    def extract_next_token(self, next_page_url: str):
        """
        Extracts the next page token from the next page URL.

        Args:
            next_page_url (str): Next page URL.

        Returns:
            str: Next page token.
        """
        return parse_qs(urlparse(next_page_url).query).get("$skiptoken")[0]

    def _get_action_params(self, action, action_fields: List[str]):
        """
        Get action parameters.

        Args:
            action (Action): Action object.
            action_fields (List[str]): List of action fields.

        Returns:
            Dict: Action parameters.
        """
        if self.partial_action_result_supported:
            action_params = action.get("params", {}).parameters
            action_id = action.get("id")
        else:
            action_params = action.parameters
            action_id = action.parameters.get("device_id")
        action_params = {
            field: action_params.get(field) for field in action_fields
        }
        action_params["action_id"] = action_id
        if action_params.get("scan_type") == "quick scan":
            action_params["quickScan"] = True
        elif action_params.get("scan_type") == "full scan":
            action_params["quickScan"] = False
        return action_params

    def create_batches_for_action(
        self,
        actions: List[Action],
        api_endpoint: str,
        batch_size: int = ACTION_BATCH_SIZE,
    ) -> Dict[int, List[Dict[str, Any]]]:
        """
        Create batches for action.

        Args:
            actions (List[Action]): List of actions.
            api_endpoint (str): API endpoint.
            batch_size (int, optional): Batch size. Defaults to
                ACTION_BATCH_SIZE.

        Returns:
            Dict[int, List[Dict[str, Any]]]: Dictionary of batches.
        """
        batches = {}
        count = 0
        batch_number = 1
        empty_device_id_skip = 0

        for action_data in actions:
            action_params = self._get_action_params(
                action=action_data,
                action_fields=["device_id", "scan_type"]
            )
            action_id = action_params.get("action_id")
            device_id = action_params.get("device_id")
            if not device_id:
                empty_device_id_skip += 1
                continue
            action_api_request = {
                "id": f"{action_id}{CUSTOM_SEPARATOR}{device_id}",
                "url": api_endpoint.format(device_id=device_id),
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
            }
            if action_params.get("scan_type", None) is None:
                action_api_request["body"] = {}
            else:
                action_api_request["body"] = {
                    "quickScan": action_params.get("quickScan"),
                }
            batches.setdefault(batch_number, []).append(
                action_api_request
            )
            count += 1

            if count == batch_size:
                batch_number += 1
                count = 0
        if empty_device_id_skip:
            self.logger.info(
                f"{self.log_prefix}: {empty_device_id_skip} device(s) will be"
                " skipped from action as 'device_id' is empty."
            )

        return batches

    def parse_batched_response(
        self, batched_response: Dict
    ) -> Tuple[int, int, Dict, List]:
        """
        Parse batched response.

        Args:
            batched_response (Dict): Batched response.

        Returns:
            Tuple[int, int, Dict, List]: Tuple of success, failed,
                failure reason, and failed action IDs.
        """
        success = 0
        failed = 0
        failure_reason = {}
        failed_action_ids = []
        for response in batched_response.get("responses", []):
            status = response.get("status")
            response_id = response.get("id").split(CUSTOM_SEPARATOR)
            action_id = response_id[0]
            device_id = response_id[1]
            if status == 204:
                success += 1
            else:
                failed += 1
                failure_reason[device_id] = response.get("body")
                failed_action_ids.append(action_id)
        return success, failed, failure_reason, failed_action_ids

    def parse_failed_batched_request(
        self,
        batched_request: List[Dict[str, Any]],
    ) -> Tuple[int, List, List]:
        """
        Parse failed batched request.

        Args:
            batched_request (List[Dict[str, Any]]): List of batched requests.

        Returns:
            Tuple[int, List, List]: Tuple of action IDs, failed action IDs,
                and failed action IDs.
        """
        action_ids = []
        for request in batched_request:
            request_id = request.get("id").split(CUSTOM_SEPARATOR)
            action_id = request_id[0]

            action_ids.append(action_id)

        return action_ids

    def _truncate_decimal(self, value) -> float:
        """
        Truncates a float to 2 decimal places.

        Args:
            value (float): Float value.

        Returns:
            float: Truncated float value.
        """
        return round(float(value), 2)

    def _format_mac_address(self, mac_address: str) -> str:
        """
        Formats a MAC address string to a colon-separated string.

        Args:
            mac_address (str): MAC address string.

        Returns:
            str: Formatted MAC address string.
        """
        if mac_address and ":" not in mac_address:
            return ":".join(
                mac_address[i: i + 2] for i in range(0, len(mac_address), 2)
            )
        return mac_address
