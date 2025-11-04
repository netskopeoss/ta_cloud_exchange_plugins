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

CRE Omnissa Workspace One UEM Plugin parser module.
"""

import json
from typing import Dict, List, Tuple, Union  # type: ignore

from requests.models import Response

from .constants import (
    CUSTOM_SEPARATOR,
    TAG_ALREADY_ATTACHED_MESSAGE,
    TAG_CHARACTER_LENGTH_LIMIT,
    TAG_NOT_ATTACHED_MESSAGE,
    VALIDATION_ERROR_MESSAGE,
)
from .exceptions import OmnissaWorkspaceOneUEMPluginException


class OmnissaWorkspaceOneUEMParser:
    """Omnissa Workspace One UEM Parser class."""

    def __init__(self, logger, log_prefix, is_ce_post_v512: bool) -> None:
        """
        OmnissaWorkspaceOneUEMParser initializer.

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
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)
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
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)

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
            action_id = ""
        action_params = {
            field: action_params.get(field) for field in action_fields
        }
        action_params["action_id"] = action_id
        return action_params

    def group_action_by_organization_id(
        self,
        actions: List,
        parse_tags: bool,
        skipped_action_ids: List[str],
    ) -> Tuple[Dict, List, Dict]:
        """
        Group actions by Organization ID.

        Args:
            actions (List): List of actions.
            parse_tags (bool): Flag to parse tags.
            skipped_action_ids (List[str]): List of skipped action ids.

        Returns:
            Tuple: Dictionary with Organization ID as key and
                list of actions as value, List of skipped action ids
        """
        grouped_actions = {}
        device_id_to_action_id = {}

        empty_org_id_skipped_devices = []
        empty_org_id_skipped_devices_action_ids = []
        empty_device_id_skip_action_ids = []
        for action in actions:
            action_params = self._get_action_params(
                action, action_fields=["device_id", "tags", "organization_id"]
            )
            organization_id = str(action_params.get("organization_id", ""))
            device_id = str(action_params.get("device_id", ""))
            if parse_tags:
                action_params.update(
                    {
                        "tags": self._convert_string_to_list(
                            action_params.get("tags"), ','
                        )
                    }
                )
            action_id = action_params.get("action_id")
            if not organization_id:
                empty_org_id_skipped_devices.append(device_id)
                empty_org_id_skipped_devices_action_ids.append(action_id)
                continue
            if not device_id:
                empty_device_id_skip_action_ids.append(action_id)
                continue

            grouped_actions.setdefault(
                organization_id,
                [],
            ).append(action_params)
            device_id_to_action_id[device_id] = action_id

        skip_logger_msg = (
            "{count} devices skipped as they do not have a '{field}'."
        )
        if empty_org_id_skipped_devices:
            logger_msg = skip_logger_msg.format(
                count=len(empty_org_id_skipped_devices),
                field="Organization ID",
            )
            self.logger.info(
                message=(
                    f"{self.log_prefix}: {logger_msg}"
                ),
                details=(
                    f"Skipped Device IDs:"
                    f" {', '.join(empty_org_id_skipped_devices)}"
                ),
            )
            skipped_action_ids.extend(empty_org_id_skipped_devices_action_ids)

        if empty_device_id_skip_action_ids:
            logger_msg = skip_logger_msg.format(
                count=len(empty_device_id_skip_action_ids),
                field="Device ID",
            )
            self.logger.info(
                message=(
                    f"{self.log_prefix}: {logger_msg}"
                ),
                details=(
                    f"Skipped Device IDs:"
                    f" {', '.join(empty_device_id_skip_action_ids)}"
                ),
            )
            skipped_action_ids.extend(empty_device_id_skip_action_ids)
        if self.partial_action_result_supported:
            return grouped_actions, skipped_action_ids, device_id_to_action_id
        return grouped_actions, [], {}

    def create_batch_for_action_execution(
        self, devices_by_tags: Dict[str, Dict], batch_size: int = 500
    ) -> Dict[str, Dict[str, Union[str, List[str]]]]:
        """
        Create batches of devices grouped by Organization ID
        for tagging operations.

        Args:
            action_data (Dict[str, Dict]): Action data

        Returns:
            Dict[str, Dict]: Dictionary with Organization ID and batch number
                as key and device information as value
        """
        devices_batch = {}
        for key, action_details in devices_by_tags.items():
            tag_id = action_details.get("tag_id")
            device_ids = action_details.get("device_ids")
            for batch_number, i in enumerate(
                range(0, len(device_ids), batch_size)
            ):
                devices_batch[f"{key}{CUSTOM_SEPARATOR}{batch_number+1}"] = {
                    "tag_id": tag_id,
                    "device_ids": device_ids[i: i + batch_size],
                }

        return devices_batch

    def get_list_of_tags_to_create(
        self, action_tags: List[str], existing_tags: List[str]
    ) -> Tuple[set[str], set[str]]:
        """
        Determine which tags need to be created and which already exist.

        This method compares the tags specified in the action with the
        existing tags on the platform to identify which tags need to be
        created and which ones can be skipped because they already exist.

        Args:
            action_tags (List[str]): List of tag names specified in the action.
            existing_tags (List[str]): List of tag names that already exist
                on the platform.

        Returns:
            Tuple: A tuple containing:
                - Set of tag names that need to be created (tags in
                    action_tags but not in existing_tags)
                - Set of tag names that already exist (intersection of
                    action_tags and existing_tags)
        """
        if not existing_tags:
            return set(action_tags), set()
        tags_to_create = set()
        tags_not_to_create = set()
        existing_tag_set = set(existing_tags)
        for action_tag in action_tags:
            if action_tag.lower() in existing_tag_set:
                tags_not_to_create.add(action_tag)
            else:
                tags_to_create.add(action_tag)
        return tags_to_create, tags_not_to_create

    def create_tag_name_to_id_dict(
        self,
        tags_name: List[str],
        tags_id_dict: Dict[str, str],
    ) -> Dict[str, str]:
        """
        Create a dictionary mapping tag names to their corresponding IDs.

        This method filters the provided tags_id_dict to include only entries
        where the tag name exists in the tags_name list.

        Args:
            tags_name (List[str]): List of tag names to include in the mapping.
            tags_id_dict (Dict[str, str]): Dictionary mapping tag names to
                their IDs.

        Returns:
            Dict: Filtered dictionary containing only the tag names
                from tags_name list with their corresponding IDs.
        """
        tag_name_to_id_dict = {}
        for tag in tags_name:
            tag_lower = tag.lower()
            if tag_lower in tags_id_dict:
                tag_name_to_id_dict[tag] = tags_id_dict[tag_lower]
        return tag_name_to_id_dict

    def get_failed_device_details(
        self,
        failure_reason: List[Dict],
        device_id_to_action_id: Dict[str, str],
        failed_action_ids: List[str],
    ) -> Tuple[Dict[str, Dict[str, str]], List[str], List[str]]:
        """
        Extract details of failed device operations and their corresponding
        action IDs.

        This method processes a list of failure reasons, extracts device
        IDs, retrieves corresponding action IDs, and compiles error
        information.

        Args:
            failure_reason (List[Dict]): List of dictionaries containing
                failure information for devices. Each dictionary should
                have 'ItemValue', 'ErrorCode', and 'Message' keys.
            device_id_to_action_id (Dict[str, str]): Mapping of device
                IDs to their action IDs.
            failed_action_ids (List[str]): Existing list of failed action
                IDs to append to.

        Returns:
            Tuple: A tuple containing:
                - Dictionary mapping device IDs to their error details
                    (ErrorCode and Message)
                - Updated list of failed action IDs
                - While tagging: List of device IDs for which tag is already
                    attached. While un-tagging: List of device IDs for which
                    tag is not attached
        """
        failed_to_tag_devices = {}
        skip = []
        for reason in failure_reason:
            device_id = reason.get("ItemValue")
            error_message = reason.get("Message")
            # In case of tagging if tag is already attached or
            # while un-tagging if tag is not attached we will
            # not consider it as failure
            if error_message.lower() in [
                TAG_ALREADY_ATTACHED_MESSAGE,
                TAG_NOT_ATTACHED_MESSAGE,
            ]:
                skip.append(device_id)
                continue
            failed_action_ids = self.get_failed_device_action_ids(
                failed_device_ids=[device_id],
                device_id_to_action_id=device_id_to_action_id,
                failed_action_ids=failed_action_ids,
            )
            failed_to_tag_devices[device_id] = {
                "ErrorCode": reason.get("ErrorCode"),
                "Message": error_message,
            }
        return (
            failed_to_tag_devices,
            failed_action_ids,
            skip
        )

    def _convert_string_to_list(
        self,
        data: str,
        separator: str = ",",
    ) -> List[str]:
        """
        Convert a string to a list of strings.

        Args:
            data (str): String to convert.
            separator (str, optional): Separator to use. Defaults to ",".

        Returns:
            List[str]: List of strings.
        """
        data_list = []
        for obj in data.split(separator):
            if obj.strip():
                data_list.append(obj.strip())
        return data_list

    def get_required_fields(
        self,
        data: List[Dict],
        required_fields: List[str],
    ) -> List[Dict]:
        """
        Extract required fields from a list of dictionaries.

        Args:
            data (List[Dict]): List of dictionaries.
            required_fields (List[str]): List of required fields.

        Returns:
            List[Dict]: List of dictionaries with only the required fields.
        """
        required_field_dict = []
        for item in data:
            required_field_dict.append(
                {field: item.get(field) for field in required_fields}
            )
        return required_field_dict

    def get_failed_device_action_ids(
        self,
        failed_device_ids: List[str],
        device_id_to_action_id: Dict,
        failed_action_ids: List[str],
    ):
        """
        Retrieve action IDs for failed devices and add them to the
        failed_action_ids list.

        This method maps device IDs to their corresponding action IDs
        and appends them to the list of failed action IDs. The operation
        is only performed if partial action result reporting is supported
        by the currentCloud Exchange version.

        Args:
            failed_device_ids (List[str]): List of device IDs that failed
                during an operation.
            device_id_to_action_id (Dict[str, str]): Mapping of device IDs
                to their action IDs.
            failed_action_ids (List[str]): Existing list of failed action
                IDs to append to.

        Returns:
            List[str]: Updated list of failed action IDs. Returns an empty
                list if partial action result reporting is not supported.
        """
        if not self.partial_action_result_supported:
            return []
        for failed_ids in failed_device_ids:
            failed_action_ids.append(device_id_to_action_id.get(failed_ids))
        return failed_action_ids

    def upsert_action_result_values(
        self,
        tag_name: str,
        success_count: int,
        failed_count: int,
        action_result: Dict,
    ):
        """
        Update or insert success and failure counts for a specific tag in
        the action result dictionary.

        Args:
            tag_name (str): The name of the tag for which to update counts.
            success_count (int): The number of successful operations to add.
            failed_count (int): The number of failed operations to add.
            action_result (Dict): The dictionary containing action results
                to be updated.

        Returns:
            Dict: The updated action result dictionary with incremented
                counters.
        """
        counter = action_result.setdefault(
            tag_name,
            {
                "success": 0,
                "failed": 0,
            },
        )
        counter["success"] += success_count
        counter["failed"] += failed_count
        return action_result

    def update_final_action_result_dict(
        self,
        batched_action_result: Dict,
        final_action_result: Dict,
    ):
        """
        Update the final action result dictionary with results from a
        batch operation.

        This method iterates through the batched action results and updates
        the final action result dictionary with success and failure counts
        for each tag.

        Args:
            batched_action_result (Dict): Dictionary containing action results
                from a batch
                operation, with tag names as keys and counters as values.
            final_action_result (Dict): The final action result dictionary
                to be updated with the batch results.

        Returns:
            Dict: The updated final action result dictionary with aggregated
                success and failure counts.
        """
        for tag_name, counter in batched_action_result.items():
            final_action_result = self.upsert_action_result_values(
                tag_name=tag_name,
                success_count=counter["success"],
                failed_count=counter["failed"],
                action_result=final_action_result,
            )
        return final_action_result

    def group_tags_by_organization(self, action_dict: Dict):
        """
        Group tags by organization.

        Args:
            action_dict: Dictionary containing actions grouped by
                organization.

        Returns:
            A dictionary mapping organizations to lists of tags.
        """
        tags = {}
        for organization_id, action_details in action_dict.items():
            unique_tags = set()
            for action in action_details:
                unique_tags.update(action.get("tags", []))
            tags[organization_id] = list(unique_tags)
        return tags

    def group_devices_by_tags(
        self, action_by_organization: Dict, upserted_tags: Dict
    ) -> Dict[str, Dict[str, Union[str, List[str]]]]:
        """
        Group devices by tags.

        Args:
            action_by_organization: Dictionary containing actions grouped
                by organization.
            upserted_tags: Dictionary containing upserted tags for
                each organization.

        Returns:
            A dictionary mapping tags to a dictionary containing device IDs
                and tag IDs.
        """
        devices_by_tags = {}
        for organization_id, actions in action_by_organization.items():
            organization_tags = upserted_tags.get(organization_id, {})
            for action in actions:
                for tag in action.get("tags", []):
                    if not organization_tags.get(tag):
                        continue
                    inner_dict = devices_by_tags.setdefault(
                        f"{organization_id}{CUSTOM_SEPARATOR}{tag}",
                        {
                            "device_ids": [],
                            "tag_id": organization_tags.get(tag),
                        },
                    )
                    inner_dict["device_ids"].append(
                        str(action.get("device_id"))
                    )

        return devices_by_tags

    def validate_tags(self, tags: str) -> bool:
        """
        Validate a comma-separated string of tags against length constraints.

        This method checks if the provided tags string contains valid tags and
        ensures that each tag doesn't exceed the maximum allowed length.

        Args:
            tags (str): A comma-separated string of tag names to validate

        Returns:
            bool: True if all tags are valid, False otherwise
        """
        tags_list = self._convert_string_to_list(data=tags)
        long_tags = self.validate_tag_length(
            tags_list=tags_list,
            max_tag_length=TAG_CHARACTER_LENGTH_LIMIT
        )
        if long_tags:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} Found"
                    f" {len(long_tags)} tag(s) with length greater than"
                    f" {TAG_CHARACTER_LENGTH_LIMIT}. Please ensure tag"
                    f" length is less than {TAG_CHARACTER_LENGTH_LIMIT}"
                    " characters."
                ),
                details=(
                    f"Tags with length greater than "
                    f"{TAG_CHARACTER_LENGTH_LIMIT}: {', '.join(long_tags)}"
                ),
            )
            return False
        return True

    def validate_tag_length(
        self,
        tags_list: set[str],
        max_tag_length: int = TAG_CHARACTER_LENGTH_LIMIT,
    ) -> List[str]:
        """
        Identify tags that exceed the maximum allowed length.

        This method checks each tag in the provided list against the
        maximum allowed length and returns a list of tags that exceed
        this limit.

        Args:
            tags_list (List[str]): List of tags to validate
            max_tag_length (int): Maximum allowed length for a tag.

        Returns:
            List[str]: List of tags that exceed the maximum allowed
                length
        """
        long_tags = []
        for tag in tags_list:
            if len(tag) > max_tag_length:
                long_tags.append(tag)
        return long_tags
