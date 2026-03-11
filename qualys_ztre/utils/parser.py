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

CRE Qualys plugin parser.
"""

import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Literal, Set, Tuple, Union

from netskope.integrations.crev2.models import Action
from requests.models import Response

from .constants import IS_PATCHABLE_MAPPING

from .exceptions import QualysPluginException, exception_handler


class QualysParser:
    """Qualys Parser class."""

    def __init__(
        self, logger, log_prefix, partial_action_result_supported: bool
    ) -> None:
        """
        QualysParser initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): Log prefix.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.partial_action_result_supported = partial_action_result_supported
        self.response_parsers = {
            "json": self.parse_json_response,
            "xml": self.parse_xml_response,
            "plain": self.parse_plain_text_response,
        }
        self.extraction_functions = {
            "json": self._extract_field_from_json_event,
            "xml": self._extract_field_from_xml_event,
        }

    def _extract_network_interfaces_data(
        self,
        network_interfaces: List[Dict]
    ) -> Dict[str, str]:
        """Flatten network interface details into per-field lists.

        Args:
            network_interfaces (List[Dict]): Raw Qualys network interface
                structures pulled from an asset payload.

        Returns:
            Dict[str, List[str]]: Mapping of normalized field names (IPv4,
                IPv6, MAC) to lists of values extracted from all interfaces.
        """
        extracted_data = {}
        extraction_info = {
            "Network Interfaces IPv4 Address": "addressIpV4",
            "Network Interfaces IPv6 Address": "addressIpV6",
            "Network Interfaces Mac Address": "macAddress",
        }
        for network_interface in network_interfaces:
            for field_name, field_to_extract in extraction_info.items():
                if field_to_extract not in network_interface:
                    continue
                extracted_data.setdefault(
                    field_name,
                    [],
                ).append(network_interface.get(field_to_extract))
        return extracted_data

    def _add_field(self, fields_dict: dict, field_name: str, value):
        """
        Add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        # Skip empty dicts to prevent MongoDB errors
        if (isinstance(value, dict) or isinstance(value, list)) and not value:
            fields_dict[field_name] = None
            return

        if isinstance(value, int) or isinstance(value, float):
            fields_dict[field_name] = value
            return

        fields_dict[field_name] = value

    def _extract_field_from_json_event(
        self,
        key: str,
        event: dict,
        default,
        transformation=None,
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
            if k not in event:
                return default
            if not isinstance(event, dict):
                return default
            event = event.get(k)
        if transformation and transformation == "string":
            return str(event)
        if transformation:
            transformation_func = getattr(self, transformation)
            return transformation_func(event)
        return event

    @exception_handler
    def extract_entity_fields(
        self,
        event: dict,
        entity_field_mapping: Dict[str, Dict[str, str]],
        event_type: Literal["json", "xml"],
        entity_name: Literal["assets", "web applications", ""] = "",
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
        extraction_function = self.extraction_functions.get(event_type)
        for field_name, field_value in entity_field_mapping.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self._add_field(
                extracted_fields,
                field_name,
                extraction_function(
                    key,
                    event,
                    default,
                    transformation,
                ),
            )

        if entity_name == "assets":
            risk_score = extracted_fields.get("Risk Score")
            if risk_score is not None:
                extracted_fields["Netskope Normalized Risk Score"] = (
                    self.calculate_netskope_normalized_risk_score(
                        risk_score=int(risk_score)
                    )
                )
            if network_interfaces := extracted_fields.get("Network Interfaces"):
                network_interface_data = self._extract_network_interfaces_data(
                    network_interfaces=network_interfaces
                )
                extracted_fields.update(network_interface_data)
                extracted_fields.pop("Network Interfaces")
            if tags := extracted_fields.get("Tags"):
                tags_list = []
                for tags_data in tags:
                    if tag_name := tags_data.get("tagName"):
                        tags_list.append(tag_name)
                extracted_fields["Tags"] = tags_list
            if users := extracted_fields.get("Users"):
                users_list = []
                for users_data in users:
                    if user_name := users_data.get("name"):
                        users_list.append(user_name)
                extracted_fields["Users"] = users_list
            if open_ports := extracted_fields.get("Open Ports"):
                ports = []
                for ports_data in open_ports:
                    if port := ports_data.get("port"):
                        ports.append(port)
                extracted_fields["Open Ports"] = ports
        if entity_name == "web applications":
            # Cannot use walrus operator here since Risk Score can be zero
            # and we want to skip normalization only when the Risk Score is
            # None.
            risk_score = extracted_fields.get("Risk Score")
            if risk_score is not None:
                extracted_fields["Netskope Normalized Risk Score"] = (
                    self.calculate_netskope_normalized_risk_score(
                        risk_score=int(risk_score)
                    )
                )
            if tags := extracted_fields.get("Tags"):
                tags_list = []
                for tag_data in tags:
                    if tag_name := tag_data.get("Tag", {}).get("name"):
                        tags_list.append(tag_name)
                extracted_fields["Tags"] = tags_list
        if "Is Patchable" in extracted_fields:
            is_patchable = extracted_fields.get("Is Patchable")
            if is_patchable is not None:
                extracted_fields["Is Patchable"] = IS_PATCHABLE_MAPPING.get(
                    str(is_patchable), is_patchable
                )
        return extracted_fields

    def _extract_field_from_xml_event(
        self,
        key: str,
        xml_element: ET.Element,
        default,
        transformation=None,
    ):
        """
        Extract field from XML event.

        Args:
            key (str): XPath-like key to fetch (supports dot notation
                for nested elements).
            xml_element (ET.Element): XML element.
            default (str,None): Default value to set.
            transformation (str, None, optional): Transformation
                function to perform on the extracted value. Defaults to None.
            extractions (str, None, optional): Extraction function to perform
                on complex datatype. Defaults to None.
            field_to_extract (str, None, optional): Field to extract from
                complex datatype. Defaults to None.

        Returns:
            Any: Value of the key from XML element.
        """
        keys = key.split(".")
        current_element = xml_element

        while keys and current_element is not None:
            k = keys.pop(0)
            # Try to find child element with this tag name
            child = current_element.find(k)
            if child is None:
                # Try to find as attribute if no child element found
                if len(keys) == 0:  # This is the last key, check attributes
                    attr_value = current_element.get(k)
                    if attr_value is not None:
                        if transformation:
                            transformation_func = getattr(self, transformation)
                            return transformation_func(attr_value)
                        return attr_value
                # If not found and we have a default, return it
                if default is not None:
                    return default
                return None
            current_element = child

        # If we've traversed all keys and have an element, get its text
        if current_element is not None:
            value = current_element.text
            if value is None and default is not None:
                return default
            if transformation and value is not None:
                transformation_func = getattr(self, transformation)
                return transformation_func(value)
            return value
        if extractions and field_to_extract:
            extraction_func = getattr(self, extractions)
            return extraction_func(xml_element, field_to_extract)
        return default

    @exception_handler
    def parse_response(
        self,
        response: Response,
        response_format: Literal["json", "xml" "plain"],
        logger_msg: str,
        is_validation: bool,
    ) -> Union[Dict, ET.Element, str]:
        response_parser_func = self.response_parsers.get(response_format)
        if not response_parser_func:
            err_msg = (
                f"Received invalid response format '{response_format}'"
                f"while {logger_msg}. Valid values are 'json', 'xml'"
                " or 'plain'."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise QualysPluginException(err_msg)
        return response_parser_func(
            response=response,
            logger_msg=logger_msg,
            is_validation=is_validation,
        )

    def parse_json_response(
        self,
        response: Response,
        logger_msg: str,
        is_validation: bool,
    ) -> Dict:
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
                    "Verify API Server URL and the API Gateway URL"
                    "provided in the configuration parameters."
                    " Check logs for more details."
                )
            raise QualysPluginException(err_msg)
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while parsing "
                f"json response while {logger_msg}. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify API Server URL and the API Gateway URL"
                    "provided in the configuration parameters."
                    " Check logs for more details."
                )
            raise QualysPluginException(err_msg)

    def parse_xml_response(
        self,
        response: Response,
        logger_msg: str,
        is_validation: bool,
    ) -> ET.Element:
        """
        Parse API Response will return XML from response object.

        Args:
            response (response): Response object.

        Returns:
            xml.etree.ElementTree.Element: Response XML.
        """
        try:
            return ET.fromstring(response.text)
        except ET.ParseError as err:
            err_msg = (
                "Invalid XML response received "
                f"from API while {logger_msg}. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify API Server URL and the API Gateway URL"
                    "provided in the configuration parameters."
                    " Check logs for more details."
                )
            raise QualysPluginException(err_msg)
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while parsing "
                f"XML response while {logger_msg}. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify API Server URL and the API Gateway URL"
                    "provided in the configuration parameters."
                    " Check logs for more details."
                )
            raise QualysPluginException(err_msg)

    def parse_plain_text_response(
        self,
        response: Response,
        logger_msg: str,
        is_validation: bool,
    ) -> str:
        """Return raw plaintext API responses without additional parsing.

        Args:
            response (Response): requests response instance.

        Returns:
            str: Body of the response as-is.
        """
        return response.text

    def create_batches(
        self, data_list: List, batch_size: int = 1000
    ) -> Dict[int, List[Union[Dict[str, str], str]]]:
        """Split a list into sequential batches of the requested size.

        Args:
            data_list (List): Items to be chunked.
            batch_size (int, optional): Maximum items per batch. Defaults to
                1000.

        Returns:
            Dict[int, List[Union[Dict[str, str], str]]]: Mapping of batch
                index (1-based) to sliced lists preserving order.

        Raises:
            ValueError: If batch_size is zero or negative.
        """
        if batch_size <= 0:
            raise ValueError("batch_size must be greater than 0")

        batches = {}
        batch_num = 1

        for i in range(0, len(data_list), batch_size):
            batches[batch_num] = data_list[i:i + batch_size]
            batch_num += 1

        return batches

    @exception_handler
    def combine_details(
        self,
        vulnerability_info: Dict,
        vulnerability_qid_to_id_field: Dict,
        host_id_to_required_fields: Dict[str, str] = None,
    ) -> List[Dict]:
        """Group vulnerability details by asset/web app and merge fields.

        Args:
            vulnerability_info (Dict): Mapping of QIDs to extracted field
                dictionaries.
            vulnerability_qid_to_id_field (Dict): Lookup from QID to owning
                asset/web-app identifier.
            host_id_to_required_fields (Dict[str, str], optional): Additional
                host metadata keyed by host ID for asset exports.

        Returns:
            List[Dict]: Aggregated records where each entry represents a single
                asset/web app along with collected QIDs and requested fields.
        """
        # Group data by host_id
        final_result = []

        for qid, vuln_data in vulnerability_info.items():
            id_field_name = (
                "Host ID" if host_id_to_required_fields else "Web Application ID"
            )
            updated_record = {}
            id_field = vulnerability_qid_to_id_field.get(qid)
            if id_field is None:
                continue
            updated_record[id_field_name] = id_field
            if host_id_to_required_fields:
                required_fields = host_id_to_required_fields.get(id_field, (0, ""))
                updated_record["Asset ID"] = required_fields[0]
                updated_record["Serial Number"] = required_fields[1]
            updated_record.update(vuln_data)
            final_result.append(updated_record)

        return final_result

    def _get_action_params(
        self, action, action_fields: List[str], parse_tags: bool = False
    ):
        """
        Get action parameters.

        Args:
            action (Action): Action object.
            action_fields (List[str]): List of action fields.
            parse_tags (bool): Whether to parse tags.

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
        if parse_tags:
            action_params["tags"] = action_params.get("tags", "").split(",")
        action_params["action_id"] = action_id
        return action_params

    def group_actions(
        self,
        group_by_field: Literal["tags", "id_field"],
        actions: List[Action],
        id_field: Literal["asset_id", "web_app_id"],
    ) -> Tuple[Dict[str, Set[str]], Dict, Set[str], int, Set]:
        """Bucket Cloud Exchange actions for bulk execution.

        Args:
            group_by_field (Literal["tags", "id_field"]): Primary grouping
                axis; "tags" groups by tag names, "id_field" by entity ID.
            actions (List[Action]): Incoming action payloads from CE.
            id_field (Literal["asset_id", "web_app_id"]): Field storing the
                entity identifier inside each action.

        Returns:
            Tuple[Dict[str, Set[str]], Dict, Set[str], int, Set]:
                grouped_actions mapping,
                id_field-to-action_id map,
                set of unique tags encountered,
                count of actions missing IDs,
                set of action IDs skipped due to empty IDs.
        """
        grouped_actions = {}
        all_action_tags = set()
        id_field_to_action_id_mapping = {}
        group_by_field = id_field if group_by_field == "id_field" else "tags"
        first_action_params = self._get_action_params(
            action=actions[0],
            action_fields=["tags", id_field],
            parse_tags=False,
        )

        # Check if tags field is a string(static) or list(source)
        parse_tags = None
        first_action_tags = first_action_params.get("tags")
        if isinstance(first_action_tags, str):
            parse_tags = True
        if isinstance(first_action_tags, list):
            parse_tags = False

        field_to_be_grouped = (
            first_action_params.keys() - {group_by_field, "action_id"}
        ).pop()
        empty_id_field_count = 0
        empty_id_field_action_id = set()
        for action in actions:
            action_params = self._get_action_params(
                action=action,
                action_fields=["tags", id_field],
                parse_tags=parse_tags,
            )

            # Create a set of all the tags present in the action
            all_action_tags.update(action_params["tags"])

            # Create mapping of id_field (asset_id, web_app_id) to action_id
            id_field_value = action_params[id_field]
            action_id = action_params["action_id"]
            if not id_field_value:
                empty_id_field_count += 1
                empty_id_field_action_id.add(action_id)
                continue
            id_field_to_action_id_mapping[id_field_value] = action_id

            # Group the action parameters based on group_by_field
            field_to_group_value = action_params.get(field_to_be_grouped)
            if not field_to_group_value:
                continue
            group_by_field_value = action_params.get(group_by_field)
            # When the group by field is Tags then we will have to
            # iterate over the list of tags
            if isinstance(group_by_field_value, List):
                for value in group_by_field_value:
                    if isinstance(field_to_group_value, List):
                        grouped_actions.setdefault(value, set()).update(
                            field_to_group_value
                        )
                    else:
                        grouped_actions.setdefault(value, set()).add(
                            field_to_group_value
                        )
            # Else the group by field will be a id_field (asset_id or
            # web_app_id).
            else:
                if isinstance(field_to_group_value, List):
                    grouped_actions.setdefault(group_by_field_value, set()).update(
                        field_to_group_value
                    )
                else:
                    grouped_actions.setdefault(group_by_field_value, set()).add(
                        field_to_group_value
                    )

        return (
            grouped_actions,
            id_field_to_action_id_mapping,
            all_action_tags,
            empty_id_field_count,
            empty_id_field_action_id,
        )

    def calculate_netskope_normalized_risk_score(self, risk_score: int) -> int:
        """
        Convert Qualys risk score to Netskope normalized risk score.

        Qualys: 0 = low risk, 1000 = high risk
        Netskope: 0 = high risk, 1000 = low risk

        Args:
            risk_score: Qualys risk score (0-1000)

        Returns:
            Netskope normalized risk score (0-1000)
        """
        # Ensure risk_score is within valid range
        risk_score = max(0, min(1000, risk_score))

        # Invert the score: 1000 - risk_score
        return 1000 - risk_score
