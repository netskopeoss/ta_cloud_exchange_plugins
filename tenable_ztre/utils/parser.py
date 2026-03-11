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

CRE Tenable Plugin parser module.
"""

import json
from dateutil import parser
from typing import Dict

from requests.models import Response
from .exceptions import TenablePluginException


class TenableParser:
    """Tenable Parser class."""

    def __init__(self, logger, log_prefix) -> None:
        """
        TenableParser initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): Log prefix.
        """
        self.logger = logger
        self.log_prefix = log_prefix

    def _extract_field_from_event(
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
                function to perform on the event value. Defaults to None.

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

    def extract_entity_fields(
        self,
        event: dict,
        entity_field_mapping: Dict[str, Dict[str, str]],
        entity: str,
    ) -> dict:
        """
        Extracts the required entity fields from the event payload as
        per the mapping provided.

        Args:
            event (dict): Event payload.
            entity_field_mapping (Dict): Mapping of entity fields to
                their corresponding keys in the event payload and
                default values.
            entity (str): Entity type.

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
                    key, event, default, transformation
                ),
            )

        if entity == "assets":
            if sources_names := extracted_fields.get("Sources Name", []):
                extracted_fields["Sources Name"] = [
                    source.get("name") for source in sources_names
                    if source.get("name")
                ]

            if hostnames := extracted_fields.get("Hostnames", []):
                hostname = self._select_hostname(hostnames)
                if hostname:
                    extracted_fields["Hostname"] = hostname

        return extracted_fields

    def _select_hostname(self, hostnames: list[str]) -> str | None:
        """
        Selects a single canonical hostname from Tenable hostnames list.

        Args:
            hostnames (list[str]): List of hostnames.

        Returns:
            str | None: Selected hostname or None if no safe choice.
        """

        if not hostnames:
            return None

        hostnames = [h.strip() for h in hostnames if h and h.strip()]
        # Rule 1: only one hostname
        if len(hostnames) == 1:
            return hostnames[0]

        # Rule 2: exactly one FQDN (contains '.')
        fqdn_hosts = [h for h in hostnames if '.' in h]
        if len(fqdn_hosts) == 1:
            return fqdn_hosts[0]

        # Rule 3: ambiguous
        return None

    def _extract_tags(self, tags):
        """Extract tags from response

        Args:
            tags (list): List of tags

        Returns:
            list: List of tags
        """
        tags_list = []
        if tags and isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, dict):
                    tag_key = tag.get("key")
                    tag_value = tag.get("value")
                    if tag_key and tag_value:
                        tags_list.append(
                            f"{tag_key}:{tag_value}"
                        )
                else:
                    tag_value = tag.strip()
                    if tag_value:
                        tags_list.append(tag_value)
        return tags_list

    def _parse_datetime(
        self,
        datetime_str: str,
    ):
        """Parse datetime string into datetime object.

        Args:
            datetime_str (str): Datetime string to parse.

        Returns:
            datetime: Parsed datetime object.
        """
        try:
            return parser.parse(datetime_str)
        except Exception:
            return None

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
            logger_msg (str): Logger message.
            is_validation (bool): Is validation.

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
                    "Verify Access Key ID and Secret Access Key "
                    "provided in the configuration parameters. "
                    "Check logs for more details."
                )
            raise TenablePluginException(err_msg)
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
                    "Verify Access Key ID and Secret Access Key "
                    "provided in the configuration parameters. "
                    "Check logs for more details."
                )
            raise TenablePluginException(err_msg)
