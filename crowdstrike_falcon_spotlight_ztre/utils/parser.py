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

CRE CrowdStrike Falcon Spotlight Plugin parser module.
"""

import json
from typing import Dict

from requests.models import Response

from .constants import CVE_EXPLOIT_STATUS_MAPPING

from .exceptions import (
    CrowdstrikeFalconSpotlightPluginException,
    exception_handler,
)


class CrowdstrikeFalconSpotlightParser:
    """CrowdStrike Falcon Spotlight Parser class."""

    def __init__(self, logger, log_prefix) -> None:
        """
        CrowdstrikeFalconSpotlightParser initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): Log prefix.
        """
        self.logger = logger
        self.log_prefix = log_prefix

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
            event = event.get(k, None)
        if transformation:
            transformation_func = getattr(self, transformation)
            return transformation_func(event)
        return event

    @exception_handler
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
        cve_exploit_status = extracted_fields.get("CVE Exploit Status")
        if isinstance(cve_exploit_status, int):
            extracted_fields[
                "CVE Exploit Status"
            ] = CVE_EXPLOIT_STATUS_MAPPING.get(int(cve_exploit_status))
        if not extracted_fields.get("CVE ID", None):
            extracted_fields["CVE ID"] = event.get("vulnerability_id")

        tags = extracted_fields.get("Tags")
        if tags and isinstance(tags, list):
            extracted_fields["Tags"] = [
                tag.strip() for tag in tags if tag.strip()
            ]
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
            raise CrowdstrikeFalconSpotlightPluginException(err_msg)
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
            raise CrowdstrikeFalconSpotlightPluginException(err_msg)
