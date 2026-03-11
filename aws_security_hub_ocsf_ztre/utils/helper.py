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

AWS Security Hub OCSF helper module.
"""

from dateutil import parser
from packaging import version
from netskope.common.api import __version__ as CE_VERSION
from netskope.common.utils import add_user_agent
from .constants import (
    MODULE_NAME,
    DEVICE_FIELD_MAPPING,
    MAXIMUM_CE_VERSION
)


class AWSSecurityHubOCSFPluginHelper(object):
    """AWSSecurityHubOCSFPluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str
    ):
        """AWS Security Hub OCSF Plugin Helper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.resolution_support = version.parse(CE_VERSION) > version.parse(
            MAXIMUM_CE_VERSION
        )
        # Patch logger methods to handle resolution parameter compatibility
        self._patch_logger_methods()

    def _patch_logger_methods(self):
        """Monkey patch logger methods to handle \
            resolution parameter compatibility."""
        # Store original methods
        original_error = self.logger.error

        def patched_error(
            message=None, details=None, resolution=None, **kwargs
        ):
            """Patched error method that handles resolution compatibility."""
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self.resolution_support:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        # Replace logger methods with patched versions
        self.logger.error = patched_error

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

        def extract(keys, value):
            if not keys:
                return value

            k = keys[0]
            rest = keys[1:]

            if isinstance(value, list):
                results = []
                for item in value:
                    extracted = extract(keys, item)
                    if extracted != default:
                        # Flatten lists at every level
                        if isinstance(extracted, list):
                            results.extend(extracted)
                        else:
                            results.append(extracted)
                return results if results else default

            if not isinstance(value, dict) or k not in value:
                return default

            return extract(rest, value.get(k, None))

        value = extract(keys, event)

        # Special handling for Resource Tags: always return a list of dicts
        if key == "data.tags":
            if isinstance(value, dict):
                return [f"{k}:{v}" for k, v in value.items()]
            elif isinstance(value, list):
                tag_list = []
                for tag_dict in value:
                    tag = tag_dict.get("value", "")
                    if tag:
                        tag_list.append(tag)
                return tag_list
            elif value is None:
                return []
            else:
                return [str(value)]

        if transformation == "string":
            return str(value)
        return value

    def _extract_entity_fields(self, event: dict) -> dict:
        """Extract entity fields from event payload.

        Args:
            event (dict): Event Payload.

        Returns:
            dict: Dictionary containing required fields.
        """
        records = []
        resources = event.get("resources", [])
        for resource in resources:
            network_interfaces = (
                resource.get("data", {}).get("network_interfaces", [])
                or []
            )
            for network_interface in network_interfaces:
                record = {}
                for field_name, field_value in DEVICE_FIELD_MAPPING.items():
                    key, default, transformation, context = (
                        field_value.get("key"),
                        field_value.get("default"),
                        field_value.get("transformation"),
                        field_value.get("context", "event"),
                    )
                    if context == "network_interface":
                        value = self._extract_field_from_event(
                            key, network_interface, default, transformation
                        )
                    elif context == "resource":
                        value = self._extract_field_from_event(
                            key, resource, default, transformation
                        )
                    else:
                        value = self._extract_field_from_event(
                            key, event, default, transformation
                        )
                    record[field_name] = value

                # Parse datetime fields
                if "Last Seen" in record:
                    record["Last Seen"] = (
                        parser.parse(record.get("Last Seen"))
                    )
                if "First Seen" in record:
                    record["First Seen"] = (
                        parser.parse(record.get("First Seen"))
                    )
                records.append(self._post_process_fields(record))

        return records

    def _flatten_field(self, value):
        """Flatten the field value.

        Args:
            value (list): List of values.

        Returns:
            str: Flattened string.
        """
        if isinstance(value, list):
            if len(value) == 1:
                return value[0]
            elif len(value) > 1:
                return ", ".join(str(v) for v in value)
            else:
                return ""
        if isinstance(value, dict):
            return str(value)
        return value

    def _post_process_fields(self, extracted_fields):
        """Post process fields.

        Args:
            extracted_fields (dict): Extracted fields.

        Returns:
            dict: Processed fields.
        """
        fields_to_flatten = [
            "VPC ID",
            "Subnet ID",
            "Region",
            "Resource UID",
            "Resource Name",
            "Private IP",
            "Public IP"
        ]
        for field in fields_to_flatten:
            if field in extracted_fields:
                extracted_fields[field] = self._flatten_field(
                    extracted_fields[field]
                )
        return extracted_fields
