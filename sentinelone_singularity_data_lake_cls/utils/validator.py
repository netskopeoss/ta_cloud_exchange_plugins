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

SentinelOne Singularity Data Lake CLS plugin mapping validator.
"""

from typing import Any, Optional

from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from netskope.integrations.cls.utils.converter import type_converter

from .constants import CEF_HEADERS, SUPPORTED_DATA_TYPES

# Shape of the whole mapping document. The "json" branch maps each
# subtype to a list of field names; an empty list means "send every
# field". CEF branches (alerts/events/webtx) are checked separately.
MAPPINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "taxonomy": {
            "type": "object",
            "properties": {
                "json": {
                    "type": "object",
                    "patternProperties": {
                        ".*": {
                            "type": "object",
                            "patternProperties": {
                                ".*": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                }
                            },
                        }
                    },
                }
            },
            "required": ["json"],
        }
    },
    "required": ["taxonomy"],
}

# Shape of one CEF subtype mapping.
CEF_FIELD_SCHEMA = {
    "type": "object",
    "properties": {
        "mapping_field": {"type": "string"},
        "default_value": {"type": "string"},
        "transformation": {"type": "string"},
        "is_json_path": {"type": "boolean"},
    },
    "additionalProperties": False,
}
CEF_SUBTYPE_SCHEMA = {
    "type": "object",
    "properties": {
        "header": {
            "type": "object",
            "propertyNames": {"enum": list(CEF_HEADERS)},
            "additionalProperties": CEF_FIELD_SCHEMA,
        },
        "extension": {
            "type": "object",
            "additionalProperties": CEF_FIELD_SCHEMA,
        },
    },
    "required": ["header", "extension"],
}
CEF_DOCUMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "delimiter": {"type": "string", "enum": ["|"]},
        "cef_version": {"type": "string", "minLength": 1},
    },
    "required": ["delimiter", "cef_version"],
}


class SentinelOneSDLValidator:
    """Checks the mapping file."""

    def __init__(self, logger: Any, log_prefix: str):
        """Store the logging details.

        Args:
            logger (Any): Cloud Exchange logger.
            log_prefix (str): Prefix put in front of every log message.
        """
        self.logger = logger
        self.log_prefix = log_prefix

    @staticmethod
    def _describe_schema_error(
        err: JsonSchemaValidationError, location_prefix: str = ""
    ) -> str:
        """Turn a jsonschema error into a plain sentence with a location.

        Args:
            err (JsonSchemaValidationError): Schema error.
            location_prefix (str): Location of the checked part inside
                the mapping, for example "taxonomy > alerts > dlp".

        Returns:
            str: For example "Check 'taxonomy > json > alerts' in the
                mapping: [] is not of type 'object'."
        """
        parts = [location_prefix] if location_prefix else []
        parts.extend(str(part) for part in err.absolute_path)
        if not parts:
            return f"Check the top level of the mapping: {err.message}."
        location = " > ".join(parts)
        return f"Check '{location}' in the mapping: {err.message}."

    def _log_error(self, message: str, details: Optional[str] = None) -> None:
        """Log a mapping problem with a fix the user can apply.

        Args:
            message (str): What is wrong.
            details (Optional[str]): Extra details.
        """
        self.logger.error(
            message=f"{self.log_prefix}: The mapping file is not valid."
            f" {message}",
            details=details,
            resolution=(
                "Fix the mapping under Settings > Log Shipper > Mapping, or"
                " reset it to the default SentinelOne Singularity Data"
                " Lake mapping."
            ),
        )

    @staticmethod
    def _check_value_source(field_mapping: dict) -> bool:
        """Check that a CEF field has a mapping_field or a default_value.

        Args:
            field_mapping (dict): One header or extension definition.

        Returns:
            bool: True if at least one of the two is not empty.
        """
        return bool(
            field_mapping.get("mapping_field")
            or field_mapping.get("default_value")
        )

    def _validate_cef_branch(self, data_type: str, branch: dict) -> bool:
        """Check the CEF mapping of one data type.

        Args:
            data_type (str): "alerts", "events" or "webtx".
            branch (dict): Subtype to header/extension mapping.

        Returns:
            bool: True if valid.
        """
        if not isinstance(branch, dict):
            self._log_error(
                f"The CEF mapping for '{data_type}' must be an object."
            )
            return False
        transformations = type_converter()
        for subtype, subtype_mapping in branch.items():
            try:
                validate(instance=subtype_mapping, schema=CEF_SUBTYPE_SCHEMA)
            except JsonSchemaValidationError as err:
                self._log_error(
                    self._describe_schema_error(
                        err, f"taxonomy > {data_type} > {subtype}"
                    ),
                    details=str(err),
                )
                return False
            for section in ("header", "extension"):
                for field, field_mapping in subtype_mapping[section].items():
                    if not self._check_value_source(field_mapping):
                        self._log_error(
                            f"CEF {section} field '{field}' of"
                            f" '{data_type}/{subtype}' needs a mapping_field"
                            " or a default_value."
                        )
                        return False
                    transformation = field_mapping.get(
                        "transformation", "String"
                    )
                    if transformation not in transformations:
                        self._log_error(
                            f"CEF {section} field '{field}' of"
                            f" '{data_type}/{subtype}' has an unknown"
                            f" transformation '{transformation}'."
                        )
                        return False
        return True

    def validate_mappings(
        self, mappings: dict, cef_required: bool = False
    ) -> bool:
        """Check that the mapping document has the expected shape.

        Args:
            mappings (dict): Parsed mapping document.
            cef_required (bool): True when the CEF format is selected. At
                least one CEF data type mapping is then required.

        Returns:
            bool: True if valid.
        """
        if not isinstance(mappings, dict):
            self._log_error("The mapping is not a JSON object.")
            return False
        try:
            validate(instance=mappings, schema=MAPPINGS_SCHEMA)
        except JsonSchemaValidationError as err:
            self._log_error(
                self._describe_schema_error(err), details=str(err)
            )
            return False

        taxonomy = mappings["taxonomy"]
        cef_branches = {
            data_type: taxonomy[data_type]
            for data_type in SUPPORTED_DATA_TYPES
            if data_type in taxonomy
        }
        if cef_required and not cef_branches:
            self._log_error(
                "CEF format is selected but the mapping has no CEF mapping"
                " for alerts, events or webtx."
            )
            return False
        if cef_branches:
            try:
                validate(instance=mappings, schema=CEF_DOCUMENT_SCHEMA)
            except JsonSchemaValidationError as err:
                self._log_error(
                    self._describe_schema_error(err), details=str(err)
                )
                return False
        for data_type, branch in cef_branches.items():
            if not self._validate_cef_branch(data_type, branch):
                return False
        return True
