"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

AWS CloudWatch CLS Plugin validator.
"""

import re
import traceback

from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from .constants import (
    REGION_NAME_REGEX,
    LOG_GROUP_NAME_PATTERN,
    LOG_NAME_MAX_LENGTH,
    LOG_NAME_MIN_LENGTH,
    LOG_STREAM_FORBIDDEN_CHARS,
    REGIONS,
)


class AWSCloudWatchValidator(object):
    """Validator for the AWS CloudWatch CLS plugin."""

    def __init__(self, logger, log_prefix):
        """Initialize AWSCloudWatchValidator.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix string.
        """
        super().__init__()
        self.logger = logger
        self.log_prefix = log_prefix

    def validate_region_name(self, region_name: str) -> bool:
        """Check that the region is one the plugin supports.

        Args:
            region_name (str): Region selected in the configuration.

        Returns:
            bool: True when the region is supported.
        """
        return region_name in REGIONS

    def validate_custom_region_name(self, region_name: str) -> bool:
        """Check a hand typed region against the AWS host label rule.

        The region is interpolated into manually built URLs, so it must
        be a valid DNS label. Nothing else about its shape is assumed;
        AWS validates the region at the connection check.

        Args:
            region_name (str): Region code typed by the user.

        Returns:
            bool: True when the value is a usable region code.
        """
        if not isinstance(region_name, str):
            return False
        return bool(re.fullmatch(REGION_NAME_REGEX, region_name.strip()))

    def validate_log_group_name(self, log_group_name: str) -> bool:
        """Check the log group name against the AWS naming rules.

        Args:
            log_group_name (str): Log group name from the configuration.

        Returns:
            bool: True when the name is valid.
        """
        if not isinstance(log_group_name, str):
            return False
        if not (
            LOG_NAME_MIN_LENGTH <= len(log_group_name) <= LOG_NAME_MAX_LENGTH
        ):
            return False
        return bool(re.match(LOG_GROUP_NAME_PATTERN, log_group_name))

    def validate_log_stream_name(self, log_stream_name: str) -> bool:
        """Check the log stream name against the AWS naming rules.

        Args:
            log_stream_name (str): Log stream name from the configuration.

        Returns:
            bool: True when the name is valid.
        """
        if not isinstance(log_stream_name, str):
            return False
        if not (
            LOG_NAME_MIN_LENGTH <= len(log_stream_name) <= LOG_NAME_MAX_LENGTH
        ):
            return False
        return not any(
            char in log_stream_name for char in LOG_STREAM_FORBIDDEN_CHARS
        )

    def validate_taxonomy(self, instance) -> None:
        """Check that a subtype block has a header and an extension.

        Args:
            instance: Subtype block from the mapping file.
        """
        schema = {
            "type": "object",
            "properties": {
                "header": {"type": "object", "minProperties": 0},
                "extension": {"type": "object", "minProperties": 0},
            },
            "required": ["header", "extension"],
        }
        validate(instance=instance, schema=schema)

    def validate_json(self, instance) -> None:
        """Check the shape of the JSON branch of the taxonomy.

        Args:
            instance: JSON branch from the mapping file.
        """
        schema = {
            "type": "object",
            "patternProperties": {
                ".*": {
                    "type": "object",
                    "patternProperties": {".*": {"type": "array"}},
                },
            },
        }
        validate(instance=instance, schema=schema)

    def validate_mapping_schema(self, mappings: dict) -> bool:
        """Check the top level shape of the mapping file.

        Args:
            mappings (dict): Parsed mapping file.

        Returns:
            bool: True when the mapping file is valid.
        """
        schema = {
            "type": "object",
            "properties": {
                "delimiter": {
                    "type": "string",
                    "minLength": 1,
                    "enum": ["|"],
                },
                "cef_version": {"type": "string", "minLength": 1},
                "taxonomy": {
                    "type": "object",
                    "properties": {
                        "alerts": {"type": "object"},
                        "events": {"type": "object"},
                    },
                    "anyOf": [
                        {"required": ["alerts"]},
                        {"required": ["events"]},
                    ],
                },
            },
            "required": ["delimiter", "taxonomy", "cef_version"],
        }

        try:
            validate(instance=mappings, schema=schema)
        except JsonSchemaValidationError as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred."
                    f" Error while checking the mapping file: {err}"
                ),
                resolution=(
                    "Provide a valid mapping under"
                    " Settings > Log Shipper > Mapping."
                ),
                details=str(traceback.format_exc()),
            )
            return False

        for data_type, dtype_taxonomy in mappings["taxonomy"].items():
            if data_type == "json":
                try:
                    self.validate_json(dtype_taxonomy)
                except JsonSchemaValidationError as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Validation error occurred."
                            " Error while checking the JSON mapping:"
                            f" {err}"
                        ),
                        resolution=(
                            "Each JSON mapping entry must be a list of"
                            " field names."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    return False
            else:
                for subtype, subtype_taxonomy in dtype_taxonomy.items():
                    try:
                        self.validate_taxonomy(subtype_taxonomy)
                    except JsonSchemaValidationError as err:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Validation error"
                                " occurred. Error while checking the"
                                f' mapping of type "{data_type}" and'
                                f' subtype "{subtype}": {err}'
                            ),
                            resolution=(
                                "Each subtype mapping must have a header"
                                " and an extension block."
                            ),
                            details=str(traceback.format_exc()),
                        )
                        return False
        return True

    def validate_aws_cloudwatch_map(self, mappings) -> bool:
        """Check the mapping file provided in the configuration.

        Args:
            mappings: Parsed mapping file.

        Returns:
            bool: True when the mapping file is valid.
        """
        if mappings is None:
            return False
        try:
            if self.validate_mapping_schema(mappings):
                return True
        except Exception:
            err_msg = "Validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return False

        return False
