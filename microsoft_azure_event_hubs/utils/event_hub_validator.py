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

Microsoft Azure Event Hubs Validator module.
"""

import io
import csv
import traceback
from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from netskope.common.api import __version__ as CE_VERSION
from packaging import version
from .event_hub_constants import MAXIMUM_CE_VERSION


class MicrosoftAzureEventHubsValidator(object):
    """Microsoft Azure Event Hubs validator class."""

    def __init__(self, logger, log_prefix):
        """Initialize."""
        self.logger = logger
        self.log_prefix = log_prefix
        self.resolution_support = version.parse(CE_VERSION) > version.parse(
            MAXIMUM_CE_VERSION
        )
        self.is_ce_version_greater_than_512 = self.resolution_support
        # Patch logger methods to handle resolution parameter compatibility
        self._patch_logger_methods()

    def _patch_logger_methods(self):
        """patch logger methods to handle resolution parameter
        compatibility."""
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

    def validate_taxonomy(self, instance):
        """Validate the schema of given taxonomy JSON.

        Args:
            instance: The JSON object to be validated

        Returns:
            True if the schema is valid, False otherwise
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

    def validate_json(self, instance):
        """Validate the schema of given taxonomy JSON.

        Args:
            instance: The JSON object to be validated

        Returns:
            True if the schema is valid, False otherwise
        """
        schema = {
            "type": "object",
            "patternProperties": {
                ".*": {
                    "type": "object",
                    "patternProperties": {
                        ".*": {
                            "type": "array",
                        }
                    },
                },
            },
        }

        validate(instance=instance, schema=schema)

    def validate_mapping_schema(self, mappings):
        """Validate mapping schema.

        Args:
            mappings (dict): Mapping file.
        """
        schema = {
            "type": "object",
            "properties": {
                "delimiter": {"type": "string", "minLength": 1, "enum": ["|"]},
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

        # If no exception is raised by validate(), the instance is valid.
        try:
            validate(instance=mappings, schema=schema)
        except JsonSchemaValidationError as err:
            self.logger.error(
                message=(
                    "{}: Validation error occurred. "
                    "Error: validating JSON schema: {}".format(
                        self.log_prefix, err
                    )
                ),
                details=str(traceback.format_exc()),
            )
            return False

        # Validate the schema of all taxonomy
        for data_type, dtype_taxonomy in mappings["taxonomy"].items():
            if data_type == "json":
                self.validate_json(dtype_taxonomy)
            else:
                for subtype, subtype_taxonomy in dtype_taxonomy.items():
                    try:
                        self.validate_taxonomy(subtype_taxonomy)
                    except JsonSchemaValidationError as err:
                        self.logger.error(
                            message=(
                                "{}: Validation error occurred. Error: "
                                'while validating JSON schema for type "{}" '
                                'and subtype "{}": {}'.format(
                                    self.log_prefix, data_type, subtype, err
                                )
                            ),
                            details=str(traceback.format_exc()),
                        )
                        return False
        return True

    def validate_event_hubs_mapping_format(self, mappings):
        """Validate field JSON mappings.

        Args:
            mappings: the JSON string to be validated

        Returns:
            Whether the provided value is valid or not.
            True in case of valid value, False otherwise
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

    def validate_valid_extensions(self, valid_extensions):
        """Validate CSV extensions.

        Args:
            valid_extensions: the CSV string to be validated

        Returns:
            Whether the provided value is valid or not.
            True in case of valid value, False otherwise
        """
        try:
            csviter = csv.DictReader(
                io.StringIO(valid_extensions), strict=True
            )  # noqa
            headers = next(csviter)

            if all(
                header in headers
                for header in ["CEF Key Name", "Length", "Data Type"]  # noqa
            ):
                return True
        except Exception:
            err_msg = "Validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return False

        return False
