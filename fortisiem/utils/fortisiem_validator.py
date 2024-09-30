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

FortiSIEM Validator."""

import io
import csv
import traceback
from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError


class FortisiemValidator(object):
    """FortiSIEM validator class."""

    def __init__(self, logger, log_prefix):
        """Initialize."""
        super().__init__()
        self.logger = logger
        self.log_prefix = log_prefix

    def validate_fortisiem_port(self, fortisiem_port):
        """Validate FortiSIEM port.

        Args:
            fortisiem_port: the FortiSIEM port to be validated

        Returns:
            Whether the provided value is valid or not.
            True in case of valid value, False otherwise
        """
        if fortisiem_port or fortisiem_port == 0:
            try:
                fortisiem_port = int(fortisiem_port)
                if not (0 <= fortisiem_port <= 65535):
                    return False
                return True
            except ValueError:
                return False
        else:
            return False

    def validate_mapping_schema(self, mappings):
        """Validate mapping schema.

        Args:
            mappings (dict): Mapping file.
        """
            
        schema = {
            "type": "object",
            "properties": {
                "taxonomy": {
                    "type": "object",
                    "properties": {
                        "json": {
                            "patternProperties": {
                                ".*": {
                                    "type": "object",
                                    "patternProperties": {
                                        ".*": {
                                            "type": "array",
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            },
        }

        # If no exception is raised by validate(), the instance is valid.
        try:
            validate(instance=mappings, schema=schema)
            return True
        except JsonSchemaValidationError as err:
            self.logger.error(
                message=(
                    "{}: Error occurred while validating Mapping "
                    "String: {}".format(self.log_prefix, err)
                ),
                details=str(traceback.format_exc()),
            )
        return False

    def validate_fortisiem_map(self, mappings):
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

        except Exception as err:
            err_msg = "Validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )

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
            )
            headers = next(csviter)

            if all(
                header in headers
                for header in ["CEF Key Name", "Length", "Data Type"]
            ):
                return True
        except Exception:
            return False

        return False
