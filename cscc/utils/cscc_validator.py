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
"""

"""Google Cloud SCC Plugin Validator class."""


import traceback
from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError


class CSCCValidator(object):
    """CSCC Validator class."""

    def __init__(self, logger, log_prefix):
        """Init method."""
        super().__init__()
        self.logger = logger
        self.log_prefix = log_prefix

    def validate_mapping_schema(self, mappings):
        """Read the given mapping file and validates its schema.

        :param mapping_file: The mapping file from which the schema is to be validated
        :return: True in case of valid schema, False otherwise
        """
        # schema for mapping file
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
                                    }
                                }
                            }
                        }
                    }
                }
            },
        }

        # If no exception is raised by validate(), the instance is valid.
        try:
            validate(instance=mappings, schema=schema)
            return True
        except JsonSchemaValidationError as err:
            err_msg = (
                "Validation error occurred. Error: "
                "validating JSON schema: {}".format(err)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc())
            )
        return False

    def validate_cscc_map(self, mappings):
        """Validate field mappings file. If not present, issues appropriate logs and exists docker.

        :param: mapping_file: the field mappings file to be validated
        :returns: Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        try:
            if self.validate_mapping_schema(mappings):
                return True
        except Exception as err:
            err_msg = (
                "Validation error occurred. Error: {}".format(str(err))
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc())
            )

        return False
