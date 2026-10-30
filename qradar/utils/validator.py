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

QRadar Plugin validator."""

import traceback

from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from . import constants as CONST
from .helper import compile_schema

mapping_validator = compile_schema(CONST.MAPPING_SCHEMA)
taxonomy_validator = compile_schema(CONST.TAXONOMY_SCHEMA)
json_taxonomy_validator = compile_schema(CONST.JSON_TAXONOMY_SCHEMA)


class QRadarValidator:
    """Validate the structure of the QRadar mapping file."""

    def __init__(self, logger, log_prefix):
        """Initialize.

        Args:
            logger: Cloud Exchange logger.
            log_prefix (str): Prefix of every log message.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.error = ""

    def _log_mapping_error(self, error):
        """Log a mapping validation error with its resolution.

        The cause is kept in ``self.error`` for the validation result.

        Args:
            error (str): Cause of the failure.
        """
        self.error = error
        self.logger.error(
            message=CONST.LOG_MESSAGE_TEMPLATE.format(
                self.log_prefix,
                CONST.MAPPING_INVALID_MESSAGE.format(error=error),
            ),
            details=str(traceback.format_exc()),
            resolution=CONST.MAPPING_RESOLUTION,
        )

    def validate_mapping_schema(self, mappings):
        """Validate the mapping file schema and every taxonomy.

        Args:
            mappings (dict): Parsed mapping file.

        Returns:
            bool: True when the schema is valid, False otherwise.
        """
        try:
            mapping_validator.validate(mappings)
        except JsonSchemaValidationError as err:
            self._log_mapping_error(
                CONST.MAPPING_SCHEMA_ERROR.format(error=err.message)
            )
            return False

        taxonomy = mappings[CONST.MAPPING_TAXONOMY]
        for data_type, data_type_taxonomy in taxonomy.items():
            if data_type == CONST.MAPPING_JSON:
                schema_items = [(None, data_type_taxonomy)]
                schema_validator = json_taxonomy_validator
            else:
                schema_items = list(data_type_taxonomy.items())
                schema_validator = taxonomy_validator
            for subtype, subtype_taxonomy in schema_items:
                try:
                    schema_validator.validate(subtype_taxonomy)
                except JsonSchemaValidationError as err:
                    self._log_mapping_error(
                        CONST.MAPPING_SUBTYPE_SCHEMA_ERROR.format(
                            data_type=data_type,
                            subtype=subtype,
                            error=err.message,
                        )
                    )
                    return False
        return True

    def validate_qradar_map(self, mappings):
        """Validate the mapping file.

        Args:
            mappings (dict): Parsed mapping file.

        Returns:
            bool: True when the mapping file is valid, False otherwise.
        """
        if not isinstance(mappings, dict):
            self._log_mapping_error(CONST.MAPPING_NOT_OBJECT_ERROR)
            return False
        try:
            return self.validate_mapping_schema(mappings)
        except Exception as err:
            self._log_mapping_error(str(err))
            return False
