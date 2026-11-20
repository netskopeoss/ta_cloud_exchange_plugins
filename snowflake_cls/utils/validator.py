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

Snowflake CLS Plugin validator.
"""

import re

from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from .constants import (
    SNOWFLAKE_IDENTIFIER_MAX_LENGTH,
    SNOWFLAKE_IDENTIFIER_RE,
)
from .utilities import normalize_base_url

# The mapping file is a pass-through: every subtype maps to an empty
# list, which map_json_data() treats as "keep every field". The schema
# below only checks the shape, so an admin who narrows the mapping in
# Settings > Log Shipper still gets a valid file.
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
                            "patternProperties": {".*": {"type": "array"}},
                        }
                    },
                }
            },
            "required": ["json"],
        }
    },
    "required": ["taxonomy"],
}


class SnowflakeValidator:
    """Checks the mapping file and Snowflake object names."""

    def __init__(self, logger, log_prefix: str):
        """Store the logging details.

        Args:
            logger: Logger object.
            log_prefix (str): Prefix put in front of every log message.
        """
        self.logger = logger
        self.log_prefix = log_prefix

    def validate_mappings(self, mappings: dict) -> bool:
        """Check that the mapping file has the expected shape.

        Args:
            mappings (dict): Parsed contents of mappings.json.

        Returns:
            bool: True if the shape is valid.
        """
        if not isinstance(mappings, dict):
            return False
        try:
            validate(instance=mappings, schema=MAPPINGS_SCHEMA)
            return True
        except JsonSchemaValidationError as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: The mapping file is not valid."
                    f" {err.message}"
                ),
                details=str(err),
                resolution=(
                    "Fix the mapping under Settings > Log Shipper, or"
                    " reset it to the default Snowflake mapping."
                ),
            )
            return False

    @staticmethod
    def is_valid_identifier(name: str) -> bool:
        """Check that a name can be used as a Snowflake object name.

        Case is not restricted here - it is matched case-sensitively,
        quoted, wherever the plugin uses it (SHOW COLUMNS and the
        Snowpipe Streaming rows URL alike), so any case can be correct
        depending on how the object was actually created in Snowflake.

        Anything outside letters, digits, underscore and dollar is
        rejected too, before it ever reaches Snowflake, as is a name
        over 255 characters - Snowflake's own limit.

        A Snowflake keyword such as TABLE is allowed. The name is
        quoted wherever it is used, so it works; the customer just has
        to create such a table with quotes.

        Args:
            name (str): Name to check.

        Returns:
            bool: True if the name is a plain identifier (any case).
        """
        if not name or not isinstance(name, str):
            return False
        name = name.strip()
        if len(name) > SNOWFLAKE_IDENTIFIER_MAX_LENGTH:
            return False
        return bool(re.match(SNOWFLAKE_IDENTIFIER_RE, name))

    @staticmethod
    def is_valid_base_url(value: str) -> bool:
        """Check that the Account URL points at Snowflake.

        Every request built from this value carries the customer's
        token, so the host has to be a Snowflake one. normalize_base_url
        does the work; anything it cannot read is refused here.

        Args:
            value (str): Account URL to check.

        Returns:
            bool: True if the URL is safe to send the token to.
        """
        return bool(normalize_base_url(value))
