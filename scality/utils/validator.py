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


Scality Plugin Validator.
"""

from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from . import constants as CONST
from .exceptions import ScalityException
from .helper import describe_boto_error, log_error, log_and_raise


class ScalityValidator:
    """Validate the Scality mappings and connection parameters."""

    def __init__(self, logger, log_prefix: str):
        """Initialize ScalityValidator.

        Args:
            logger: Cloud Exchange logger object.
            log_prefix (str): Log prefix of the plugin configuration.
        """
        self.logger = logger
        self.log_prefix = log_prefix

    def validate_mappings(self, mappings: dict) -> bool:
        """Validate the mappings JSON structure using jsonschema.

        Checks that ``taxonomy.json`` exists and that each data type
        maps its subtypes to lists of field names. Only the JSON format
        is validated because the plugin supports JSON only.

        Args:
            mappings (dict): Parsed mappings dict from mappings.json.

        Returns:
            bool: True when the structure is valid, False otherwise.
        """
        if not isinstance(mappings, dict):
            return False
        try:
            validate(instance=mappings, schema=CONST.MAPPINGS_SCHEMA)
            return True
        except JsonSchemaValidationError as err:
            log_error(
                self.logger,
                self.log_prefix,
                "validating the Scality mappings",
                (
                    "Ensure that the mapping file is valid and every"
                    " subtype maps to a list of fields under"
                    " Settings > Log Shipper."
                ),
                cause=err.message,
                details=str(err),
            )
            return False

    def validate_credentials(self, scality_client) -> None:
        """Validate the credentials against the Scality instance.

        Args:
            scality_client (ScalityClient): Client used to reach
                Scality.

        Raises:
            ScalityException: When the credentials cannot be validated.
        """
        try:
            s3_resource = scality_client.get_aws_resource()
            for _ in s3_resource.buckets.all():
                break
        except ScalityException:
            raise
        except Exception as exp:
            cause, resolution = describe_boto_error(exp)
            log_and_raise(
                self.logger,
                self.log_prefix,
                "validating credentials",
                resolution
                or (
                    "Ensure that the Access Key and Secret Access Key"
                    " are valid and that the user has permission to"
                    f" list buckets on {CONST.PLATFORM_NAME}."
                ),
                cause=cause,
            )
