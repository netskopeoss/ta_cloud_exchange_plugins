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

Palo Alto Networks Cortex XDR Plugin validator.
"""

import traceback
from urllib.parse import urlparse

from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from . import constants as CONST


class CortexXDRValidator:
    """Validate the URL and the mapping of the plugin."""

    def __init__(self, logger, log_prefix: str):
        """Initialize.

        Args:
            logger: Cloud Exchange logger.
            log_prefix (str): Log prefix.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.error = ""

    @staticmethod
    def validate_url(url: str) -> bool:
        """Return True for an HTTP or HTTPS URL with a host.

        Args:
            url (str): URL.

        Returns:
            bool: True when the URL is valid.
        """
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        return parsed.scheme in CONST.URL_SCHEMES and bool(parsed.netloc)

    def validate_mappings(self, mappings: dict) -> bool:
        """Validate the mapping against the JSON mapping schema.

        Args:
            mappings (dict): Parsed mapping.

        Returns:
            bool: True when the mapping is valid. The error is kept in
                ``self.error`` otherwise.
        """
        try:
            validate(instance=mappings, schema=CONST.MAPPING_SCHEMA)
            return True
        except JsonSchemaValidationError as err:
            self.error = err.message
            self.logger.error(
                message=CONST.LOG_MESSAGE_TEMPLATE.format(
                    self.log_prefix,
                    CONST.MAPPING_INVALID_MESSAGE.format(error=err.message),
                ),
                details=str(traceback.format_exc()),
                resolution=CONST.MAPPING_RESOLUTION,
            )
        return False
