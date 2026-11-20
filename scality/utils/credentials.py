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


Scality Plugin Credentials.
"""

from typing import Any, Dict, Tuple

from . import constants as CONST


class ScalityCredentials:
    """Read the Scality connection parameters from the configuration."""

    @staticmethod
    def _get_stripped_value(configuration: Dict, key: str) -> Any:
        """Return a configuration value, stripping strings only.

        A missing or non string value is returned as received so that
        ``validate`` can report it instead of raising an
        ``AttributeError``.

        Args:
            configuration (Dict): Plugin configuration parameters.
            key (str): Configuration key to read.

        Returns:
            Any: The configuration value.
        """
        value = configuration.get(key)
        return value.strip() if isinstance(value, str) else value

    @staticmethod
    def get_credentials(configuration: Dict) -> Tuple:
        """Get the Scality connection parameters.

        Args:
            configuration (Dict): Plugin configuration parameters.

        Returns:
            Tuple: Endpoint URL, Access Key, Secret Access Key and
                Bucket Name.
        """
        endpoint_url = ScalityCredentials._get_stripped_value(
            configuration, CONST.CONFIG_ENDPOINT_URL
        )
        if isinstance(endpoint_url, str):
            endpoint_url = endpoint_url.rstrip("/")
        access_key = ScalityCredentials._get_stripped_value(
            configuration, CONST.CONFIG_ACCESS_KEY
        )
        secret_access_key = configuration.get(CONST.CONFIG_SECRET_ACCESS_KEY)
        bucket_name = ScalityCredentials._get_stripped_value(
            configuration, CONST.CONFIG_BUCKET_NAME
        )

        return endpoint_url, access_key, secret_access_key, bucket_name
