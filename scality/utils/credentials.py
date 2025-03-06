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

Get credentials for Scality.
"""


class ScalityCredentials:
    """Scality get credential class."""

    def __init__(self, configuration, logger, proxy, log_prefix, user_agent):
        """Init method.
        args:
            configuration: the configuration object.
            logger: the logger object.
            proxy: the proxy object.
            log_prefix: the log prefix.
            user_agent: the user agent.
        """
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.log_prefix = log_prefix
        self.user_agent = user_agent

    def get_credentials(self, configuration):
        """Get credentials from the environment variables.

        Returns:
            Tuple of access key and secret key.
        """
        endpoint_url = configuration.get("endpoint_url", "").strip().strip("/")
        access_key = configuration.get("access_key").strip()
        secret_access_key = configuration.get("secret_access_key")
        bucket_name = configuration.get("bucket_name").strip()

        return endpoint_url, access_key, secret_access_key, bucket_name
