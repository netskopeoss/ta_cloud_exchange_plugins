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

Scality validator.
"""

import traceback
from .exception import ScalityException


class ScalityValidator(object):
    """Scality validator class."""

    def __init__(self, configuration, logger, proxy, log_prefix, user_agent):
        """Initialize.

        Args:
            configuration: the configuration object.
            logger: the logger object.
            proxy: the proxy object.
            log_prefix: the log prefix.
            user_agent: the user agent.
        """
        super().__init__()
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.log_prefix = log_prefix
        self.useragent = user_agent

    def validate_credentials(self, aws_client):
        """Validate credentials.

        Args:
            scality_public_key: the scality public key to establish connection
            with scality S3.
            scality_private_key: the scality private key to establish connection
            with scality S3.

        Returns:
            Whether the provided value is valid or not. True in case of
            valid value, False otherwise
        """
        try:
            s3_resource = aws_client.get_aws_resource()
            for _ in s3_resource.buckets.all():
                break
            return True
        except ScalityException as err:
            raise err
        except Exception as exp:
            err_msg = (
                "Error occurred while validating credentials. "
                "Verify the provided configuration parameters and "
                "make sure all the required bucket permissions "
                "are attached to the user."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ScalityException(err_msg)

    def validate_max_file_size(self, max_file_size):
        """Validate max file size.

        Args:
            max_file_size: the max file size to be validated

        Returns:
            Whether the provided value is valid or not.
            True in case of valid value, False otherwise
        """
        if max_file_size:
            try:
                max_file_size = int(max_file_size)
                if 0 < max_file_size <= 100:
                    return True
                return False
            except ValueError:
                return False
        else:
            return False

    def validate_max_duration(self, max_duration):
        """Validate max duration.

        Args:
            max_duration: the max duration to be validated

        Returns:
            Whether the provided value is valid or not.
            True in case of valid value, False otherwise
        """
        if max_duration:
            try:
                max_duration = int(max_duration)
                if max_duration > 0:
                    return True
                return False
            except ValueError:
                return False
        else:
            return False
