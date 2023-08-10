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

"""Amazon Security Lake validator."""


import boto3
from botocore.config import Config
from .amazon_security_lake_constants import REGIONS
from .amazon_security_lake_client import AmazonSecurityLakeClient
from .amazon_security_lake_generate_temporary_credentials import AmazonSecurityLakeGenerateTemporaryCredentials


class AmazonSecurityLakeValidator(object):
    """Amazon Security Lake validator class."""

    def __init__(self, configuration, logger, proxy, storage, log_prefix):
        """Initialize."""
        super().__init__()
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.storage = storage
        self.log_prefix = log_prefix
        self.aws_public_key = None
        self.aws_private_key = None
        self.aws_session_token = None


    def validate_region_name(self, region_name):
        """Validate region name.

        Args:
            region_name: the region name to be validated

        Returns:
            Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        if region_name:
            try:
                if region_name == "None":
                    return True
                if region_name in REGIONS:
                    return True
                return False
            except ValueError:
                return False
        else:
            return False

    def validate_credentials(self, aws_client):
        """Validate credentials.

        Args:
            aws_public_key: the aws public key to establish connection with Amazon Security Lake.
            aws_private_key: the aws private key to establish connection with Amazon Security Lake.

        Returns:
            Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        try:

            amazon_security_lake_resource = boto3.resource(
                    "s3",
                    aws_access_key_id=aws_client.aws_public_key,
                    aws_secret_access_key=aws_client.aws_private_key,
                    aws_session_token=aws_client.aws_session_token,
                    region_name=self.configuration.get("region_name"),
                    config=Config(proxies=self.proxy),
                )

            for _ in amazon_security_lake_resource.buckets.all():
                break
            return True
        except Exception as e:
            raise e
