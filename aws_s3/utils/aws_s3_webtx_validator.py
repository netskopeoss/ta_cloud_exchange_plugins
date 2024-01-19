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

AWS S3 WebTx validator.
"""

import boto3
from botocore.exceptions import NoCredentialsError
from botocore.config import Config
from .aws_s3_webtx_constants import REGIONS
from .aws_s3_exceptions import AWSS3WebTXException


class AWSS3WebTxValidator(object):
    """AWS S3 WebTx validator class."""

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

    def validate_region_name(self, region_name):
        """Validate region name.

        Args:
            region_name: the region name to be validated

        Returns:
            Whether the provided value is valid or not.
            True in case of valid value, False otherwise
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
            aws_public_key: the aws public key to establish connection
            with AWS S3.
            aws_private_key: the aws private key to establish connection
            with AWS S3.

        Returns:
            Whether the provided value is valid or not. True in case of
            valid value, False otherwise
        """
        try:
            s3_resource = boto3.resource(
                "s3",
                aws_access_key_id=aws_client.aws_public_key,
                aws_secret_access_key=aws_client.aws_private_key,
                aws_session_token=aws_client.aws_session_token,
                region_name=self.configuration.get("region_name"),
                config=Config(proxies=self.proxy),
            )

            for _ in s3_resource.buckets.all():
                break
            return True
        except NoCredentialsError as exp:
            err_msg = (
                "No AWS Credentials were found in the environment."
                " Deploy the plugin into AWS environment or use AWS IAM "
                "Roles Anywhere authentication method."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}.",
                details=f"Error: {exp}",
            )
            raise AWSS3WebTXException(err_msg)
        except Exception as exp:
            err_msg = (
                "Error occurred while validating credentials. "
                "Make sure all the required bucket permissions "
                "are attached to the user."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}.",
                details=f"Error: {exp}",
            )
            raise AWSS3WebTXException(err_msg)
