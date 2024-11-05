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

AWS Verified Access validator.
"""

import traceback
from ..lib import boto3
from ..lib.botocore.config import Config
from .constants import REGIONS
from .exceptions import AWSVerifiedAccessException
from .constants import PLUGIN_NAME
from ..lib.botocore.exceptions import ClientError


class AWSVerifiedAccessValidator(object):
    """AWS Verified Access validator class."""

    def __init__(
        self, configuration, logger, proxy, storage, log_prefix, user_agent
    ):
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
        self.useragent = user_agent

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
            aws_client: the aws client object

        Returns:
            Returns the validated aws client object
        """
        try:
            cloudwatch_logs = boto3.client(
                "logs",
                aws_access_key_id=aws_client.aws_public_key,
                aws_secret_access_key=aws_client.aws_private_key,
                aws_session_token=aws_client.aws_session_token,
                region_name=self.configuration["region_name"].strip(),
                config=Config(proxies=self.proxy, user_agent=self.useragent),
            )
            return cloudwatch_logs
        except ClientError:
            err_msg = "Invalid AWS Credentials provided."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
        except Exception:
            err_msg = (
                f"Error occurred while creating {PLUGIN_NAME} client object."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise AWSVerifiedAccessException(err_msg)
