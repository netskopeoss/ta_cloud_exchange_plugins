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

AWS Security Hub validator.
"""

import boto3
import traceback
from botocore.config import Config
from .exceptions import AWSSecurityHubException
from botocore.exceptions import ClientError


class AWSSecurityHubValidator(object):
    """AWS Security Hub validator class."""

    def __init__(
        self, region_name, logger, proxy, log_prefix, user_agent
    ):
        """Initialize."""
        super().__init__()
        self.region_name = region_name
        self.logger = logger
        self.proxy = proxy
        self.log_prefix = log_prefix
        self.aws_public_key = None
        self.aws_private_key = None
        self.aws_session_token = None
        self.useragent = user_agent

    def validate_credentials(self, aws_client):
        """Validate credentials.

        Args:
            aws_client: the aws client object

        Returns:
            Returns the validated aws client object
        """
        try:
            securityhub = boto3.client(
                "securityhub",
                aws_access_key_id=aws_client.aws_public_key,
                aws_secret_access_key=aws_client.aws_private_key,
                aws_session_token=aws_client.aws_session_token,
                region_name=self.region_name,
                config=Config(proxies=self.proxy, user_agent=self.useragent),
            )
            return securityhub
        except ClientError as err:
            err_msg = "Invalid AWS Credentials provided."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise AWSSecurityHubException(err_msg)
        except Exception as exp:
            err_msg = "Error occurred while validating credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AWSSecurityHubException(err_msg)

    def validate_aws_securityhub(self, securityhub_client):
        """Validate queue url using queue name.

        Args:
            securityhub_client (object): SecurityHub client object.

        Returns:
            Whether the provided value is valid or not. True in case of
            valid value, False otherwise
        """
        try:
            # response from securityhub client
            response = securityhub_client.get_findings(
                MaxResults=1
            )

            # Check if the queue exists
            if response:
                return True
            else:
                err_msg = (
                    "Unable to validate AWS SecurityHub credentials."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise AWSSecurityHubException(err_msg)
        except Exception as exp:
            err_msg = (
                "Invalid authentication parameters provided."
                " Check logs for more details."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise AWSSecurityHubException(err_msg)
