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

CRE AWS Security Hub Plugin constants.

"""

import traceback
import boto3
from botocore.exceptions import (
    NoCredentialsError,
    ClientError,
    ReadTimeoutError,
)
from botocore.config import Config
from .generate_temporary_credentials import (
    AWSSecurityHubGenerateTemporaryCredentials,
)
from datetime import datetime, timedelta
from .exceptions import AWSSecurityHubException
from .constants import (
    PLATFORM_NAME,
    DATE_FORMAT,
    RETRY_ATTEMPTS,
    RETRY_MODE,
)


class AWSSecurityHubClient:
    """AWS Security Hub Client Class."""

    def __init__(
        self, configuration, logger, proxy, storage, log_prefix, user_agent
    ):
        """Init method."""
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.storage = storage
        self.log_prefix = log_prefix
        self.useragent = user_agent
        self.aws_private_key = None
        self.aws_public_key = None
        self.aws_session_token = None

    def set_credentials(self):
        try:
            if (
                self.configuration.get("authentication_method")
                == "aws_iam_roles_anywhere"
            ):
                temp_creds_obj = AWSSecurityHubGenerateTemporaryCredentials(
                    self.configuration,
                    self.logger,
                    self.proxy,
                    self.storage,
                    self.log_prefix,
                    self.useragent,
                )
                if not self.storage or not self.storage.get("credentials"):
                    self.storage = {}
                    temporary_credentials = (
                        temp_creds_obj.generate_temporary_credentials()
                    )
                    credentials = temporary_credentials.get("credentialSet")[
                        0
                    ].get("credentials")
                    if credentials:
                        self.storage["credentials"] = credentials
                    else:
                        raise AWSSecurityHubException(
                            "Unable to generate Temporary Credentials. "
                            "Check the configuration parameters."
                        )

                elif datetime.strptime(
                    self.storage.get("credentials", {}).get("expiration"),
                    DATE_FORMAT,
                ) <= datetime.utcnow() + timedelta(hours=0, minutes=3):
                    temporary_credentials = (
                        temp_creds_obj.generate_temporary_credentials()
                    )
                    credentials = temporary_credentials.get("credentialSet")[
                        0
                    ].get("credentials")
                    self.storage["credentials"] = credentials
                credentials_from_storage = self.storage.get("credentials")
                self.aws_public_key = credentials_from_storage.get(
                    "accessKeyId"
                )
                self.aws_private_key = credentials_from_storage.get(
                    "secretAccessKey"
                )
                self.aws_session_token = credentials_from_storage.get(
                    "sessionToken"
                )
            return self.storage
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
            raise AWSSecurityHubException(err_msg)
        except AWSSecurityHubException:
            raise
        except Exception as err:
            err_msg = "Error occurred while setting credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise AWSSecurityHubException(err_msg)

    def get_aws_securityhub_client(self):
        """To get aws securityhub client."""
        try:
            securityhub = boto3.client(
                "securityhub",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=self.configuration["region_name"].strip(),
                config=Config(
                    proxies=self.proxy,
                    user_agent=self.useragent,
                    retries={
                        "total_max_attempts": RETRY_ATTEMPTS + 1, # Total attempts including initial request
                        "mode": RETRY_MODE
                    }
                ),
            )
            return securityhub
        except ReadTimeoutError as exp:
            err_msg = (
                "Read timeout error occurred while creating "
                f"AWS s3 client object for {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AWSSecurityHubException(str(exp))
        except ClientError as error:
            if (
                hasattr(error, "response")
                and error.response
                and error.response.get("Error", {}).get("Message")
            ):
                err_msg = error.response["Error"].get("Message")
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise AWSSecurityHubException(err_msg)
            else:
                self.logger.error(
                    message=f"{self.log_prefix}: {str(error)}",
                    details=traceback.format_exc(),
                )
                raise AWSSecurityHubException(str(error))
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {PLATFORM_NAME} client object."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AWSSecurityHubException(err_msg)
