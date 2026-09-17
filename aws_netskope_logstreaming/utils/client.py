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

AWS D2C Client Class.
"""

import traceback
import boto3
from botocore.exceptions import (
    NoCredentialsError,
    ClientError,
    ReadTimeoutError,
)
from datetime import datetime, timedelta, timezone
from botocore.config import Config

from .exceptions import AWSD2CProviderException
from .generate_temp_creds import (
    AWSD2CProviderGenerateTemporaryCredentials,
)
from . import constants as CONST
from .helper import handle_and_raise


class AWSD2CProviderClient:
    """AWSD2CProvider Client Class."""

    def __init__(
        self, configuration, logger, proxy, storage, log_prefix
    ):
        """Init method."""
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.storage = storage
        self.log_prefix = log_prefix
        self.aws_private_key = None
        self.aws_public_key = None
        self.aws_session_token = None

    def _fetch_temporary_credentials(
        self,
        temp_creds_obj: AWSD2CProviderGenerateTemporaryCredentials,
        action: str,
    ) -> dict:
        """Generate temporary credentials via IAM Roles Anywhere.

        Args:
            temp_creds_obj (AWSD2CProviderGenerateTemporaryCredentials):
                Temporary credentials generator object.
            action (str): Action being performed, used in the error
                message. i.e. "generate" or "refresh".

        Returns:
            dict: Temporary credentials returned by IAM Roles Anywhere.

        Raises:
            AWSD2CProviderException: If no credentials were returned.
        """
        temporary_credentials = temp_creds_obj.generate_temporary_credentials()
        credential_set = temporary_credentials.get("credentialSet") or []
        credentials = (
            credential_set[0].get("credentials") if credential_set else None
        )
        if not credentials:
            raise AWSD2CProviderException(
                f"Unable to {action} Temporary Credentials. "
                "Check the configuration parameters."
            )
        return credentials

    def _is_credentials_expiring(self, credentials: dict) -> bool:
        """Check whether the cached credentials are about to expire.

        Credentials are refreshed a few minutes before they actually
        expire so that a long running pull cycle never ends up using
        credentials that expire mid-request.

        Args:
            credentials (dict): Cached credentials from the storage.

        Returns:
            bool: True if the credentials expire within the refresh
                buffer or the expiration could not be determined.
        """
        expiration = credentials.get("expiration")
        if not expiration:
            return True
        try:
            expiry = datetime.fromisoformat(
                str(expiration).replace("Z", "+00:00")
            )
        except ValueError:
            # Unparsable expiration - refresh rather than risk using
            # credentials that have already expired.
            return True
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry <= datetime.now(timezone.utc) + timedelta(
            minutes=CONST.CREDENTIALS_REFRESH_BUFFER_MINUTES
        )

    def set_credentials(self):
        """Set the AWS credentials used by the boto3 clients.

        For the 'Deployed on AWS' authentication method nothing is set
        here - boto3 resolves the IAM instance profile or role attached
        to the AWS environment. For 'AWS IAM Roles Anywhere' temporary
        credentials are generated and cached in the plugin storage, and
        refreshed once they are about to expire.

        Returns:
            dict: Plugin storage containing the cached credentials.

        Raises:
            AWSD2CProviderException: On credential errors.
        """
        try:
            if (
                self.configuration.get("authentication_method")
                == CONST.AWS_IAM_ROLES_ANYWHERE
            ):
                temp_creds_obj = AWSD2CProviderGenerateTemporaryCredentials(
                    self.configuration,
                    self.logger,
                    self.proxy,
                    self.storage,
                    self.log_prefix,
                    CONST.USER_AGENT,
                )
                cached_credentials = (
                    self.storage.get("credentials") if self.storage else None
                )
                if not cached_credentials:
                    self.storage = {}
                    self.storage["credentials"] = (
                        self._fetch_temporary_credentials(
                            temp_creds_obj, "generate"
                        )
                    )
                elif self._is_credentials_expiring(cached_credentials):
                    self.storage["credentials"] = (
                        self._fetch_temporary_credentials(
                            temp_creds_obj, "refresh"
                        )
                    )

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
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=exp,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )
        except AWSD2CProviderException:
            raise
        except Exception as err:
            err_msg = "Error occurred while setting credentials."
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )

    def _get_aws_client(self, service_name: str):
        """Create and return a boto3 client for the given AWS service.

        Args:
            service_name (str): AWS service name. i.e. "sqs" or "s3".

        Returns:
            botocore.client.BaseClient: boto3 client object.

        Raises:
            AWSD2CProviderException: On boto3 client creation errors.
        """
        try:
            return boto3.client(
                service_name,
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=self.configuration.get("region_name", "").strip(),
                config=Config(
                    proxies=self.proxy,
                    user_agent=CONST.USER_AGENT,
                ),
            )
        except ReadTimeoutError as exp:
            err_msg = (
                "Read timeout error occurred while creating "
                f"AWS {service_name.upper()} client object "
                f"for {CONST.PLATFORM_NAME}."
            )
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=exp,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )
        except ClientError as error:
            if (
                hasattr(error, "response")
                and error.response
                and error.response.get("Error", {}).get("Message")
            ):
                err_msg = error.response["Error"].get("Message")
                handle_and_raise(
                    logger=self.logger,
                    log_prefix=self.log_prefix,
                    err=error,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                )
            else:
                handle_and_raise(
                    logger=self.logger,
                    log_prefix=self.log_prefix,
                    err_msg=str(error),
                    details_msg=str(traceback.format_exc()),
                )
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating AWS {service_name.upper()} "
                f"client object for {CONST.PLATFORM_NAME}."
            )
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=exp,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )

    def get_sqs_client(self):
        """To get aws sqs client."""
        return self._get_aws_client("sqs")

    def get_s3_client(self):
        """To get aws s3 client."""
        return self._get_aws_client("s3")

    def validate_queue_url_using_name(self, sqs_client, queue_name):
        """Validate queue url using queue name.

        Args:
            sqs_client (object): SQS client object.
            queue_name (str): Queue name.

        Returns:
            Whether the provided value is valid or not. True in case of
            valid value, False otherwise
        """
        try:
            # response from sqs client
            response = sqs_client.get_queue_url(QueueName=str(queue_name))

            # Check if the queue exists
            if response and response.get("QueueUrl"):
                queue_url = response.get("QueueUrl")
                # Read a single message to confirm the role also has the
                # permissions needed to consume from the queue at pull time.
                sqs_client.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=1,
                    WaitTimeSeconds=2,
                    MessageAttributeNames=["All"],
                )
                return True
            else:
                err_msg = (
                    "Invalid AWS SQS Queue Name provided. "
                    f"The provided queue '{queue_name}' does not exist."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise AWSD2CProviderException(err_msg)
        except sqs_client.exceptions.QueueDoesNotExist as err:
            err_msg = (
                f"Invalid AWS SQS Queue Name '{queue_name}' provided in "
                "the configuration parameters. Make sure the provided "
                "queue exists and has all the required permissions."
            )
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )
        except ClientError as err:
            err_msg = (
                "Error occurred while connecting to AWS SQS Queue "
                f"{queue_name}. Make sure the provided queue exists"
                " and has all the required permissions."
            )
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while "
                f"connecting to AWS SQS Queue {queue_name}."
            )
            handle_and_raise(
                logger=self.logger,
                log_prefix=self.log_prefix,
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )
