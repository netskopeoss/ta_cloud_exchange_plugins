"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

AWS CloudWatch CLS Plugin client.
"""

import datetime
import traceback

import boto3
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    ReadTimeoutError,
)

from .constants import (
    ACCESS_DENIED_ERROR_CODES,
    INVALID_CREDENTIALS_ERROR_CODES,
    MAX_RETRIES,
    PLATFORM_NAME,
    READ_TIMEOUT,
    IAM_RESOLUTION_CREATE,
    IAM_RESOLUTION_DESCRIBE_GROUPS,
    IAM_RESOLUTION_PUT,
    IAM_RESOLUTION_VALIDATION,
    PARTITION_AWS,
    CONNECT_TIMEOUT,
    CREDENTIAL_REFRESH_MINUTES,
    RESOURCE_ALREADY_EXISTS_ERROR_CODE,
    RESOURCE_NOT_FOUND_ERROR_CODE,
)
from .exceptions import (
    AWSCloudWatchPluginError,
    AWSCloudWatchResourceNotFoundError,
)
from .helper import get_effective_region, get_region_partition
from .generate_temp_creds import (
    AWSCloudWatchGenerateTemporaryCredentials,
)

# Page size used when looking for an existing log group or log stream.
DESCRIBE_PAGE_LIMIT = 50
# Upper bound on describe pages, so a large account cannot loop forever.
MAX_DESCRIBE_PAGES = 20


class AWSCloudWatchClient:
    """Build the boto3 logs client and talk to CloudWatch Logs."""

    def __init__(
        self,
        configuration,
        logger,
        proxy,
        storage,
        log_prefix,
        user_agent,
        ssl_validation=None,
    ):
        """Init method.

        Args:
            configuration (dict): Plugin configuration parameters.
            logger: Logger object.
            proxy (dict): Proxy settings.
            storage (dict): Plugin storage.
            log_prefix (str): Log prefix.
            user_agent (str): User agent sent to AWS.
            ssl_validation: Callable returning the plugin SSL validation
                flag, as in aws_s3_edm. The client is reused across
                pushes, so the value is read on each call rather than
                captured once.
        """
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.storage = storage
        self.log_prefix = log_prefix
        self.useragent = user_agent
        self._ssl_validation = ssl_validation
        self.aws_private_key = None
        self.aws_public_key = None
        self.aws_session_token = None
        # Temporary credentials are cached on this client instance only
        # and never written to the plugin storage, as in aws_s3_edm.
        self._credentials = None

    # ───────────────────────── AUTHENTICATION ────────────────────────────

    def _get_verify(self):
        """Get the SSL validation setting for boto3 and requests.

        Returns:
            bool: True unless the plugin explicitly set it to False.
        """
        value = self._ssl_validation() if self._ssl_validation else True
        return value if isinstance(value, bool) else True

    def _discard_stored_credentials(self) -> None:
        """Remove credentials left in storage by earlier versions."""
        if isinstance(self.storage, dict):
            self.storage.pop("credentials", None)

    def clear_credentials(self) -> None:
        """Forget the temporary credentials and any stored leftovers."""
        self._credentials = None
        self.aws_public_key = None
        self.aws_private_key = None
        self.aws_session_token = None
        self._discard_stored_credentials()

    @staticmethod
    def _is_expiring(credentials: dict) -> bool:
        """Check whether temporary credentials are close to expiry.

        Args:
            credentials (dict): Cached temporary credentials.

        Returns:
            bool: True when fewer than the refresh threshold minutes
                remain, or the expiry cannot be read.
        """
        expiration = credentials.get("expiration")
        if not expiration:
            return True
        try:
            expires_at = datetime.datetime.fromisoformat(
                str(expiration).replace("Z", "+00:00")
            )
        except ValueError:
            return True
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(
                tzinfo=datetime.timezone.utc
            )
        threshold = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(minutes=CREDENTIAL_REFRESH_MINUTES)
        return expires_at <= threshold

    def set_credentials(self):
        """Resolve the AWS credentials for the configured auth method.

        For 'Deployed on AWS' this is a no-op: botocore resolves the
        credentials from the environment. For 'AWS IAM Roles Anywhere'
        the temporary credentials are cached on this client instance and
        refreshed shortly before they expire. One Cloud Exchange plugin
        instance serves many push() calls, so this keeps CreateSession
        to one call per plugin instance instead of one per push.

        Following aws_s3_edm, the credentials are never written to the
        plugin storage, and any left there by an earlier version are
        discarded.

        Returns:
            dict: The temporary credentials, or None for Deployed on AWS.

        Raises:
            AWSCloudWatchPluginError: On credential errors.
        """
        try:
            self._discard_stored_credentials()
            if (
                self.configuration.get("authentication_method")
                != "aws_iam_roles_anywhere"
            ):
                self._credentials = None
                return None

            credentials = self._credentials
            if not credentials or self._is_expiring(credentials):
                self.logger.debug(
                    f"{self.log_prefix}: Generating temporary credentials"
                    " using AWS IAM Roles Anywhere."
                )
                temporary_credentials = (
                    AWSCloudWatchGenerateTemporaryCredentials(
                        self.configuration,
                        self.logger,
                        self.proxy,
                        self.storage,
                        self.log_prefix,
                        self.useragent,
                        self._get_verify(),
                    ).generate_temporary_credentials()
                )
                credential_set = temporary_credentials.get(
                    "credentialSet", []
                )
                credentials = (
                    credential_set[0].get("credentials")
                    if credential_set
                    else None
                )
                if not credentials:
                    raise AWSCloudWatchPluginError(
                        "Unable to generate Temporary Credentials."
                        " Check the configuration parameters."
                    )

            self._credentials = credentials
            self.aws_public_key = credentials.get("accessKeyId")
            self.aws_private_key = credentials.get("secretAccessKey")
            self.aws_session_token = credentials.get("sessionToken")
            return credentials
        except NoCredentialsError as exp:
            self._raise_no_credentials(exp)
        except AWSCloudWatchPluginError:
            raise
        except Exception as err:
            err_msg = "Error occurred while setting credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {err}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the AWS credentials are correct and"
                    " the IAM role has the required CloudWatch Logs"
                    " permissions."
                ),
            )
            raise AWSCloudWatchPluginError(err_msg)

    # ───────────────────────── CLIENT ────────────────────────────────────

    def get_cloudwatch_client(self, validation_retries=None):
        """Create the boto3 CloudWatch Logs client.

        The caller must call set_credentials() first.

        Args:
            validation_retries (int): Retry count to use instead of the
                default. Pass 0 during validation so the user gets the
                error straight away.

        Returns:
            botocore.client.CloudWatchLogs: CloudWatch Logs client.

        Raises:
            AWSCloudWatchPluginError: When the client cannot be created.
        """
        try:
            retries = {
                "max_attempts": (
                    validation_retries
                    if validation_retries is not None
                    else MAX_RETRIES
                ),
                "mode": "standard",
            }
            return boto3.client(
                "logs",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=get_effective_region(self.configuration),
                verify=self._get_verify(),
                config=Config(
                    proxies=self.proxy,
                    # APN first for AWS Partner Network attribution, the
                    # Cloud Exchange agent appended after it.
                    user_agent=self.useragent,
                    connect_timeout=CONNECT_TIMEOUT,
                    read_timeout=READ_TIMEOUT,
                    retries=retries,
                ),
            )
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {PLATFORM_NAME} client"
                " object."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise AWSCloudWatchPluginError(err_msg)

    # ───────────────────────── ERROR MAPPING ─────────────────────────────

    def _iam_resolution(self, template: str) -> str:
        """Fill an access denied hint with the configured target.

        The log group and log stream names come from the configuration,
        never from an example, so the operator sees their own ARNs.

        Args:
            template (str): One of the IAM_RESOLUTION_* templates.

        Returns:
            str: Hint naming the exact actions and resource ARNs.
        """
        region = get_effective_region(self.configuration)
        return template.format(
            partition=get_region_partition(region) or PARTITION_AWS,
            region=region or "<region>",
            group=(
                self.configuration.get("log_group_name", "").strip()
                or "<log-group-name>"
            ),
            stream=(
                self.configuration.get("log_stream_name", "").strip()
                or "<log-stream-name>"
            ),
        )

    def _handle_client_error(self, err, action: str, resolution=None):
        """Turn a botocore ClientError into a plugin error.

        Args:
            err (ClientError): Error raised by boto3.
            action (str): Short description of what the plugin was doing.
            resolution (str): Access denied hint for the call that
                failed. Falls back to the validation hint, which is the
                broadest, when a caller does not supply one.

        Raises:
            AWSCloudWatchResourceNotFoundError: When the log group or the
                log stream does not exist.
            AWSCloudWatchPluginError: For every other AWS error.
        """
        error_code = err.response.get("Error", {}).get("Code", "")
        log_group_name = self.configuration.get("log_group_name", "").strip()

        if error_code == RESOURCE_NOT_FOUND_ERROR_CODE:
            err_msg = (
                f"Log group or log stream was not found while {action}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                resolution=(
                    "Check that the Log Group Name and the Log Stream Name"
                    " are correct, or allow the plugin to create them with"
                    " logs:CreateLogGroup and logs:CreateLogStream."
                ),
                details=traceback.format_exc(),
            )
            raise AWSCloudWatchResourceNotFoundError(err_msg)

        if error_code in INVALID_CREDENTIALS_ERROR_CODES:
            err_msg = "Invalid AWS Credentials provided."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                resolution=(
                    "Check the Authentication Method and the AWS"
                    " credentials provided in the configuration parameters."
                ),
                details=traceback.format_exc(),
            )
            raise AWSCloudWatchPluginError(err_msg)

        if error_code in ACCESS_DENIED_ERROR_CODES:
            err_msg = (
                f"Access denied by AWS while {action}. The IAM role does"
                " not have the permissions this plugin needs."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                resolution=self._iam_resolution(
                    resolution or IAM_RESOLUTION_VALIDATION
                ),
                details=traceback.format_exc(),
            )
            raise AWSCloudWatchPluginError(err_msg)

        err_msg = f"Error occurred while {action}."
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg} Error: {err}",
            details=traceback.format_exc(),
        )
        raise AWSCloudWatchPluginError(err_msg)

    def _raise_no_credentials(self, exp):
        """Report a missing AWS credential chain.

        Args:
            exp (Exception): The botocore error.

        Raises:
            AWSCloudWatchPluginError: Always.
        """
        err_msg = (
            "No AWS Credentials were found in the environment."
            " Deploy the plugin into an AWS environment or use"
            " AWS IAM Roles Anywhere authentication."
        )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=f"Error: {exp}",
            resolution=(
                "Ensure that the plugin is deployed in an AWS"
                " environment with an attached IAM role, or switch the"
                " Authentication Method to 'AWS IAM Roles Anywhere'."
            ),
        )
        raise AWSCloudWatchPluginError(err_msg)

    def _handle_connection_error(self, exp, action: str):
        """Turn a botocore connection error into a plugin error.

        Args:
            exp (Exception): Error raised by boto3.
            action (str): Short description of what the plugin was doing.

        Raises:
            AWSCloudWatchPluginError: Always.
        """
        err_msg = (
            f"Could not reach {PLATFORM_NAME} while {action}."
            " Check the network connection, the proxy settings and the"
            " AWS CloudWatch Region Name."
        )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg} Error: {exp}",
            details=traceback.format_exc(),
        )
        raise AWSCloudWatchPluginError(err_msg)

    # ───────────────────────── RESOURCE BOOTSTRAP ────────────────────────

    def validate_credentials(self, cloudwatch_client) -> None:
        """Check the credentials and the describe permission.

        Calls DescribeLogGroups once. No log event is written.

        Args:
            cloudwatch_client: boto3 CloudWatch Logs client.

        Raises:
            AWSCloudWatchPluginError: When the call fails.
        """
        log_group_name = self.configuration.get("log_group_name", "").strip()
        try:
            cloudwatch_client.describe_log_groups(
                logGroupNamePrefix=log_group_name, limit=1
            )
        except ClientError as err:
            self._handle_client_error(
                err,
                "checking the AWS credentials",
                IAM_RESOLUTION_DESCRIBE_GROUPS,
            )
        except (
            EndpointConnectionError,
            ConnectTimeoutError,
            ReadTimeoutError,
            ConnectionClosedError,
        ) as exp:
            self._handle_connection_error(
                exp, "checking the AWS credentials"
            )
        except NoCredentialsError as exp:
            self._raise_no_credentials(exp)
        except AWSCloudWatchPluginError:
            raise
        except Exception as exp:
            err_msg = "Error occurred while checking the AWS credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise AWSCloudWatchPluginError(err_msg)

    def _is_log_group_present(self, cloudwatch_client, log_group_name) -> bool:
        """Check whether the log group already exists.

        Args:
            cloudwatch_client: boto3 CloudWatch Logs client.
            log_group_name (str): Log group to look for.

        Returns:
            bool: True when the log group exists.
        """
        next_token = None
        for _ in range(MAX_DESCRIBE_PAGES):
            kwargs = {
                "logGroupNamePrefix": log_group_name,
                "limit": DESCRIBE_PAGE_LIMIT,
            }
            if next_token:
                kwargs["nextToken"] = next_token
            response = cloudwatch_client.describe_log_groups(**kwargs)
            for log_group in response.get("logGroups", []):
                if log_group.get("logGroupName") == log_group_name:
                    return True
            next_token = response.get("nextToken")
            if not next_token:
                break
        return False

    def _is_log_stream_present(
        self, cloudwatch_client, log_group_name, log_stream_name
    ) -> bool:
        """Check whether the log stream already exists.

        Args:
            cloudwatch_client: boto3 CloudWatch Logs client.
            log_group_name (str): Log group that holds the stream.
            log_stream_name (str): Log stream to look for.

        Returns:
            bool: True when the log stream exists.
        """
        next_token = None
        for _ in range(MAX_DESCRIBE_PAGES):
            kwargs = {
                "logGroupName": log_group_name,
                "logStreamNamePrefix": log_stream_name,
                "limit": DESCRIBE_PAGE_LIMIT,
            }
            if next_token:
                kwargs["nextToken"] = next_token
            response = cloudwatch_client.describe_log_streams(**kwargs)
            for log_stream in response.get("logStreams", []):
                if log_stream.get("logStreamName") == log_stream_name:
                    return True
            next_token = response.get("nextToken")
            if not next_token:
                break
        return False

    def create_log_group_and_stream(self, cloudwatch_client) -> None:
        """Create the log group and stream without any Describe call.

        Used on the push path, where DescribeLogGroups (10 TPS) and
        DescribeLogStreams (25 TPS) are account wide quotas that would
        throttle ingestion and force account wide IAM. CreateLogGroup
        and CreateLogStream are idempotent for our purposes: an existing
        resource answers ResourceAlreadyExistsException, which is
        success here.

        Args:
            cloudwatch_client: boto3 CloudWatch Logs client.

        Raises:
            AWSCloudWatchPluginError: When creation fails for any other
                reason.
        """
        log_group_name = self.configuration.get("log_group_name", "").strip()
        log_stream_name = self.configuration.get(
            "log_stream_name", ""
        ).strip()

        for create, kwargs, label in (
            (
                cloudwatch_client.create_log_group,
                {"logGroupName": log_group_name},
                f"log group '{log_group_name}'",
            ),
            (
                cloudwatch_client.create_log_stream,
                {
                    "logGroupName": log_group_name,
                    "logStreamName": log_stream_name,
                },
                f"log stream '{log_stream_name}'",
            ),
        ):
            try:
                create(**kwargs)
                self.logger.info(
                    f"{self.log_prefix}: Created the {label} on"
                    f" {PLATFORM_NAME}."
                )
            except ClientError as err:
                error_code = err.response.get("Error", {}).get("Code", "")
                if error_code == RESOURCE_ALREADY_EXISTS_ERROR_CODE:
                    self.logger.debug(
                        f"{self.log_prefix}: The {label} already exists"
                        f" on {PLATFORM_NAME}."
                    )
                    continue
                self._handle_client_error(
                    err,
                    f"creating the {label}",
                    IAM_RESOLUTION_CREATE,
                )
            except (
                EndpointConnectionError,
                ConnectTimeoutError,
                ReadTimeoutError,
                ConnectionClosedError,
            ) as exp:
                self._handle_connection_error(exp, f"creating the {label}")
            except NoCredentialsError as exp:
                self._raise_no_credentials(exp)
            except AWSCloudWatchPluginError:
                raise
            except Exception as exp:
                err_msg = f"Error occurred while creating the {label}."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                raise AWSCloudWatchPluginError(err_msg)

    def ensure_log_group_and_stream(self, cloudwatch_client) -> None:
        """Check the log group and stream, creating them when missing.

        This uses DescribeLogGroups and DescribeLogStreams, which are
        account wide low quota APIs, so it runs in validate() only.
        The push path uses create_log_group_and_stream() instead.

        Args:
            cloudwatch_client: boto3 CloudWatch Logs client.

        Raises:
            AWSCloudWatchPluginError: When the check or the create fails.
        """
        log_group_name = self.configuration.get("log_group_name", "").strip()
        log_stream_name = self.configuration.get(
            "log_stream_name", ""
        ).strip()

        try:
            if not self._is_log_group_present(
                cloudwatch_client, log_group_name
            ):
                try:
                    cloudwatch_client.create_log_group(
                        logGroupName=log_group_name
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Created the log group"
                        f" '{log_group_name}' on {PLATFORM_NAME}."
                    )
                except ClientError as err:
                    error_code = err.response.get("Error", {}).get("Code", "")
                    if error_code != RESOURCE_ALREADY_EXISTS_ERROR_CODE:
                        raise
                    self.logger.debug(
                        f"{self.log_prefix}: The log group"
                        f" '{log_group_name}' was created by another"
                        " thread. Using the existing log group."
                    )

            if not self._is_log_stream_present(
                cloudwatch_client, log_group_name, log_stream_name
            ):
                try:
                    cloudwatch_client.create_log_stream(
                        logGroupName=log_group_name,
                        logStreamName=log_stream_name,
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Created the log stream"
                        f" '{log_stream_name}' in the log group"
                        f" '{log_group_name}' on {PLATFORM_NAME}."
                    )
                except ClientError as err:
                    error_code = err.response.get("Error", {}).get("Code", "")
                    if error_code != RESOURCE_ALREADY_EXISTS_ERROR_CODE:
                        raise
                    self.logger.debug(
                        f"{self.log_prefix}: The log stream"
                        f" '{log_stream_name}' was created by another"
                        " thread. Using the existing log stream."
                    )
        except ClientError as err:
            self._handle_client_error(
                err, "checking the log group and the log stream"
            )
        except (
            EndpointConnectionError,
            ConnectTimeoutError,
            ReadTimeoutError,
            ConnectionClosedError,
        ) as exp:
            self._handle_connection_error(
                exp, "checking the log group and the log stream"
            )
        except NoCredentialsError as exp:
            self._raise_no_credentials(exp)
        except AWSCloudWatchPluginError:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while checking the log group and the log"
                " stream."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise AWSCloudWatchPluginError(err_msg)

    # ───────────────────────── SEND ──────────────────────────────────────

    def put_log_events(self, cloudwatch_client, log_events: list) -> dict:
        """Send one batch of log events to CloudWatch Logs.

        Args:
            cloudwatch_client: boto3 CloudWatch Logs client.
            log_events (list): Log events sorted by timestamp.

        Returns:
            dict: PutLogEvents response.

        Raises:
            AWSCloudWatchResourceNotFoundError: When the log group or the
                log stream is missing.
            AWSCloudWatchPluginError: For every other failure.
        """
        log_group_name = self.configuration.get("log_group_name", "").strip()
        log_stream_name = self.configuration.get(
            "log_stream_name", ""
        ).strip()
        try:
            return cloudwatch_client.put_log_events(
                logGroupName=log_group_name,
                logStreamName=log_stream_name,
                logEvents=log_events,
            )
        except ClientError as err:
            self._handle_client_error(
                err, "sending log(s)", IAM_RESOLUTION_PUT
            )
        except (
            EndpointConnectionError,
            ConnectTimeoutError,
            ReadTimeoutError,
            ConnectionClosedError,
        ) as exp:
            self._handle_connection_error(exp, "sending log(s)")
        except NoCredentialsError as exp:
            self._raise_no_credentials(exp)
        except AWSCloudWatchPluginError:
            raise
        except Exception as exp:
            err_msg = (
                f"Error occurred while pushing log(s) to {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise AWSCloudWatchPluginError(err_msg)
