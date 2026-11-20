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

AWS S3 Events, Alerts Client Class.
"""

import datetime
import threading
import traceback

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError

from .aws_s3_events_alerts_exception import AWSS3EventsAlertsException
from .aws_s3_events_alerts_generate_temp_creds import (
    AWSS3GenerateTemporaryCredentials,
)


class AWSS3EventsAlertsClient:
    """AWS S3 Events, Alerts Client Class."""

    def __init__(
        self,
        configuration,
        logger,
        proxy,
        storage,
        log_prefix,
        user_agent,
    ):
        """Initialize AWSS3EventsAlertsClient.

        Args:
            configuration (dict): Plugin configuration parameters.
            logger: Logger object.
            proxy (dict): Proxy configuration.
            storage (dict): Plugin storage dict.
            log_prefix (str): Log prefix string.
            user_agent (str): User-agent string for boto3.
        """
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
        """Set AWS credentials from configuration or IAM Roles Anywhere.

        Returns:
            dict: Updated storage dict with cached credentials.

        Raises:
            AWSS3EventsAlertsException: On credential errors.
        """
        try:
            if (
                self.configuration.get("authentication_method")
                == "aws_iam_roles_anywhere"
            ):
                temp_creds_obj = AWSS3GenerateTemporaryCredentials(
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
                    credential_set = temporary_credentials.get(
                        "credentialSet", []
                    )
                    credentials = (
                        credential_set[0].get("credentials")
                        if credential_set
                        else None
                    )
                    if credentials:
                        self.storage["credentials"] = credentials
                    else:
                        raise AWSS3EventsAlertsException(
                            "Unable to generate Temporary Credentials."
                            " Check the configuration parameters."
                        )
                elif (
                    not self.storage.get("credentials", {}).get(
                        "expiration"
                    )
                    or datetime.datetime.fromisoformat(
                        self.storage.get("credentials")
                        .get("expiration")
                        .replace("Z", "+00:00")
                    )
                    <= datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(minutes=3)
                ):
                    temporary_credentials = (
                        temp_creds_obj.generate_temporary_credentials()
                    )
                    credential_set = temporary_credentials.get(
                        "credentialSet", []
                    )
                    credentials = (
                        credential_set[0].get("credentials")
                        if credential_set
                        else None
                    )
                    if credentials:
                        self.storage["credentials"] = credentials
                    else:
                        raise AWSS3EventsAlertsException(
                            "Unable to refresh Temporary Credentials."
                            " Check the configuration parameters."
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
                " Deploy the plugin into an AWS environment or use"
                " AWS IAM Roles Anywhere authentication."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {exp}",
                resolution=(
                    "Ensure that the plugin is deployed in an AWS"
                    " environment or use AWS IAM Roles Anywhere"
                    " authentication."
                ),
            )
            raise AWSS3EventsAlertsException(err_msg)
        except AWSS3EventsAlertsException:
            raise
        except Exception as err:
            err_msg = "Error occurred while setting credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {err}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the AWS credentials are correct and"
                    " the IAM role has the required S3 permissions."
                ),
            )
            raise AWSS3EventsAlertsException(err_msg)

    def get_aws_client(self):
        """Create and return a boto3 S3 client object.

        Returns:
            botocore.client.S3: S3 client.

        Raises:
            AWSS3EventsAlertsException: On boto3 creation errors.
        """
        try:
            s3_client = boto3.client(
                "s3",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=self.configuration.get(
                    "region_name", ""
                ).strip(),
                config=Config(
                    proxies=self.proxy,
                    user_agent=self.useragent,
                ),
            )
            return s3_client
        except Exception as exp:
            err_msg = "Error occurred while creating AWS S3 client object."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {exp}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the AWS region and credentials are"
                    " correctly configured."
                ),
            )
            raise AWSS3EventsAlertsException(err_msg)

    def get_aws_sts_client(self):
        """Create and return a boto3 STS client object.

        Used solely to resolve the caller's own AWS account ID via
        ``get_caller_identity`` for bucket ownership verification.
        This call requires no IAM permission — it is exempt from
        identity-based policy enforcement and works with any valid
        AWS credentials.

        Returns:
            botocore.client.STS: STS client.

        Raises:
            AWSS3EventsAlertsException: On boto3 creation errors.
        """
        try:
            sts_client = boto3.client(
                "sts",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=self.configuration.get(
                    "region_name", ""
                ).strip(),
                config=Config(
                    proxies=self.proxy,
                    user_agent=self.useragent,
                ),
            )
            return sts_client
        except Exception as exp:
            err_msg = (
                "Error occurred while creating AWS STS client object."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {exp}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the AWS region and credentials are"
                    " correctly configured."
                ),
            )
            raise AWSS3EventsAlertsException(err_msg)

    def _verify_bucket_ownership(
        self,
        s3_client,
        bucket_name: str,
        externally_provisioned: str,
    ):
        """Verify bucket ownership matches 'Externally Provisioned
        Bucket'.

        A plain HeadBucket only proves the bucket is *accessible* — it
        returns 200 regardless of which AWS account owns the bucket,
        as long as permissions (cross-account bucket policy, or
        same-account IAM policy) allow it. That makes it impossible to
        tell, from HeadBucket alone, whether ``externally_provisioned``
        actually matches the real owner of the bucket.

        This method closes that gap using the ``ExpectedBucketOwner``
        parameter: HeadBucket is re-run with the caller's own AWS
        account ID (from ``sts:GetCallerIdentity``) as the expected
        owner. AWS enforces this check strictly — it returns 403 if
        the bucket belongs to a different account, even when the
        caller has full read/write access to it via a bucket policy.
        This lets the plugin detect a bucket that is fully accessible
        but owned by the "wrong" account for the configured setting.

        If ``sts:GetCallerIdentity`` itself is denied (for example, by
        an AWS Organizations SCP, an explicit IAM deny, or a
        restrictive STS VPC endpoint policy), ownership cannot be
        determined at all. Rather than blocking configuration on a
        gap this check introduces, that case is treated the same way
        as ``_verify_bucket_region`` treats a missing
        ``s3:GetBucketLocation`` permission — skipped with a debug
        log, falling back to trusting the configured
        'Externally Provisioned Bucket' value as-is.

        Args:
            s3_client: boto3 S3 client object.
            bucket_name (str): Bucket name to check.
            externally_provisioned (str): Configured 'yes' or 'no'
                value for 'Externally Provisioned Bucket'.

        Raises:
            AWSS3EventsAlertsException: If the bucket's actual
                ownership does not match the configured
                'Externally Provisioned Bucket' value, or on
                unexpected STS/S3 errors.
        """
        sts_client = self.get_aws_sts_client()
        try:
            own_account_id = sts_client.get_caller_identity().get(
                "Account"
            )
        except ClientError as err:
            err_code = err.response.get("Error", {}).get("Code", "")
            if err_code in ("403", "AccessDenied"):
                self.logger.debug(
                    f"{self.log_prefix}: Skipping bucket ownership"
                    f" verification for '{bucket_name}' —"
                    " sts:GetCallerIdentity is not permitted (blocked"
                    " by an AWS Organizations SCP, an explicit IAM"
                    " deny, or a restrictive STS VPC endpoint policy)."
                    " Trusting the configured 'Externally Provisioned"
                    " Bucket' value as-is."
                )
                return
            err_msg = (
                "Error occurred while retrieving the AWS account"
                " identity for bucket ownership verification."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {err}",
            )
            raise AWSS3EventsAlertsException(err_msg)
        except Exception as exp:
            err_msg = (
                "Error occurred while retrieving the AWS account"
                " identity for bucket ownership verification."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {exp}",
            )
            raise AWSS3EventsAlertsException(err_msg)

        try:
            s3_client.head_bucket(
                Bucket=bucket_name, ExpectedBucketOwner=own_account_id
            )
            is_own_account = True
        except ClientError as err:
            err_code = err.response.get("Error", {}).get("Code", "")
            if err_code in ("403", "AccessDenied"):
                is_own_account = False
            else:
                err_msg = (
                    "Error occurred while verifying AWS S3 bucket"
                    " ownership."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"Error: {err}",
                )
                raise AWSS3EventsAlertsException(err_msg)

        if externally_provisioned == "no" and not is_own_account:
            err_msg = (
                f"AWS S3 Bucket '{bucket_name}' belongs to a"
                " different AWS account, but 'Externally"
                " Provisioned Bucket' is set to 'No'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Set 'Externally Provisioned Bucket' to 'Yes'"
                    " since this bucket belongs to an external AWS"
                    " account, or provide a bucket name that belongs"
                    " to your own AWS account."
                ),
            )
            raise AWSS3EventsAlertsException(err_msg)

        if externally_provisioned == "yes" and is_own_account:
            err_msg = (
                f"AWS S3 Bucket '{bucket_name}' belongs to your own"
                " AWS account, but 'Externally Provisioned Bucket'"
                " is set to 'Yes'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Set 'Externally Provisioned Bucket' to 'No'"
                    " since this bucket belongs to your own AWS"
                    " account, or provide a bucket name that belongs"
                    " to an external AWS account."
                ),
            )
            raise AWSS3EventsAlertsException(err_msg)

    def is_bucket_exists(
        self,
        s3_client,
        bucket_name: str,
        externally_provisioned: bool = False,
    ) -> bool:
        """Check whether the S3 bucket exists and is accessible.

        Uses HeadBucket which requires only ``s3:ListBucket`` on the
        specific bucket — no account-wide ``s3:ListAllMyBuckets`` needed.

        S3 bucket names are globally unique, so the HTTP status is
        interpreted strictly:

        * 200              → bucket exists and is accessible → True
        * 404/NoSuchBucket → bucket does not exist anywhere → False
        * 403/AccessDenied → owned by a different account or role
          cannot access it → raises immediately with a clear message

        Args:
            s3_client: boto3 S3 client object.
            bucket_name (str): Target bucket name.
            externally_provisioned (bool): Whether the bucket is
                externally provisioned (cross-account). Tailors the
                403 guidance towards a missing cross-account IAM
                grant instead of a bucket-name collision.

        Returns:
            bool: True if accessible, False if not found (404).

        Raises:
            AWSS3EventsAlertsException: On 403 or unexpected S3 errors.
        """
        try:
            s3_client.head_bucket(Bucket=bucket_name)
            return True
        except ClientError as err:
            err_code = err.response.get("Error", {}).get("Code", "")
            if err_code in ("404", "NoSuchBucket"):
                return False
            if err_code in ("403", "AccessDenied"):
                if externally_provisioned:
                    err_msg = (
                        f"AWS S3 Bucket '{bucket_name}' is not"
                        " accessible. Since the bucket is configured"
                        " as externally provisioned, this is most"
                        " likely a missing cross-account IAM"
                        " permission rather than a bucket name"
                        " collision."
                    )
                    resolution = (
                        "Ensure that the external AWS account's"
                        " bucket policy grants this IAM role"
                        " s3:ListBucket, s3:GetBucketLocation and"
                        " s3:PutObject permissions on the bucket."
                    )
                else:
                    err_msg = (
                        f"AWS S3 Bucket '{bucket_name}' already"
                        " exists at a different region or is not"
                        " accessible. Please try with a different"
                        " bucket name or use the correct region."
                    )
                    resolution = (
                        "Possible causes and resolutions:\n"
                        "• Bucket name is taken by a different AWS"
                        " account: provide a globally unique bucket"
                        " name.\n"
                        "• IAM role should have s3:ListBucket, "
                        "s3:GetBucketLocation and s3:PutObject permissions "
                        "on the bucket."
                    )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"Error: {err}",
                    resolution=resolution,
                )
                raise AWSS3EventsAlertsException(err_msg)
            err_msg = (
                "Error occurred while checking existence of S3 bucket."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {err}",
            )
            raise AWSS3EventsAlertsException(err_msg)
        except AWSS3EventsAlertsException:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while checking existence of S3 bucket."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {exp}",
            )
            raise AWSS3EventsAlertsException(err_msg)

    def _create_bucket(
        self, s3_client, bucket_name: str, region_name: str
    ):
        """Create an S3 bucket in the configured region.

        Args:
            s3_client: boto3 S3 client object.
            bucket_name (str): Name of the bucket to create.
            region_name (str): AWS region for the new bucket.

        Raises:
            AWSS3EventsAlertsException: On S3 creation errors.
        """
        try:
            if region_name == "us-east-1":
                s3_client.create_bucket(Bucket=bucket_name)
            else:
                s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={
                        "LocationConstraint": region_name
                    },
                )
        except ClientError as create_err:
            err_msg = create_err.response["Error"].get(
                "Message", str(create_err)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {create_err}",
                resolution=(
                    "Ensure the IAM role has s3:CreateBucket"
                    " permission and the bucket name is globally"
                    " unique."
                ),
            )
            raise AWSS3EventsAlertsException(err_msg)
        except Exception as exp:
            err_msg = (
                "Error occurred while creating AWS S3 bucket"
                f" '{bucket_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {exp}",
            )
            raise AWSS3EventsAlertsException(err_msg)

    def _verify_bucket_region(
        self, s3_client, bucket_name: str, region_name: str
    ):
        """Verify the bucket's actual region matches the configured region.

        If ``s3:GetBucketLocation`` is not granted the check is skipped
        with a debug log — the format-validated configured region is
        trusted in that case.

        Args:
            s3_client: boto3 S3 client object.
            bucket_name (str): Bucket name to check.
            region_name (str): Expected region from configuration.

        Raises:
            AWSS3EventsAlertsException: On region mismatch or S3 errors.
        """
        try:
            location = s3_client.get_bucket_location(Bucket=bucket_name)
            bucket_region = (
                location.get("LocationConstraint") or "us-east-1"
            )
            if bucket_region != region_name:
                err_msg = (
                    f"AWS S3 bucket '{bucket_name}' exists but is in"
                    f" region '{bucket_region}', not the configured"
                    f" region '{region_name}'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that the AWS S3 Bucket Region Name in"
                        " the plugin configuration is set to"
                        f" '{bucket_region}' to match the actual"
                        " bucket region."
                    ),
                )
                raise AWSS3EventsAlertsException(err_msg)
        except AWSS3EventsAlertsException:
            raise
        except ClientError as err:
            err_code = err.response.get("Error", {}).get("Code", "")
            if err_code in ("403", "AccessDenied"):
                self.logger.debug(
                    f"{self.log_prefix}: Skipping bucket region"
                    f" verification for '{bucket_name}' —"
                    " s3:GetBucketLocation permission is not available."
                    " Ensure the configured AWS S3 Bucket Region Name"
                    " matches the bucket's actual region."
                )
            else:
                err_msg = (
                    "Error occurred while verifying the AWS S3 bucket"
                    " region."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"Error: {err}",
                )
                raise AWSS3EventsAlertsException(err_msg)
        except Exception as exp:
            err_msg = (
                "Error occurred while verifying the AWS S3 bucket"
                " region."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {exp}",
            )
            raise AWSS3EventsAlertsException(err_msg)

    def verify_bucket_exists(self) -> bool:
        """Verify the S3 bucket exists and is in the correct region.

        Orchestrates four focused steps:
          1. ``is_bucket_exists``        — HeadBucket accessibility
             check.
          2. ``_verify_bucket_ownership`` — only when the bucket
             already exists; confirms the bucket's actual AWS account
             ownership matches 'Externally Provisioned Bucket'.
          3. Conditional creation        — only when ep=no and bucket
             absent.
          4. ``_verify_bucket_region``   — region match confirmation.

        Behaviour on a missing bucket (404) depends on
        ``externally_provisioned_bucket``:

        * ``no``  — plugin creates the bucket in the configured region.
        * ``yes`` — plugin raises immediately; external buckets must be
          pre-created by the owning team.

        A 403 from HeadBucket always raises regardless of ep setting.

        Returns:
            bool: True when the bucket is accessible in the configured
                region.

        Raises:
            AWSS3EventsAlertsException: On any unrecoverable error,
                including an ep/ownership mismatch.
        """
        bucket_name = self.configuration.get("bucket_name", "").strip()
        region_name = self.configuration.get("region_name", "").strip()
        externally_provisioned = (
            self.configuration.get(
                "externally_provisioned_bucket", "no"
            )
            .strip()
            .lower()
        )
        s3_client = self.get_aws_client()

        bucket_found = self.is_bucket_exists(
            s3_client,
            bucket_name,
            externally_provisioned=externally_provisioned == "yes",
        )

        if bucket_found:
            self._verify_bucket_ownership(
                s3_client, bucket_name, externally_provisioned
            )
        elif externally_provisioned == "yes":
            err_msg = (
                f"AWS S3 Bucket '{bucket_name}' does not exist"
                " or is not accessible from the external account."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the S3 bucket exists in the"
                    " external AWS account and the IAM role has"
                    " s3:ListBucket, s3:GetBucketLocation and"
                    " s3:PutObject permissions on the bucket."
                ),
            )
            raise AWSS3EventsAlertsException(err_msg)
        else:
            self._create_bucket(s3_client, bucket_name, region_name)

        self._verify_bucket_region(s3_client, bucket_name, region_name)
        return True

    def push(self, file_name: str, data_type: str, subtype: str):
        """Upload a local file to the S3 bucket.

        Args:
            file_name (str): Local file path to upload.
            data_type (str): Data type — 'alerts', 'events', or 'webtx'.
            subtype (str): Subtype — e.g. 'dlp', 'page', 'v2'.

        Raises:
            AWSS3EventsAlertsException: On S3 upload errors.
        """
        curr_time = datetime.datetime.now()
        if data_type is None:
            object_name = (
                f"year={curr_time.year}/month={curr_time.month}"
                f"/day={curr_time.day}/hour={curr_time.hour}"
                f"/{int(curr_time.timestamp())}"
                f"_{threading.get_ident()}.txt"
            )
        else:
            object_name = (
                f"{data_type}/feedname={subtype}"
                f"/year={curr_time.year}/month={curr_time.month}"
                f"/day={curr_time.day}/hour={curr_time.hour}"
                f"/{int(curr_time.timestamp())}"
                f"_{threading.get_ident()}.txt"
            )
        try:
            bucket_name = self.configuration.get(
                "bucket_name", ""
            ).strip()
            s3_client = self.get_aws_client()
            s3_client.upload_file(
                file_name,
                bucket_name,
                object_name,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully uploaded log(s) to"
                f" AWS S3 bucket {bucket_name} as object file."
                f" Object File Name: {object_name}"
            )
        except Exception as exp:
            bucket_name = self.configuration.get("bucket_name", "")
            err_msg = (
                f"Error occurred while uploading log(s) to AWS S3"
                f" Bucket {bucket_name}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the IAM role has s3:GetBucketLocation,"
                    " s3:PutObject, s3:ListBucket permissions for"
                    f" bucket '{bucket_name}' and the bucket still"
                    " exists."
                ),
                details=f"Error: {exp}",
            )
            raise AWSS3EventsAlertsException(err_msg)
