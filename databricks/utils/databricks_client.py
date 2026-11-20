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

Databricks CLS Plugin S3 Client.
"""

import datetime
import threading
import traceback

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError

from .databricks_exception import DatabricksException
from .databricks_generate_temp_creds import DatabricksGenerateTempCreds


class DatabricksClient:
    """AWS S3 client for the Databricks CLS Plugin."""

    def __init__(
        self,
        configuration,
        logger,
        proxy,
        storage,
        log_prefix,
        user_agent,
    ):
        """Initialize DatabricksClient.

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
            DatabricksException: On credential errors.
        """
        try:
            if (
                self.configuration.get("authentication_method")
                == "aws_iam_roles_anywhere"
            ):
                temp_creds_obj = DatabricksGenerateTempCreds(
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
                        raise DatabricksException(
                            "Unable to generate Temporary Credentials."
                            " Check the configuration parameters."
                        )
                elif datetime.datetime.fromisoformat(
                    self.storage.get("credentials")
                    .get("expiration")
                    .replace("Z", "+00:00")
                ) <= datetime.datetime.now(
                    datetime.timezone.utc
                ) + datetime.timedelta(
                    minutes=3
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
                        raise DatabricksException(
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
            )
            raise DatabricksException(err_msg)
        except DatabricksException:
            raise
        except Exception as err:
            err_msg = "Error occurred while setting credentials."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} {err}"),
                details=traceback.format_exc(),
            )
            raise DatabricksException(err_msg)

    def get_aws_client(self):
        """Create and return a boto3 S3 client object.

        Returns:
            botocore.client.S3: S3 client.

        Raises:
            DatabricksException: On boto3 creation errors.
        """
        try:
            s3_client = boto3.client(
                "s3",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=self.configuration.get("region_name", "").strip(),
                config=Config(
                    proxies=self.proxy,
                    user_agent=self.useragent,
                ),
            )
            return s3_client
        except Exception as exp:
            err_msg = "Error occurred while creating AWS S3 client object."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} {exp}"),
                details=traceback.format_exc(),
            )
            raise DatabricksException(err_msg)

    def is_bucket_exists(self, s3_client, bucket_name: str) -> bool:
        """Check whether the S3 bucket exists in the configured account.

        Uses HeadBucket, which requires only s3:ListBucket on the specific
        bucket — avoiding the account-wide s3:ListAllMyBuckets permission
        needed by ListBuckets.

        S3 bucket names are globally unique across all AWS accounts, so the
        HTTP status is interpreted strictly:
          - 200            -> bucket exists in this account and is usable.
          - 404 / NoSuchBucket -> bucket does not exist anywhere.
          - 403 / AccessDenied -> the name is owned by a different AWS
            account, or the role cannot access it. The bucket is not
            usable, so this is treated as a validation failure rather
            than assumed to exist.

        Args:
            s3_client: boto3 S3 client object.
            bucket_name (str): Target bucket name.

        Returns:
            bool: True if the bucket exists and is accessible (200).
                  False if the bucket does not exist (404).

        Raises:
            DatabricksException: On a 403 (name owned by another account /
                not accessible) or any unexpected S3 API error.
        """
        try:
            s3_client.head_bucket(Bucket=bucket_name)
            return True
        except ClientError as err:
            err_code = err.response.get("Error", {}).get("Code", "")
            if err_code in ("404", "NoSuchBucket"):
                return False
            if err_code in ("403", "AccessDenied"):
                # S3 names are global. With valid credentials, a 403 means
                # the bucket is owned by another account (or is otherwise
                # inaccessible) — it cannot be used, so fail validation.
                self.logger.debug(
                    f"{self.log_prefix}: HeadBucket on '{bucket_name}'"
                    " returned 403 (AccessDenied) — the bucket name is"
                    " owned by another AWS account or is not accessible to"
                    f" the configured role. Error: {err}"
                )
                return False
            err_msg = "Error occurred while checking existence of S3 bucket."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {err}",
            )
            raise DatabricksException(err_msg)
        except DatabricksException:
            raise
        except Exception as exp:
            err_msg = "Error occurred while checking existence of S3 bucket."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {exp}",
            )
            raise DatabricksException(err_msg)

    def verify_bucket_exists(self) -> bool:
        """Verify the configured S3 bucket exists and is in the correct region.

        Checks both existence and that the bucket's actual region matches the
        configured region. A region mismatch causes upload_file to fail with
        a 301 PermanentRedirect at push time, so it must be caught here.

        Returns:
            bool: True if the bucket exists in the configured region.

        Raises:
            DatabricksException: If the bucket does not exist, is in a
                different region, or on S3 API errors.
        """
        bucket_name = self.configuration.get("bucket_name", "").strip()
        region_name = self.configuration.get("region_name", "").strip()
        s3_client = self.get_aws_client()

        if not self.is_bucket_exists(s3_client, bucket_name):
            return False

        try:
            location = s3_client.get_bucket_location(Bucket=bucket_name)
            bucket_region = location.get("LocationConstraint") or "us-east-1"
            if bucket_region != region_name:
                err_msg = (
                    f"AWS S3 bucket '{bucket_name}' exists but is in"
                    f" region '{bucket_region}', not the configured"
                    f" region '{region_name}'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that the AWS S3 Bucket Region Name"
                        f" in the plugin configuration is set to"
                        f" '{bucket_region}' to match the actual"
                        " bucket region."
                    ),
                )
                raise DatabricksException(err_msg)
        except DatabricksException:
            raise
        except ClientError as err:
            err_code = err.response.get("Error", {}).get("Code", "")
            if err_code in ("403", "AccessDenied"):
                # s3:GetBucketLocation not granted — skip region check.
                # Region format already validated; trust configured value.
                self.logger.debug(
                    f"{self.log_prefix}: Skipping bucket region verification"
                    f" for '{bucket_name}' — s3:GetBucketLocation permission"
                    " is not available. Ensure the configured AWS S3 Bucket"
                    " Region Name matches the bucket's actual region."
                )
            else:
                err_msg = (
                    "Error occurred while verifying the AWS S3 bucket region."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"Error: {err}",
                )
                raise DatabricksException(err_msg)
        except Exception as exp:
            err_msg = (
                "Error occurred while verifying the AWS S3 bucket region."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {exp}",
            )
            raise DatabricksException(err_msg)

        return True

    def push(self, file_name: str, data_type: str, subtype: str):
        """Upload a local file to the S3 bucket.

        Args:
            file_name (str): Local file path to upload.
            data_type (str): Data type — 'alerts' or 'events'.
            subtype (str): Subtype — e.g. 'dlp', 'page'.

        Raises:
            DatabricksException: On S3 upload errors.
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
            bucket_name = self.configuration.get("bucket_name", "").strip()
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
                f" Object File Name: {object_name}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the IAM role has s3:GetBucketLocation, "
                    "s3:PutObject, s3:ListBucket "
                    f"permissions for bucket '{bucket_name}' and"
                    " the bucket still exists."
                ),
                details=f"Error: {exp}",
            )
            raise DatabricksException(err_msg)
