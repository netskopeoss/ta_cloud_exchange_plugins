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

AWS S3 client: credentials, boto3 client, error mapping and object checks.
"""

import datetime
from typing import Optional

import boto3
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    CredentialRetrievalError,
    NoCredentialsError,
    PartialCredentialsError,
)

from .constants import (
    ACCESS_DENIED_CODES,
    ARCHIVE_ACCESS_TIERS,
    AUTH_ERROR_CODES,
    AUTH_ROLES_ANYWHERE,
    BOTO_CONNECT_TIMEOUT,
    BOTO_MAX_ATTEMPTS,
    BOTO_READ_TIMEOUT,
    CHANGED_OBJECT_CODES,
    CREDENTIAL_REFRESH_MINUTES,
    FORMAT_PLAIN,
    GLACIER_STORAGE_CLASSES,
    MAX_COMPRESSED_SIZE,
    OPERATION_ACTIONS,
    NOT_FOUND_CODES,
    REGION_ERROR_CODES,
)
from .exception import AWSS3EDMException, ObjectChangedError
from .generate_temp_creds import AWSS3GenerateTemporaryCredentials
from .helper import (
    AWSS3EDMBase,
    format_size,
    get_effective_region,
    get_object_format,
    safe_error_text,
)
from .decompressor import AWSS3EDMDecompressor
from .downloader import AWSS3EDMDownloader


class AWSS3EDMClient(AWSS3EDMBase):
    """AWS S3 client: credentials, boto3 client, errors, file checks."""

    default_action = "connecting to AWS S3"

    def __init__(
        self,
        logger,
        log_prefix: str,
        proxy: Optional[dict],
        storage: Optional[dict],
        user_agent: str,
        ssl_validation=None,
    ) -> None:
        """Initialize the client.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix.
            proxy (dict): Proxy settings.
            storage (dict): Plugin storage, shared in place. ``None`` when
                the plugin is created only to render fields. The temporary
                credentials are never written to it.
            user_agent (str): User agent used for AWS calls.
            ssl_validation (callable, optional): Returns the Cloud Exchange
                SSL validation setting (read when it is needed, as CE sets
                it after creating the plugin). Defaults to True.
        """
        super().__init__(logger, log_prefix)
        self.proxy = proxy
        self.storage = storage
        self.user_agent = user_agent
        self._ssl_validation = ssl_validation
        self._credentials = None
        self._client = None
        self._client_key = None
        self.decompressor = AWSS3EDMDecompressor(logger, log_prefix)
        self.downloader = AWSS3EDMDownloader(
            logger, log_prefix, self, self.decompressor
        )

    def pull_sample(
        self, configuration: dict, info: dict, sample_path: str
    ) -> None:
        """Pull the sample of the object (see the downloader).

        Args:
            configuration (dict): Step 1 configuration parameters.
            info (dict): Object metadata from ``validate_object``.
            sample_path (str): Local path of the sample file.
        """
        self.downloader.pull_sample(configuration, info, sample_path)

    def download_object(
        self,
        configuration: dict,
        info: dict,
        destination: str,
        strip_bom: bool = False,
    ) -> None:
        """Download the raw object to a local file (see the downloader).

        Args:
            configuration (dict): Step 1 configuration parameters.
            info (dict): Object metadata from ``validate_object``.
            destination (str): Local file path.
            strip_bom (bool): Remove a UTF-8 BOM at the file start.
        """
        self.downloader.download_object(
            configuration, info, destination, strip_bom
        )

    def fetch_object(
        self,
        configuration: dict,
        info: dict,
        output_dir: str,
        file_base: str,
    ) -> str:
        """Download and decompress the object (see the downloader).

        Args:
            configuration (dict): Step 1 configuration parameters.
            info (dict): Object metadata from ``validate_object``.
            output_dir (str): Local output directory.
            file_base (str): Local file name without extension.

        Returns:
            str: Path of the local CSV/TXT file.
        """
        return self.downloader.fetch_object(
            configuration, info, output_dir, file_base
        )

    def _get_proxies(self) -> dict:
        """Get the proxy settings without empty entries.

        Returns:
            dict: Proxy settings keyed by scheme.
        """
        return {
            scheme: url for scheme, url in (self.proxy or {}).items() if url
        }

    def _get_verify(self) -> bool:
        """Get the SSL validation setting (True unless it is a bool False).

        Returns:
            bool: Value for the ``verify`` argument of boto3 and requests.
        """
        value = self._ssl_validation() if self._ssl_validation else True
        return value if isinstance(value, bool) else True

    def _discard_stored_credentials(self) -> None:
        """Remove credentials left in storage by earlier versions or runs."""
        if self.storage is not None:
            self.storage.pop("credentials", None)

    def clear_credentials(self) -> None:
        """Forget the temporary credentials (and any stored leftovers)."""
        self._credentials = None
        self._client = None
        self._client_key = None
        self._discard_stored_credentials()

    @staticmethod
    def _is_expiring(credentials: dict) -> bool:
        """Check whether temporary credentials are (about to be) expired.

        Args:
            credentials (dict): Cached temporary credentials.

        Returns:
            bool: True if fewer than the refresh threshold minutes remain.
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
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        threshold = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(minutes=CREDENTIAL_REFRESH_MINUTES)
        return expires_at <= threshold

    def refresh_credentials(self, configuration: dict) -> Optional[dict]:
        """Get valid credentials, refreshing Roles Anywhere ones if needed.

        The credentials are cached on this client instance only and are
        never written to the plugin storage.

        Args:
            configuration (dict): Step 1 configuration parameters.

        Returns:
            Optional[dict]: Temporary credentials for Roles Anywhere, or
                None when the default credential chain must be used.
        """
        self._discard_stored_credentials()
        if configuration.get("authentication_method") != AUTH_ROLES_ANYWHERE:
            self._credentials = None
            return None
        credentials = self._credentials
        if not credentials or self._is_expiring(credentials):
            self.logger.debug(
                f"{self.log_prefix}: Generating temporary credentials "
                "using AWS IAM Roles Anywhere."
            )
            credentials = AWSS3GenerateTemporaryCredentials(
                configuration,
                self.logger,
                self._get_proxies(),
                self.storage,
                self.log_prefix,
                self.user_agent,
                self._get_verify(),
            ).generate_temporary_credentials()
        self._credentials = credentials
        return credentials

    def get_client(self, configuration: dict):
        """Get a boto3 S3 client, refreshing credentials when required.

        Args:
            configuration (dict): Step 1 configuration parameters.

        Raises:
            AWSS3EDMException: If the client cannot be created.

        Returns:
            botocore.client.S3: The S3 client.
        """
        credentials = self.refresh_credentials(configuration)
        region = get_effective_region(configuration)
        verify = self._get_verify()
        client_key = (
            verify,
            region,
            credentials.get("accessKeyId") if credentials else None,
            credentials.get("sessionToken") if credentials else None,
        )
        if self._client is not None and self._client_key == client_key:
            return self._client
        client_args = {
            "region_name": region,
            "verify": verify,
            "config": Config(
                proxies=self._get_proxies() or None,
                user_agent=self.user_agent,
                retries={
                    "total_max_attempts": BOTO_MAX_ATTEMPTS,
                    "mode": "standard",
                },
                connect_timeout=BOTO_CONNECT_TIMEOUT,
                read_timeout=BOTO_READ_TIMEOUT,
            ),
        }
        if credentials:
            client_args.update(
                {
                    "aws_access_key_id": credentials.get("accessKeyId"),
                    "aws_secret_access_key": credentials.get(
                        "secretAccessKey"
                    ),
                    "aws_session_token": credentials.get("sessionToken"),
                }
            )
        try:
            self._client = boto3.client("s3", **client_args)
        except Exception as error:
            raise self._error(
                "Error occurred while creating the AWS S3 client. Error: "
                f"{safe_error_text(error)}",
                "Ensure that the AWS S3 Bucket Region is correct.",
            ) from error
        self._client_key = client_key
        return self._client

    def _describe_client_error(
        self,
        code: str,
        message: str,
        operation: str,
        bucket: str,
        key: Optional[str],
    ) -> tuple:
        """Convert an S3 error code to a user message and resolution.

        Args:
            code (str): S3 error code.
            message (str): S3 error message.
            operation (str): S3 operation name.
            bucket (str): Bucket name.
            key (Optional[str]): Object key.

        Returns:
            tuple: ``(error message, resolution)``.
        """
        target = f"bucket '{bucket}'"
        if key:
            target = f"file path '{key}' in the bucket '{bucket}'"
        is_bucket_call = operation in ("head_bucket", "get_bucket_location")
        if code == "400" and operation in ("head_bucket", "head_object"):
            return (
                "AWS rejected the request (HTTP 400). The AWS credentials "
                "are invalid or expired, or the system clock of the Cloud "
                "Exchange host is skewed.",
                "Ensure that the AWS credentials are valid and the system "
                "time of the Cloud Exchange host is correct (NTP).",
            )
        if code in AUTH_ERROR_CODES:
            return (
                "AWS authentication failed. The AWS credentials are "
                f"invalid or expired (error code: {code}).",
                "Ensure that the host IAM role or the AWS IAM Roles "
                "Anywhere configuration is valid and the system clock is "
                "correct.",
            )
        if "kms" in code.lower() or "kms:" in (message or "").lower():
            return (
                f"Access to the KMS key that encrypts the {target} was "
                "denied.",
                "Ensure that the 'kms:Decrypt' permission on the KMS key is "
                "granted to the IAM role used by the plugin.",
            )
        if code == "InvalidObjectState":
            return (
                f"The {target} is archived (Glacier/Deep Archive) and "
                "cannot be read.",
                "Ensure that the file is restored from the archive tier "
                "before using it in the plugin.",
            )
        if code in CHANGED_OBJECT_CODES:
            return (
                f"The {target} was modified while it was being downloaded.",
                "Ensure that the export job writes the file atomically.",
            )
        if code == "NoSuchBucket" or (
            code in NOT_FOUND_CODES and is_bucket_call
        ):
            return (
                f"AWS S3 bucket '{bucket}' was not found.",
                "Ensure that the AWS S3 Bucket Name is correct.",
            )
        if code in NOT_FOUND_CODES:
            return (
                f"The {target} was not found.",
                "Ensure that the File Path is the exact path "
                "(case-sensitive) of an existing file in the bucket and "
                "does not include the bucket name (for example "
                "\"bucket/folder/file.csv\" must be "
                "\"folder/file.csv\").",
            )
        if code in ACCESS_DENIED_CODES:
            return self._describe_access_denied(is_bucket_call, target)
        if code in REGION_ERROR_CODES:
            return (
                f"The bucket '{bucket}' is in a different region than the "
                "configured AWS S3 Bucket Region.",
                "Ensure that the AWS S3 Bucket Region is the region in "
                "which the bucket resides.",
            )
        return (
            f"Error occurred while accessing the {target} (error code: "
            f"{code or 'unknown'}).",
            "Ensure that the AWS configuration is valid, refer to the "
            "error details in the logs.",
        )

    @staticmethod
    def _describe_access_denied(is_bucket_call: bool, target: str) -> tuple:
        """Build the access denied message.

        HeadBucket and HeadObject return a 403 without an error body, so
        expired or invalid credentials and a skewed system clock cannot be
        told apart from a missing permission.

        Args:
            is_bucket_call (bool): True for bucket level operations.
            target (str): Description of the bucket or object.

        Returns:
            tuple: ``(error message, resolution)``.
        """
        credentials_hint = (
            "the AWS credentials are invalid or expired, the system clock "
            "of the Cloud Exchange host is skewed"
        )
        if is_bucket_call:
            return (
                f"Access denied to the {target}. The IAM role may be "
                "missing the 's3:ListBucket' permission, "
                f"{credentials_hint}, or the bucket policy denies access.",
                "Ensure that the 's3:ListBucket' permission on the bucket is "
                "granted to the IAM role used by the plugin, the "
                "credentials are valid and the system time is correct "
                "(NTP).",
            )
        return (
            f"Access denied to the {target}. The IAM role may be missing "
            "the 's3:GetObject' permission, the file does not exist and "
            "the role is missing the 's3:ListBucket' permission, or "
            f"{credentials_hint}.",
            "Ensure that 's3:GetObject' on the file and 's3:ListBucket' on "
            "the bucket are granted to the IAM role used by the plugin, "
            "the File Path is correct, the credentials are valid and the "
            "system time is correct (NTP).",
        )

    def map_error(
        self,
        error: Exception,
        operation: str,
        bucket: str,
        key: Optional[str] = None,
    ) -> AWSS3EDMException:
        """Map a boto3/botocore exception to a plugin exception.

        Args:
            error (Exception): The raised exception.
            operation (str): S3 operation name.
            bucket (str): Bucket name.
            key (Optional[str]): Object key.

        Returns:
            AWSS3EDMException: Exception to raise (already logged).
        """
        action = OPERATION_ACTIONS.get(operation, self.default_action)
        if isinstance(error, NoCredentialsError):
            return self._error(
                "No AWS credentials were found in the environment. Deploy "
                "the plugin into an AWS environment or use the AWS IAM "
                "Roles Anywhere authentication method.",
                "Ensure that Cloud Exchange is deployed on AWS with an IAM "
                "role attached or select the AWS IAM Roles Anywhere "
                "authentication method.",
                action=action,
            )
        if isinstance(error, PartialCredentialsError):
            return self._error(
                "The AWS credentials found in the environment are "
                f"incomplete. Error: {safe_error_text(error)}",
                "Ensure that the credentials provided by the host "
                "environment (IAM role or environment variables) are "
                "complete or use the AWS IAM Roles Anywhere method.",
                action=action,
            )
        if isinstance(error, CredentialRetrievalError):
            return self._error(
                "Unable to retrieve the AWS credentials from the "
                f"environment. Error: {safe_error_text(error)}",
                "Ensure that an IAM role is attached to the Cloud Exchange "
                "host and its credential provider (for example the "
                "instance metadata service) is reachable, or use the AWS "
                "IAM Roles Anywhere method.",
                action=action,
            )
        if isinstance(error, ClientError):
            err_response = error.response.get("Error", {})
            code = str(err_response.get("Code", ""))
            err_msg, resolution = self._describe_client_error(
                code, err_response.get("Message", ""), operation, bucket, key
            )
            if code in CHANGED_OBJECT_CODES:
                return ObjectChangedError(message=err_msg)
            return self._error(
                f"{err_msg} Error: {safe_error_text(error)}",
                resolution,
                action=action,
            )
        error_name = type(error).__name__
        if isinstance(error, BotoCoreError) and (
            error_name == "ParamValidationError"
        ):
            return self._error(
                "The bucket name or file path is not valid for AWS S3. "
                f"Error: {safe_error_text(error)}",
                "Ensure that the AWS S3 Bucket Name and the File Path are "
                "valid.",
                action="validating the AWS S3 bucket",
            )
        if isinstance(error, BotoCoreError) and error_name in (
            "IncompleteReadError",
            "ResponseStreamingError",
        ):
            return self._error(
                "The download was interrupted before the whole range was "
                f"received. Error: {safe_error_text(error)}",
                "Ensure that the connection between the Cloud Exchange "
                "host and AWS S3 is stable and run the pull again.",
                action="downloading the file",
            )
        if isinstance(error, BotoCoreError):
            return self._error(
                f"Unable to connect to AWS S3 ({operation}). Error: "
                f"{safe_error_text(error)}",
                "Ensure that the Cloud Exchange host can reach AWS S3 "
                "directly or through the configured proxy.",
                action=action,
            )
        return self._error(
            f"An unexpected error occurred while performing {operation} "
            "on AWS S3.",
            "Ensure that the AWS configuration is valid, refer to the "
            "error details in the logs.",
            action=action,
        )

    def call(
        self,
        operation: str,
        method,
        bucket: str,
        key: Optional[str] = None,
        **kwargs,
    ):
        """Call a boto3 method and map its errors to plugin exceptions.

        Args:
            operation (str): S3 operation name used in messages.
            method: The boto3 client method.
            bucket (str): Bucket name.
            key (Optional[str]): Object key.
            **kwargs: Arguments for the boto3 method.

        Raises:
            AWSS3EDMException: On any error.

        Returns:
            Any: Response of the boto3 method.
        """
        try:
            return method(**kwargs)
        except AWSS3EDMException:
            raise
        except Exception as error:
            raise self.map_error(error, operation, bucket, key) from error

    def verify_bucket_region(
        self, client, bucket: str, region: str
    ) -> None:
        """Verify that the bucket resides in the configured region.

        The check is skipped when ``s3:GetBucketLocation`` is denied.

        Args:
            client: boto3 S3 client.
            bucket (str): Bucket name.
            region (str): Configured region.

        Raises:
            AWSS3EDMException: On a region mismatch or S3 errors.
        """
        try:
            location = client.get_bucket_location(Bucket=bucket)
        except ClientError as error:
            code = str(error.response.get("Error", {}).get("Code", ""))
            if code in ACCESS_DENIED_CODES:
                self.logger.info(
                    f"{self.log_prefix}: Skipping the region verification "
                    f"of bucket '{bucket}' as the 's3:GetBucketLocation' "
                    "permission is not granted, the region was not "
                    "verified."
                )
                return
            raise self.map_error(
                error, "get_bucket_location", bucket
            ) from error
        except Exception as error:
            raise self.map_error(
                error, "get_bucket_location", bucket
            ) from error
        bucket_region = location.get("LocationConstraint") or "us-east-1"
        if bucket_region == "EU":
            bucket_region = "eu-west-1"
        if bucket_region != region:
            raise self._error(
                f"AWS S3 bucket '{bucket}' is in region '{bucket_region}', "
                f"not in the configured region '{region}'.",
                "Ensure that the AWS S3 Bucket Region in the plugin "
                "configuration is the region in which the bucket resides.",
                details=f"Bucket region: {bucket_region}.",
                action="validating the AWS S3 bucket region",
            )

    def get_object_info(self, client, bucket: str, key: str) -> dict:
        """Get the metadata of the S3 object using HeadObject.

        Args:
            client: boto3 S3 client.
            bucket (str): Bucket name.
            key (str): Object key.

        Returns:
            dict: Object metadata.
        """
        response = self.call(
            "head_object",
            client.head_object,
            bucket,
            key,
            Bucket=bucket,
            Key=key,
        )
        return {
            "content_length": int(response.get("ContentLength") or 0),
            "etag": response.get("ETag"),
            "storage_class": response.get("StorageClass") or "STANDARD",
            "restore": response.get("Restore"),
            "archive_status": response.get("ArchiveStatus"),
        }

    def _check_storage_class(self, info: dict, key: str) -> None:
        """Ensure the object is not archived without a completed restore.

        Args:
            info (dict): Object metadata.
            key (str): Object key.

        Raises:
            AWSS3EDMException: If the object cannot be read.
        """
        restore = info.get("restore") or ""
        is_archived = (
            info.get("storage_class") in GLACIER_STORAGE_CLASSES
            or info.get("archive_status") in ARCHIVE_ACCESS_TIERS
        )
        if not is_archived or 'ongoing-request="false"' in restore:
            return
        if 'ongoing-request="true"' in restore:
            err_msg = (
                f"The restore of the archived file path '{key}' is still in "
                "progress."
            )
            resolution = (
                "Ensure that the restore request is completed before "
                "using the file."
            )
        else:
            err_msg = (
                f"The file path '{key}' is archived (Glacier/Deep Archive) "
                "and has not been restored."
            )
            resolution = (
                "Ensure that the file is restored from the archive tier "
                "and try again."
            )
        raise self._error(
            err_msg,
            resolution,
            details=err_msg,
            action="validating the file path",
        )

    def validate_object_info(self, info: dict, key: str) -> None:
        """Validate the object metadata (TDD 6.2 steps 5, 6 and 8).

        Args:
            info (dict): Object metadata.
            key (str): Object key.

        Raises:
            AWSS3EDMException: If the object is not usable.
        """
        if key.endswith("/"):
            raise self._error(
                f"The File Path '{key}' is a folder, not a file.",
                "Ensure that the File Path is the exact path of a file in "
                "the bucket.",
                details=f"File path: {key}",
                action="validating the file path",
            )
        size = info.get("content_length", 0)
        if size <= 0:
            raise self._error(
                f"The file path '{key}' is empty.",
                "Ensure that the file contains a header row and at least "
                "one record.",
                details=f"File size: {size} bytes.",
                action="validating the file path",
            )
        self._check_storage_class(info, key)
        if get_object_format(key) == FORMAT_PLAIN:
            return
        if size > MAX_COMPRESSED_SIZE:
            raise self._error(
                f"The size of the file path '{key}' ({format_size(size)}) "
                f"exceeds the maximum supported size of "
                f"{format_size(MAX_COMPRESSED_SIZE)} for compressed "
                "files.",
                "Ensure that the file is smaller than the supported size or "
                "split it into smaller files.",
                details=(
                    f"File size: {size} bytes. "
                    f"Limit: {MAX_COMPRESSED_SIZE} bytes."
                ),
                action="validating the file path",
            )

    def validate_object(self, configuration: dict) -> dict:
        """Validate credentials, bucket, region and object (TDD 6.2).

        Args:
            configuration (dict): Step 1 configuration parameters.

        Raises:
            AWSS3EDMException: On the first failed check.

        Returns:
            dict: Metadata of the validated object.
        """
        bucket = configuration.get("bucket_name", "").strip()
        key = configuration.get("filepath", "").strip()
        region = get_effective_region(configuration)
        client = self.get_client(configuration)
        self.call(
            "head_bucket",
            client.head_bucket,
            bucket,
            Bucket=bucket,
        )
        self.verify_bucket_region(client, bucket, region)
        info = self.get_object_info(client, bucket, key)
        self.validate_object_info(info, key)
        self.logger.debug(
            f"{self.log_prefix}: Successfully validated the file path "
            f"'{key}' in the bucket '{bucket}'."
        )
        return info
