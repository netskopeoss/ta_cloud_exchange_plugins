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

AWS S3 WebTx client: credentials, boto3 clients, bucket checks and upload.
"""

import datetime
import hashlib
from typing import Any, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError

from . import constants as CONST
from .generate_temp_creds import (
    AWSS3GenerateTemporaryCredentials,
    has_required_credentials,
)
from .helper import (
    build_object_key,
    get_effective_region,
    log_and_raise,
    normalize_externally_provisioned,
    safe_error_text,
)


class AWSS3WebTxClient:
    """AWS S3 WebTx client."""

    def __init__(
        self,
        configuration: dict,
        logger: Any,
        proxy: Optional[dict],
        storage: Optional[dict],
        log_prefix: str,
        user_agent: str,
        ssl_validation: bool = True,
    ) -> None:
        """Initialize the client.

        Args:
            configuration (dict): Plugin configuration parameters.
            logger: CE logger object.
            proxy (Optional[dict]): CE proxy settings.
            storage (Optional[dict]): Storage used to cache the Roles
                Anywhere temporary credentials (updated in place).
            log_prefix (str): Log prefix.
            user_agent (str): User agent string.
            ssl_validation (bool): CE SSL validation setting.
        """
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.storage = storage
        self.log_prefix = log_prefix
        self.user_agent = user_agent
        self.ssl_validation = ssl_validation
        self.aws_access_key_id = None
        self.aws_secret_access_key = None
        self.aws_session_token = None

    def _get_proxies(self) -> dict:
        """Get the proxy settings without empty entries.

        Returns:
            dict: Proxy URLs keyed by scheme.
        """
        return {
            scheme: url
            for scheme, url in (self.proxy or {}).items()
            if url
        }

    def _get_verify(self) -> bool:
        """Get the SSL validation setting (True unless it is False).

        Returns:
            bool: Value of ``verify`` for boto3 and requests.
        """
        value = self.ssl_validation
        return value if isinstance(value, bool) else True

    def _get_credentials_fingerprint(self) -> str:
        """Fingerprint the configuration the credentials were created for.

        The private key and the Password Phrase are not part of it.

        Returns:
            str: SHA-256 hex digest.
        """
        certificate = self.configuration.get(CONST.PUBLIC_CERTIFICATE_FILE_KEY)
        certificate = certificate if isinstance(certificate, str) else ""
        parts = [
            str(self.configuration.get(key) or "").strip()
            for key in (
                CONST.PROFILE_ARN_KEY,
                CONST.ROLE_ARN_KEY,
                CONST.TRUST_ANCHOR_ARN_KEY,
            )
        ]
        parts.append(get_effective_region(self.configuration))
        parts.append(
            hashlib.sha256(
                certificate.strip().encode(CONST.TEXT_ENCODING)
            ).hexdigest()
        )
        return hashlib.sha256(
            CONST.FINGERPRINT_SEPARATOR.join(parts).encode(CONST.TEXT_ENCODING)
        ).hexdigest()

    @staticmethod
    def _is_expiring(
        credentials: dict, now: Optional[datetime.datetime] = None
    ) -> bool:
        """Check whether temporary credentials are expired or expiring.

        Args:
            credentials (dict): Cached temporary credentials.
            now (Optional[datetime.datetime]): Current UTC time.

        Returns:
            bool: True when the expiry is missing or invalid, or fewer than
                ``CREDENTIAL_REFRESH_MINUTES`` minutes remain.
        """
        expiration = credentials.get(CONST.EXPIRATION_KEY)
        if not expiration:
            return True
        try:
            expires_at = datetime.datetime.fromisoformat(
                str(expiration).replace(
                    CONST.ISO_UTC_SUFFIX, CONST.ISO_UTC_OFFSET
                )
            )
        except ValueError:
            return True
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        now = now or datetime.datetime.now(datetime.timezone.utc)
        threshold = now + datetime.timedelta(
            minutes=CONST.CREDENTIAL_REFRESH_MINUTES
        )
        return expires_at <= threshold

    def set_credentials(self) -> None:
        """Set the AWS credentials used by the boto3 clients.

        Deployed on AWS uses the boto3 default credential chain. AWS IAM
        Roles Anywhere reuses the cached temporary credentials, or creates
        new ones when they are missing, incomplete, expire in fewer than 3
        minutes or were created for a different configuration. The storage
        is updated in place. Roles Anywhere never falls back to the boto3
        default credential chain.

        Raises:
            AWSS3WebTxException: When temporary credentials cannot be
                generated (already logged).
        """
        if (
            self.configuration.get(CONST.AUTHENTICATION_METHOD_KEY)
            != CONST.AUTH_ROLES_ANYWHERE
        ):
            return
        store = self.storage if isinstance(self.storage, dict) else {}
        fingerprint = self._get_credentials_fingerprint()
        credentials = store.get(CONST.CREDENTIALS_KEY)
        if (
            has_required_credentials(credentials)
            and store.get(CONST.CREDENTIALS_FINGERPRINT_KEY) == fingerprint
            and not self._is_expiring(credentials)
        ):
            self.logger.debug(
                f"{self.log_prefix}: Reusing the cached temporary "
                "credentials of AWS IAM Roles Anywhere."
            )
        else:
            credentials = AWSS3GenerateTemporaryCredentials(
                self.configuration,
                self.logger,
                self._get_proxies(),
                self.log_prefix,
                self.user_agent,
                self._get_verify(),
            ).generate_temporary_credentials()
            store[CONST.CREDENTIALS_KEY] = credentials
            store[CONST.CREDENTIALS_FINGERPRINT_KEY] = fingerprint
            self.logger.debug(
                f"{self.log_prefix}: Generated new temporary credentials "
                "using AWS IAM Roles Anywhere."
            )
        self.aws_access_key_id = credentials.get(CONST.ACCESS_KEY_ID_KEY)
        self.aws_secret_access_key = credentials.get(
            CONST.SECRET_ACCESS_KEY_KEY
        )
        self.aws_session_token = credentials.get(CONST.SESSION_TOKEN_KEY)

    def _get_client_kwargs(self) -> dict:
        """Build the keyword arguments of ``boto3.client``.

        Returns:
            dict: Region, SSL verification, botocore Config (proxy, user
                agent, retries, timeouts) and credentials when set.
        """
        client_kwargs = dict(
            region_name=get_effective_region(self.configuration),
            verify=self._get_verify(),
            config=Config(
                proxies=self._get_proxies() or None,
                user_agent=self.user_agent,
                connect_timeout=CONST.BOTO_CONNECT_TIMEOUT,
                read_timeout=CONST.BOTO_READ_TIMEOUT,
                retries=dict(
                    total_max_attempts=CONST.BOTO_MAX_ATTEMPTS,
                    mode=CONST.BOTO_RETRY_MODE,
                ),
            ),
        )
        if self.aws_access_key_id:
            client_kwargs.update(
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                aws_session_token=self.aws_session_token,
            )
        return client_kwargs

    def _create_boto_client(self, service: str) -> Any:
        """Create a boto3 client.

        Args:
            service (str): AWS service name (``s3`` or ``sts``).

        Raises:
            AWSS3WebTxException: When the client cannot be created.

        Returns:
            botocore.client.BaseClient: The boto3 client.
        """
        try:
            return boto3.client(service, **self._get_client_kwargs())
        except Exception as err:
            log_and_raise(
                self.logger,
                self.log_prefix,
                f"creating the AWS {service.upper()} client",
                "Ensure that the AWS S3 Bucket Region Name (or AWS Custom "
                "Region) is correct.",
                cause=safe_error_text(err),
                details=safe_error_text(err),
                err=err,
            )

    def get_aws_client(self) -> Any:
        """Create the boto3 S3 client.

        Returns:
            botocore.client.S3: The S3 client.
        """
        return self._create_boto_client(CONST.S3_SERVICE)

    def get_aws_sts_client(self) -> Any:
        """Create the boto3 STS client (ownership check only).

        Returns:
            botocore.client.STS: The STS client.
        """
        return self._create_boto_client(CONST.STS_SERVICE)

    def _raise_no_credentials(self, err: BaseException) -> None:
        """Log and raise that no AWS credentials were found.

        Args:
            err (BaseException): The NoCredentialsError.

        Raises:
            AWSS3WebTxException: Always.
        """
        log_and_raise(
            self.logger,
            self.log_prefix,
            "loading AWS credentials",
            "Ensure that the plugin is deployed on AWS with an IAM role "
            "attached, or use the 'AWS IAM Roles Anywhere' authentication "
            "method.",
            cause="No AWS credentials were found in the environment.",
            details=safe_error_text(err),
            err=err,
        )

    def _raise_bucket_error(
        self,
        bucket: str,
        err: BaseException,
        action: Optional[str] = None,
    ) -> None:
        """Log and raise an unexpected AWS S3 error.

        Args:
            bucket (str): Bucket name.
            err (BaseException): Original error.
            action (Optional[str]): What was being done.

        Raises:
            AWSS3WebTxException: Always.
        """
        log_and_raise(
            self.logger,
            self.log_prefix,
            action or f"verifying AWS S3 Bucket '{bucket}'",
            CONST.BUCKET_CHECK_RESOLUTION,
            cause=safe_error_text(err),
            details=safe_error_text(err),
            err=err,
        )

    @staticmethod
    def _error_code(err: BaseException) -> str:
        """Get the error code of a botocore ClientError.

        Args:
            err (BaseException): The error.

        Returns:
            str: Error code, empty when unavailable.
        """
        response = getattr(err, "response", None) or {}
        error = response.get(CONST.ERROR_KEY, {})
        return str(error.get(CONST.ERROR_CODE_KEY, ""))

    def is_bucket_exists(self, s3_client: Any, bucket: str, ep: str) -> bool:
        """Check whether the bucket exists using HeadBucket.

        Args:
            s3_client: boto3 S3 client.
            bucket (str): Bucket name.
            ep (str): Externally Provisioned Bucket value (yes/no).

        Raises:
            AWSS3WebTxException: On access denied or unexpected errors.

        Returns:
            bool: True when the bucket is accessible, False when it does
                not exist (404).
        """
        try:
            s3_client.head_bucket(Bucket=bucket)
            return True
        except NoCredentialsError as err:
            self._raise_no_credentials(err)
        except ClientError as err:
            code = self._error_code(err)
            if code in CONST.NOT_FOUND_CODES:
                return False
            if code in CONST.ACCESS_DENIED_CODES:
                if ep == CONST.EP_YES:
                    cause = (
                        "Access denied. The bucket is configured as "
                        "externally provisioned, so this is most likely a "
                        "missing cross-account permission."
                    )
                    resolution = (
                        "Ensure that the external AWS account's bucket "
                        "policy grants this IAM role s3:ListBucket, "
                        "s3:GetBucketLocation and s3:PutObject permissions "
                        "on the bucket."
                    )
                else:
                    cause = (
                        "Access denied. The bucket name may already be "
                        "taken by another AWS account, or the IAM role "
                        "does not have access to the bucket."
                    )
                    resolution = (
                        "Ensure that the bucket name is globally unique "
                        "(not owned by another AWS account), and that the "
                        "IAM role has s3:ListBucket, s3:GetBucketLocation "
                        "and s3:PutObject permissions on the bucket and "
                        "s3:CreateBucket permission so that the plugin can "
                        "create the bucket when it does not exist."
                    )
                log_and_raise(
                    self.logger,
                    self.log_prefix,
                    f"accessing AWS S3 Bucket '{bucket}'",
                    resolution,
                    cause=cause,
                    details=safe_error_text(err),
                    err=err,
                )
            self._raise_bucket_error(bucket, err)
        except Exception as err:
            self._raise_bucket_error(bucket, err)

    def _get_own_account_id(self, bucket: str) -> Optional[str]:
        """Get the AWS account id of the credentials.

        Args:
            bucket (str): Bucket name (for messages).

        Raises:
            AWSS3WebTxException: On unexpected STS errors.

        Returns:
            Optional[str]: The account id, or None when
                ``sts:GetCallerIdentity`` is denied.
        """
        sts_client = self.get_aws_sts_client()
        try:
            return sts_client.get_caller_identity().get(CONST.ACCOUNT_KEY)
        except NoCredentialsError as err:
            self._raise_no_credentials(err)
        except ClientError as err:
            if self._error_code(err) in CONST.ACCESS_DENIED_CODES:
                self.logger.debug(
                    f"{self.log_prefix}: Skipping the ownership check of "
                    f"AWS S3 Bucket '{bucket}' as sts:GetCallerIdentity is "
                    "not permitted. The configured 'Externally Provisioned "
                    "Bucket' value is trusted."
                )
                return None
            self._raise_bucket_error(
                bucket, err, "verifying AWS S3 Bucket ownership"
            )
        except Exception as err:
            self._raise_bucket_error(
                bucket, err, "verifying AWS S3 Bucket ownership"
            )

    def _verify_bucket_ownership(
        self, s3_client: Any, bucket: str, ep: str
    ) -> None:
        """Check that the bucket owner matches Externally Provisioned Bucket.

        HeadBucket is run again with ``ExpectedBucketOwner`` set to the own
        account id: AWS returns 403 when another account owns the bucket.

        Args:
            s3_client: boto3 S3 client.
            bucket (str): Bucket name.
            ep (str): Externally Provisioned Bucket value (yes/no).

        Raises:
            AWSS3WebTxException: On an ownership mismatch or errors.
        """
        own_account_id = self._get_own_account_id(bucket)
        if not own_account_id:
            return
        try:
            s3_client.head_bucket(
                Bucket=bucket, ExpectedBucketOwner=own_account_id
            )
            is_own_account = True
        except NoCredentialsError as err:
            self._raise_no_credentials(err)
        except ClientError as err:
            if self._error_code(err) not in CONST.ACCESS_DENIED_CODES:
                self._raise_bucket_error(
                    bucket, err, "verifying AWS S3 Bucket ownership"
                )
            is_own_account = False
        except Exception as err:
            self._raise_bucket_error(
                bucket, err, "verifying AWS S3 Bucket ownership"
            )
        if ep == CONST.EP_NO and not is_own_account:
            log_and_raise(
                self.logger,
                self.log_prefix,
                "verifying AWS S3 Bucket ownership",
                "Ensure that 'Externally Provisioned Bucket' is set to "
                "'Yes', or provide a bucket owned by your AWS account.",
                cause=(
                    f"Bucket '{bucket}' belongs to a different AWS account "
                    "but 'Externally Provisioned Bucket' is set to 'No'."
                ),
            )
        if ep == CONST.EP_YES and is_own_account:
            log_and_raise(
                self.logger,
                self.log_prefix,
                "verifying AWS S3 Bucket ownership",
                "Ensure that 'Externally Provisioned Bucket' is set to "
                "'No', or provide a bucket owned by the external AWS "
                "account.",
                cause=(
                    f"Bucket '{bucket}' belongs to your AWS account but "
                    "'Externally Provisioned Bucket' is set to 'Yes'."
                ),
            )

    def _create_bucket(self, s3_client: Any, bucket: str, region: str) -> None:
        """Create the bucket in the effective region.

        Args:
            s3_client: boto3 S3 client.
            bucket (str): Bucket name.
            region (str): Effective region.

        Raises:
            AWSS3WebTxException: When the bucket cannot be created.
        """
        try:
            if region == CONST.DEFAULT_REGION:
                s3_client.create_bucket(Bucket=bucket)
            else:
                s3_client.create_bucket(
                    Bucket=bucket,
                    CreateBucketConfiguration={
                        CONST.LOCATION_CONSTRAINT_KEY: region
                    },
                )
        except NoCredentialsError as err:
            self._raise_no_credentials(err)
        except ClientError as err:
            if self._error_code(err) in CONST.BUCKET_OWNED_CODES:
                self.logger.debug(
                    f"{self.log_prefix}: AWS S3 Bucket '{bucket}' already "
                    "exists in your AWS account."
                )
                return
            self._raise_create_error(bucket, err)
        except Exception as err:
            self._raise_create_error(bucket, err)
        self.logger.debug(
            f"{self.log_prefix}: Created AWS S3 Bucket '{bucket}' in the "
            f"region '{region}'."
        )

    def _raise_create_error(self, bucket: str, err: BaseException) -> None:
        """Log and raise that the bucket could not be created.

        Args:
            bucket (str): Bucket name.
            err (BaseException): Original error.

        Raises:
            AWSS3WebTxException: Always.
        """
        log_and_raise(
            self.logger,
            self.log_prefix,
            f"creating AWS S3 Bucket '{bucket}'",
            "Ensure that the IAM role has s3:CreateBucket permission and the "
            "bucket name is globally unique.",
            cause=safe_error_text(err),
            details=safe_error_text(err),
            err=err,
        )

    def _verify_bucket_region(
        self, s3_client: Any, bucket: str, region: str
    ) -> None:
        """Check that the bucket is in the effective region.

        The check is skipped with a debug log when s3:GetBucketLocation is
        not granted.

        Args:
            s3_client: boto3 S3 client.
            bucket (str): Bucket name.
            region (str): Effective region.

        Raises:
            AWSS3WebTxException: On a region mismatch or errors.
        """
        try:
            location = s3_client.get_bucket_location(Bucket=bucket)
        except NoCredentialsError as err:
            self._raise_no_credentials(err)
        except ClientError as err:
            if self._error_code(err) in CONST.ACCESS_DENIED_CODES:
                self.logger.debug(
                    f"{self.log_prefix}: Skipping the region check of AWS "
                    f"S3 Bucket '{bucket}' as s3:GetBucketLocation is not "
                    "permitted."
                )
                return
            self._raise_bucket_error(
                bucket, err, "verifying AWS S3 Bucket region"
            )
        except Exception as err:
            self._raise_bucket_error(
                bucket, err, "verifying AWS S3 Bucket region"
            )
        bucket_region = (location or {}).get(
            CONST.LOCATION_CONSTRAINT_KEY
        ) or CONST.DEFAULT_REGION
        if bucket_region != region:
            log_and_raise(
                self.logger,
                self.log_prefix,
                "verifying AWS S3 Bucket region",
                "Ensure that the AWS S3 Bucket Region Name (or AWS Custom "
                f"Region) is set to '{bucket_region}'.",
                cause=(
                    f"Bucket '{bucket}' is in region '{bucket_region}', not "
                    f"'{region}'."
                ),
            )

    def verify_bucket_exists(self) -> bool:
        """Verify the bucket (validation only; never called by push).

        * HeadBucket 200: ownership check, then region check.
        * HeadBucket 404: Externally Provisioned Bucket ``yes`` is an error
          (the bucket is never created); ``no`` creates the bucket in the
          effective region, then checks the region.
        * HeadBucket 403: access denied error.

        Raises:
            AWSS3WebTxException: On any failure (already logged).

        Returns:
            bool: True when the bucket can be used.
        """
        bucket = (self.configuration.get(CONST.BUCKET_NAME_KEY) or "").strip()
        region = get_effective_region(self.configuration)
        ep = normalize_externally_provisioned(
            self.configuration.get(CONST.EXTERNALLY_PROVISIONED_BUCKET_KEY)
        )
        s3_client = self.get_aws_client()
        if self.is_bucket_exists(s3_client, bucket, ep):
            self._verify_bucket_ownership(s3_client, bucket, ep)
        elif ep == CONST.EP_YES:
            log_and_raise(
                self.logger,
                self.log_prefix,
                f"verifying AWS S3 Bucket '{bucket}'",
                "Ensure that the bucket is created in the external AWS "
                "account and the IAM role is granted access to it.",
                cause=(
                    "The bucket does not exist or is not accessible from "
                    "the external account."
                ),
            )
        else:
            self._create_bucket(s3_client, bucket, region)
        self._verify_bucket_region(s3_client, bucket, region)
        return True

    def push(
        self,
        file_name: str,
        subtype: Optional[str],
    ) -> str:
        """Upload a local gzip file to the bucket.

        The bucket is neither checked nor created here.

        Args:
            file_name (str): Path of the local gzip file.
            subtype (Optional[str]): Subtype received by push.

        Raises:
            AWSS3WebTxException: When the upload fails (already logged).

        Returns:
            str: The object key.
        """
        bucket = (self.configuration.get(CONST.BUCKET_NAME_KEY) or "").strip()
        key = build_object_key(subtype)
        s3_client = self.get_aws_client()
        try:
            s3_client.upload_file(file_name, bucket, key)
        except NoCredentialsError as err:
            self._raise_no_credentials(err)
        except Exception as err:
            log_and_raise(
                self.logger,
                self.log_prefix,
                f"uploading WebTx logs to AWS S3 Bucket '{bucket}'",
                "Ensure that the bucket exists, the IAM role has "
                "s3:PutObject (and kms:GenerateDataKey for SSE-KMS) "
                "permission, and the CE host can reach AWS S3.",
                cause=f"{safe_error_text(err).rstrip('.')}. Object: '{key}'.",
                details=safe_error_text(err),
                err=err,
            )
        self.logger.debug(
            f"{self.log_prefix}: Uploaded object '{key}' to AWS S3 Bucket "
            f"'{bucket}'."
        )
        return key
