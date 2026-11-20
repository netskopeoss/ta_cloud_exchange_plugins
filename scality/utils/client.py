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


Scality Client Class.
"""

import re
from typing import Any, Dict, NoReturn, Optional

import boto3
from botocore.config import Config

from . import constants as CONST
from .credentials import ScalityCredentials
from .exceptions import (
    BucketNameAlreadyTaken,
    BucketNotFoundError,
    ScalityException,
)
from .helper import (
    build_object_key,
    describe_boto_error,
    log_and_raise,
    log_error,
)


class ScalityClient:
    """Scality client class."""

    def __init__(
        self,
        configuration: Dict,
        logger,
        proxy: Dict,
        log_prefix: str,
        user_agent: str,
    ) -> None:
        """Initialize ScalityClient.

        Args:
            configuration (dict): Plugin configuration parameters.
            logger: Cloud Exchange logger object.
            proxy (dict): Proxy configuration.
            log_prefix (str): Log prefix of the plugin configuration.
            user_agent (str): User agent sent with every request.
        """
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.log_prefix = log_prefix
        self.useragent = user_agent

    def _get_region_name(self, endpoint_url: Any) -> Optional[str]:
        """Extract the AWS region from an AWS style endpoint URL.

        A Scality endpoint URL does not match the pattern, so no region
        is sent to boto3 - the behaviour of version 1.0.0.

        Args:
            endpoint_url (str): Configured endpoint URL.

        Returns:
            Optional[str]: The region name, or None.
        """
        if not isinstance(endpoint_url, str):
            return None
        region_name = re.search(CONST.EXTRACT_AWS_REGION_REGEX, endpoint_url)
        return region_name.group(1) if region_name else None

    def _raise_boto_error(
        self, error: BaseException, action: str, resolution: str
    ) -> NoReturn:
        """Log a boto3 failure and raise ``ScalityException``.

        The resolution of the error itself wins over the one of the
        caller, so a connection failure is never reported with a
        credentials resolution.

        Args:
            error (BaseException): The error raised by boto3.
            action (str): What was being done.
            resolution (str): Resolution used when the error says
                nothing more specific; starts with ``Ensure that``.

        Raises:
            ScalityException: Always.
        """
        cause, mapped_resolution = describe_boto_error(error)
        log_and_raise(
            self.logger,
            self.log_prefix,
            action,
            mapped_resolution or resolution,
            cause=cause,
        )

    def get_aws_resource(self) -> Any:
        """Create the Scality S3 resource object.

        Returns:
            boto3 resource: The S3 resource object.

        Raises:
            ScalityException: When the resource cannot be created.
        """
        action = f"creating the {CONST.PLATFORM_NAME} resource object"
        resolution = (
            f"Ensure that the {CONST.PLATFORM_NAME} Endpoint URL, Access Key"
            " and Secret Access Key provided in the configuration"
            " parameters are correct."
        )
        try:
            endpoint_url, access_key, secret_access_key, _ = (
                ScalityCredentials.get_credentials(self.configuration)
            )
            region_name = self._get_region_name(endpoint_url)
            retries = {
                "max_attempts": CONST.VALIDATION_MAX_RETRIES,
                "mode": CONST.RETRY_MODE,
            }
            config = Config(
                proxies=self.proxy,
                user_agent=self.useragent,
                retries=retries,
            )
            if region_name and region_name in CONST.REGIONS:
                return boto3.resource(
                    CONST.S3_SERVICE_NAME,
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_access_key,
                    endpoint_url=endpoint_url,
                    region_name=region_name,
                    config=config,
                )
            return boto3.resource(
                CONST.S3_SERVICE_NAME,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_access_key,
                endpoint_url=endpoint_url,
                config=config,
            )
        except Exception as exp:
            self._raise_boto_error(exp, action, resolution)

    def get_aws_client(
        self, validation_retries: Optional[int] = None
    ) -> Any:
        """Create the Scality S3 client object.

        Args:
            validation_retries (Optional[int]): Retry count used during
                validation.

        Returns:
            boto3 client: The S3 client object.

        Raises:
            ScalityException: When the client cannot be created.
        """
        action = f"creating the {CONST.PLATFORM_NAME} client object"
        resolution = (
            f"Ensure that the {CONST.PLATFORM_NAME} Endpoint URL, Access Key"
            " and Secret Access Key provided in the configuration"
            " parameters are correct."
        )
        try:
            endpoint_url, access_key, secret_access_key, _ = (
                ScalityCredentials.get_credentials(self.configuration)
            )
            region_name = self._get_region_name(endpoint_url)
            retries = {
                "max_attempts": (
                    validation_retries
                    if validation_retries is not None
                    else CONST.MAX_RETRIES
                ),
                "mode": CONST.RETRY_MODE,
            }
            config = Config(
                proxies=self.proxy,
                user_agent=self.useragent,
                read_timeout=CONST.READ_TIMEOUT,
                retries=retries,
            )
            if region_name and region_name in CONST.REGIONS:
                return boto3.client(
                    CONST.S3_SERVICE_NAME,
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_access_key,
                    endpoint_url=endpoint_url,
                    region_name=region_name,
                    config=config,
                )
            return boto3.client(
                CONST.S3_SERVICE_NAME,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_access_key,
                endpoint_url=endpoint_url,
                config=config,
            )
        except Exception as exp:
            self._raise_boto_error(exp, action, resolution)

    def is_bucket_exists(
        self,
        s3_client: Any,
        bucket_name: str,
        region_name: Optional[str],
    ) -> bool:
        """Check whether the configured bucket exists on Scality.

        Args:
            s3_client: Scality S3 client object.
            bucket_name (str): Configured bucket name.
            region_name (Optional[str]): Region of an AWS style
                endpoint URL.

        Returns:
            bool: True when the bucket exists.

        Raises:
            BucketNotFoundError: When the bucket does not exist on a
                Scality endpoint.
            BucketNameAlreadyTaken: When the bucket exists in another
                region of an AWS style endpoint.
            ScalityException: On any other failure.
        """
        action = f"verifying {CONST.PLATFORM_NAME} Bucket '{bucket_name}'"
        try:
            buckets = s3_client.list_buckets().get(CONST.BUCKETS_KEY, [])
            if region_name and region_name in CONST.REGIONS:
                for bucket in buckets:
                    if bucket_name != bucket.get(CONST.BUCKET_NAME_KEY, ""):
                        continue
                    bucket_location = s3_client.get_bucket_location(
                        Bucket=bucket.get(CONST.BUCKET_NAME_KEY, "")
                    )[CONST.LOCATION_CONSTRAINT_KEY]
                    if bucket_location is None:
                        bucket_location = CONST.DEFAULT_REGION
                    if str(region_name) == str(bucket_location):
                        return True
                    raise BucketNameAlreadyTaken(
                        log_error(
                            self.logger,
                            self.log_prefix,
                            action,
                            (
                                "Ensure that the Endpoint URL points to"
                                " the region where the bucket exists,"
                                " or provide a different Bucket Name."
                            ),
                            cause=(
                                f"The bucket exists in region"
                                f" '{bucket_location}' and not in region"
                                f" '{region_name}'."
                            ),
                        )
                    )
                return False
            for bucket in buckets:
                if bucket_name == bucket.get(CONST.BUCKET_NAME_KEY, ""):
                    return True
            raise BucketNotFoundError(
                log_error(
                    self.logger,
                    self.log_prefix,
                    action,
                    (
                        "Ensure that the bucket exists on"
                        f" {CONST.PLATFORM_NAME} and that the Bucket Name"
                        " provided in the configuration parameters is"
                        " correct."
                    ),
                    cause=(
                        f"The bucket does not exist on {CONST.PLATFORM_NAME}."
                    ),
                )
            )
        except ScalityException:
            raise
        except Exception as exp:
            self._raise_boto_error(
                exp,
                action,
                (
                    "Ensure that the user has permission to list the"
                    f" buckets of the {CONST.PLATFORM_NAME} instance."
                ),
            )

    def get_bucket(
        self, validation_retries: Optional[int] = None
    ) -> Optional[Dict]:
        """Return the configured bucket, creating it when possible.

        A bucket is created only for an AWS style endpoint URL, exactly
        as in version 1.0.0. On a Scality endpoint a missing bucket
        raises ``BucketNotFoundError``.

        Args:
            validation_retries (Optional[int]): Retry count used during
                validation.

        Returns:
            dict: The created bucket, or None when the bucket exists.

        Raises:
            ScalityException: When the bucket cannot be verified or
                created.
        """
        endpoint_url, _, _, bucket_name = (
            ScalityCredentials.get_credentials(self.configuration)
        )
        action = (
            f"getting or creating {CONST.PLATFORM_NAME} Bucket"
            f" '{bucket_name}'"
        )
        try:
            s3_client = self.get_aws_client(
                validation_retries=validation_retries
            )
            region_name = self._get_region_name(endpoint_url)

            if self.is_bucket_exists(s3_client, bucket_name, region_name):
                return None

            self.logger.info(
                f"{self.log_prefix}: The bucket provided in the"
                f" configuration parameters does not exist on"
                f" {CONST.PLATFORM_NAME} hence creating bucket:"
                f" {bucket_name}."
            )
            if region_name == CONST.DEFAULT_REGION:
                return s3_client.create_bucket(Bucket=bucket_name)
            return s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    CONST.LOCATION_CONSTRAINT_KEY: region_name
                },
            )
        except ScalityException:
            raise
        except Exception as exp:
            self._raise_boto_error(
                exp,
                action,
                (
                    "Ensure that the user has permission to create"
                    " buckets and that the Bucket Name is unique."
                ),
            )

    def push(self, file_name: str, data_type: str, subtype: str) -> str:
        """Upload a local object file to the Scality bucket.

        Args:
            file_name (str): Local path of the file to upload.
            data_type (str): Data type - ``alerts``, ``events`` or
                ``webtx``.
            subtype (str): Subtype of the pushed logs.

        Returns:
            str: The object key the file was uploaded to.

        Raises:
            ScalityException: When the upload fails.
        """
        _, _, _, bucket_name = ScalityCredentials.get_credentials(
            self.configuration
        )
        object_name = build_object_key(data_type, subtype)
        try:
            s3_client = self.get_aws_client()
            s3_client.upload_file(
                file_name,
                bucket_name,
                object_name,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully uploaded log(s) to"
                f" {CONST.PLATFORM_NAME} Bucket {bucket_name} as object file."
                f" Object File Name: {object_name}"
            )
            return object_name
        except ScalityException:
            raise
        except Exception as exp:
            self._raise_boto_error(
                exp,
                (
                    f"uploading the object file to {CONST.PLATFORM_NAME}"
                    f" Bucket '{bucket_name}'. Object:"
                    f" '{object_name}'"
                ),
                (
                    "Ensure that the bucket exists, that the user has"
                    " permission to put objects in it and that"
                    f" {CONST.PLATFORM_NAME} is reachable from Cloud"
                    " Exchange."
                ),
            )
