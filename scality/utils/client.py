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
import boto3
import traceback
import threading
from botocore.exceptions import ClientError, ReadTimeoutError
from boto3.exceptions import S3UploadFailedError
from datetime import datetime
from botocore.config import Config

from .credentials import (
    ScalityCredentials,
)
from .exception import ScalityException
from .constants import (
    REGIONS,
    EXTRACT_AWS_REGION_REGEX,
    VALIDATION_MAX_RETRIES,
    MAX_RETRIES,
    READ_TIMEOUT,
    PLUGIN_NAME,
)


class BucketNameAlreadyTaken(Exception):
    pass


class BucketNotFoundError(Exception):
    pass


class ScalityClient:
    """Scality Client Class."""

    def __init__(self, configuration, logger, proxy, log_prefix, user_agent):
        """Init method.

        Args:
            configuration: the configuration object.
            logger: the logger object.
            proxy: the proxy object.
            log_prefix: the log prefix.
            user_agent: the user agent.
        """
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.log_prefix = log_prefix
        self.useragent = user_agent

    def get_aws_resource(self):
        """To get scality resource."""
        try:
            region_name = None
            s3_resource = None
            endpoint_url, access_key, secret_access_key, _ = (
                ScalityCredentials.get_credentials(self, self.configuration)
            )

            region_name = re.search(EXTRACT_AWS_REGION_REGEX, endpoint_url)

            if region_name:
                region_name = region_name.group(1)

            retries = {
                "max_attempts": VALIDATION_MAX_RETRIES,
                "mode": "standard",
            }

            if region_name and region_name in REGIONS:
                s3_resource = boto3.resource(
                    "s3",
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_access_key,
                    endpoint_url=endpoint_url,
                    region_name=region_name,
                    config=Config(
                        proxies=self.proxy,
                        user_agent=self.useragent,
                        retries=retries,
                    ),
                )
            else:
                s3_resource = boto3.resource(
                    "s3",
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_access_key,
                    endpoint_url=endpoint_url,
                    config=Config(
                        proxies=self.proxy,
                        user_agent=self.useragent,
                        retries=retries,
                    ),
                )
            return s3_resource
        except ReadTimeoutError as exp:
            err_msg = (
                "Read timeout error occurred while creating "
                f"{PLUGIN_NAME} resource object."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ScalityException(str(exp))
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
                raise ScalityException(err_msg)
            else:
                self.logger.error(
                    message=f"{self.log_prefix}: {str(error)}",
                    details=traceback.format_exc(),
                )
                raise ScalityException(str(error))
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {PLUGIN_NAME} resource object."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise ScalityException(err_msg)

    def get_aws_client(self, validation_retries=None):
        """To get scality client."""
        try:
            region_name = None
            s3_client = None
            endpoint_url, access_key, secret_access_key, _ = (
                ScalityCredentials.get_credentials(self, self.configuration)
            )

            region_name = re.search(EXTRACT_AWS_REGION_REGEX, endpoint_url)

            if region_name:
                region_name = region_name.group(1)

            retries = {
                "max_attempts": (
                    validation_retries
                    if validation_retries is not None
                    else MAX_RETRIES
                ),
                "mode": "standard",
            }

            if region_name and region_name in REGIONS:
                s3_client = boto3.client(
                    "s3",
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_access_key,
                    endpoint_url=endpoint_url,
                    region_name=region_name,
                    config=Config(
                        proxies=self.proxy,
                        user_agent=self.useragent,
                        read_timeout=READ_TIMEOUT,
                        retries=retries,
                    ),
                )
            else:
                s3_client = boto3.client(
                    "s3",
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_access_key,
                    endpoint_url=endpoint_url,
                    config=Config(
                        proxies=self.proxy,
                        user_agent=self.useragent,
                        read_timeout=READ_TIMEOUT,
                        retries=retries,
                    ),
                )
            return s3_client
        except ReadTimeoutError as exp:
            err_msg = (
                "Read timeout error occurred while creating "
                f"{PLUGIN_NAME} client object."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ScalityException(str(exp))
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
                raise ScalityException(err_msg)
            else:
                self.logger.error(
                    message=f"{self.log_prefix}: {str(error)}",
                    details=traceback.format_exc(),
                )
                raise ScalityException(str(error))

        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {PLUGIN_NAME} client object."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ScalityException(err_msg)

    def is_bucket_exists(self, s3_client, bucket_name, region_name):
        """To check if a bucket exists or not on scality.

        Args:
            s3_client : scality client
            bucket_name : scality bucket name
            region_name : scality region name

        Returns:
            boolean: True or False
        """
        try:
            buckets = s3_client.list_buckets().get("Buckets", [])
            if region_name and region_name in REGIONS:
                for bucket in buckets:
                    if bucket_name == bucket.get("Name", ""):
                        bucket_location = s3_client.get_bucket_location(
                            Bucket=bucket.get("Name", "")
                        )["LocationConstraint"]
                        if bucket_location is None:
                            bucket_location = "us-east-1"
                        if str(region_name) == str(bucket_location):
                            return True
                        err_msg = (
                            "Provided bucket name already exists in another"
                            " region. Provide valid bucket name."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=traceback.format_exc(),
                        )
                        raise BucketNameAlreadyTaken(err_msg)
                return False
            else:
                for bucket in buckets:
                    if bucket_name == bucket.get("Name", ""):
                        return True
                err_msg = (
                    f"Provided bucket does not exist on {PLUGIN_NAME}. "
                    "Provide valid bucket name."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise BucketNotFoundError(err_msg)

        except BucketNotFoundError:
            raise
        except BucketNameAlreadyTaken:
            raise
        except ScalityException:
            raise
        except Exception as exp:
            err_msg = "Error occurred while checking existence of bucket."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ScalityException(err_msg)

    def get_bucket(self, validation_retries=None):
        """To get bucket if exists or create bucket."""
        try:
            region_name = None
            s3_client = None
            endpoint_url, _, _, bucket_name = (
                ScalityCredentials.get_credentials(self, self.configuration)
            )
            s3_client = self.get_aws_client(
                validation_retries=validation_retries
            )
            region_name = re.search(EXTRACT_AWS_REGION_REGEX, endpoint_url)
            if region_name:
                region_name = region_name.group(1)

            if not self.is_bucket_exists(
                s3_client,
                bucket_name,
                region_name,
            ):
                log_msg = (
                    "The bucket provided in the configuration parameter"
                    f"does not exist on {PLUGIN_NAME} hence "
                    f"creating bucket: {bucket_name}."
                )
                self.logger.info(message=f"{self.log_prefix}: {log_msg}")
                if region_name == "us-east-1":
                    bucket = s3_client.create_bucket(
                        Bucket=bucket_name,
                    )
                else:
                    location = {"LocationConstraint": region_name}
                    bucket = s3_client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration=location,
                    )
                return bucket
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
                raise ScalityException(err_msg)
            else:
                self.logger.error(
                    message=f"{self.log_prefix}: {str(error)}",
                    details=traceback.format_exc(),
                )
                raise ScalityException(str(error))
        except BucketNameAlreadyTaken:
            raise
        except BucketNotFoundError:
            raise
        except ScalityException:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while getting/creating bucket."
                f" Bucket Name: {bucket_name}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ScalityException(err_msg)

    def push(self, file_name: str, data_type: str, subtype: str):
        """Push method.

        Args:
            file_name (str): Name of the file.
            data_type (str): Data type.
            subtype (str): Sub type.
        """
        curr_time = datetime.now()
        object_name_prefix = f"{data_type}/feedname={subtype}/year={curr_time.year}/month={curr_time.month}/day={curr_time.day}/hour={curr_time.hour}/{int(curr_time.timestamp())}_{threading.get_ident()}"  # noqa
        if data_type == "webtx":
            object_name = f"{object_name_prefix}.gz"
        else:
            object_name = f"{object_name_prefix}.txt"

        try:
            bucket_name = self.configuration.get("bucket_name", "").strip()
            s3_client = self.get_aws_client()
            s3_client.upload_file(
                file_name,
                bucket_name,
                object_name,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully Uploaded log(s) to"
                f" {PLUGIN_NAME} bucket {bucket_name} as object file."
                f" Object File Name: {object_name}"
            )
        except S3UploadFailedError as err:
            err_msg = f"Error occurred while uploading file to {PLUGIN_NAME}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ScalityException(str(err))
        except ScalityException as err:
            raise err
        except Exception as exp:
            err_msg = f"Error occurred while pushing logs to {PLUGIN_NAME}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ScalityException(str(exp))
