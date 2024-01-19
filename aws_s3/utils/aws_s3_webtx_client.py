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
AWS S3 WebTx Client Class.
"""

import threading
import traceback
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from datetime import datetime
from botocore.config import Config
from .aws_s3_generate_temporary_credentials import (
    AWSS3GenerateTemporaryCredentials,
)
from .aws_s3_exceptions import AWSS3WebTXException


class BucketNameAlreadyTaken(Exception):
    pass


class AWSS3WebTxClient:
    """AWS S3 WebTx Client Class."""

    def __init__(self, configuration, logger, proxy, storage, log_prefix, user_agent):
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
                    credentials = temporary_credentials.get("credentialSet")[0].get(
                        "credentials"
                    )
                    if credentials:
                        self.storage["credentials"] = credentials
                    else:
                        raise AWSS3WebTXException(
                            "Unable to generate Temporary Credentials. "
                            "Check the configuration parameters."
                        )

                elif datetime.datetime.strptime(
                    self.storage.get("credentials").get("expiration"),
                    "%Y-%m-%dT%H:%M:%SZ",
                ) <= datetime.datetime.utcnow() - datetime.timedelta(
                    hours=0, minutes=3
                ):
                    temporary_credentials = (
                        temp_creds_obj.generate_temporary_credentials()
                    )
                    credentials = temporary_credentials.get("credentialSet")[0].get(
                        "credentials"
                    )
                    self.storage["credentials"] = credentials
                credentials_from_storage = self.storage.get("credentials")
                self.aws_public_key = credentials_from_storage.get("accessKeyId")
                self.aws_private_key = credentials_from_storage.get("secretAccessKey")
                self.aws_session_token = credentials_from_storage.get("sessionToken")
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
            raise AWSS3WebTXException(err_msg)
        except AWSS3WebTXException:
            raise
        except Exception as err:
            err_msg = "Error occurred while setting credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise AWSS3WebTXException(err_msg)

    def get_aws_resource(self):
        """To get aws resource."""
        try:
            s3_resource = boto3.resource(
                "s3",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                region_name=self.configuration.get("region_name").strip(),
                config=Config(proxies=self.proxy, user_agent=self.useragent),
            )
            return s3_resource
        except Exception as exp:
            err_msg = "Error occurred while creating AWS S3 resource object."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise AWSS3WebTXException(err_msg)

    def get_aws_client(self):
        """To get aws client."""
        try:
            s3_client = boto3.client(
                "s3",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=self.configuration.get("region_name").strip(),
                config=Config(proxies=self.proxy, user_agent=self.useragent),
            )
            return s3_client
        except Exception as exp:
            err_msg = "Error occurred while creating AWS S3 client object."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise AWSS3WebTXException(err_msg)

    def is_bucket_exists(self, s3_client, bucket_name, region_name):
        """To check if a bucket exists or not."""
        try:
            buckets = s3_client.list_buckets().get("Buckets", [])
            for bucket in buckets:
                if bucket_name == bucket.get("Name", ""):
                    bucket_location = s3_client.get_bucket_location(
                        Bucket=bucket.get("Name", "")
                    )["LocationConstraint"]
                    if bucket_location is None:
                        bucket_location = "us-east-1"
                    if str(region_name) == str(bucket_location):
                        return True
                    raise BucketNameAlreadyTaken
            return False
        except BucketNameAlreadyTaken:
            raise
        except AWSS3WebTXException:
            raise
        except Exception as exp:
            err_msg = "Error occurred while checking existence of bucket."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {exp}",
            )
            raise AWSS3WebTXException(err_msg)

    def get_bucket(self):
        """To get bucket if exists or create bucket."""
        try:
            bucket_name = self.configuration.get("bucket_name", "").strip()
            region_name = self.configuration.get("region_name", "").strip()
            s3_client = self.get_aws_client()
            if not self.is_bucket_exists(
                s3_client,
                bucket_name,
                region_name,
            ):
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
                raise AWSS3WebTXException(err_msg)
            else:
                raise AWSS3WebTXException(str(error))
        except BucketNameAlreadyTaken:
            raise
        except AWSS3WebTXException:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while getting/creating bucket."
                f" Bucket Name: {bucket_name}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {exp}",
            )
            raise AWSS3WebTXException(err_msg)

    def push(self, file_name: str, data_type: str, subtype: str):
        """Push method.

        Args:
            file_name (str): Name of the file.
            data_type (str): Data type.
            subtype (str): Sub type.
        """
        curr_time = datetime.now()
        if data_type is None:
            object_name = f"webtx/year={curr_time.year}/month={curr_time.month}/day={curr_time.day}/hour={curr_time.hour}/{int(curr_time.timestamp())}_{threading.get_ident()}.gz"  # noqa
        else:
            object_name = f"{data_type}/feedname={subtype}/year={curr_time.year}/month={curr_time.month}/day={curr_time.day}/hour={curr_time.hour}/{int(curr_time.timestamp())}_{threading.get_ident()}.gz"  # noqa
        try:
            bucket_name = self.configuration.get("bucket_name", "").strip()
            s3_client = self.get_aws_client()
            s3_client.upload_file(
                file_name,
                bucket_name,
                object_name,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully Uploaded log(s) to AWS S3 "
                f"bucket {bucket_name} as object file."
                f" Object File Name: {object_name}"
            )
        except Exception as exp:
            err_msg = (
                f"{self.log_prefix}: Error occurred while "
                f"pushing log(s) object to AWS S3 Bucket {bucket_name} "
                f"as a file object. Object File Name: {object_name}"
            )
            self.logger.error(message=err_msg, details=f"Error: {exp}")
            raise AWSS3WebTXException(err_msg)
