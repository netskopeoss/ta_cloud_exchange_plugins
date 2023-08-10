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
"""

"""Amazon Security Lake Client Class."""


import traceback
import boto3
import time
import uuid
import datetime
from botocore.config import Config
from .amazon_security_lake_generate_temporary_credentials import (
    AmazonSecurityLakeGenerateTemporaryCredentials
)


class BucketNameAlreadyTaken(Exception):
    """Custom Exception Class for """
    pass


class AmazonSecurityLakeClient:
    """Amazon Security Lake Client Class."""

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
            if(
                self.configuration.get("authentication_method") == "aws_iam_roles_anywhere"
            ):
                temp_creds_obj = AmazonSecurityLakeGenerateTemporaryCredentials(
                    self.configuration,
                    self.logger,
                    self.proxy
                )
                if not self.storage or not self.storage.get("credentials"):
                    self.storage = {}
                    temporary_credentials = temp_creds_obj.generate_temporary_credentials()
                    credentials = temporary_credentials.get("credentialSet")[0].get(
                        "credentials"
                    )
                    if credentials:
                        self.storage["credentials"] = credentials
                    else:
                        raise Exception("Unable to generate Temporary Credentials. Check the configuration paramters.")

                elif datetime.datetime.strptime(self.storage.get("credentials").get("expiration"), '%Y-%m-%dT%H:%M:%SZ') <= datetime.datetime.utcnow()-datetime.timedelta(hours=0, minutes=3):
                    temporary_credentials = temp_creds_obj.generate_temporary_credentials()
                    credentials = temporary_credentials.get("credentialSet")[0].get(
                        "credentials"
                    )
                    self.storage["credentials"] = credentials
                credentials_from_storage = self.storage.get("credentials")
                self.aws_public_key = credentials_from_storage.get("accessKeyId")
                self.aws_private_key = credentials_from_storage.get("secretAccessKey")
                self.aws_session_token = credentials_from_storage.get("sessionToken")
            return self.storage
        except Exception as err:
            raise err

    def get_aws_resource(self):
        """To get aws resource."""
        try:
            amazon_security_lake_resource = boto3.resource(
                "s3",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                region_name=self.configuration.get("region_name").strip(),
                config=Config(
                    proxies=self.proxy,
                    user_agent=self.useragent
                ),
            )
            return amazon_security_lake_resource
        except Exception:
            raise

    def get_aws_client(self):
        """To get aws client."""
        try:
            amazon_security_lake_client = boto3.client(
                "s3",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=self.configuration.get("region_name").strip(),
                config=Config(
                    proxies=self.proxy,
                    user_agent=self.useragent
                ),
            )
            return amazon_security_lake_client
        except Exception:
            raise

    def is_bucket_exists(self, bucket_name, region_name):
        """To check if a bucket exists or not."""
        try:
            amazon_security_lake_client = self.get_aws_client()
            buckets = amazon_security_lake_client.list_buckets()["Buckets"]
            for bucket in buckets:
                if (bucket_name == bucket["Name"]):
                    bucket_location = amazon_security_lake_client.get_bucket_location(
                        Bucket=bucket["Name"]
                    )["LocationConstraint"]
                    if bucket_location == None:
                        bucket_location = "us-east-1"
                    if str(region_name) == str(bucket_location):
                        return True
                    raise BucketNameAlreadyTaken
            return False
        except Exception:
            raise

    def get_bucket(self):
        """To get bucket if exists or create bucket."""
        try:
            if not self.is_bucket_exists(
                self.configuration.get("bucket_name").strip(),
                self.configuration.get("region_name").strip()
            ):
                amazon_security_lake_client = self.get_aws_client()
                if self.configuration.get("region_name").strip() == "us-east-1":
                    bucket = amazon_security_lake_client.create_bucket(
                        Bucket=self.configuration.get("bucket_name").strip(),
                    )
                else:
                    location = {
                        "LocationConstraint": self.configuration.get("region_name").strip()
                    }
                    bucket = amazon_security_lake_client.create_bucket(
                        Bucket=self.configuration.get("bucket_name").strip(),
                        CreateBucketConfiguration=location,
                    )
                return bucket
        except Exception as e:
            raise e

    def push(self, file_name, data_type, subtype):
        """Push method."""
        cur_time = int(time.time())
        if data_type is None:
            object_name = f'webtx_{cur_time}_{str(uuid.uuid1())}'
        else:
            object_name = (
                f'{data_type}_{subtype}_{cur_time}_{str(uuid.uuid1())}'
            )
        try:
            amazon_security_lake_client = self.get_aws_client()
            amazon_security_lake_client.upload_file(
                file_name, self.configuration.get("bucket_name").strip(),
                object_name
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully Uploaded to "
                f"AWS S3 as object file.{object_name}"
            )
        except Exception as e:
            error_message = (
                f"{self.log_prefix}: "
                f"Error occurred while Pushing data object: {e}"
            )
            self.logger.error(
                message=error_message,
                details=traceback.format_exc()
            )
            raise
