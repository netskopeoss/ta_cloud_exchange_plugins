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


import boto3
import time
import uuid
from botocore.config import Config

class BucketNameAlreadyTaken(Exception):
    pass

class AmazonSecurityLakeClient:
    """Amazon Security Lake Client Class."""

    def __init__(self, configuration, logger, proxy):
        """Init method."""
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy

    def get_aws_resource(self):
        """To get aws resource."""
        try:
            if self.configuration["region_name"] == "None":
                amazon_security_lake_resource = boto3.resource(
                    "s3",
                    aws_access_key_id=self.configuration["aws_public_key"],
                    aws_secret_access_key=self.configuration[
                        "aws_private_key"
                    ],
                    config=Config(proxies=self.proxy),
                )
                return amazon_security_lake_resource
            else:
                amazon_security_lake_resource = boto3.resource(
                    "s3",
                    aws_access_key_id=self.configuration["aws_public_key"],
                    aws_secret_access_key=self.configuration[
                        "aws_private_key"
                    ],
                    region_name=self.configuration["region_name"],
                    config=Config(proxies=self.proxy),
                )
                return amazon_security_lake_resource
        except Exception:
            raise

    def get_aws_client(self):
        """To get aws client."""
        try:
            if self.configuration["region_name"] == "None":
                amazon_security_lake_client = boto3.client(
                    "s3",
                    aws_access_key_id=self.configuration["aws_public_key"],
                    aws_secret_access_key=self.configuration[
                        "aws_private_key"
                    ],
                    config=Config(proxies=self.proxy),
                )
                return amazon_security_lake_client
            else:
                amazon_security_lake_client = boto3.client(
                    "s3",
                    aws_access_key_id=self.configuration["aws_public_key"],
                    aws_secret_access_key=self.configuration[
                        "aws_private_key"
                    ],
                    region_name=self.configuration["region_name"],
                    config=Config(proxies=self.proxy),
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
                    if str(region_name) == str(bucket_location):
                        return True
                    raise BucketNameAlreadyTaken
            return False
        except Exception:
            raise

    def get_bucket(self):
        """To get bucket if exists or create bucket."""
        try:
            if not self.is_bucket_exists(self.configuration["bucket_name"].strip(), self.configuration["region_name"]):
                amazon_security_lake_client = self.get_aws_client()
                if self.configuration["region_name"] == "None":
                    bucket = amazon_security_lake_client.create_bucket(
                        Bucket=self.configuration["bucket_name"].strip(),
                    )
                else:
                    location = {
                        "LocationConstraint": self.configuration["region_name"]
                    }
                    bucket = amazon_security_lake_client.create_bucket(
                        Bucket=self.configuration["bucket_name"].strip(),
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
            object_name = f'{data_type}_{subtype}_{cur_time}_{str(uuid.uuid1())}'
        try:
            amazon_security_lake_client = self.get_aws_client()
            amazon_security_lake_client.upload_file(
                file_name, self.configuration["bucket_name"].strip(), object_name
            )
            self.logger.info(
                f"Amazon Security Lake Plugin: Successfully Uploaded to AWS S3 as object file.{object_name}"
            )
        except Exception as e:
            self.logger.error(f"Amazon Security Lake Plugin: Error occurred while Pushing data object: {e}")
            raise
