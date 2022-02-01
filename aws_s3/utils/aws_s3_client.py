"""AWS S3 Client Class."""
import boto3
import time
import uuid
from botocore.config import Config


class AWSS3Client:
    """AWS S3 Client Class."""

    def __init__(self, configuration, logger, proxy):
        """Init method."""
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy

    def get_aws_resource(self):
        """To get aws resource."""
        try:
            if self.configuration["region_name"] == "None":
                s3_resource = boto3.resource(
                    "s3",
                    aws_access_key_id=self.configuration["aws_public_key"],
                    aws_secret_access_key=self.configuration[
                        "aws_private_key"
                    ],
                    config=Config(proxies=self.proxy),
                )
                return s3_resource
            else:
                s3_resource = boto3.resource(
                    "s3",
                    aws_access_key_id=self.configuration["aws_public_key"],
                    aws_secret_access_key=self.configuration[
                        "aws_private_key"
                    ],
                    region_name=self.configuration["region_name"],
                    config=Config(proxies=self.proxy),
                )
                return s3_resource
        except Exception:
            raise

    def get_aws_client(self):
        """To get aws client."""
        try:
            if self.configuration["region_name"] == "None":
                s3_client = boto3.client(
                    "s3",
                    aws_access_key_id=self.configuration["aws_public_key"],
                    aws_secret_access_key=self.configuration[
                        "aws_private_key"
                    ],
                    config=Config(proxies=self.proxy),
                )
                return s3_client
            else:
                s3_client = boto3.client(
                    "s3",
                    aws_access_key_id=self.configuration["aws_public_key"],
                    aws_secret_access_key=self.configuration[
                        "aws_private_key"
                    ],
                    region_name=self.configuration["region_name"],
                    config=Config(proxies=self.proxy),
                )
                return s3_client
        except Exception:
            raise

    def is_bucket_exists(self, bucket_name):
        """To check if a bucket exists or not."""
        try:
            s3_client = self.get_aws_client()
            buckets = s3_client.list_buckets()
            for bucket in buckets["Buckets"]:
                if bucket_name == bucket["Name"]:
                    return True
            return False
        except Exception:
            raise

    def get_bucket(self):
        """To get bucket if exists or create bucket."""
        try:
            if not self.is_bucket_exists(self.configuration["bucket_name"]):
                s3_client = self.get_aws_client()
                if self.configuration["region_name"] == "None":
                    bucket = s3_client.create_bucket(
                        Bucket=self.configuration["bucket_name"],
                    )
                else:
                    location = {
                        "LocationConstraint": self.configuration["region_name"]
                    }
                    bucket = s3_client.create_bucket(
                        Bucket=self.configuration["bucket_name"],
                        CreateBucketConfiguration=location,
                    )
                return bucket
        except Exception as e:
            raise e

    def push(self, file_name, data_type, subtype):
        """Push method."""
        cur_time = int(time.time())
        if data_type is None:
            object_name = f'{self.configuration["obj_prefix"]}_webtx_{cur_time}_{str(uuid.uuid1())}'
        else:
            object_name = f'{self.configuration["obj_prefix"]}_{data_type}_{subtype}_{cur_time}_{str(uuid.uuid1())}'
        try:
            s3_client = self.get_aws_client()
            s3_client.upload_file(
                file_name, self.configuration["bucket_name"], object_name
            )
            self.logger.info(
                f"Successfully Uploaded to AWS S3 as object file.{object_name}"
            )
        except Exception as e:
            self.logger.error(f"Error occurred while Pushing data object: {e}")
            raise
