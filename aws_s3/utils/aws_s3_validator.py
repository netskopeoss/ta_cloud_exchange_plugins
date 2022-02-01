"""AWS S3 validator."""

import boto3
from botocore.config import Config
from .aws_s3_constants import REGIONS


class AWSS3Validator(object):
    """AWS S3 validator class."""

    def __init__(self, logger, proxy):
        """Initialize."""
        super().__init__()
        self.logger = logger
        self.proxy = proxy

    def validate_max_file_size(self, max_file_size):
        """Validate max file size.

        Args:
            max_file_size: the max file size to be validated

        Returns:
            Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        if max_file_size:
            try:
                max_file_size = int(max_file_size)
                if 0 < max_file_size <= 100:
                    return True
                return False
            except ValueError:
                return False
        else:
            return False

    def validate_max_duration(self, max_duration):
        """Validate max duration.

        Args:
            max_duration: the max duration to be validated

        Returns:
            Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        if max_duration:
            try:
                max_duration = int(max_duration)
                if max_duration > 0:
                    return True
                return False
            except ValueError:
                return False
        else:
            return False

    def validate_region_name(self, region_name):
        """Validate region name.

        Args:
            region_name: the region name to be validated

        Returns:
            Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        if region_name:
            try:
                if region_name == "None":
                    return True
                if region_name in REGIONS:
                    return True
                return False
            except ValueError:
                return False
        else:
            return False

    def validate_credentials(self, aws_public_key, aws_private_key):
        """Validate credentials.

        Args:
            aws_public_key: the aws public key to establish connection with aws s3.
            aws_private_key: the aws private key to establish connection with aws s3.

        Returns:
            Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        try:
            s3_resource = boto3.resource(
                "s3",
                aws_access_key_id=aws_public_key,
                aws_secret_access_key=aws_private_key,
                config=Config(proxies=self.proxy),
            )
            # Print out bucket names
            for _ in s3_resource.buckets.all():
                break
            return True
        except Exception as e:
            print(e)
            raise
