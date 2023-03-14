from ..lib import boto3
from ..lib.botocore.config import Config

class AWSCloudtrailClient:
    """AWS cloudtrail Client Class."""

    def __init__(self, configuration, logger, proxy):
        """Init method."""
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy

    def get_cloudtrail_client(self, service):
        """To get aws cloudtrail client."""
        try:
            cloudtrail_client = boto3.client(
                service,
                aws_access_key_id=self.configuration.get("aws_public_key").strip(),
                aws_secret_access_key=self.configuration[
                    "aws_private_key"
                ].strip(),
                region_name=self.configuration.get("channel_arn").split(":")[3],
                config=Config(proxies=self.proxy),
            )
            return cloudtrail_client
        except Exception:
            raise
