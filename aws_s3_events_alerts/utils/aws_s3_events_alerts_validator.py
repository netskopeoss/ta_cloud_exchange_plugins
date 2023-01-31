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

"""AWS S3 Events, Alerts validator."""


import boto3
from botocore.config import Config
from .aws_s3_events_alerts_constants import REGIONS


class AWSS3EventsAlertsValidator(object):
    """AWS S3 Events, Alerts validator class."""

    def __init__(self, logger, proxy):
        """Initialize."""
        super().__init__()
        self.logger = logger
        self.proxy = proxy

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
            for _ in s3_resource.buckets.all():
                break
            return True
        except Exception as e:
            self.logger.error(f"AWS S3 Events, Alerts Plugin: Error while validating creadentials: {e}") 
            raise
