"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Databricks CLS Plugin Validator.
"""

import traceback

from botocore.exceptions import ClientError, NoCredentialsError
from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from .databricks_constants import REGIONS
from .databricks_exception import DatabricksException


class DatabricksValidator:
    """Validator class for the Databricks CLS plugin."""

    def __init__(self, logger, log_prefix: str):
        """Initialize DatabricksValidator.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix for messages.
        """
        self.logger = logger
        self.log_prefix = log_prefix

    def validate_region_name(self, region_name: str) -> bool:
        """Validate that the AWS region name is a recognised value.

        Args:
            region_name (str): AWS region name to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        if not region_name:
            return False
        return region_name in REGIONS

    def validate_mappings(self, mappings: dict) -> bool:
        """Validate the mappings JSON structure using jsonschema.

        Checks that taxonomy.json exists and that each data_type maps
        subtypes to lists of field names. Only JSON format is validated
        — CEF fields (delimiter, cef_version) are not required.

        Args:
            mappings (dict): Parsed mappings dict from mappings.json.

        Returns:
            bool: True if structure is valid, False otherwise.
        """
        if not isinstance(mappings, dict):
            return False
        try:
            schema = {
                "type": "object",
                "properties": {
                    "taxonomy": {
                        "type": "object",
                        "properties": {
                            "json": {
                                "type": "object",
                                "patternProperties": {
                                    ".*": {
                                        "type": "object",
                                        "patternProperties": {
                                            ".*": {"type": "array"}
                                        },
                                    }
                                },
                            }
                        },
                        "required": ["json"],
                    }
                },
                "required": ["taxonomy"],
            }
            validate(instance=mappings, schema=schema)
            return True
        except JsonSchemaValidationError as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Mapping validation error."
                    f" {err.message}"
                ),
                details=str(err),
            )
            return False

    def validate_credentials(self, databricks_client) -> bool:
        """Validate AWS credentials using HeadBucket on the configured bucket.

        Uses HeadBucket which requires only s3:ListBucket on the target
        bucket, avoiding the account-wide s3:ListAllMyBuckets permission.
        A 403 or 404 response still confirms credentials are valid — only
        auth-level errors indicate bad credentials.

        Args:
            databricks_client: DatabricksClient instance with credentials set.

        Returns:
            bool: True if credentials are valid and S3 is reachable.

        Raises:
            DatabricksException: If credentials are missing or invalid.
        """
        try:
            bucket_name = databricks_client.configuration.get(
                "bucket_name", ""
            ).strip()
            s3_client = databricks_client.get_aws_client()
            s3_client.head_bucket(Bucket=bucket_name)
            return True
        except ClientError as err:
            err_code = err.response["Error"]["Code"]
            # 403/404 both confirm credentials work — bucket access or
            # existence is validated separately in verify_bucket_exists.
            if err_code in ("403", "404", "AccessDenied", "NoSuchBucket"):
                return True
            err_msg = "Error occurred while validating AWS credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {err}",
            )
            raise DatabricksException(err_msg)
        except NoCredentialsError as err:
            err_msg = (
                "No AWS Credentials were found in the environment."
                " Deploy the plugin into an AWS environment or use"
                " AWS IAM Roles Anywhere authentication."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {err}",
            )
            raise DatabricksException(err_msg)
        except DatabricksException:
            raise
        except Exception as err:
            err_msg = "Error occurred while validating AWS credentials."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} {err}"),
                details=traceback.format_exc(),
            )
            raise DatabricksException(err_msg)
