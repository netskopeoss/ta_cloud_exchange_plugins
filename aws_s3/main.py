"""AWS S3 Plugin."""
import os
from typing import List
from tempfile import NamedTemporaryFile

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from .utils.aws_s3_validator import (
    AWSS3Validator,
)
from .utils.aws_s3_client import AWSS3Client


class AWSS3Plugin(PluginBase):
    """The AWS S3 plugin implementation class."""

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw netskope JSON data into target platform supported data formats.

        Args:
            raw_data (list): The raw data to be tranformed.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested (DLP, anomaly etc. in case of alerts)

        Raises:
            NotImplementedError: If the method is not implemented.

        Returns:
            List: list of transformed data.
        """
        return raw_data

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform."""
        try:
            aws_client = AWSS3Client(
                self.configuration, self.logger, self.proxy
            )

            temp_obj_file = NamedTemporaryFile("wb", delete=False)
            for data in transformed_data:
                temp_obj_file.write(data)
            temp_obj_file.flush()

            try:
                aws_client.push(temp_obj_file.name, data_type, subtype)
            except Exception:
                raise
            finally:
                temp_obj_file.close()
                os.unlink(temp_obj_file.name)
        except Exception as e:
            self.logger.error(f"Error while pushing to AWS S3: {e}")
            raise

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        aws_validator = AWSS3Validator(self.logger, self.proxy)

        if (
            "aws_public_key" not in configuration
            or type(configuration["aws_public_key"]) != str
            or not configuration["aws_public_key"].strip()
        ):
            self.logger.error(
                "AWS S3 Plugin: Validation error occurred. Error: "
                "Invalid AWS Access Key ID (Public Key) found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid AWS Access Key ID (Public Key) provided.",
            )

        if (
            "aws_private_key" not in configuration
            or type(configuration["aws_private_key"]) != str
            or not configuration["aws_private_key"].strip()
        ):
            self.logger.error(
                "AWS S3 Plugin: Validation error occurred. Error: "
                "Invalid AWS Secret Access Key (Private Key) found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid AWS Secret Access Key (Private Key) provided.",
            )

        if (
            "region_name" not in configuration
            or type(configuration["region_name"]) != str
            or not aws_validator.validate_region_name(
                configuration["region_name"]
            )
        ):
            self.logger.error(
                "AWS S3 Plugin: Validation error occurred. Error: "
                "Invalid Region Name found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid Region Name provided.",
            )

        if (
            "bucket_name" not in configuration
            or type(configuration["bucket_name"]) != str
            or not configuration["bucket_name"].strip()
        ):
            self.logger.error(
                "AWS S3 Plugin: Validation error occurred. Error: "
                "Invalid Bucket Name found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Bucket Name provided."
            )

        if (
            "obj_prefix" not in configuration
            or type(configuration["obj_prefix"]) != str
            or not configuration["obj_prefix"].strip()
        ):
            self.logger.error(
                "AWS S3 Plugin: Validation error occurred. Error: "
                "Invalid Object Prefix found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Object Prefix provided."
            )

        if (
            "max_file_size" not in configuration
            or not aws_validator.validate_max_file_size(
                configuration["max_file_size"]
            )
        ):
            self.logger.error(
                "AWS S3 Plugin: Validation error occurred. Error: "
                "Invalid Max File Size found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Max File Size provided."
            )

        if (
            "max_duration" not in configuration
            or not aws_validator.validate_max_duration(
                configuration["max_duration"]
            )
        ):
            self.logger.error(
                "AWS S3 Plugin: Validation error occurred. Error: "
                "Invalid Max File Size found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Max File Size provided."
            )

        try:
            aws_validator.validate_credentials(
                configuration["aws_public_key"].strip(),
                configuration["aws_private_key"].strip(),
            )
        except Exception:
            self.logger.error(
                "AWS S3 Plugin: Validation error occurred. Error: "
                "Invalid AWS Access Key ID (Public Key) and AWS Secret Access Key "
                "(Private Key) found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid AWS Access Key ID (Public Key) or AWS Secret Access "
                "Key (Private Key) found in the configuration parameters.",
            )

        try:
            aws_client = AWSS3Client(configuration, self.logger, self.proxy)
            aws_client.get_bucket()
        except Exception as err:
            self.logger.error(
                f"AWS S3 Plugin: Validation error occurred. Error: {err}"
            )
            return ValidationResult(
                success=False,
                message="Validation Error. Check logs for more details.",
            )

        return ValidationResult(success=True, message="Validation successful.")
