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
AWS S3 Webtx Plugin.
"""
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import os
from typing import List
import traceback

from tempfile import NamedTemporaryFile


from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from .utils.aws_s3_webtx_validator import (
    AWSS3WebTxValidator,
)
from .utils.aws_s3_webtx_constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
)
from .utils.aws_s3_exceptions import AWSS3WebTXException
from .utils.aws_s3_webtx_client import AWSS3WebTxClient, BucketNameAlreadyTaken
from netskope.common.utils import add_user_agent


class AWSS3WebTxPlugin(PluginBase):
    """The AWS S3 WebTx plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize AWS S3 WebTx Plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = AWSS3WebTxPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _add_user_agent(self, header=None) -> str:
        """Add User-Agent to any request.

        Args:
            header: Headers needed to pass to the Third Party Platform.

        Returns:
            str: String containing user agent.
        """
        plugin_name, plugin_version = self._get_plugin_info()

        header = add_user_agent(header)
        user_agent = f"{header.get('User-Agent', 'netskope-ce')}-{MODULE_NAME.lower()}-{plugin_name.lower().replace(' ','_')}-v{plugin_version.lower()}"  # noqa
        return user_agent

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw netskope JSON data into target platform supported
          data formats.

        Args:
            raw_data (list): The raw data to be transformed.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested (DLP, anomaly
             etc. in case of alerts)

        Raises:
            NotImplementedError: If the method is not implemented.

        Returns:
            List: list of transformed data.
        """
        return raw_data

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform.

        Args:
            transformed_data (List): List of data to push to S3 bucket.
            data_type (str): Data type.
            subtype (str): Subtype

        Returns:
            PushResult: Push Result containing message and status.
        """
        try:
            skipped_logs, successful_log_push_counter = 0, 0
            bucket_name = self.configuration.get("bucket_name", "").strip()
            user_agent = self._add_user_agent()
            aws_client = AWSS3WebTxClient(
                self.configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                user_agent,
            )
            aws_client.set_credentials()
            temp_obj_file = NamedTemporaryFile("wb", delete=False)
            for data in transformed_data:
                if data:
                    try:
                        temp_obj_file.write(data)
                        successful_log_push_counter += 1
                    except Exception as exp:
                        err_msg = (
                            "Error occurred while "
                            "writing log(s) to temporary object file."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {exp}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        skipped_logs += 1
                else:
                    skipped_logs += 1
            temp_obj_file.flush()
            aws_client.push(temp_obj_file.name, data_type, subtype)
            temp_obj_file.close()
            os.unlink(temp_obj_file.name)
            if skipped_logs > 0:
                self.logger.debug(
                    f"{self.log_prefix}: Received empty log(s) from PubSub "
                    f"or failed to write to the object file for {skipped_logs}"
                    " log(s) hence ingestion of those log(s) were skipped."
                )
            log_msg = (
                "[{}] [{}] Successfully ingested {} log(s)"
                " to {} AWS S3 Bucket {}.".format(
                    data_type,
                    subtype,
                    successful_log_push_counter,
                    self.plugin_name,
                    bucket_name,
                )
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(
                success=True,
                message=log_msg,
            )
        except Exception as exp:
            err_msg = (
                "Error occurred while pushing "
                f"log(s) to AWS S3 Bucket {bucket_name}."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            raise AWSS3WebTXException(err_msg)

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidationResult: Validation Result.
        """
        aws_validator = AWSS3WebTxValidator(
            configuration,
            self.logger,
            self.proxy,
            self.storage,
            self.log_prefix,
        )

        # Validate Authentication Method
        authentication_method = configuration.get(
            "authentication_method", ""
        ).strip()
        if not authentication_method:
            err_msg = (
                "Authentication Method is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. "
                f"Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        if authentication_method not in [
            "aws_iam_roles_anywhere",
            "deployed_on_aws",
        ]:
            error_msg = (
                "Invalid value for Authentication Method provided. "
                "Allowed values are "
                "'AWS IAM Roles Anywhere' or 'Deployed on AWS'."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred."
                f" Error: {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=f"{error_msg}",
            )
        if authentication_method == "aws_iam_roles_anywhere":
            pass_phrase = configuration.get("pass_phrase")
            if not pass_phrase:
                err_msg = (
                    "Password Phrase is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{err_msg}",
                )
            elif not isinstance(pass_phrase, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. "
                    "Error: Invalid Password Phrase found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Password Phrase provided.",
                )
            # Validate Private Key File.
            private_key_file = configuration.get(
                "private_key_file", ""
            ).strip()
            if not private_key_file:
                error_msg = (
                    "Private Key is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix} Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )
            elif not isinstance(private_key_file, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. "
                    "Error: Invalid Private Key found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Private Key provided.",
                )
            else:
                try:
                    serialization.load_pem_private_key(
                        private_key_file.encode("utf-8"), None
                    )
                except Exception:
                    try:
                        serialization.load_pem_private_key(
                            private_key_file.encode("utf-8"),
                            password=str.encode(pass_phrase),
                        )
                    except Exception:
                        err_msg = (
                            "Invalid Private Key provided."
                            " Private Key should be in a valid PEM format."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Validation error "
                                f"occurred. Error: {err_msg}"
                            ),
                            details=traceback.format_exc(),
                        )
                        return ValidationResult(
                            success=False,
                            message=f"{err_msg}",
                        )

            # Validate Certificate Body.
            public_certificate_file = configuration.get(
                "public_certificate_file", ""
            ).strip()
            if not public_certificate_file:
                error_msg = (
                    "Certificate Body is a required configuration"
                    " parameter when 'AWS IAM Roles Anywhere' "
                    "is selected as Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix} Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )
            elif not isinstance(public_certificate_file, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid Certificate Body found in "
                    "the configuration parameters."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Certificate Body provided.",
                )
            else:
                try:
                    x509.load_pem_x509_certificate(
                        public_certificate_file.encode()
                    )
                except Exception:
                    err_msg = (
                        "Invalid Certificate Body provided. "
                        "Certificate Body should be in valid Pem Format."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Validation error occurred. "
                            f"Error: {err_msg}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    return ValidationResult(
                        success=False,
                        message=f"{err_msg}",
                    )

            # Validate Profile ARN.
            profile_arn = configuration.get("profile_arn", "").strip()
            if not profile_arn:
                error_msg = (
                    "Profile ARN is a required configuration parameter when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")
            elif not isinstance(profile_arn, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid Profile ARN found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False, message="Invalid Profile ARN provided."
                )

            # Validate Role ARN.
            role_arn = configuration.get("role_arn", "").strip()
            if not role_arn:
                error_msg = (
                    "Role ARN is a required configuration parameter when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")

            elif not isinstance(role_arn, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"Invalid Role ARN found in the configuration parameters."
                )
                return ValidationResult(
                    success=False, message="Invalid Role ARN provided."
                )

            # Validate Trust Anchor ARN.
            trust_anchor_arn = configuration.get(
                "trust_anchor_arn", ""
            ).strip()
            if not trust_anchor_arn:
                error_msg = (
                    "Trust Anchor ARN is a required configuration parameter "
                    "when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")

            elif not isinstance(trust_anchor_arn, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid Trust Anchor ARN found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False, message="Invalid Trust Anchor ARN provided."
                )

        # Validate Region Name.
        region_name = configuration.get("region_name", "").strip()
        if not region_name:
            error_msg = (
                "AWS S3 Bucket Region Name is a "
                "required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. "
                f"Error: {error_msg}"
            )
            return ValidationResult(success=False, message=error_msg)
        elif not (
            isinstance(region_name, str)
            and aws_validator.validate_region_name(region_name)
        ):
            error_msg = (
                "Invalid AWS S3 Bucket Region Name found in "
                "the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred."
                f" Error: {error_msg}"
            )
            return ValidationResult(success=False, message=error_msg)

        bucket_name = configuration.get("bucket_name", "").strip()
        if not bucket_name:
            err_msg = (
                "AWS S3 Bucket Name is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                f"{err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(bucket_name, str):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Invalid AWS S3 Bucket Name found in the"
                " configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid AWS S3 Bucket Name provided."
            )

        # Validate Max File Size.
        max_file_size = configuration.get("max_file_size")
        if max_file_size is None:
            err_msg = "Max File Size is the required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                f"{err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not (
            isinstance(max_file_size, int)
            and aws_validator.validate_max_file_size(max_file_size)
        ):
            err_msg = (
                "Maximum File Size should be an integer between 1 to 100."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Invalid Maximum File Size found in the "
                f"configuration parameters. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=f"Invalid Max File Size provided. {err_msg}",
            )

        # Validate Max Duration.
        max_duration = configuration.get("max_duration")
        if max_duration is None:
            err_msg = "Max Duration is the required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                f"{err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not (
            isinstance(max_duration, int)
            and aws_validator.validate_max_duration(max_duration)
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Invalid Max Duration found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Max Duration provided."
            )
        # Validate Auth Credentials.
        try:
            user_agent = self._add_user_agent()
            aws_client = AWSS3WebTxClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                user_agent,
            )
            aws_client.set_credentials()
            aws_validator.validate_credentials(aws_client)
        except AWSS3WebTXException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {exp}"
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"Validation error occurred. {exp}",
            )
        except Exception as err:
            error_msg = (
                "Invalid authentication parameters provided."
                " Check logs for more details."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred."
                    f" Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{error_msg}",
            )
        try:
            aws_client.get_bucket()
        except BucketNameAlreadyTaken:
            err_msg = (
                "Provided AWS S3 Bucket Name already exists at a "
                "different region. Please try with different name or "
                "use the correct region."
            )
            error_msg = (
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            self.logger.error(
                message=error_msg, details=traceback.format_exc()
            )
            return ValidationResult(success=False, message=err_msg)
        except AWSS3WebTXException as exp:
            err_msg = f"Validation error occurred. {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)
        except ValueError as err:
            error_msg = (
                f"{self.log_prefix}: Validation error occurred. "
                f"Error: {err}"
            )
            self.logger.error(
                message=error_msg, details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message=(
                    "Validation error occurred. "
                    "Check logs for more details."
                ),
            )
        except Exception as err:
            error_msg = f"{self.log_prefix}: Validation error occurred. {err}"
            self.logger.error(
                message=error_msg, details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message=(
                    "Validation error occurred. Check logs"
                    " for more details."
                ),
            )
        self.logger.debug(
            f"{self.log_prefix}: Successfully validated"
            " configuration parameters."
        )
        return ValidationResult(success=True, message="Validation successful.")
