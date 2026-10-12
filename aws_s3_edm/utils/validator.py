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

Validate the configuration parameters of the AWS S3 EDM plugin (no network).
"""

import re
from typing import Optional

from netskope.integrations.edm.plugin_base import ValidationResult

from .constants import (
    AUTH_METHODS,
    AUTH_ROLES_ANYWHERE,
    CUSTOM_REGION_VALUE,
    INVALID_DELIMITERS,
    MAX_KEY_LENGTH_BYTES,
    REGIONS,
    REGION_NAME_REGEX,
    SUPPORTED_EXTENSIONS,
)
from .generate_temp_creds import (
    AWSS3GenerateTemporaryCredentials,
    MissingPassPhraseError,
    UnsupportedKeyTypeError,
)
from .helper import (
    AWSS3EDMBase,
    build_error_message,
    get_effective_region,
    get_region_partition,
)


class AWSS3EDMValidator(AWSS3EDMBase):
    """Validate the plugin configuration parameters (no network)."""

    default_action = "validating the configuration parameters"

    def __init__(self, logger, log_prefix: str) -> None:
        """Initialize the validator.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix.
        """
        super().__init__(logger, log_prefix)

    def _validation_failure(
        self, err_msg: str, resolution: str
    ) -> ValidationResult:
        """Log a validation error and build a failed ValidationResult.

        Args:
            err_msg (str): Error message shown to the user.
            resolution (str): Actionable resolution.

        Returns:
            ValidationResult: Failed validation result.
        """
        self.logger.error(
            message=(
                f"{self.log_prefix}: "
                f"{build_error_message(self.default_action, err_msg)}"
            ),
            details=err_msg,
            resolution=resolution,
        )
        return ValidationResult(success=False, message=err_msg)

    def _check_required_string(
        self,
        configuration: dict,
        key: str,
        label: str,
        suffix: str = "",
    ) -> Optional[ValidationResult]:
        """Check that a parameter is a non-empty string.

        Args:
            configuration (dict): Step 1 configuration parameters.
            key (str): Parameter key.
            label (str): Parameter label used in messages.
            suffix (str): Extra text appended to the required message.

        Returns:
            Optional[ValidationResult]: Failure result or None.
        """
        value = configuration.get(key)
        if not value:
            return self._validation_failure(
                f"{label} is a required configuration parameter{suffix}.",
                f"Ensure that a valid {label} is provided.",
            )
        if not isinstance(value, str) or not value.strip():
            return self._validation_failure(
                "Invalid value provided for the configuration parameter "
                f"{label}.",
                f"Ensure that the {label} is a non-empty string value.",
            )
        return None

    def _validate_auth_method(
        self, configuration: dict
    ) -> Optional[ValidationResult]:
        """Validate the authentication method.

        Args:
            configuration (dict): Step 1 configuration parameters.

        Returns:
            Optional[ValidationResult]: Failure result or None.
        """
        method = configuration.get("authentication_method")
        if not method:
            return self._validation_failure(
                "Authentication Method is a required configuration "
                "parameter.",
                "Ensure that a valid Authentication Method is selected.",
            )
        if method not in AUTH_METHODS:
            return self._validation_failure(
                "Invalid value provided for the configuration parameter "
                "Authentication Method.",
                "Ensure that 'Deployed on AWS' or 'AWS IAM Roles Anywhere' "
                "is selected as the Authentication Method.",
            )
        return None

    def _validate_pem_values(
        self, configuration: dict
    ) -> Optional[ValidationResult]:
        """Validate the PEM encoded private key and certificate.

        Args:
            configuration (dict): Step 1 configuration parameters.

        Returns:
            Optional[ValidationResult]: Failure result or None.
        """
        try:
            private_key = AWSS3GenerateTemporaryCredentials.load_private_key(
                configuration.get("private_key_file", "").strip(),
                configuration.get("pass_phrase"),
            )
            AWSS3GenerateTemporaryCredentials.ensure_rsa_key(private_key)
        except MissingPassPhraseError:
            return self._validation_failure(
                "Private Key is encrypted and no Password Phrase was "
                "provided.",
                "Ensure that the Password Phrase of the encrypted Private "
                "Key is provided.",
            )
        except UnsupportedKeyTypeError:
            return self._validation_failure(
                "Unsupported Private Key type provided. Only RSA private "
                "keys are supported.",
                "Ensure that an RSA private key (PEM) that matches the "
                "certificate registered with the IAM Roles Anywhere trust "
                "anchor is provided.",
            )
        except Exception:
            return self._validation_failure(
                "Invalid Private Key or Password Phrase provided. Private "
                "Key must be in valid PEM format.",
                "Ensure that the Private Key is in valid PEM format and the "
                "Password Phrase matches the encryption key.",
            )
        try:
            AWSS3GenerateTemporaryCredentials.load_certificate(
                configuration.get("public_certificate_file", "").strip()
            )
        except Exception:
            return self._validation_failure(
                "Invalid Certificate Body provided. Certificate Body must "
                "be in valid PEM format.",
                "Ensure that the Certificate Body is a valid PEM encoded "
                "X.509 certificate.",
            )
        return None

    def _validate_roles_anywhere(
        self, configuration: dict
    ) -> Optional[ValidationResult]:
        """Validate the IAM Roles Anywhere parameters.

        Args:
            configuration (dict): Step 1 configuration parameters.

        Returns:
            Optional[ValidationResult]: Failure result or None.
        """
        suffix = (
            " when 'AWS IAM Roles Anywhere' is selected as Authentication "
            "Method"
        )
        for key, label in (
            ("private_key_file", "Private Key"),
            ("public_certificate_file", "Certificate Body"),
        ):
            failure = self._check_required_string(
                configuration, key, label, suffix
            )
            if failure:
                return failure
        pass_phrase = configuration.get("pass_phrase")
        if pass_phrase is not None and not isinstance(pass_phrase, str):
            return self._validation_failure(
                "Invalid value provided for the configuration parameter "
                "Password Phrase.",
                "Ensure that the Password Phrase is a string value.",
            )
        failure = self._validate_pem_values(configuration)
        if failure:
            return failure
        for key, label in (
            ("profile_arn", "Profile ARN"),
            ("role_arn", "Role ARN"),
            ("trust_anchor_arn", "Trust Anchor ARN"),
        ):
            failure = self._check_required_string(
                configuration, key, label, suffix
            )
            if failure:
                return failure
        return None

    def _validate_region(
        self, configuration: dict
    ) -> Optional[ValidationResult]:
        """Validate the region (dropdown or Custom Region).

        Args:
            configuration (dict): Step 1 configuration parameters.

        Returns:
            Optional[ValidationResult]: Failure result or None.
        """
        failure = self._check_required_string(
            configuration, "region_name", "AWS S3 Bucket Region"
        )
        if failure:
            return failure
        if configuration["region_name"].strip() == CUSTOM_REGION_VALUE:
            failure = self._validate_custom_region(configuration)
        elif configuration["region_name"].strip() not in REGIONS:
            failure = self._validation_failure(
                "Invalid AWS S3 Bucket Region provided in the "
                "configuration parameters.",
                "Ensure that a valid AWS region is selected from the "
                "available choices.",
            )
        if failure:
            return failure
        if configuration.get("authentication_method") != AUTH_ROLES_ANYWHERE:
            return None
        return self._validate_roles_anywhere_region(
            get_effective_region(configuration)
        )

    def _validate_custom_region(
        self, configuration: dict
    ) -> Optional[ValidationResult]:
        """Validate the AWS Custom Region (only used when it is selected).

        Only the host label safety guard is applied; AWS validates the
        region at the connection check.

        Args:
            configuration (dict): Step 1 configuration parameters.

        Returns:
            Optional[ValidationResult]: Failure result or None.
        """
        failure = self._check_required_string(
            configuration, "custom_region_name", "AWS Custom Region"
        )
        if failure:
            return failure
        region = configuration["custom_region_name"].strip()
        if not re.fullmatch(REGION_NAME_REGEX, region):
            return self._validation_failure(
                "Invalid AWS Custom Region provided in the configuration "
                "parameters. It must be a valid region name (letters, "
                "digits and hyphens, 1 to 63 characters, not starting or "
                "ending with a hyphen).",
                "Ensure that the AWS Custom Region is the AWS region code of "
                "the bucket, e.g. us-gov-west-1.",
            )
        return None

    def _validate_roles_anywhere_region(
        self, region: str
    ) -> Optional[ValidationResult]:
        """Reject regions whose Roles Anywhere endpoint cannot be built.

        This protects the manually built endpoint host only; the ARNs are
        not parsed (AWS validates them).

        Args:
            region (str): The effective region.

        Returns:
            Optional[ValidationResult]: Failure result or None.
        """
        if get_region_partition(region) is None:
            return self._validation_failure(
                f"IAM Roles Anywhere is not supported for the region "
                f"'{region}' (ISO and AWS European Sovereign Cloud "
                "regions are not supported).",
                "Ensure that Deployed on AWS or a region of the aws, aws-cn "
                "or aws-us-gov partition is used.",
            )
        return None

    def _validate_bucket_name(
        self, configuration: dict
    ) -> Optional[ValidationResult]:
        """Validate the bucket name (mandatory, non-empty string only).

        AWS (and botocore) validate the name itself.

        Args:
            configuration (dict): Step 1 configuration parameters.

        Returns:
            Optional[ValidationResult]: Failure result or None.
        """
        failure = self._check_required_string(
            configuration, "bucket_name", "AWS S3 Bucket Name"
        )
        if failure:
            return failure
        return None

    def _validate_filepath(
        self, configuration: dict
    ) -> Optional[ValidationResult]:
        """Validate the file path (File Path).

        Args:
            configuration (dict): Step 1 configuration parameters.

        Returns:
            Optional[ValidationResult]: Failure result or None.
        """
        failure = self._check_required_string(
            configuration, "filepath", "File Path"
        )
        if failure:
            return failure
        key = configuration["filepath"].strip()
        lowered = key.lower()
        supported = ", ".join(SUPPORTED_EXTENSIONS)
        if lowered.startswith("s3://"):
            return self._validation_failure(
                "File Path should be the file path only and must not "
                "start with 's3://'.",
                "Ensure that only the file path (e.g. folder/data.csv) is "
                "provided, without the s3:// prefix and the bucket name.",
            )
        if key.endswith("/"):
            return self._validation_failure(
                "File Path should point to a file and must not end with "
                "'/'.",
                "Ensure that the File Path is the exact path of the file to "
                "be pulled.",
            )
        if len(key.encode("utf-8")) > MAX_KEY_LENGTH_BYTES:
            return self._validation_failure(
                "File Path is too long. A file path can have at most "
                f"{MAX_KEY_LENGTH_BYTES} bytes.",
                "Ensure that the File Path is a valid file path.",
            )
        if not lowered.endswith(SUPPORTED_EXTENSIONS):
            return self._validation_failure(
                "Invalid file path provided in the configuration "
                f"parameter. The plugin only supports {supported} files.",
                "Ensure that the File Path ends with one of the supported "
                f"extensions: {supported}.",
            )
        return None

    def _validate_delimiter(
        self, configuration: dict
    ) -> Optional[ValidationResult]:
        """Validate the delimiter.

        Args:
            configuration (dict): Step 1 configuration parameters.

        Returns:
            Optional[ValidationResult]: Failure result or None.
        """
        delimiter = configuration.get("delimiter", ",")
        if not isinstance(delimiter, str) or not delimiter:
            return self._validation_failure(
                "Invalid value provided for the configuration parameter "
                "Delimiter.",
                "Ensure that the Delimiter is a non-empty string value. Tab "
                "and space delimiters are not supported because Cloud "
                "Exchange trims configuration values.",
            )
        if len(delimiter) != 1:
            return self._validation_failure(
                "Delimiter should be a single character.",
                "Ensure that a single character (e.g. ',', '|', ';') is "
                "provided for Delimiter.",
            )
        if delimiter in INVALID_DELIMITERS:
            return self._validation_failure(
                "The provided Delimiter is not supported.",
                "Ensure that the Delimiter is not a double quote or a "
                "line break character.",
            )
        return None

    def _validate_remove_quotes(
        self, configuration: dict
    ) -> Optional[ValidationResult]:
        """Validate the Remove Quotes parameter.

        Args:
            configuration (dict): Step 1 configuration parameters.

        Returns:
            Optional[ValidationResult]: Failure result or None.
        """
        if not isinstance(configuration.get("remove_quotes", False), bool):
            return self._validation_failure(
                "Invalid value provided for the configuration parameter "
                "Remove Quotes.",
                "Ensure that Remove Quotes is a valid boolean value.",
            )
        return None

    def validate_configuration_parameters(
        self, configuration: dict
    ) -> ValidationResult:
        """Validate the step 1 configuration parameters (no network).

        Args:
            configuration (dict): Step 1 configuration parameters.

        Returns:
            ValidationResult: Result of the validation.
        """
        checks = [self._validate_auth_method]
        if configuration.get("authentication_method") == AUTH_ROLES_ANYWHERE:
            checks.append(self._validate_roles_anywhere)
        checks.extend(
            [
                self._validate_region,
                self._validate_bucket_name,
                self._validate_filepath,
                self._validate_delimiter,
                self._validate_remove_quotes,
            ]
        )
        for check in checks:
            failure = check(configuration)
            if failure:
                return failure
        return ValidationResult(
            success=True,
            message="Successfully validated configuration parameters.",
        )
