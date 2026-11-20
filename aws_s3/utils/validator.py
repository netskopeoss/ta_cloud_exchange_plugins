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

AWS S3 WebTx configuration validator (no network calls).
"""

import re
from typing import Any, Optional

from . import constants as CONST
from .generate_temp_creds import (
    AWSS3GenerateTemporaryCredentials,
    MissingPassPhraseError,
    UnsupportedKeyTypeError,
)
from .helper import (
    get_arn_region,
    get_effective_region,
    log_error,
)


class AWSS3WebTxValidator:
    """Validate the AWS S3 WebTx configuration parameters.

    Every method returns None on success, or the logged error message
    (without the log prefix) to show in the ValidationResult.
    """

    def __init__(self, logger: Any, log_prefix: str) -> None:
        """Initialize the validator.

        Args:
            logger: CE logger object.
            log_prefix (str): Log prefix.
        """
        self.logger = logger
        self.log_prefix = log_prefix

    def _failure(
        self,
        cause: str,
        resolution: str,
        action: str = CONST.VALIDATION_ACTION,
    ) -> str:
        """Log a validation error.

        Args:
            cause (str): Specific reason.
            resolution (str): Resolution starting with "Ensure that".
            action (str): What was being done.

        Returns:
            str: The logged message without the log prefix.
        """
        return log_error(
            self.logger, self.log_prefix, action, resolution, cause=cause
        )

    def _check_required_string(
        self, configuration: dict, key: str, label: str, suffix: str = ""
    ) -> Optional[str]:
        """Check that a parameter is a non-empty string.

        The type is checked before the value is stripped.

        Args:
            configuration (dict): Plugin configuration parameters.
            key (str): Parameter key.
            label (str): Parameter label used in messages.
            suffix (str): Text appended to the "required" sentence.

        Returns:
            Optional[str]: Error message or None.
        """
        value = configuration.get(key)
        if value is None or value == "":
            return self._failure(
                f"{label} is a required configuration parameter{suffix}.",
                f"Ensure that a valid {label} is provided.",
            )
        if not isinstance(value, str) or not value.strip():
            return self._failure(
                "Invalid value provided for the configuration parameter "
                f"{label}.",
                f"Ensure that the {label} is a non-empty string value.",
            )
        return None

    def _validate_pem_values(self, configuration: dict) -> Optional[str]:
        """Validate the PEM encoded Private Key and Certificate Body.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: Error message or None.
        """
        generator = AWSS3GenerateTemporaryCredentials
        try:
            private_key = generator.load_private_key(
                configuration.get(CONST.PRIVATE_KEY_FILE_KEY).strip(),
                configuration.get(CONST.PASS_PHRASE_KEY),
            )
            generator.ensure_rsa_key(private_key)
        except MissingPassPhraseError:
            return self._failure(
                "Private Key is encrypted and no Password Phrase was "
                "provided.",
                "Ensure that the Password Phrase of the encrypted Private "
                "Key is provided.",
            )
        except UnsupportedKeyTypeError:
            return self._failure(
                "Unsupported Private Key type provided. Only RSA private "
                "keys are supported.",
                "Ensure that an RSA private key (PEM) that matches the "
                "certificate registered with the IAM Roles Anywhere trust "
                "anchor is provided.",
            )
        except Exception:
            return self._failure(
                "Invalid Private Key or Password Phrase provided. Private "
                "Key must be in valid PEM format.",
                "Ensure that the Private Key is in valid PEM format and the "
                "Password Phrase matches the encryption key.",
            )
        try:
            generator.load_certificate(
                configuration.get(CONST.PUBLIC_CERTIFICATE_FILE_KEY).strip()
            )
        except Exception:
            return self._failure(
                "Invalid Certificate Body provided. Certificate Body must "
                "be in valid PEM format.",
                "Ensure that the Certificate Body is a valid PEM encoded "
                "X.509 certificate.",
            )
        return None

    def validate_roles_anywhere(self, configuration: dict) -> Optional[str]:
        """Validate the AWS IAM Roles Anywhere parameters.

        The Password Phrase is optional (only needed for an encrypted
        Private Key) and is never stripped.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: Error message or None.
        """
        for key, label in (
            (CONST.PRIVATE_KEY_FILE_KEY, CONST.PRIVATE_KEY_LABEL),
            (CONST.PUBLIC_CERTIFICATE_FILE_KEY, CONST.CERTIFICATE_BODY_LABEL),
        ):
            failure = self._check_required_string(
                configuration, key, label, CONST.ROLES_ANYWHERE_SUFFIX
            )
            if failure:
                return failure
        pass_phrase = configuration.get(CONST.PASS_PHRASE_KEY)
        if pass_phrase is not None and not isinstance(pass_phrase, str):
            return self._failure(
                "Invalid value provided for the configuration parameter "
                "Password Phrase.",
                "Ensure that the Password Phrase is a string value.",
            )
        failure = self._validate_pem_values(configuration)
        if failure:
            return failure
        for key, label in (
            (CONST.PROFILE_ARN_KEY, CONST.PROFILE_ARN_LABEL),
            (CONST.ROLE_ARN_KEY, CONST.ROLE_ARN_LABEL),
            (CONST.TRUST_ANCHOR_ARN_KEY, CONST.TRUST_ANCHOR_ARN_LABEL),
        ):
            failure = self._check_required_string(
                configuration, key, label, CONST.ROLES_ANYWHERE_SUFFIX
            )
            if failure:
                return failure
        return None

    def validate_format(self, configuration: dict) -> Optional[str]:
        """Validate that the JSON format is selected (JSON-only plugin).

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: Error message or None.
        """
        if configuration.get("transformData", "json") == "json":
            return None
        return self._failure(
            "Only the JSON format is supported by this plugin.",
            "Ensure that 'JSON' is selected as the format in the plugin "
            "configuration.",
        )

    def validate_bucket_name(self, configuration: dict) -> Optional[str]:
        """Validate the AWS S3 bucket naming rules (no network call).

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: Error message or None.
        """
        bucket = (configuration.get(CONST.BUCKET_NAME_KEY) or "").strip()
        if re.fullmatch(
            CONST.BUCKET_NAME_REGEX, bucket
        ) and not bucket.endswith(CONST.BUCKET_RESERVED_SUFFIXES):
            return None
        return self._failure(
            "Invalid AWS S3 Bucket Name provided.",
            "Ensure that the AWS S3 Bucket Name is 3 to 63 characters long, "
            "contains only lowercase letters, numbers, dots and hyphens, "
            "starts and ends with a letter or number, and is not formatted "
            "as an IP address.",
        )

    def validate_region(self, configuration: dict) -> Optional[str]:
        """Validate the region dropdown and the AWS Custom Region.

        A stale AWS Custom Region is ignored when a dropdown region is
        selected.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: Error message or None.
        """
        selected = configuration.get(CONST.REGION_NAME_KEY)
        selected = selected.strip() if isinstance(selected, str) else ""
        if selected == CONST.CUSTOM_REGION_VALUE:
            failure = self._validate_custom_region(configuration)
            if failure:
                return failure
        elif selected not in CONST.REGIONS:
            return self._failure(
                "Invalid AWS S3 Bucket Region Name provided.",
                "Ensure that a region is selected from the available "
                "choices, or select Custom Region.",
            )
        method = configuration.get(CONST.AUTHENTICATION_METHOD_KEY)
        if method != CONST.AUTH_ROLES_ANYWHERE:
            return None
        return self._validate_roles_anywhere_region(
            configuration, get_effective_region(configuration)
        )

    def _validate_custom_region(self, configuration: dict) -> Optional[str]:
        """Validate the AWS Custom Region (DNS host label guard).

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: Error message or None.
        """
        custom = configuration.get(CONST.CUSTOM_REGION_NAME_KEY)
        if custom is None or (isinstance(custom, str) and not custom.strip()):
            return self._failure(
                "AWS Custom Region is a required configuration parameter "
                "when 'Custom Region' is selected.",
                "Ensure that the AWS Custom Region is provided, e.g. "
                "us-gov-west-1.",
            )
        if not isinstance(custom, str) or not re.fullmatch(
            CONST.REGION_NAME_REGEX, custom.strip()
        ):
            return self._failure(
                "Invalid AWS Custom Region provided.",
                "Ensure that the AWS Custom Region contains only letters, "
                "digits and hyphens and is the region code of the bucket, "
                "e.g. us-gov-west-1.",
            )
        return None

    def _validate_roles_anywhere_region(
        self, configuration: dict, region: str
    ) -> Optional[str]:
        """Validate the ARN regions for AWS IAM Roles Anywhere.

        A region that does not exist is not checked here; it fails when
        the endpoint is called.

        Args:
            configuration (dict): Plugin configuration parameters.
            region (str): Effective region.

        Returns:
            Optional[str]: Error message or None.
        """
        for key, label in (
            (CONST.PROFILE_ARN_KEY, "Profile"),
            (CONST.TRUST_ANCHOR_ARN_KEY, "Trust Anchor"),
        ):
            arn_region = get_arn_region(configuration.get(key))
            if arn_region and arn_region != region:
                return self._failure(
                    f"The region in the {label} ARN '{arn_region}' does "
                    f"not match the AWS S3 Bucket Region '{region}'.",
                    "Ensure that the AWS S3 Bucket Region (or AWS Custom "
                    "Region) is the region of the bucket, and that the "
                    "Profile ARN and Trust Anchor ARN use the same region.",
                )
        return None
