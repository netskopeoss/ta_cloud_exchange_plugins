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
Google Cloud Storage configuration validator (no network calls).
"""

import json
import re
from typing import Any, Optional

from . import constants as CONST
from .helper import log_error, parse_key_file


class GCPStorageValidator:
    """Validate the Google Cloud Storage configuration parameters.

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

    def _failure(self, cause: str, resolution: str) -> str:
        """Log a validation error.

        Args:
            cause (str): Specific reason.
            resolution (str): Resolution starting with "Ensure that".

        Returns:
            str: The logged message.
        """
        return log_error(
            self.logger,
            self.log_prefix,
            CONST.VALIDATION_ACTION,
            resolution,
            cause=cause,
            details=cause,
        )

    def _check_string(
        self, value: Any, label: str, resolution: str
    ) -> Optional[str]:
        """Check that a required parameter is a non-empty string.

        The empty check and the type check are separate so that the user
        gets the exact reason.

        Args:
            value (Any): Parameter value.
            label (str): Parameter label.
            resolution (str): Resolution when the check fails.

        Returns:
            Optional[str]: Error message, None when valid.
        """
        if value is None or (isinstance(value, str) and not value.strip()):
            return self._failure(
                f"{label} is a required configuration parameter.",
                resolution,
            )
        if not isinstance(value, str):
            return self._failure(
                f"Invalid value provided for {label}. It must be a string.",
                resolution,
            )
        return None

    def validate_key_file(self, configuration: dict) -> Optional[str]:
        """Validate the Service Account key file.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: Error message, None when valid.
        """
        value = configuration.get(CONST.KEY_FILE_KEY)
        resolution = (
            "Ensure that the contents of the Service Account JSON key file "
            f"are provided in {CONST.KEY_FILE_LABEL}."
        )
        if message := self._check_string(value, CONST.KEY_FILE_LABEL,
                                         resolution):
            return message
        try:
            parsed = parse_key_file(value)
        except (ValueError, json.JSONDecodeError):
            return self._failure(
                f"Invalid value provided for {CONST.KEY_FILE_LABEL}. It is "
                "not a valid JSON object.",
                resolution,
            )
        missing = [
            field
            for field in CONST.REQUIRED_KEY_FILE_FIELDS
            if not isinstance(parsed.get(field), str)
            or not parsed.get(field).strip()
        ]
        if missing:
            return self._failure(
                f"Invalid value provided for {CONST.KEY_FILE_LABEL}. "
                f"Required field(s) missing: {', '.join(missing)}.",
                resolution,
            )
        if parsed.get("type") != CONST.SERVICE_ACCOUNT_TYPE:
            return self._failure(
                f"Invalid value provided for {CONST.KEY_FILE_LABEL}. The "
                "key file is not of a Service Account.",
                resolution,
            )
        return None

    def validate_bucket_name(self, configuration: dict) -> Optional[str]:
        """Validate the bucket name against the bucket naming rules.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: Error message, None when valid.
        """
        value = configuration.get(CONST.BUCKET_NAME_KEY)
        resolution = (
            "Ensure that the Bucket Name is 3 to 63 characters long, "
            "contains only lowercase letters, numbers, dashes, underscores "
            "and dots, and starts and ends with a letter or number."
        )
        if message := self._check_string(
            value, CONST.BUCKET_NAME_LABEL, resolution
        ):
            return message
        name = value.strip()
        if (
            not re.fullmatch(CONST.BUCKET_NAME_REGEX, name)
            or re.fullmatch(CONST.IP_ADDRESS_REGEX, name)
            or name.startswith(CONST.BUCKET_RESERVED_PREFIX)
            or CONST.BUCKET_RESERVED_WORD in name.replace("0", "o")
        ):
            return self._failure(
                f"Invalid value provided for {CONST.BUCKET_NAME_LABEL}.",
                resolution,
            )
        return None

    def validate_location(self, configuration: dict) -> Optional[str]:
        """Validate the Region Name and the Custom Region.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: Error message, None when valid.
        """
        value = configuration.get(CONST.LOCATION_KEY)
        resolution = (
            f"Ensure that a valid {CONST.LOCATION_LABEL} is selected."
        )
        if message := self._check_string(
            value, CONST.LOCATION_LABEL, resolution
        ):
            return message
        if value.strip() != CONST.CUSTOM_LOCATION_VALUE:
            if value.strip() not in CONST.LOCATIONS:
                return self._failure(
                    f"Invalid value provided for {CONST.LOCATION_LABEL}.",
                    resolution,
                )
            return None
        custom = configuration.get(CONST.CUSTOM_LOCATION_KEY)
        resolution = (
            f"Ensure that a valid location (e.g. me-central2) is provided "
            f"in {CONST.CUSTOM_LOCATION_LABEL}."
        )
        if message := self._check_string(
            custom, CONST.CUSTOM_LOCATION_LABEL, resolution
        ):
            return message
        if not re.fullmatch(CONST.LOCATION_REGEX, custom.strip()):
            return self._failure(
                f"Invalid value provided for {CONST.CUSTOM_LOCATION_LABEL}.",
                resolution,
            )
        return None

    def validate_storage_class(self, configuration: dict) -> Optional[str]:
        """Validate the storage class.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: Error message, None when valid.
        """
        value = configuration.get(CONST.STORAGE_CLASS_KEY)
        resolution = (
            f"Ensure that a valid {CONST.STORAGE_CLASS_LABEL} is selected."
        )
        if message := self._check_string(
            value, CONST.STORAGE_CLASS_LABEL, resolution
        ):
            return message
        if value.strip() not in CONST.STORAGE_CLASSES:
            return self._failure(
                f"Invalid value provided for {CONST.STORAGE_CLASS_LABEL}.",
                resolution,
            )
        return None

    def validate_object_prefix(self, configuration: dict) -> Optional[str]:
        """Validate the object prefix.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: Error message, None when valid.
        """
        value = configuration.get(CONST.OBJECT_PREFIX_KEY)
        resolution = (
            f"Ensure that the {CONST.OBJECT_PREFIX_LABEL} is provided and "
            f"is not longer than {CONST.OBJECT_PREFIX_MAX_LENGTH} characters."
        )
        if message := self._check_string(
            value, CONST.OBJECT_PREFIX_LABEL, resolution
        ):
            return message
        prefix = value.strip()
        if len(prefix) > CONST.OBJECT_PREFIX_MAX_LENGTH:
            return self._failure(
                f"Invalid value provided for {CONST.OBJECT_PREFIX_LABEL}.",
                resolution,
            )
        # The prefix is the top-level folder of the object name. Google
        # Cloud Storage rejects names with control characters and with
        # '.' or '..' path segments, and an empty folder name is not wanted.
        folder = prefix.strip("/")
        segments = folder.split("/")
        if (
            not folder
            or re.search(r"[\x00-\x1f\x7f]", prefix)
            or any(segment in ("", ".", "..") for segment in segments)
        ):
            return self._failure(
                f"Invalid value provided for {CONST.OBJECT_PREFIX_LABEL}. "
                "It must be a folder name that has no empty, '.' or '..' "
                "path segments and no control characters.",
                "Ensure that the Object Prefix is a folder name such as "
                "'netskope' or 'netskope/logs'.",
            )
        return None

    def validate_compression(self, configuration: dict) -> Optional[str]:
        """Validate the compression.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: Error message, None when valid.
        """
        value = configuration.get(
            CONST.COMPRESSION_KEY, CONST.COMPRESSION_GZIP
        )
        if value not in CONST.COMPRESSION_OPTIONS:
            return self._failure(
                f"Invalid value provided for {CONST.COMPRESSION_LABEL}.",
                f"Ensure that a valid {CONST.COMPRESSION_LABEL} is "
                "selected.",
            )
        return None

    def validate_format(self, configuration: dict) -> Optional[str]:
        """Run all the checks that need no network call.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[str]: First error message, None when all are valid.
        """
        for check in (
            self.validate_key_file,
            self.validate_bucket_name,
            self.validate_location,
            self.validate_storage_class,
            self.validate_object_prefix,
            self.validate_compression,
        ):
            if message := check(configuration):
                return message
        return None
