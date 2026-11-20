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

AWS S3 WebTx Plugin.
"""

import copy
from tempfile import NamedTemporaryFile
from typing import Any, List, Optional

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils.client import AWSS3WebTxClient
from .utils import constants as CONST
from .utils.exceptions import AWSS3WebTxException
from .utils.helper import (
    log_and_raise,
    log_error,
    normalize_externally_provisioned,
    remove_local_file,
    serialize_records,
)
from .utils.validator import AWSS3WebTxValidator


class AWSS3WebTxPlugin(PluginBase):
    """The AWS S3 WebTx plugin implementation class."""

    def __init__(self, name: Optional[str], *args: Any, **kwargs: Any) -> None:
        """Initialize the AWS S3 WebTx plugin.

        Args:
            name (Optional[str]): Configuration name.
            *args (Any): Positional arguments of PluginBase.
            **kwargs (Any): Keyword arguments of PluginBase.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{CONST.MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get the plugin name and version from the manifest.

        Returns:
            tuple: (plugin name, plugin version).
        """
        try:
            manifest_json = AWSS3WebTxPlugin.metadata
            plugin_name = manifest_json.get(
                CONST.MANIFEST_NAME_KEY, CONST.PLUGIN_NAME
            )
            plugin_version = manifest_json.get(
                CONST.MANIFEST_VERSION_KEY, CONST.PLUGIN_VERSION
            )
            return plugin_name, plugin_version
        except Exception:
            log_error(
                self.logger,
                f"{CONST.MODULE_NAME} {CONST.PLUGIN_NAME}",
                "getting plugin details",
                "Ensure that the plugin manifest.json is valid.",
            )
        return CONST.PLUGIN_NAME, CONST.PLUGIN_VERSION

    def _get_client(
        self, configuration: dict, storage: Optional[dict]
    ) -> AWSS3WebTxClient:
        """Create the AWS S3 WebTx client.

        Args:
            configuration (dict): Plugin configuration parameters.
            storage (Optional[dict]): Storage for the cached credentials.

        Returns:
            AWSS3WebTxClient: The client.
        """
        return AWSS3WebTxClient(
            configuration,
            self.logger,
            self.proxy,
            storage,
            self.log_prefix,
            CONST.USER_AGENT,
            ssl_validation=self.ssl_validation,
        )

    def get_dynamic_fields(self) -> list:
        """Return the configuration fields for the Authentication Method.

        Returns:
            list: Roles Anywhere fields (only for 'AWS IAM Roles Anywhere')
                followed by the fields shown for every method.
        """
        configuration = getattr(self, "configuration", None) or {}
        method = configuration.get(CONST.AUTHENTICATION_METHOD_KEY)
        if method == CONST.AUTH_ROLES_ANYWHERE:
            return copy.deepcopy(
                CONST.ROLES_ANYWHERE_FIELDS + CONST.COMMON_FIELDS
            )
        else:
            return copy.deepcopy(CONST.COMMON_FIELDS)

    def _validation_failure(
        self, cause: str, resolution: str
    ) -> ValidationResult:
        """Log a validation error and build the failed result.

        Args:
            cause (str): Specific reason.
            resolution (str): Resolution starting with "Ensure that".

        Returns:
            ValidationResult: Failed result with the logged message.
        """
        message = log_error(
            self.logger,
            self.log_prefix,
            CONST.VALIDATION_ACTION,
            resolution,
            cause=cause,
        )
        return ValidationResult(success=False, message=message)

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Any,
        required_cause: str,
        required_resolution: str,
        invalid_cause: str,
        invalid_resolution: str,
        allowed_values: Optional[tuple] = None,
    ) -> Optional[ValidationResult]:
        """Validate a required configuration parameter.

        The type is checked before any value is compared, so a non-string
        value never reaches ``strip``.

        Args:
            field_name (str): Parameter label.
            field_value (Any): Parameter value.
            required_cause (str): Message when the value is empty.
            required_resolution (str): Resolution when the value is empty.
            invalid_cause (str): Message when the value is invalid.
            invalid_resolution (str): Resolution when the value is invalid.
            allowed_values (Optional[tuple]): Allowed values.

        Returns:
            Optional[ValidationResult]: Failed result, or None when valid.
        """
        if field_value is None or (
            isinstance(field_value, str) and not field_value.strip()
        ):
            return self._validation_failure(
                required_cause, required_resolution
            )
        if not isinstance(field_value, str):
            return self._validation_failure(invalid_cause, invalid_resolution)
        if allowed_values is not None and field_value not in allowed_values:
            return self._validation_failure(invalid_cause, invalid_resolution)
        self.logger.debug(
            f"{self.log_prefix}: Validation successful for '{field_name}'."
        )
        return None

    def _validate_connectivity(
        self, configuration: dict
    ) -> Optional[ValidationResult]:
        """Check the credentials and the bucket (creates it if allowed).

        A fresh credential store is used so that credentials created for a
        configuration that is not saved yet never reach the CE storage.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Optional[ValidationResult]: Failed result, or None when valid.
        """
        try:
            client = self._get_client(configuration, {})
            client.set_credentials()
            client.verify_bucket_exists()
        except AWSS3WebTxException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception:
            bucket = configuration.get(CONST.BUCKET_NAME_KEY, "").strip()
            message = log_error(
                self.logger,
                self.log_prefix,
                f"verifying AWS S3 Bucket '{bucket}'",
                CONST.BUCKET_CHECK_RESOLUTION,
            )
            return ValidationResult(success=False, message=message)
        return None

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidationResult: Validation result (message without prefix).
        """
        validator = AWSS3WebTxValidator(self.logger, self.log_prefix)
        if message := validator.validate_format(configuration):
            return ValidationResult(success=False, message=message)

        authentication_method = configuration.get(
            CONST.AUTHENTICATION_METHOD_KEY
        )
        if result := self._validate_configuration_parameters(
            CONST.AUTHENTICATION_METHOD_LABEL,
            authentication_method,
            required_cause=(
                "Authentication Method is a required configuration "
                "parameter."
            ),
            required_resolution=(
                "Ensure that a valid Authentication Method is selected."
            ),
            invalid_cause=(
                "Invalid value provided for the configuration parameter "
                "Authentication Method."
            ),
            invalid_resolution=(
                "Ensure that 'Deployed on AWS' or 'AWS IAM Roles Anywhere' "
                "is selected as the Authentication Method."
            ),
            allowed_values=CONST.AUTH_METHODS,
        ):
            return result

        if authentication_method == CONST.AUTH_ROLES_ANYWHERE:
            if message := validator.validate_roles_anywhere(configuration):
                return ValidationResult(success=False, message=message)

        if result := self._validate_configuration_parameters(
            CONST.EXTERNALLY_PROVISIONED_BUCKET_LABEL,
            normalize_externally_provisioned(
                configuration.get(CONST.EXTERNALLY_PROVISIONED_BUCKET_KEY)
            ),
            required_cause=(
                "Invalid value provided for Externally Provisioned Bucket."
            ),
            required_resolution=(
                "Ensure that 'Yes' or 'No' is selected for Externally "
                "Provisioned Bucket."
            ),
            invalid_cause=(
                "Invalid value provided for Externally Provisioned Bucket."
            ),
            invalid_resolution=(
                "Ensure that 'Yes' or 'No' is selected for Externally "
                "Provisioned Bucket."
            ),
            allowed_values=CONST.EP_VALUES,
        ):
            return result

        if message := validator.validate_region(configuration):
            return ValidationResult(success=False, message=message)

        if result := self._validate_configuration_parameters(
            CONST.BUCKET_NAME_LABEL,
            configuration.get(CONST.BUCKET_NAME_KEY),
            required_cause=(
                "AWS S3 Bucket Name is a required configuration parameter."
            ),
            required_resolution=(
                "Ensure that the AWS S3 Bucket Name is provided."
            ),
            invalid_cause="Invalid value provided for AWS S3 Bucket Name.",
            invalid_resolution=(
                "Ensure that the AWS S3 Bucket Name is a string value."
            ),
        ):
            return result

        if message := validator.validate_bucket_name(configuration):
            return ValidationResult(success=False, message=message)

        if result := self._validate_connectivity(configuration):
            return result

        self.logger.debug(
            f"{self.log_prefix}: Successfully validated configuration "
            "parameters."
        )
        return ValidationResult(success=True, message="Validation successful.")

    def transform(
        self,
        raw_data: List[Any],
        data_type: Optional[str],
        subtype: Optional[str],
    ) -> List[Any]:
        """Return the WebTx data unchanged.

        The records are serialized in ``push``, which owns the gzip file.

        Args:
            raw_data (list): Parsed WebTx records (dict).
            data_type (str): Data type.
            subtype (str): Subtype.

        Returns:
            List[Any]: The records as received.
        """
        return raw_data

    @staticmethod
    def _get_log_tag(
        data_type: Optional[str], subtype: Optional[str]
    ) -> str:
        """Build the ``[data type] [subtype]`` tag of push logs.

        Args:
            data_type (Optional[str]): Data type.
            subtype (Optional[str]): Subtype.

        Returns:
            str: e.g. ``[webtx] [v2]``.
        """
        tag = f"[{data_type or CONST.WEBTX_DATA_TYPE}]"
        if subtype:
            tag = f"{tag} [{subtype}]"
        return tag

    def push(
        self,
        transformed_data: Optional[List[Any]],
        data_type: Optional[str],
        subtype: Optional[str],
    ) -> PushResult:
        """Upload the WebTx data to the AWS S3 bucket as one gzip object.

        The records are serialized first; credentials are fetched (Roles
        Anywhere CreateSession) only when there is something to upload.

        Args:
            transformed_data (list): Parsed WebTx records (dict).
            data_type (str): Data type, ``webtx``.
            subtype (str): WebTx subtype (feed name), e.g. ``v2``.

        Raises:
            AWSS3WebTxException: When the upload fails, so that CE retries.

        Returns:
            PushResult: Push result.
        """
        tag = self._get_log_tag(data_type, subtype)
        if data_type != CONST.WEBTX_DATA_TYPE:
            message = (
                f"{tag} Data type '{data_type}' is not supported, only "
                "WebTx data is supported. The log(s) were skipped."
            )
            self.logger.info(f"{self.log_prefix}: {message}")
            return PushResult(success=True, message=message)

        bucket = ""
        temp_path = None
        try:
            # A non-string value raises here and is logged below.
            bucket = self.configuration.get(CONST.BUCKET_NAME_KEY).strip()
            with NamedTemporaryFile(
                "wb", delete=False, suffix=CONST.TEMP_FILE_SUFFIX
            ) as temp_file:
                temp_path = temp_file.name
                result = serialize_records(transformed_data or [], temp_file)
            if result.failed:
                log_error(
                    self.logger,
                    self.log_prefix,
                    f"serializing {result.failed} WebTx log(s); they were "
                    "skipped",
                    "Ensure that the source plugin sends valid WebTx "
                    "records.",
                    details=(
                        f"{tag} {result.failed} WebTx log(s) are not parsed "
                        "WebTx records or could not be converted to JSON."
                    ),
                )
            if result.skipped:
                self.logger.info(
                    f"{self.log_prefix}: {tag} Skipped {result.skipped} "
                    "empty WebTx log(s)."
                )
            if not result.written:
                message = f"{tag} No WebTx log(s) to ingest."
                self.logger.debug(
                    f"{self.log_prefix}: {message} Nothing was uploaded."
                )
                return PushResult(success=True, message=message)
            client = self._get_client(self.configuration, self.storage)
            client.set_credentials()
            key = client.push(temp_path, subtype)
            message = (
                f"{tag} Successfully ingested {result.written} log(s) to "
                f"AWS S3 Bucket '{bucket}'. Object: '{key}'."
            )
            self.logger.info(f"{self.log_prefix}: {message}")
            return PushResult(success=True, message=message)
        except AWSS3WebTxException:
            raise
        except Exception as err:
            log_and_raise(
                self.logger,
                self.log_prefix,
                f"pushing WebTx logs to AWS S3 Bucket '{bucket}'",
                "Ensure that the plugin configuration is valid. Check the "
                "logs for details.",
                err=err,
            )
        finally:
            remove_local_file(temp_path)
