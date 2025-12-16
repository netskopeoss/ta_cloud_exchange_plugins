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

"""CLS Google Chronicle Plugin."""


import sys
import time
import datetime
import traceback
import json
import re
import urllib
from typing import List, Union, Callable, Tuple
from jsonpath import jsonpath
from packaging import version

from google.oauth2 import service_account
from netskope.common.api import __version__ as CE_VERSION
from netskope.common.utils import AlertsHelper, add_user_agent
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from .utils.chronicle_client import (
    ChronicleClient,
)
from .utils.chronicle_helper import (
    get_chronicle_mappings,
    validate_chronicle_mappings,
    split_into_size,
    patch_logger_methods,
)
from .utils.chronicle_udm_generator import (  # NOQA: E501
    UDMGenerator,
)
from .utils.chronicle_exceptions import (
    MappingValidationError,
    EmptyExtensionError,
    FieldNotFoundError,
    GoogleChroniclePluginException,
)
from .utils.chronicle_validator import (
    ChronicleValidator,
)
from .utils.chronicle_constants import (
    SCOPES,
    DUMMY_DATA,
    DEFAULT_URL,
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    DUMMY_DATA_JSON,
    MAXIMUM_CORE_VERSION,
    BATCH_SIZE
)


class ChroniclePlugin(PluginBase):
    """The Chronicle plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init method.

        Args:
            name (str): Configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.resolution_support = version.parse(CE_VERSION) > version.parse(
            MAXIMUM_CORE_VERSION
        )
        self.is_ce_version_greater_than_512 = self.resolution_support
        self.logger.error = patch_logger_methods(
            self.logger, self.resolution_support
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = ChroniclePlugin.metadata
            plugin_name = metadata_json.get("name", PLUGIN_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
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

    def _add_user_agent(self, headers={}) -> str:
        """Add User-Agent in the headers of any request.

        Returns:
            str: String containing the User-Agent.
        """
        if headers and "User-Agent" in headers:
            return headers

        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.replace(" ", "-").lower(),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: List = None,
        custom_validation_func: Callable = None,
        is_required: bool = False,
        additional_msg: str = "",
        validation_err_msg: str = "Validation error occurred. ",
    ) -> Union[ValidationResult, None]:
        """
        Validate the given configuration field value.

        Args:
            field_name (str): Name of the configuration field.
            field_value (str, List, bool, int): Value of the configuration
                field.
            field_type (type): Expected type of the configuration field.
            allowed_values (List, optional): List of allowed values for
                the configuration field. Defaults to None.
            custom_validation_func (Callable, optional): Custom validation
                function to be applied. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.
            additional_msg (str, optional): Additional message to be logged
                in case of validation failure. Defaults to "".
            validation_err_msg (str, optional): Error message to be logged in
                case of validation failure. Defaults to "Validation error
                occurred. ".

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        if field_type is str:
            field_value = field_value.strip()
        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = f"{field_name} is a required configuration parameter"
            resolution = (
                f"Ensure that {field_name} value is provided in the "
                "configuration parameters"
            )
            if additional_msg:
                err_msg += f" {additional_msg}"
                resolution += f" {additional_msg}"
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}.",
                resolution=f"{resolution}.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(field_value, field_type):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
                resolution=(
                    f"Ensure that valid value for {field_name} is "
                    "provided in the configuration parameters."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if custom_validation_func and not custom_validation_func(field_value):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
                resolution=(
                    f"Ensure that valid value for {field_name} is "
                    "provided in the configuration parameters."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if allowed_values:
            allowed_values_str = (
                ", ".join(value.capitalize() for value in allowed_values)
            )
            if len(allowed_values) <= 5:
                err_msg = (
                    f"Invalid value provided for the configuration"
                    f" parameter '{field_name}'. Allowed values are"
                    f" {allowed_values_str}."
                )
            else:
                err_msg = (
                    f"Invalid value for '{field_name}' provided "
                    f"in the configuration parameters."
                )
            if field_type is str and field_value not in allowed_values:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                    ),
                    resolution=(
                        f"Ensure that valid value for {field_name} is "
                        "provided in the configuration parameters "
                        "and it should be one of "
                        f"{allowed_values_str}."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        validation_msg = f"{self.log_prefix}: Validation error occurred."

        transform_data_json = self._transformation_compatibility_check(
            configuration
        )
        if transform_data_json:
            log_source_identifier = configuration.get(
                "log_source_identifier", ""
            ).strip()
            additional_msg = (
                "if transformed data is not enabled "
                "or JSON Format is selected in 'Basic Information'"
            )

            # Validate Log Source Identifier
            if validation_result := self._validate_configuration_parameters(
                field_name="Log Source Identifier",
                field_value=log_source_identifier,
                field_type=str,
                is_required=True,
                additional_msg=additional_msg,
            ):
                return validation_result

        # Validate Service Account Key
        service_account_key = configuration.get(
            "service_account_key", ""
        ).strip()
        if validation_result := self._validate_configuration_parameters(
            field_name="Service Account Key",
            field_value=service_account_key,
            field_type=str,
            is_required=True,
        ):
            return validation_result

        # Validate Customer ID
        customer_id = configuration.get("customer_id", "").strip()
        if validation_result := self._validate_configuration_parameters(
            field_name="Customer ID",
            field_value=customer_id,
            field_type=str,
            is_required=True,
        ):
            return validation_result

        # Validate Region
        region = configuration.get("region", "").strip()
        if validation_result := self._validate_configuration_parameters(
            field_name="Region",
            field_value=region,
            field_type=str,
            allowed_values=["usa", "europe", "asia", "custom"],
            is_required=True,
        ):
            return validation_result

        # Validate credentials
        try:
            self._validate_auth(configuration)
        except GoogleChroniclePluginException as err:
            err_msg = re.sub(
                r"key=(.*?) ",
                "key=******** ",
                f"Could not validate authentication credentials. "
                f"Error: {repr(err)}.",
            )
            resolution = (
                "Check the Service Account Key provided "
                "in the configuration parameters."
            )
            self.logger.error(
                message=f"{validation_msg} {err_msg}",
                details=f"{err}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False,
                message="Error while connecting to Chronicle. "
                "Please check Service Account Key.",
            )

        try:
            flag, url_path_value = self.udm_events_url_check(configuration)
            if not flag:
                error_message = (
                    f"Please enter the URL without {url_path_value}"
                )
                self.logger.error(
                    message=f"{validation_msg} {error_message}",
                    resolution=error_message,
                )
                return ValidationResult(
                    success=False,
                    message=error_message,
                )

            region = configuration.get("region", "")
            custom_region = configuration.get("custom_region", "").strip()
            # Validate Custom Region URL
            if validation_result := self._validate_configuration_parameters(
                field_name="Custom Region URL",
                field_value=custom_region,
                field_type=str,
            ):
                return validation_result
            result = self._check_dummy_post(configuration)
            if not result and region != "custom":
                error_message = "Invalid credentials or region."
                resolution = (
                    "Check the Service Account Key, Customer ID "
                    "and Region provided in the configuration parameters."
                )
                self.logger.error(
                    message=f"{validation_msg} {error_message}",
                    resolution=resolution,
                )
                return ValidationResult(
                    success=False,
                    message=error_message,
                    resolution=resolution,
                )
            if region == "custom" and (not result or custom_region == ""):
                error_message = "Invalid Custom Region URL provided."
                resolution = (
                    "Provide a valid Custom Region URL in "
                    "the configuration parameters."
                )
                self.logger.error(
                    message=f"{validation_msg} {error_message}",
                    resolution=resolution,
                )
                return ValidationResult(
                    success=False,
                    message=error_message,
                    resolution=resolution,
                )
        except GoogleChroniclePluginException as ex:
            if region != "custom":
                error_message = (
                    "Error occurred while validating the credentials. "
                    "Make sure that the Service Account Key, Region "
                    "and Customer ID is correct."
                )
                resolution = (
                    "Make sure that the Service Account Key, Region "
                    "and Customer ID is correct."
                )
            elif region == "custom" or custom_region == "":
                error_message = (
                    "Error occurred while validating the credentials. "
                    "Make sure that the custom region URL is correct."
                )
                resolution = (
                    "Make sure that the custom region URL is correct."
                )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Exception: {repr(ex)}."
                ),
                details=str(traceback.format_exc()),
                resolution=resolution,
            )
            return ValidationResult(
                success=False,
                message=error_message,
            )
        except Exception as ex:
            error_message = "Error occurred with while validating credentials."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Exception: {repr(ex)}."
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{error_message} Check logs for more details.",
            )
        mappings_validation_result = self.validate_mappings()

        if not mappings_validation_result.success:
            return mappings_validation_result

        return ValidationResult(success=True, message="Validation successful.")

    def validate_mappings(self):
        """Validate the Chronicle mappings for all data type.

        Raises:
            MappingValidationError: When validation fails for \
                any of the configured data_type.
        """
        validation_err_msg = (
            f"{self.log_prefix}: Mapping validation error occurred."
        )
        err_msg = "Invalid attribute mapping provided."
        chronicle_validator = ChronicleValidator(self.logger, self.log_prefix)

        def _validate_json_data(json_string):
            """Validate that the jsonData should not be empty."""
            try:
                json_object = json.loads(json_string)
                if not bool(json_object):
                    raise ValueError("JSON data should not be empty.")
            except json.decoder.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON: {e}")
            except Exception as e:
                raise ValueError(f"Error occurred while validating JSON: {e}.")
            return json_object

        try:
            mappings = _validate_json_data(self.mappings.get("jsonData"))
        except Exception as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )

        if (
            not isinstance(mappings, dict)
            or not chronicle_validator.validate_chronicle_mapping_format(mappings)
        ):
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        for data_type in mappings.get("taxonomy", {}).keys():
            try:
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Validating the mappings for "
                        f"chronicle {data_type}."
                    )
                )
                validate_chronicle_mappings(mappings, data_type)
            except MappingValidationError as mapping_validation_error:
                self.logger.error(
                    message=(
                        f"{validation_err_msg} {err_msg} Error: "
                        f"{mapping_validation_error}"
                    ),
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

        return ValidationResult(
            success=True,
            message="Mappings validation successful.",
        )

    def udm_events_url_check(self, configuration):
        """Check url.

        Args:
            configuration (dict): plugin configuration
        """
        BASE_URL = configuration.get("custom_region", "").strip()
        parsed = urllib.parse.urlparse(BASE_URL)
        if not (parsed.scheme in ["http", "https"] and parsed.netloc != ""):
            return True, ""
        if parsed.path.strip() == "/" or parsed.path == "":
            return True, parsed.path.strip()
        else:
            return False, parsed.path.strip()

    def _validate_auth(self, configuration: dict) -> ValidationResult:
        """Validate service account key by making REST API call."""
        try:
            credentials = (
                service_account.Credentials.from_service_account_info(
                    json.loads(configuration["service_account_key"]),
                    scopes=SCOPES,
                )
            )
        except Exception as ex:
            raise GoogleChroniclePluginException(ex)

    def _check_dummy_post(self, configuration: dict):
        try:

            if configuration.get("region", "") == "custom":
                BASE_URL = configuration.get("custom_region", "").strip()
            else:
                BASE_URL = DEFAULT_URL[configuration.get("region", "usa")]

            if (
                not self._url_valid(BASE_URL)
                and configuration.get("region", "") == "custom"
            ):
                return False

            chronicle_client = ChronicleClient(
                configuration, self.logger, self.log_prefix, self.plugin_name
            )
            headers = self._add_user_agent()
            if configuration.get("region", "") == "custom":
                headers.update(
                    {
                        "x-goog-user-project": configuration.get(
                            "custom_region", ""
                        ).strip()
                    }
                )
            transform_data_json = self._transformation_compatibility_check(
                configuration
            )
            if transform_data_json:
                result = chronicle_client.ingest(
                    DUMMY_DATA_JSON, headers=headers, is_validate=True
                )
            else:
                result = chronicle_client.ingest(
                    DUMMY_DATA, headers=headers, is_validate=True
                )

            if result:
                return True
            else:
                return False
        except GoogleChroniclePluginException as err:
            raise GoogleChroniclePluginException(str(err))
        except Exception as err:
            raise GoogleChroniclePluginException(str(err))

    def _url_valid(self, base_url):
        parsed = urllib.parse.urlparse(base_url.strip())
        if parsed.scheme in ["http", "https"] and parsed.netloc != "":
            return True
        else:
            return False

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform.

        Args:
            transformed_data (list): The transformed data to be ingested.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested \
            (DLP, anomaly etc. in case of alerts)

        Returns:
            PushResult: Result indicating ingesting outcome and message
        """
        try:
            batch_size = sys.getsizeof(f"{transformed_data}")
            if batch_size > BATCH_SIZE:
                transformed_data = split_into_size(transformed_data)
            else:
                transformed_data = [transformed_data]

            chronicle_client = ChronicleClient(
                self.configuration,
                self.logger,
                self.log_prefix,
                self.plugin_name,
            )
            headers = self._add_user_agent()

            skipped_count = 0
            total_count = 0
            page = 0

            for chunk in transformed_data:
                page += 1
                try:
                    chronicle_client.ingest(chunk, headers=headers)
                    log_msg = (
                        f"[{data_type}][{subtype}] Successfully ingested "
                        f"{len(chunk)} {data_type} for page {page} "
                        f"to {self.plugin_name}."
                    )
                    self.logger.info(f"{self.log_prefix}: {log_msg}")
                    total_count += len(chunk)
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}] "
                            f"Error occurred while ingesting data. "
                            f"Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skipped_count += len(chunk)
                    continue
            if skipped_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skipped_count} records "
                    "due to some unexpected error occurred, "
                    "check logs for more details."
                )

            log_msg = (
                f"[{data_type}][{subtype}] Successfully ingested "
                f"{total_count} {data_type} to {self.plugin_name}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
        except GoogleChroniclePluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while ingesting "
                    f"[{data_type}][{subtype}]. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise err
        except Exception as err:
            err_msg = (
                f"Error occurred while ingesting "
                f"[{data_type}][{subtype}] data to {PLUGIN_NAME}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}" f" Error: {str(err)}"
                ),
                details=str(traceback.format_exc()),
            )
            raise err

    def get_mapping_value_from_json_path(self, data, json_path):
        """To Fetch the value from given JSON object using given JSON path.

        Args:
            data: JSON object from which the value is to be fetched
            json_path: JSON path indicating the path of the value in given JSON

        Returns:
            fetched value.
        """
        return jsonpath(data, json_path)

    def get_mapping_value_from_field(self, data, field):
        """To Fetch the value from given field.

        Args:
            data: JSON object from which the value is to be fetched
            field: Field whose value is to be fetched

        Returns:
            fetched value.
        """
        return (
            data[field]
            if data[field] or isinstance(data[field], int)
            else "null"
        )

    def get_subtype_mapping(self, mappings, subtype):
        """To Retrieve subtype mappings case insensitively.

        Args:
            mappings: Mapping JSON from which subtypes are to be retrieved
            subtype: Subtype (e.g. DLP for alerts) for which the mapping is
            to be fetched

        Returns:
            Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def get_headers(self, header_mappings, data, data_type, subtype):
        """To Create a dictionary of UDM headers from given header mappings.

        Args:
            subtype: Subtype for which the headers are being transformed
            data_type: Data type for which the headers are being transformed
            header_mappings: UDM header mapping with Netskope fields
            data: The alert/event for which the UDM header is being generated

        Returns:
            header dict
        """
        headers = {}
        helper = AlertsHelper()
        tenant = helper.get_tenant_cls(self.source)
        mapping_variables = {"$tenant_name": tenant.name}

        try:
            headers["metadata.event_timestamp"] = (
                datetime.datetime.utcfromtimestamp(
                    data.get("timestamp", time.time())
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
            )
        except Exception:
            raise

        missing_fields = []
        # Iterate over mapped headers
        for udm_header, header_mapping in header_mappings.items():
            try:
                headers[udm_header] = self.get_field_value_from_data(
                    header_mapping, data, data_type, subtype, False
                )

                # Handle variable mappings
                if (
                    isinstance(headers[udm_header], str)
                    and headers[udm_header].lower() in mapping_variables
                ):
                    headers[udm_header] = mapping_variables[
                        headers[udm_header].lower()
                    ]
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return headers

    def get_extensions(self, extension_mappings, data, data_type, subtype):
        """Fetch extensions from given mappings.

        Args:
            subtype: Subtype for which the headers are being transformed
            data_type: Data type for which the headers are being transformed
            extension_mappings: Mapping of extensions
            data: The data to be transformed

        Returns:
            extensions (dict)
        """
        extension = {}
        missing_fields = []

        # Iterate over mapped extensions
        for udm_extension, extension_mapping in extension_mappings.items():
            try:
                extension[udm_extension] = self.get_field_value_from_data(
                    extension_mapping,
                    data,
                    data_type,
                    subtype,
                    is_json_path="is_json_path" in extension_mapping,
                )
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return extension

    def get_field_value_from_data(
        self, extension_mapping, data, data_type, subtype, is_json_path=False
    ):
        """To Fetch the value of extension based on "mapping" and "default".

        Args:
            extension_mapping: Dict containing "mapping" and "default" fields
            data: Data instance retrieved from Netskope
            subtype: Subtype for which the extension are being transformed
            data_type: Data type for which the headers are being transformed
            is_json_path: Whether the mapped value is JSON path or direct
            field name

        Returns:
            Fetched values of extension

        ---------------------------------------------------------------------
             Mapping          |    Response    |    Retrieved Value
        ----------------------|                |
        default  |  Mapping   |                |
        ---------------------------------------------------------------------
           P     |     P      |        P       |           Mapped
           P     |     P      |        NP      |           Default
           P     |     NP     |        P       |           Default
           NP    |     P      |        P       |           Mapped
           P     |     NP     |        NP      |           Default
           NP    |     P      |        NP      |           -
           NP    |     NP     |        P       |           - (Not possible)
           NP    |     NP     |        NP      |           - (Not possible)
        -----------------------------------------------------------------------
        """
        if (
            "mapping_field" in extension_mapping
            and extension_mapping["mapping_field"]
        ):
            if is_json_path:
                # If mapping field specified by JSON path is present in data,
                #  map that field, else skip by raising
                # exception:
                value = self.get_mapping_value_from_json_path(
                    data, extension_mapping["mapping_field"]
                )
                if value:
                    return ",".join(map(str, value))
                else:
                    raise FieldNotFoundError(
                        extension_mapping["mapping_field"]
                    )
            else:
                # TODO: Add merging feild logic
                # If mapping is present in data, map that field,
                # else skip by raising exception
                field_list = extension_mapping["mapping_field"].split("-")
                if len(field_list) == 1:
                    if (
                        extension_mapping["mapping_field"] in data
                    ):  # case #1 and case #4
                        return self.get_mapping_value_from_field(
                            data, extension_mapping["mapping_field"]
                        )
                    elif "default_value" in extension_mapping:
                        # If mapped value is not found in response and default
                        #  is mapped, map the default value (case #2)
                        return extension_mapping["default_value"]
                    else:  # case #6
                        raise FieldNotFoundError(
                            extension_mapping["mapping_field"]
                        )
                out_list = []
                for field in field_list:
                    field = field.strip(" ")
                    field = field.strip("[]")
                    if field == "NULL":
                        out_list.append("NULL")
                    elif field in data:  # case #1 and case #4
                        out_list.append(
                            self.get_mapping_value_from_field(data, field)
                        )
                    elif "default_value" in extension_mapping:
                        # If mapped value is not found in response and default
                        # is mapped, map the default value (case #2)
                        return extension_mapping["default_value"]
                    else:  # case #6
                        raise FieldNotFoundError(
                            extension_mapping["mapping_field"]
                        )
                return " - ".join(out_list)
        else:
            # If mapping is not present, 'default_value' must be there
            # because of validation (case #3 and case #5)
            return extension_mapping["default_value"]

    def map_json_data(self, mappings, data, data_type, subtype):
        """Filter the raw data and returns the filtered data.

        :param mappings: List of fields to be pushed
        :param data: Data to be mapped (retrieved from Netskope)
        :param logger: Logger object for logging purpose
        :return: Mapped data based on fields given in mapping file
        """
        if mappings == []:
            return data

        mapped_dict = {}
        for key in mappings:
            if key in data:
                mapped_dict[key] = data[key]

        return mapped_dict

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw data into target platform supported data formats.

        Args:
            raw_data (list): The raw data to be tranformed.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested
            (DLP, anomaly etc. in case of alerts)

        Returns:
            List: list of transformed data.
        """
        skip_count = 0
        skipped_logs = 0
        data_type_sub_type = f"[{data_type}][{subtype}] - "
        transform_data_json = self._transformation_compatibility_check(
            self.configuration
        )

        (
            udm_version,
            chronicle_mappings
        ) = self._validate_chronicle_mappings_helper(
            data_type_sub_type, data_type
        )
        if transform_data_json:
            try:
                subtype_mapping = self.get_subtype_mapping(
                    chronicle_mappings["json"][data_type], subtype
                )
                if not subtype_mapping:
                    transformed_data = []
                    for data in raw_data:
                        if data:
                            result = {
                                "log_text": json.dumps(data),
                                "ts_epoch_microseconds": int(
                                    datetime.datetime.now().timestamp() * 1_000_000
                                )
                            }
                            transformed_data.append(result)
                        else:
                            skipped_logs += 1
                    return transformed_data

            except GoogleChroniclePluginException:
                raise
            except Exception as err:
                error_msg = (
                    f"{data_type_sub_type}"
                    "Error occurred while retrieving "
                    f"mappings."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise GoogleChroniclePluginException(error_msg)

            transformed_data = []

            for data in raw_data:
                mapped_dict = self.map_json_data(subtype_mapping, data)
                if mapped_dict:
                    result = {
                            "log_text": json.dumps(mapped_dict),
                            "ts_epoch_microseconds": int(
                                datetime.datetime.now().timestamp() * 1_000_000
                            )
                        }
                    transformed_data.append(result)
                else:
                    skipped_logs += 1

            if skipped_logs > 0:
                self.logger.info(
                    "{}: {} Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured JSON mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(
                        self.log_prefix, data_type_sub_type, skipped_logs
                    )
                )
            return transformed_data

        else:
            transformed_data = []
            udm_generator = UDMGenerator(
                self.mappings, udm_version, self.logger, self.log_prefix
            )
            # First retrieve the mapping of subtype being transformed
            try:
                subtype_mapping = self.get_subtype_mapping(
                    chronicle_mappings[data_type], subtype
                )
            except Exception:
                err_msg = (
                    f"Error occurred while retrieving "
                    f"mappings for subtype {subtype}. "
                    "Transformation of current batch will be skipped."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {err_msg}"),
                    details=str(traceback.format_exc()),
                )
                raise

            total_skip_fields = {}
            for data in raw_data:
                if not data:
                    skip_count += 1
                    continue
                # Generating the UDM header
                try:
                    header = self.get_headers(
                        subtype_mapping["header"], data, data_type, subtype
                    )
                except Exception as err:
                    err_msg = (
                        f"[{data_type}][{subtype}]: Error occurred while "
                        f"creating UDM header: {str(err)}. Transformation of "
                        f"current record will be skipped."
                    )
                    self.logger.error(
                        message=(f"{self.log_prefix}: {err_msg}"),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1
                    continue

                try:
                    extension = self.get_extensions(
                        subtype_mapping["extension"], data, data_type, subtype
                    )
                except Exception as err:
                    err_msg = (
                        f"[{data_type}][{subtype}]: Error occurred while "
                        f"creating UDM extension: {str(err)}."
                        f" Transformation of the current record "
                        "will be skipped."
                    )
                    self.logger.error(
                        message=(f"{self.log_prefix}: {err_msg}"),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1
                    continue

                try:
                    udm_generated_event, skip_fields = udm_generator.get_udm_event(
                        data, header, extension, data_type, subtype
                    )
                    for field in skip_fields:
                        total_skip_fields[field] = total_skip_fields.get(field, 0) + 1
                    if udm_generated_event:
                        transformed_data.append(udm_generated_event)

                    # pass
                except EmptyExtensionError:
                    err_msg = (
                        f"[{data_type}][{subtype}]: Got empty extension "
                        "during transformation. Transformation of "
                        "current record will be skipped."
                    )
                    self.logger.error(
                        message=(f"{self.log_prefix}: {err_msg}"),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1
                except Exception as err:
                    err_msg = (
                        f"[{data_type}][{subtype}]: An error occurred "
                        f"during transformation. Error: {str(err)}."
                    )
                    self.logger.error(
                        message=(f"{self.log_prefix}: {err_msg}"),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1
            if skip_count > 0:
                self.logger.debug(
                    "{}: Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(self.log_prefix, skip_count)
                )

            if total_skip_fields:
                skip_message = (
                    f"[{data_type}][{subtype}]: Plugin couldn't process "
                    f"{len(total_skip_fields)} field(s) because they "
                    "either had null values or invalid values. "
                    "Expand the log to view skipped field(s)."
                )
                self.logger.info(
                    message=f"{self.log_prefix}: {skip_message}",
                    details=json.dumps(total_skip_fields)
                )

            return transformed_data

    def _validate_chronicle_mappings_helper(
        self, data_type_sub_type: str, data_type: str
    ):
        """Helper function to validate chronicle mappings.

        Args:
            data_type_sub_type (str):
                Data type and subtype for which the mappings are to be fetched
            data_type (str):
                Data type (alert/event) for which the mappings are to be
                fetched
        """
        udm_version = None
        chronicle_mappings = None
        try:
            if not self.is_ce_version_greater_than_512:
                validate_chronicle_mappings(self.mappings, data_type)
            udm_version, chronicle_mappings = get_chronicle_mappings(
                    self.mappings
                )

        except KeyError as err:
            error_msg = (
                f"{data_type_sub_type}"
                "An error occurred while fetching the mappings."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                details=str(traceback.format_exc()),
            )
            raise GoogleChroniclePluginException(error_msg)
        except MappingValidationError as err:
            error_msg = (
                f"{data_type_sub_type}"
                "An error occurred while validating the mapping file."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {error_msg} {err}"),
                details=str(traceback.format_exc()),
            )
            raise GoogleChroniclePluginException(error_msg)
        except Exception as err:
            error_msg = (
                f"{data_type_sub_type}"
                "An error occurred while mapping "
                "data using given json mappings."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                details=str(traceback.format_exc()),
            )
            raise GoogleChroniclePluginException(error_msg)

        return udm_version, chronicle_mappings

    def _transformation_compatibility_check(self, configuration: dict):
        """Check the transformation compatibility.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            bool: True if transformation is enabled, False otherwise.
        """
        transform_data_json = False
        if not self.is_ce_version_greater_than_512:
            if not configuration.get("transformData", True):
                transform_data_json = True
        else:
            if configuration.get("transformData", "json") == "json":
                transform_data_json = True
        return transform_data_json
