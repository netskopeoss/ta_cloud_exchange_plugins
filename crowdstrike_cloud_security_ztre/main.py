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

CRE CrowdStrike Cloud Security plugin.
"""

import traceback
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Tuple, Type, Union
from urllib.parse import urlparse

from netskope.common.api import __version__ as CE_VERSION
from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)
from packaging import version

from .utils.constants import (
    ALLOWED_VALUE_MESSAGE,
    BASE_URLS,
    CLOUD_SERVICES,
    CROWDSTRIKE_DATE_FORMAT,
    EMPTY_ERROR_MESSAGE,
    INTEGER_THRESHOLD,
    IOA_CLOUD_PROVIDERS,
    IOA_FIELD_MAPPING,
    IOA_RESOURCES_PAGE_SIZE,
    IOM_CLOUD_PROVIDERS,
    IOM_ENTITY_NAME,
    IOM_FIELD_MAPPING,
    IOM_PAGE_SIZE,
    MAXIMUM_CE_VERSION,
    MODULE_NAME,
    NORMALIZATION_MULTIPLIER,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PULL_IOA_EVENTS_ENDPOINT,
    PULL_IOM_EVENT_DETAILS_ENDPOINT,
    PULL_IOM_EVENT_IDS_ENDPOINT,
    TYPE_ERROR_MESSAGE,
    VALIDATION_ERROR_MESSAGE,
    VALUE_OUT_OF_RANGE_ERROR_MESSAGE,
)
from .utils.helper import (
    CrowdstrikeCloudSecurityPluginException,
    CrowdstrikePluginHelper,
)


class CrowdstrikeCloudSecurityPlugin(PluginBase):
    """CrowdStrike Cloud Security plugin Class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """CrowdStrike Cloud Security plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self._is_ce_post_v512 = self._check_ce_version()
        self._patch_error_logger()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.crowdstrike_helper = CrowdstrikePluginHelper(
            logger=self.logger,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            log_prefix=self.log_prefix,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
            configuration=self.configuration,
        )

    def _check_ce_version(self):
        """Check if CE version is greater than v5.1.2.

        Returns:
            bool: True if CE version is greater than v5.1.2, False otherwise.
        """
        return version.parse(CE_VERSION) > version.parse(MAXIMUM_CE_VERSION)

    def _patch_error_logger(self):
        """Monkey patch logger methods to handle resolution parameter
        compatibility.
        """
        # Store original methods
        original_error = self.logger.error

        def patched_error(
            message=None,
            details=None,
            resolution=None,
            **kwargs,
        ):
            """Patched error method that handles resolution compatibility."""
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self._is_ce_post_v512:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        # Replace logger methods with patched versions
        self.logger.error = patched_error

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = CrowdstrikeCloudSecurityPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLUGIN_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: Type,
        allowed_values: List = None,
        max_value: int = None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
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
            max_value (int, optional): Maximum allowed value for the
                configuration field. Defaults to None.
            custom_validation_func (Callable, optional): Custom validation
                function to be applied. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        if isinstance(field_value, str):
            field_value = field_value.strip()
        if is_required and not isinstance(field_value, int) and not field_value:
            err_msg = EMPTY_ERROR_MESSAGE.format(field_name=field_name)
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    f"Please provide some value for field {field_name}."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if is_required and not isinstance(field_value, field_type) or (
            custom_validation_func and not custom_validation_func(field_value)
        ):
            err_msg = TYPE_ERROR_MESSAGE.format(field_name=field_name)
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    f"Please provide a valid value for {field_name} field."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if allowed_values:
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            if field_type is str and field_value not in allowed_values:
                allowed_value_msg = ALLOWED_VALUE_MESSAGE.format(
                    allowed_values=', '.join(allowed_values)
                )
                self.logger.error(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}{err_msg}",
                    details=allowed_value_msg,
                    resolution=allowed_value_msg,
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif field_type is List:
                invalid_values = []
                for value in field_value:
                    if value not in allowed_values:
                        invalid_values.append(value)
                if invalid_values:
                    allowed_value_msg = ALLOWED_VALUE_MESSAGE.format(
                        allowed_values=', '.join(allowed_values)
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                            f" {err_msg}"
                        ),
                        details=(
                            f"Invalid values: {', '.join(invalid_values)}\n"
                            f"{allowed_value_msg}"
                        ),
                        resolution=allowed_value_msg
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
        if max_value and isinstance(field_value, int) and (
            field_value > max_value or field_value < 0
        ):
            if max_value == INTEGER_THRESHOLD:
                max_value = "2^62"
            err_msg = TYPE_ERROR_MESSAGE.format(field_name=field_name)
            err_msg += VALUE_OUT_OF_RANGE_ERROR_MESSAGE.format(
                max_value=max_value
            )
            self.logger.error(
                f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}{err_msg}",
                resolution=(
                    f"Please provide a value between 0 and {max_value}."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name="User Name",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Resource ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Display Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Event ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="AWS Account ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Azure Account ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Policy ID",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Policy Statement",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Severity",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Cloud Provider",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Cloud Service",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Cloud Region",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Vertex ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Vertex Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Event State",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Event Category",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Event Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Event Source",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Event Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Management Event",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Request ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Source IP Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="User ARN",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="AWS Access Key ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Principal ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Confidence",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Join Keys",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Resource UUID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER,
                    ),
                ],
            ),
            Entity(
                name="Cloud Workloads (Applications)",
                fields=[
                    EntityField(
                        name="Instance ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Instance Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Instance Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Instance State",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Instance Public IP Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Instance Private IP Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Instance Public DNS Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Instance Private DNS Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Instance VPC ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Instance Subnet ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Instance Platform",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Instance Architecture",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="IOM Event ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Resource ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Resource ID Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Resource URL",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Resource UUID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Cloud Provider",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Cloud Service",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Security Group",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="NACL ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Port(s)",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Region",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Severity",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Policy Statement",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(name="Tags", type=EntityFieldType.LIST),
                    EntityField(
                        name="Is Managed", type=EntityFieldType.STRING
                    ),
                ],
            ),
        ]

    def _extract_field_from_event(
        self, key: str, event: dict, default, transformation=None
    ):
        """Extract field from event.

        Args:
            key (str): Key to fetch.
            event (dict): Event dictionary.
            default (str,None): Default value to set.
            transformation (str, None, optional): Transformation
                to perform on key. Defaults to None.

        Returns:
            Any: Value of the key from event.
        """
        keys = key.split(".")
        while keys:
            k = keys.pop(0)
            if k not in event and default is not None:
                return default
            event = event.get(k, {})
        if transformation and transformation == "string":
            return str(event)
        return event

    def _extract_ioa_fields(
        self, event: dict, include_normalization: bool = True
    ) -> dict:
        """Extract IOA fields.

        Args:
            event (dict): Event payload.
            include_normalization (bool, optional): Include normalization or
                not ? Defaults to True.

        Returns:
            dict: Extracted fields dictionary.
        """
        extracted_fields = {}

        self.add_field(
            extracted_fields,
            "User Name",
            event.get("user_identity", {}).get("user_name", ""),
        )
        self.add_field(
            extracted_fields,
            "Resource ID",
            event.get("aggregate", {}).get("resource", {}).get("id", [""])[0],
        )
        if not extracted_fields.get(
            "Resource ID"
        ) and not extracted_fields.get("User Name"):
            return {}

        for field_name, field_value in IOA_FIELD_MAPPING.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, event, default, transformation
                ),
            )

        self.add_field(
            extracted_fields,
            "Resource UUID",
            event.get("aggregate", {})
            .get("resource", {})
            .get("uuid", [""])[0],
        )
        if (
            event.get("aggregate", {}).get("score") is not None
            and include_normalization
        ):
            score = int(event.get("aggregate", {}).get("score"))
            normalized_score = abs(100 - score) * NORMALIZATION_MULTIPLIER
            self.add_field(
                extracted_fields,
                "Netskope Normalized Score",
                normalized_score,
            )

        return extracted_fields

    def _fetch_ioa_events(
        self,
        checkpoint: datetime,
        base_url: str,
        auth_header: Dict,
    ) -> List[dict]:
        """Fetch IOA Events from CrowdStrike.

        Args:
           checkpoint(datetime): Checkpoint.
           base_url(str): Base URL.
           auth_header(dict): Auth header.

        Returns:
            List[dict]: List of extracted users details.
        """
        self.logger.info(
            f"{self.log_prefix}: Pulling users from IOA events "
            f"from {PLATFORM_NAME}."
        )
        endpoint = PULL_IOA_EVENTS_ENDPOINT.format(base_url=base_url)
        date_filter = checkpoint.strftime(CROWDSTRIKE_DATE_FORMAT)

        next_token = None
        ioa_cloud_provider = self.configuration.get("ioa_cloud_provider", [])
        ioa_cloud_service = self.configuration.get("ioa_cloud_service")
        params = {
            "limit": PAGE_SIZE,
            "date_time_since": date_filter,
        }
        if ioa_cloud_service:
            params["service"] = ioa_cloud_service
        records = {}
        skip_count = 0
        for provider in ioa_cloud_provider:
            page = 1
            params["cloud_provider"] = provider
            self.logger.info(
                f"{self.log_prefix}: Pulling IOA Events for"
                f" {provider} Cloud Provider."
            )
            provider_record_count = 0
            while True:
                page_record_count = 0
                if next_token:
                    params["next_token"] = next_token
                resp_json = self.crowdstrike_helper.api_helper(
                    method="GET",
                    url=endpoint,
                    headers=auth_header,
                    logger_msg=(
                        f"pulling IOA events for {provider} Cloud Provider"
                        f" for page {page} from {PLATFORM_NAME}"
                    ),
                    params=params,
                )
                for event in resp_json.get("resources", {}).get("events", []):
                    try:
                        extracted_fields = self._extract_ioa_fields(
                            event=event, include_normalization=False
                        )
                        if extracted_fields:
                            username = extracted_fields.get("User Name")
                            resource_id = extracted_fields.get("Resource ID")
                            records[(username, resource_id)] = extracted_fields
                            page_record_count += 1
                            provider_record_count += 1
                        else:
                            skip_count += 1
                    except Exception as exp:
                        event_id = event.get("event_id")
                        err_msg = (
                            f"Unable to extract fields from event"
                            f' having Event ID "{event_id}".'
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {exp}"
                            ),
                            details=f"Event: {event}",
                        )
                        skip_count += 1

                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched"
                    f" {page_record_count} user record(s) in page {page} for"
                    f" {provider} Cloud Provider. Total unique User records"
                    f" fetched: {len(records)}."
                )
                next_token = (
                    resp_json.get("meta", {})
                    .get("pagination", {})
                    .get("next_token")
                )
                if (
                    not next_token
                    or len(resp_json.get("resources", {}).get("events", []))
                    < PAGE_SIZE
                ):
                    break

                page += 1

            self.logger.info(
                f"{self.log_prefix}: Successfully fetched"
                f" {provider_record_count} user record(s) for"
                f" {provider} Cloud Provider."
            )

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} IOA event(s)"
                f" because they might not contain User Name and Resource ID "
                "in their response or fields could not be extracted from them."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(records)}"
            f" unique user record(s) from IOA Events"
            f" from {PLATFORM_NAME}."
        )
        records_list = list(records.values())
        return records_list

    def add_field(self, fields_dict: dict, field_name: str, value):
        """Function to add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        fields_dict[field_name] = value

    def _extract_iom_fields(self, event: dict) -> dict:
        """Extract IOM fields from event payload.

        Args:
            event (dict): Event Payload.

        Returns:
            dict: Dictionary containing required fields.
        """
        extracted_fields = {}
        for field_name, field_value in IOM_FIELD_MAPPING.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, event, default, transformation
                ),
            )
        tags = event.get("tags", {})
        if isinstance(tags, dict):
            self.add_field(
                extracted_fields,
                "Tags",
                [f"{k} = {v}" for k, v in tags.items()],
            )

        return extracted_fields

    def _get_iom_details(
        self,
        base_url: str,
        headers: dict,
        event_ids: List,
        page: int = 0,
        batch: int = 0,
    ) -> Tuple[Dict, int]:
        """Get IOM Event details.

        Args:
            base_url (str): Base URL.
            headers (dict): Headers.
            event_ids (List): Event Ids list.
            page (int): Page number.
            batch (int): Batch number.

        Returns:
            Dictionary|int: Dictionary containing details|int containing
              skip count.
        """

        iom_details_endpoint = PULL_IOM_EVENT_DETAILS_ENDPOINT.format(
            base_url=base_url
        )
        records = {}
        skip_count = 0
        details_batch = 1
        for i in range(0, len(event_ids), IOM_PAGE_SIZE):
            try:
                batch_log = f"batch(Event IDs) {details_batch}"
                payload = {"ids": event_ids[i : i + IOM_PAGE_SIZE]}  # noqa
                logger_msg = (
                    f"pulling details for {len(payload['ids'])} "
                    f"IOM Event IDs for page {page}, {batch_log}"
                )
                if batch:
                    logger_msg = logger_msg + f", batch {batch}"

                resp_json = self.crowdstrike_helper.api_helper(
                    method="GET",
                    url=iom_details_endpoint,
                    headers=headers,
                    params=payload,
                    logger_msg=logger_msg,
                    show_params=False,
                )
                for event in resp_json.get("resources", []):
                    try:
                        # Extract fields from event
                        resource_attributes = event.get(
                            "resource_attributes", {}
                        )
                        if not resource_attributes:
                            skip_count += 1
                            continue
                        instance_id = resource_attributes.get("Instance Id")

                        # Check if Instance ID is present
                        if not instance_id:
                            skip_count += 1
                            continue
                        extracted_data = self._extract_iom_fields(event)
                        records[instance_id] = extracted_data
                    except Exception:
                        event_id = event.get("id")
                        err_msg = (
                            "Unable to extract record from IOM event"
                            f' ID "{event_id}" for page {page}, {batch_log}'
                        )
                        if batch:
                            err_msg = err_msg + f", batch {batch}"
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}.",
                            details=str(traceback.format_exc()),
                        )
                        skip_count += 1
                        continue
                # Increment Details batch counter.
                details_batch += 1
            except CrowdstrikeCloudSecurityPluginException as err:
                err_msg = (
                    f"Error occurred while fetching IOM"
                    f" event details for page {page}, {batch_log}"
                )
                if batch:
                    err_msg = err_msg + f", batch {batch}"
                err_msg += f" Error: {str(err)}"
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}.",
                    details=str(traceback.format_exc()),
                )
                if payload.get("ids"):
                    skip_count += len(payload["ids"])
                details_batch += 1
                continue
            except Exception as err:
                err_msg = (
                    "Unexpected error occurred while fetching IOM"
                    f" event details for page {page}, {batch_log}"
                )
                if batch:
                    err_msg = err_msg + f", batch {batch}"
                err_msg += f" Error: {str(err)}"
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}.",
                    details=str(traceback.format_exc()),
                )
                if payload.get("ids"):
                    skip_count += len(payload["ids"])
                details_batch += 1
                continue
        return records, skip_count

    def _fetch_iom_events(
        self,
        filter_query: str,
        batch: int = 0,
        is_update: bool = False,
        headers: dict = {},
        base_url: str = "",
    ) -> List[dict]:
        """Fetch IOM events from CrowdStrike Cloud Security platform.

        Args:
            filter_query (str): Filter Query.
            batch (int, optional): Batch number. Defaults to 0.
            is_update (bool, optional): Is this update call? Defaults to False.
            headers (dict, optional): Headers. Defaults to {}.
            base_url (str, optional): Base URL. Defaults to "".

        Returns:
            List[dict]: List of fetched IOM fields dictionary.
        """
        iom_ids_endpoint = PULL_IOM_EVENT_IDS_ENDPOINT.format(
            base_url=base_url
        )
        params = {
            "limit": PAGE_SIZE,
            "sort": "timestamp|asc",
            "filter": filter_query,
        }
        records = {}
        page = 1
        skip_count = 0
        next_token = None
        show_params = not is_update
        try:
            while True:
                if next_token:
                    params["next_token"] = next_token
                page_records = {}
                logger_msg = f"pulling IOM Event IDs for page {page}"
                if batch:
                    logger_msg = logger_msg + (
                        f", batch {batch} to update the records"
                    )

                resp_json = self.crowdstrike_helper.api_helper(
                    method="GET",
                    url=iom_ids_endpoint,
                    headers=headers,
                    params=params,
                    logger_msg=logger_msg,
                    show_params=show_params,
                )
                event_ids = resp_json.get("resources", [])
                if event_ids:
                    page_records, page_skip_count = self._get_iom_details(
                        base_url=base_url,
                        headers=headers,
                        event_ids=event_ids,
                        page=page,
                        batch=batch,
                    )
                    skip_count += page_skip_count
                    records.update(page_records)
                    if is_update:
                        log_msg = (
                            f"Successfully fetched {len(page_records)} "
                            f"unique {IOM_ENTITY_NAME} record(s) from "
                            f"{len(event_ids)} Event ID(s) in page {page} "
                            f", batch {batch}. Total unique {IOM_ENTITY_NAME} "
                            f"record(s) fetched: {len(records)}."
                        )
                    else:
                        log_msg = (
                            f"Successfully fetched {len(page_records)}"
                            f" unique {IOM_ENTITY_NAME} record(s) from "
                            f"{len(event_ids)} Event ID(s) in page {page}."
                            f" Total unique {IOM_ENTITY_NAME} record(s)"
                            f" fetched: {len(records)}."
                        )
                    self.logger.info(f"{self.log_prefix}: {log_msg}")
                next_token = (
                    resp_json.get("meta", {})
                    .get("pagination", {})
                    .get("next_token")
                )
                if not next_token or not resp_json.get("resources", []):
                    break

                page += 1
            if skip_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skip_count} IOM Event ID(s)"
                    " because they either do not have an Instance ID or"
                    " fields could not be extracted from them."
                )

            if not is_update:
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{len(records)} unique {IOM_ENTITY_NAME} record(s) "
                    f"from {PLATFORM_NAME}."
                )
            return records
        except CrowdstrikeCloudSecurityPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while "
                "pulling records from IOM events"
            )
            if batch:
                err_msg = err_msg + f" for batch {batch}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {exp}",
                details=str(traceback.format_exc()),
            )

    def fetch_records(self, entity: Entity) -> list:
        """Get the all the Agent ID list from the Query Endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token.

        Returns:
            list[Record]: list of hosts fetched from CrowdStrike.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity.lower()} records from "
            f"{PLATFORM_NAME} platform."
        )

        checkpoint = self.last_run_at
        if not checkpoint:
            initial_range = int(self.configuration.get("days", 7))
            checkpoint = datetime.now() - timedelta(days=initial_range)

        records = []
        entity_name = entity.lower()
        try:
            base_url, client_id, client_secret = (
                self.crowdstrike_helper.get_credentials(
                    self.configuration
                )
            )
            headers = self.crowdstrike_helper.get_auth_header(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
            )
            if entity == "Users":
                records.extend(
                    self._fetch_ioa_events(
                        checkpoint=checkpoint,
                        base_url=base_url,
                        auth_header=headers,
                    )
                )
            elif entity == IOM_ENTITY_NAME:
                iom_cloud_provider = self.configuration.get(
                    "iom_cloud_provider", []
                )
                iom_cloud_services = self.configuration.get(
                    "iom_cloud_service", []
                )
                checkpoint = checkpoint.strftime(CROWDSTRIKE_DATE_FORMAT)
                filter_query = f"scan_time: >='{checkpoint}'"
                if iom_cloud_provider:
                    filter_query += f"+cloud_provider: {iom_cloud_provider}"
                if iom_cloud_services:
                    filter_query += (
                        f"+cloud_service_keyword: {iom_cloud_services}"
                    )
                fetched_iom_events = self._fetch_iom_events(
                    filter_query=filter_query,
                    headers=headers,
                    base_url=base_url,
                )
                records.extend(list(fetched_iom_events.values()))
            else:
                err_msg = (
                    f"Invalid entity found {PLUGIN_NAME} only supports "
                    "Users and Applications Entities."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise CrowdstrikeCloudSecurityPluginException(err_msg)
            return records
        except CrowdstrikeCloudSecurityPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while pulling {entity_name} "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise CrowdstrikeCloudSecurityPluginException(err_msg)

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """
        Updating records for Users and Applications from CrowdStrike Cloud
        Security platform.

        Args:
            agent_ids (list[Record]): list of records containing host's agent
                 ids.

        Returns:
            list[Record]: list of records with updated fields.
        """
        fetched_records = {}
        self.logger.info(
            f"{self.log_prefix}: Updating {entity.lower()}"
            f" records from {PLATFORM_NAME}."
        )
        # To only fetch newly created detections.
        checkpoint = self.last_run_at
        if not checkpoint:
            initial_range = int(self.configuration.get("days", 7))
            checkpoint = datetime.now() - timedelta(days=initial_range)
        date_filter = checkpoint.strftime(CROWDSTRIKE_DATE_FORMAT)

        base_url, client_id, client_secret = (
            self.crowdstrike_helper.get_credentials(self.configuration)
        )
        headers = self.crowdstrike_helper.get_auth_header(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
        )
        if entity == "Users":
            resource_ids = []

            for record in records:
                if record.get("Resource ID"):
                    resource_ids.append(record.get("Resource ID"))
            log_msg = (
                f"{len(resource_ids)} user record(s) will "
                f"be updated in the batch of {IOA_RESOURCES_PAGE_SIZE}."
            )
            if len(records) - len(resource_ids) > 0:
                log_msg = log_msg + (
                    f" Skipped {len(records) - len(resource_ids)} records as "
                    "they do not have Resource ID field in it."
                )
            self.logger.info(f"{self.log_prefix}: {log_msg}")

            ioa_cloud_provider = self.configuration.get(
                "ioa_cloud_provider", []
            )
            ioa_cloud_service = self.configuration.get("ioa_cloud_service")
            params = {
                "limit": IOA_RESOURCES_PAGE_SIZE,
                "date_time_since": date_filter,
            }
            if ioa_cloud_service:
                params["service"] = ioa_cloud_service

            endpoint = PULL_IOA_EVENTS_ENDPOINT.format(base_url=base_url)
            skip_count = 0
            for provider in ioa_cloud_provider:
                # Add cloud provider.
                params["cloud_provider"] = provider
                provider_record_count = 0
                page = 1
                for i in range(0, len(resource_ids), IOA_RESOURCES_PAGE_SIZE):
                    page_record_count = 0
                    payload = resource_ids[
                        i : i + IOA_RESOURCES_PAGE_SIZE  # noqa
                    ]
                    params["resource_id"] = payload
                    resp_json = self.crowdstrike_helper.api_helper(
                        url=endpoint,
                        method="GET",
                        headers=headers,
                        params=params,
                        logger_msg=(
                            f"pulling {len(payload)} user(s) data for page"
                            f" {page} from {PLATFORM_NAME}"
                        ),
                        show_params=False,
                    )
                    for event in resp_json.get("resources", {}).get(
                        "events", []
                    ):
                        try:
                            extracted_fields = self._extract_ioa_fields(
                                event=event, include_normalization=True
                            )
                            if extracted_fields:
                                previous_record_count = len(fetched_records)
                                fetched_records.update(
                                    {
                                        event.get("aggregate", {})
                                        .get("resource", {})
                                        .get("id", [""])[0]: extracted_fields
                                    }
                                )

                                if (
                                    len(fetched_records)
                                    > previous_record_count
                                ):
                                    page_record_count += 1
                                    provider_record_count += 1
                            else:
                                skip_count += 1

                        except Exception as exp:
                            event_id = event.get("event_id")
                            err_msg = (
                                f"Unable to extract fields from event"
                                f' having Event ID "{event_id}".'
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg} "
                                    f"Error: {exp}"
                                ),
                                details=f"Event: {event}",
                            )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched"
                        f" {page_record_count} unique user record(s) in"
                        f" page {page} for {provider} Cloud Provider. "
                        "Total user record(s) fetched: "
                        f"{len(fetched_records)}."
                    )
                    page += 1

                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched"
                    f" {provider_record_count} unique user record(s) for"
                    f" {provider} Cloud Provider from {PLATFORM_NAME}."
                )

            if skip_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skip_count} IOA event(s)"
                    " because they might not contain User Name and "
                    "Resource ID in their response or fields could not be "
                    "extracted from them."
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched"
                f" {len(fetched_records)} unique user record(s) for"
                f" update from {PLATFORM_NAME}."
            )
            # Checking for match in existing records.
            count = 0
            updated_records = []
            for record in records:
                record_id = record.get("Resource ID")
                if record_id and record_id in fetched_records:
                    updated_records.append(fetched_records[record_id])
                    count += 1

            self.logger.info(
                f"{self.log_prefix}: Successfully updated {count} "
                f"user record(s) out of {len(updated_records)}"
                f" from {PLATFORM_NAME}."
            )
            return updated_records
        elif entity == IOM_ENTITY_NAME:
            resource_ids = []
            for record in records:
                if record.get("Resource ID"):
                    resource_ids.append(record.get("Resource ID"))
                elif record.get("Instance ID"):
                    resource_ids.append(record.get("Instance ID"))
            log_msg = (
                f"{len(resource_ids)} {IOM_ENTITY_NAME} record(s) will"
                f" be updated in the batch of {PAGE_SIZE}."
            )
            if len(records) - len(resource_ids) > 0:
                log_msg = log_msg + (
                    f" Skipped {len(records) - len(resource_ids)} "
                    f"{IOM_ENTITY_NAME} record(s) as they might not have"
                    " Instance ID or Resource ID field in them."
                )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            iom_cloud_provider = self.configuration.get(
                "iom_cloud_provider", []
            )
            iom_cloud_services = self.configuration.get(
                "iom_cloud_service", []
            )
            batch = 1
            for i in range(0, len(resource_ids), PAGE_SIZE):
                payload = resource_ids[i : i + PAGE_SIZE]  # noqa
                filter_query = f"scan_time: >='{date_filter}'"
                filter_query += f"+resource_id: {payload}"
                if iom_cloud_provider:
                    filter_query += f"+cloud_provider: {iom_cloud_provider}"
                if iom_cloud_services:
                    filter_query += (
                        f"+cloud_service_keyword: {iom_cloud_services}"
                    )
                fetched_records.update(
                    self._fetch_iom_events(
                        filter_query=filter_query,
                        is_update=True,
                        headers=headers,
                        base_url=base_url,
                        batch=batch,
                    )
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched"
                    f" {len(fetched_records)} unique {IOM_ENTITY_NAME}"
                    f" record(s) in batch {batch} for update from"
                    f" {PLATFORM_NAME}."
                )
                batch += 1
            # Checking for match in existing records if it
            # exists then update fields.
            count = 0
            updated_records = []
            for record in records:
                if (
                    record.get("Instance ID")
                    and record.get("Instance ID") in fetched_records
                ):
                    record_id = record["Instance ID"]
                    updated_records.append(fetched_records[record_id])
                    count += 1

                elif (
                    record.get("Resource ID")
                    and record.get("Resource ID") in fetched_records
                ):
                    record_id = record["Resource ID"]
                    updated_records.append(fetched_records[record_id])
                    count += 1

            self.logger.info(
                f"{self.log_prefix}: Successfully updated {count}"
                f" {IOM_ENTITY_NAME} record(s) out of {len(records)}"
                f" from {PLATFORM_NAME}."
            )

        return updated_records

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def validate_action(self, action: Action):
        """Validate Netskope configuration."""
        if action.value not in ["generate"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        return ValidationResult(
            success=True, message="Validation successful."
        )

    def get_action_params(self, action: Action):
        """Get action params."""
        return []

    def execute_action(self, action: Action):
        """Execute action on the record."""
        if action.value == "generate":
            pass

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success
            flag and message.
        """
        # Validate Base URL
        base_url = configuration.get("base_url", "").strip()
        if validation_error := self._validate_configuration_parameters(
            field_name="Base URL",
            field_type=str,
            field_value=base_url,
            custom_validation_func=self._validate_url,
            allowed_values=BASE_URLS,
            is_required=True,
        ):
            return validation_error

        # Validate Client ID
        client_id = configuration.get("client_id", "")
        if validation_error := self._validate_configuration_parameters(
            field_name="Client ID",
            field_type=str,
            field_value=client_id,
            is_required=True,
        ):
            return validation_error

        # Validate Client Secret
        client_secret = configuration.get("client_secret", "")
        if validation_error := self._validate_configuration_parameters(
            field_name="Client Secret",
            field_type=str,
            field_value=client_secret,
            is_required=True,
        ):
            return validation_error

        # Validate IOA Cloud Provider
        ioa_cloud_provider = configuration.get("ioa_cloud_provider", [])
        if validation_error := self._validate_configuration_parameters(
            field_name="IOA Cloud Provider",
            field_type=List,
            field_value=ioa_cloud_provider,
            allowed_values=IOA_CLOUD_PROVIDERS,
            is_required=True,
        ):
            return validation_error

        # Validate IOA Cloud Services
        ioa_cloud_service = configuration.get("ioa_cloud_service", "")
        if validation_error := self._validate_configuration_parameters(
            field_name="IOA Cloud Service",
            field_type=List,
            field_value=ioa_cloud_service,
            allowed_values=CLOUD_SERVICES,
            is_required=False,
        ):
            return validation_error

        # Validate IOM Cloud Provider
        iom_cloud_provider = configuration.get("iom_cloud_provider", [])
        if validation_error := self._validate_configuration_parameters(
            field_name="IOM Cloud Provider",
            field_type=List,
            field_value=iom_cloud_provider,
            allowed_values=IOM_CLOUD_PROVIDERS,
            is_required=True,
        ):
            return validation_error

        # Validate IOM Cloud Services
        iom_cloud_service = configuration.get("iom_cloud_service", [])
        if validation_error := self._validate_configuration_parameters(
            field_name="IOM Cloud Service",
            field_type=List,
            field_value=iom_cloud_service,
            allowed_values=CLOUD_SERVICES,
            is_required=False,
        ):
            return validation_error

        # Validate Initial Range
        days = configuration.get("days")
        if validation_error := self._validate_configuration_parameters(
            field_name="Initial Range",
            field_type=int,
            field_value=days,
            max_value=INTEGER_THRESHOLD,
            is_required=True,
        ):
            return validation_error

        # Validate Auth Credentials
        return self.validate_auth_params(configuration)

    def validate_auth_params(self, configuration: dict) -> ValidationResult:
        """Validate the authentication params with CrowdStrike platform.

        Args:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2
            token.
            base_url (str): Base url of crowd strike
            initial_range (str): Initial Range.
        Returns:
            ValidationResult: ValidationResult object having validation
            results after making
            an API call.
        """
        try:
            base_url, client_id, client_secret = (
                self.crowdstrike_helper.get_credentials(configuration)
            )
            date_filter = datetime.now().strftime(CROWDSTRIKE_DATE_FORMAT)

            auth_token_header = self.crowdstrike_helper.get_auth_header(
                client_id, client_secret, base_url, True
            )
            # Validate connection with IOA Events APIs.
            query_endpoint = PULL_IOA_EVENTS_ENDPOINT.format(
                base_url=base_url,
            )
            params = {
                "limit": 1,
                "date_time_since": date_filter,
            }
            ioa_cloud_service = configuration.get("ioa_cloud_service", "")
            if ioa_cloud_service:
                params["service"] = ioa_cloud_service

            params["cloud_provider"] = "aws"
            self.crowdstrike_helper.api_helper(
                method="GET",
                url=query_endpoint,
                headers=auth_token_header,
                logger_msg=(
                    "checking connectivity with IOA Event "
                    f"APIs for {PLATFORM_NAME}"
                ),
                params=params,
                is_handle_error_required=True,
                is_validation=True,
                regenerate_auth_token=False,
            )

            # Validate connection with IOM Event APIs.
            iom_ids_endpoint = PULL_IOM_EVENT_IDS_ENDPOINT.format(
                base_url=base_url
            )
            iom_cloud_provider = configuration.get("iom_cloud_provider", [])
            iom_cloud_services = configuration.get("iom_cloud_service", [])
            params = {
                "limit": 1,
                "sort": "timestamp|desc",
                "filter": (
                    f"scan_time: >='{date_filter}'+"
                    f"cloud_provider: {iom_cloud_provider}+"
                    f"cloud_service_keyword: {iom_cloud_services}"
                ),
            }
            self.crowdstrike_helper.api_helper(
                method="GET",
                url=iom_ids_endpoint,
                headers=auth_token_header,
                params=params,
                logger_msg=(
                    "checking connectivity with IOM Event "
                    f"APIs for {PLATFORM_NAME}"
                ),
                is_validation=True,
                regenerate_auth_token=False,
            )
            log_msg = f"Validation Successful for {PLUGIN_NAME}."
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(message=log_msg, success=True)
        except CrowdstrikeCloudSecurityPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )
