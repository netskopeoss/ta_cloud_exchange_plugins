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

Netskope CRE plugin."""

import copy
import json
import re
import time
import traceback
from datetime import datetime, timezone
from typing import Callable, Dict, List, Literal, Optional, Tuple, Union

from netskope.common.utils import (
    AlertsHelper,
    resolve_secret,
)
from netskope.common.utils.handle_exception import (
    handle_status_code,
)
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper
from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
    ActionResult
)
from netskope.integrations.crev2.utils import get_latest_values
from requests.exceptions import ConnectionError
from .utils.constants import (
    PAGE_SIZE,
    MAX_HOSTS_PER_PRIVATE_APP,
    REGEX_HOST,
    REGEX_EMAIL,
    REGEX_TAG,
    REGEX_FOR_DOMAIN,
    MODULE_NAME,
    PLUGIN,
    PLUGIN_VERSION,
    URLS,
    ERROR_APP_DOES_NOT_EXIST,
    SUCCESS,
    ADD_REMOVE_USER_BATCH_SIZE,
    APP_INSTANCE_BATCH_SIZE,
    TAG_APP_BATCH_SIZE,
    TAG_NOT_FOUND,
    USER_FIELD_MAPPING,
    USERS_BATCH_SIZE,
    APPLICATIONS_BATCH_SIZE,
    TAG_APP_TAG_LENGTH,
    TAG_DEVICE_TAG_LENGTH,
    PRIVATE_APP_TAG_MAX_LENGTH,
    TAG_DEVICE_BATCH_SIZE,
    TAG_EXISTS,
    DEVICE_FIELD_MAPPING,
    MAX_TAGS_PER_DEVICE,
    TAG_CACHE_PAGE_SIZE,
    DEVICE_BULK_TAG_INTER_BATCH_SLEEP,
    TAG_ACTION_LABEL_MAP,
    PENDING_CHANGES_DETECTED,
    V2_SERVICE_PROFILE,
    V2_SERVICE_PROFILE_BY_ID,
    SERVICE_PROFILE_TYPE_CUSTOM,
    SERVICE_PROFILE_PAGE_SIZE,
    MAX_DESTINATION_PROFILE_NAME_LENGTH,
    MAX_DESTINATION_PROFILE_DESC_LENGTH,
    DESTINATION_PROFILE_NAME_FORBIDDEN_CHARS,
    DESTINATION_PROFILE_PAYLOAD_LIMIT,
    DESTINATION_PROFILE_PAYLOAD_SAFETY_BUFFER,
    DESTINATION_PROFILE_VALUES_PER_APPEND,
    DESTINATION_PROFILE_REGEX_TOTAL_LIMIT,
    MATCH_TYPE_OPTIONS,
    MAX_DNS_PROFILE_NAME_LENGTH,
    MAX_DNS_PROFILE_DESC_LENGTH,
    DNS_PROFILE_FORBIDDEN_CHARS,
    MAX_SERVICE_PROFILE_NAME_LENGTH,
    MAX_SERVICE_PROFILE_DESC_LENGTH,
    DNS_PROFILE_ACTION_TYPE_OPTIONS,
    BLOCK_ALL_EXCEPT_ALLOW_LIST_OPTIONS,
    CUSTOM_SEPARATOR,
    CUSTOM_SEPARATOR_DEVICE_CLASSIFICATION,
    OPERATION_OPTIONS,
    SERVICE_PROFILE_OPERATION_OPTIONS,
    DNS_PROFILE_PAYLOAD_LIMIT,
    DNS_PROFILE_PAYLOAD_SAFETY_BUFFER,
    DEVICE_CLASSIFICATION_PAGE_SIZE,
    MAX_DEVICE_CLASSIFICATION_NAME_LENGTH,
    DEVICE_CLASSIFICATION_DEFAULT_DESCRIPTION,
    DEVICE_CLASSIFICATION_OS_OPTIONS,
    DEVICE_CLASSIFICATION_OPERATOR_OPTIONS,
    DESTINATION_PROFILE_ACTION_PARAMS,
    DNS_PROFILE_ACTION_PARAMS,
    SERVICE_PROFILE_ACTION_PARAMS,
    DEVICE_CLASSIFICATION_ACTION_PARAMS,
)
from .utils.helper import (
    NetskopePluginHelper,
    NetskopeException,
    _capitalize_first,
)

plugin_provider_helper = PluginProviderHelper()


class PrivateAppLimitReachedError(Exception):
    """Raised when the tenant's maximum private app count is reached.

    Netskope returns this as an HTTP 200 with a body of
    ``{"status": "error", "message": "The maximum number ... has been
    reached."}`` when a private app create would exceed the tenant limit.
    It is treated as a non-fatal stop signal during roll-over (the
    remaining hosts are skipped) rather than a hard action failure.
    """


class NetskopePlugin(PluginBase):
    """Netskope plugin implementation."""

    def __init__(
        self,
        name,
        configuration,
        storage,
        last_run_at,
        logger,
        use_proxy=False,
        ssl_validation=True,
    ):
        """Initialize."""
        super().__init__(
            name,
            configuration,
            storage,
            last_run_at,
            logger,
            use_proxy,
            ssl_validation,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.netskope_helper = NetskopePluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
        )
        self.provide_action_id = True

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = NetskopePlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLUGIN, PLUGIN_VERSION)

    def get_entities(self) -> List[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name="email",
                        type=EntityFieldType.STRING,
                        description=(
                            "User email address. This field can be used to"
                            " merge User records with other CRE plugins."
                        ),
                        required=True,
                    ),
                    EntityField(
                        name="ubaScore",
                        type=EntityFieldType.NUMBER,
                        description="User Behavior Analytics risk score.",
                    ),
                    EntityField(
                        name="policyName",
                        type=EntityFieldType.STRING,
                        description="Security policy name applied to user.",
                    ),
                    EntityField(
                        name="cci",
                        type=EntityFieldType.NUMBER,
                        description="Netskope Confidence Correlation Index.",
                    ),
                    EntityField(
                        name="ccl",
                        type=EntityFieldType.STRING,
                        description="Netskope Confidence Correlation Level.",
                    ),
                    EntityField(
                        name="deviceClassification",
                        type=EntityFieldType.STRING,
                        description="Device classification category.",
                    ),
                    EntityField(
                        name="policyAction",
                        type=EntityFieldType.LIST,
                        description="Policy actions applied to traffic.",
                    ),
                    EntityField(
                        name="severity",
                        type=EntityFieldType.STRING,
                        description="Security event severity level.",
                    ),
                    EntityField(
                        name="destinationIP",
                        type=EntityFieldType.STRING,
                        description="Destination server IP address.",
                    ),
                    EntityField(
                        name="sourceRegion",
                        type=EntityFieldType.STRING,
                        description="Geographic region of source.",
                    ),
                    EntityField(
                        name="sourceIP",
                        type=EntityFieldType.STRING,
                        description="Source IP address.",
                    ),
                    EntityField(
                        name="userIP",
                        type=EntityFieldType.STRING,
                        description="User's public IP address.",
                    ),
                    EntityField(
                        name="policyID",
                        type=EntityFieldType.STRING,
                        description="Unique policy identifier.",
                    ),
                ],
            ),
            Entity(
                name="Applications",
                fields=[
                    EntityField(
                        name="applicationId",
                        type=EntityFieldType.STRING,
                        description="Unique application identifier.",
                    ),
                    EntityField(
                        name="applicationName",
                        type=EntityFieldType.STRING,
                        required=True,
                        description="Application name.",
                    ),
                    EntityField(
                        name="vendor",
                        type=EntityFieldType.STRING,
                        description="Software vendor or publisher.",
                    ),
                    EntityField(
                        name="source",
                        type=EntityFieldType.STRING,
                        description="Application discovery source.",
                    ),
                    EntityField(
                        name="cci",
                        type=EntityFieldType.NUMBER,
                        description="Netskope Confidence Correlation Index.",
                    ),
                    EntityField(
                        name="ccl",
                        type=EntityFieldType.STRING,
                        description="Netskope Confidence Correlation Level.",
                    ),
                    EntityField(
                        name="categoryName",
                        type=EntityFieldType.STRING,
                        description="Application category classification.",
                    ),
                    EntityField(
                        name="users",
                        type=EntityFieldType.LIST,
                        description="Users accessing application.",
                    ),
                    EntityField(
                        name="deepLink",
                        type=EntityFieldType.STRING,
                        description="Direct dashboard link to application.",
                    ),
                    EntityField(
                        name="customTags",
                        type=EntityFieldType.LIST,
                        description="Custom tags assigned to application.",
                    ),
                    EntityField(
                        name="discoveryDomains",
                        type=EntityFieldType.LIST,
                        description="Domains for application discovery.",
                    ),
                    EntityField(
                        name="steeringDomains",
                        type=EntityFieldType.LIST,
                        description="Domains for steering policies.",
                    ),
                ],
            ),
            Entity(
                name="Devices",
                fields=[
                    EntityField(
                        name="Device ID",
                        type=EntityFieldType.STRING,
                        required=True,
                        description="Unique device identifier.",
                    ),
                    EntityField(
                        name="Hostname",
                        type=EntityFieldType.STRING,
                        required=True,
                        description=(
                            "Device hostname or computer name. This field"
                            " can be used to merge device records with other"
                            " CRE plugins."
                        ),
                    ),
                    EntityField(
                        name="Netskope Device UID",
                        type=EntityFieldType.STRING,
                        required=True,
                        description="Unique identifier assigned by Netskope.",
                    ),
                    EntityField(
                        name="Mac Addresses",
                        type=EntityFieldType.LIST,
                        description="Device MAC addresses.",
                    ),
                    EntityField(
                        name="Last Connected from Private IP",
                        type=EntityFieldType.STRING,
                        description="Last private IP connection.",
                    ),
                    EntityField(
                        name="Last Connected from Public IP",
                        type=EntityFieldType.STRING,
                        description="Last public IP connection.",
                    ),
                    EntityField(
                        name="Device Serial Number",
                        type=EntityFieldType.STRING,
                        required=True,
                        description=(
                            "Manufacturer device serial number. "
                            "This field can be used to merge device"
                            " records with other CRE Plugins."
                        ),
                    ),
                    EntityField(
                        name="Operating System",
                        type=EntityFieldType.STRING,
                        description="Device operating system name.",
                    ),
                    EntityField(
                        name="Operating System Version",
                        type=EntityFieldType.STRING,
                        description="Operating system version number.",
                    ),
                    EntityField(
                        name="Device Make",
                        type=EntityFieldType.STRING,
                        description="Device manufacturer brand.",
                    ),
                    EntityField(
                        name="Device Model",
                        type=EntityFieldType.STRING,
                        description="Device model name or number.",
                    ),
                    EntityField(
                        name="Last Updated Timestamp",
                        type=EntityFieldType.DATETIME,
                        description="Last device information update time.",
                    ),
                    EntityField(
                        name="Management ID",
                        type=EntityFieldType.STRING,
                        description="Device management system identifier.",
                    ),
                    EntityField(
                        name="Steering Config",
                        type=EntityFieldType.STRING,
                        description="Applied steering policy configuration.",
                    ),
                    EntityField(
                        name="Region",
                        type=EntityFieldType.STRING,
                        description="Device geographic region",
                    ),
                    EntityField(
                        name="User Name",
                        type=EntityFieldType.STRING,
                        description=(
                            "Primary device user name. This field can be used"
                            " to merge User records from other CRE plugins or"
                            " make this field as unique and use it as a"
                            " reference in other plugin that supports user"
                            " name reference field."
                        ),
                    ),
                    EntityField(
                        name="User Key",
                        type=EntityFieldType.LIST,
                        required=True,
                        description="Device user identifiers or keys",
                    ),
                    EntityField(
                        name="Device Classification Status",
                        type=EntityFieldType.STRING,
                        description="Current device classification status",
                    ),
                    EntityField(
                        name="Tags",
                        type=EntityFieldType.LIST,
                        description="Tags assigned to the device",
                    ),
                ],
            ),
        ]

    def _convert_string_to_list(self, data_object: Dict, key: str) -> Dict:
        """
        Converts a string field in a dictionary to a list field, if needed.

        Args:
            data_object (Dict): The dictionary containing the field.
            key (str): The key of the field to convert.

        Returns:
            Dict: The dictionary with the field converted to a list if needed.
        """
        if isinstance(data_object.get(key), str):
            data_object[key] = [data_object.get(key)]
        return data_object

    def _add_field(self, fields_dict: dict, field_name: str, value):
        """
        Add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        # Skip empty dicts to prevent MongoDB errors
        if (isinstance(value, dict) or isinstance(value, list)) and not value:
            fields_dict[field_name] = None
            return

        if isinstance(value, int) or isinstance(value, float):
            fields_dict[field_name] = value
            return

        fields_dict[field_name] = value

    def _extract_field_from_event(
        self,
        key: str,
        event: dict,
        default,
        transformation=None,
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
            if k not in event:
                return default
            if not isinstance(event, dict):
                return default
            event = event.get(k)
        if transformation and transformation == "string":
            return str(event)
        return event

    def _extract_entity_fields(
        self,
        event: dict,
        entity_field_mapping: Dict[str, Dict[str, str]],
        entity: str,
    ) -> list[dict]:
        """
        Extracts the required entity fields from the event payload as
        per the mapping provided.

        Args:
            event (dict): Event payload.
            entity_field_mapping (Dict): Mapping of entity fields to
                their corresponding keys in the event payload and
                default values.
            entity (str): Entity name.

        Returns:
            list[dict]: List of dictionaries containing the extracted
                entity fields. For Users entity with comma-separated
                emails, returns multiple records.
        """
        extracted_fields = {}
        for field_name, field_value in entity_field_mapping.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self._add_field(
                fields_dict=extracted_fields,
                field_name=field_name,
                value=self._extract_field_from_event(
                    key=key,
                    event=event,
                    default=default,
                    transformation=transformation,
                ),
            )

        if entity == "Users":
            email_value = extracted_fields.get("email", "")
            if email_value and "," in email_value:
                emails = [
                    email.strip()
                    for email in email_value.split(",")
                    if email.strip()
                ]
                records = []
                for email in emails:
                    record = extracted_fields.copy()
                    record["email"] = email
                    records.append(record)
                return records
            else:
                return [extracted_fields] if extracted_fields else []

        # If the CSV response has multiple values for mac address field they
        # are separated by '|' and the tenant plugin parses it into a list
        # of strings but for single value in mac address field it is parsed
        # to a string hence converting it into list of string
        if entity == "Devices":
            extracted_fields = self._convert_string_to_list(
                data_object=extracted_fields,
                key="Mac Addresses",
            )
            # The userkey earlier was going as str, but
            # in the netity mapping we have made it as list now
            # so it should also be returned as list
            extracted_fields = self._convert_string_to_list(
                data_object=extracted_fields,
                key="User Key",
            )
            # Converting Unix timestamp to datetime object
            last_updated_timestamp = extracted_fields.get(
                "Last Updated Timestamp"
            )
            try:
                converted_datetime = (
                    datetime.fromtimestamp(
                        last_updated_timestamp, timezone.utc
                    )
                )
            except Exception:
                converted_datetime = None
            extracted_fields["Last Updated Timestamp"] = converted_datetime
        return [extracted_fields] if extracted_fields else []

    def fetch_records(self, entity: str) -> list[dict]:
        """Fetch user and application records from Netskope alerts.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        if entity == "Users":
            return self._fetch_users()
        elif entity == "Devices":
            return self._fetch_devices()
        elif entity == "Applications":
            return self._fetch_applications()
        else:
            raise ValueError(f"Unsupported entity '{entity}'")

    def _get_applications_dict(self, application_events: List):
        """Convert the application event to dict.

        Args:
            application_events (list): Events of application type.

        Return:
            application_dict (dict): application dictionary.
        """
        application_dict = {}
        for application_event in application_events:
            existing_user = application_dict.get(
                application_event.get("app", "").lower(), {}
            ).get("user", [])
            if not existing_user:
                users = (
                    [application_event.get("user")]
                    if application_event.get("user")
                    else []
                )
            else:
                existing_user.append(application_event.get("user", []))
                users = existing_user
            application_dict[application_event.get("app", "").lower()] = {
                "applicationName": application_event.get("app"),
                "cci": application_event.get("cci", None),
                "ccl": application_event.get("ccl", "unknown"),
                "users": users,
                "categoryName": application_event.get("appcategory"),
            }
        return application_dict

    def _fetch_app_details(self, applications):
        """Fetch application details from Netskope.

        Args:
            applications (dict): Dictionary of applications.

        Raises:
            NetskopeException: Error while fetching application details.
        """
        url = (
            f"{self.tenant.parameters.get('tenantName').strip()}"
            f"{URLS.get('V2_CCI_APP')}"
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        application_names = []
        last_element_counter = 0
        total_event_len = len(applications.keys())
        logger_msg = "fetching application details"
        self.logger.debug(
            f"{self.log_prefix}: {logger_msg.capitalize()} for "
            f"{total_event_len} applications."
        )
        try:
            for application in applications.keys():
                application_names.append(application)
                last_element_counter += 1
                if (
                    len(application_names) == APPLICATIONS_BATCH_SIZE
                    or last_element_counter >= total_event_len
                ):
                    app_names_req = ";".join(application_names)
                    params = {"apps": app_names_req}
                    response = self.netskope_helper._api_call_helper(
                        url=url,
                        method="get",
                        params=params,
                        error_codes=["CRE_1033", "CRE_1034"],
                        headers=headers,
                        proxies=self.proxy,
                        message=(
                            f"Error occurred while {logger_msg}"
                        ),
                        logger_msg=logger_msg
                    )

                    if response.get("data", []):
                        for apps in response.get("data", []):
                            if (
                                apps.get("app_name").lower() not in
                                applications
                            ):
                                continue
                            applications[apps.get("app_name").lower()][
                                "applicationId"
                            ] = (str(apps["id"]) if "id" in apps else None)
                            applications[apps.get("app_name").lower()][
                                "vendor"
                            ] = apps.get("organisation", None)
                            if apps.get("cci", None) is not None:
                                applications[apps.get("app_name").lower()][
                                    "cci"
                                ] = apps.get("cci", None)
                            if apps.get("ccl", None):
                                applications[apps.get("app_name").lower()][
                                    "ccl"
                                ] = apps.get("ccl", None)
                            if apps.get("category_name", None):
                                applications[apps.get("app_name").lower()][
                                    "categoryName"
                                ] = apps.get("category_name", None)
                    application_names = []
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched application "
            f"details for {total_event_len} application(s)."
        )

    def _create_applications(self, applications):
        """Pull the app information from Netskope Tenant.

        Args:
            applications (dict): Dictionary of applications.

        Returns:
            List[grc.models.Application]: List of app data \
                received from the Netskope.
        """
        app_data = []

        try:
            skip_app_count = 0
            for app in applications.values():
                deeplink = "-"
                if app.get("applicationId", None):
                    deeplink = (
                        f"{self.tenant.parameters.get('tenantName')}/ns#/"
                        f"app_index_detail/index/{app['applicationId']}"
                    )
                try:
                    app_obj = {
                        "applicationId": app.get("applicationId", None),
                        "applicationName": app.get("applicationName"),
                        "vendor": app.get("vendor"),
                        "source": self.name,
                        "cci": app.get("cci"),
                        "ccl": app.get("ccl"),
                        "categoryName": app.get("categoryName"),
                        "users": app.get("users"),
                        "deepLink": deeplink,
                        "customTags": app.get("tag_details", []),
                        "discoveryDomains": app.get("domain_details", {}).get(
                            "discovery_domains", []
                        ),
                        "steeringDomains": app.get("domain_details", {}).get(
                            "steering_domains", []
                        ),
                    } | ({} if "_id" not in app else {"_id": app.get("_id")})
                    app_data.append(app_obj)
                except Exception:
                    skip_app_count += 1
            self.logger.info(
                f"{self.log_prefix}: Successfully extracted"
                f" {len(app_data)} application(s) from the "
                f"Netskope Tenant. Skipped {skip_app_count} "
                "application(s) due to invalid data."
            )
            apps = [
                {k: v for k, v in app.items() if v} for app in app_data
            ]
            return apps
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while "
                f"processing applications. Error: {e}"
            )
        return app_data

    def _fetch_app_domains(self, applications):
        """Fetch the domain details for each application.

        Args:
            applications (dict): Dictionary of applications.

        Returns:
            None
        """
        url = (
            f"{self.tenant.parameters.get('tenantName').strip()}"
            f"{URLS.get('V2_CCI_DOMAINS')}"
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        application_ids = []
        last_element_counter = 0
        total_event_len = len(applications.keys())
        logger_msg = "fetching the domain details of the application(s)"
        self.logger.debug(
            f"{self.log_prefix}: {logger_msg.capitalize()} for "
            f"{total_event_len} application(s)."
        )
        try:
            for _, application_details in applications.items():
                application_ids.append(
                    str(application_details.get("applicationId", ""))
                )
                last_element_counter += 1
                if (
                    len(application_ids) == APPLICATIONS_BATCH_SIZE
                    or last_element_counter >= total_event_len
                ):
                    app_ids_req = ";".join(application_ids)
                    params = {"ids": app_ids_req}

                    response = self.netskope_helper._api_call_helper(
                        url=url,
                        method="get",
                        params=params,
                        headers=headers,
                        proxies=self.proxy,
                        error_codes=["CRE_1026", "CRE_1027"],
                        message=(
                            f"Error occurred while {logger_msg}"
                        ),
                        logger_msg=logger_msg
                    )

                    if response.get("data"):
                        for domain_details in response.get("data", []):
                            app_name = (
                                domain_details.get("app_name", "").lower()
                            )
                            if app_name not in applications:
                                continue
                            applications[app_name]["domain_details"] = {
                                "id": domain_details.get("id", ""),
                                "discovery_domains": domain_details.get(
                                    "discovery_domains", []
                                ),
                                "steering_domains": domain_details.get(
                                    "steering_domains", []
                                ),
                            }

                    application_ids = []
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched the domain "
            f"details for {total_event_len} application(s)."
        )

    def _fetch_app_tags(self, applications):
        """Fetch the tag details for each applications.

        Args:
            applications (dict): Dictionary of applications.

        Returns:
            None
        """
        url = (
            f"{self.tenant.parameters.get('tenantName').strip()}"
            f"{URLS.get('V2_CCI_TAGS')}"
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        application_names = []
        last_element_counter = 0
        total_event_len = len(applications.keys())
        logger_msg = "fetching the tag details of the applications"
        self.logger.debug(
            f"{self.log_prefix}: {logger_msg.capitalize()} for "
            f"{total_event_len} applications."
        )
        try:
            for application in applications.keys():
                application_names.append(application)
                last_element_counter += 1
                if (
                    len(application_names) == APPLICATIONS_BATCH_SIZE
                    or last_element_counter >= total_event_len
                ):
                    app_names_req = ";".join(application_names)
                    params = {"apps": app_names_req}
                    response = self.netskope_helper._api_call_helper(
                        url=url,
                        method="get",
                        params=params,
                        headers=headers,
                        proxies=self.proxy,
                        error_codes=["CRE_1028", "CRE_1029"],
                        message=(
                            f"Error occurred while {logger_msg}"
                        ),
                        logger_msg=logger_msg
                    )

                    if response.get("data"):
                        for app_name, tag_details in response.get("data", {}).items():
                            tag_dict_with_sanctioned = {
                                "id": tag_details.get("id"),
                                "tags": [],
                            }
                            sanction_value = tag_details.get(
                                "sanctioned", ""
                            ).lower()
                            app_type = tag_details.get("app_type")
                            custom_tags = tag_details.get("tags", [])
                            if sanction_value == "no":
                                tag_dict_with_sanctioned["tags"].append(
                                    "Unsanctioned"
                                )
                            elif sanction_value == "yes":
                                tag_dict_with_sanctioned["tags"].append(
                                    "Sanctioned"
                                )

                            tag_dict_with_sanctioned["tags"].append(app_type)
                            tag_dict_with_sanctioned["tags"].extend(
                                custom_tags
                            )
                            applications[app_name.lower()]["tag_details"] = (
                                tag_dict_with_sanctioned["tags"]
                            )

                    application_names = []
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched the tag "
            f"details for {total_event_len} application(s)."
        )

    def _fetch_applications(self) -> list[dict]:
        """Fetch applications from Netskope application events."""
        events = self.data if (self.data_type == "events" and self.sub_type == "application") else []
        self.logger.info(
            f"{self.log_prefix}: Processing {len(events)} "
            "application events."
        )
        applications_dict = self._get_applications_dict(
            events
        )
        self._fetch_app_details(applications_dict)
        applications = self._create_applications(applications_dict)

        return applications

    def _fetch_users(self) -> list[dict]:
        """Fetch users from Netskope UBA alerts."""
        alerts = self.data if self.data_type == "alerts" else []
        self.logger.info(
            f"{self.log_prefix}: Processing {len(alerts)} UBA alerts."
        )
        users = []
        empty_userkey_count = 0
        skipped_count = 0
        for users_data in alerts:
            if users_data.get("userkey", None) is None:
                empty_userkey_count += 1
            extracted_data = None
            try:
                extracted_data = self._extract_entity_fields(
                    event=users_data,
                    entity_field_mapping=USER_FIELD_MAPPING,
                    entity="Users",
                )
                if extracted_data:
                    users.extend(extracted_data)
                else:
                    skipped_count += 1
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"extracting user fields. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_count += 1
        if empty_userkey_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {empty_userkey_count}"
                " alerts due to empty userkey."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(users)}"
            f" user(s) and skipped {skipped_count} user(s) records"
            " from the Netskope Tenant."
        )
        return users

    def _update_users(self, records: list[dict]):
        """Update user scores.

        Args:
            records (list): List of users to update.

        Returns:
            list: List of updated users.
        """
        tenant_name = (
            self.tenant.parameters.get('tenantName', '').strip()
        )
        url = f"{tenant_name}{URLS.get('V2_GET_UCI')}"
        token = resolve_secret(self.tenant.parameters.get("v2token", ""))
        headers = {
            "Netskope-API-Token": token,
            "Content-Type": "application/json",
        }
        updated_users = []
        batch_count = 1
        try:
            for i in range(0, len(records), USERS_BATCH_SIZE):
                users = []
                for record in records[i : i + USERS_BATCH_SIZE]:  # noqa: E203
                    users.append(record.get("email", ""))
                payload = json.dumps(
                    {"users": users, "fromTime": 0, "capPerUser": 1}
                )
                logger_msg = (
                    f"fetching scores for {len(users)} user(s) in "
                    f"batch {batch_count}"
                )
                response = self.netskope_helper._api_call_helper(
                    url=url,
                    method="post",
                    error_codes=["CRE_1014", "CRE_1027"],
                    headers=headers,
                    data=payload,
                    proxies=self.proxy,
                    message=f"Error occurred while {logger_msg}",
                    logger_msg=logger_msg,
                )

                try:
                    for record in records[i : i + USERS_BATCH_SIZE]:  # noqa
                        match = list(
                            filter(
                                lambda user: user.get("userId", "").lower() in
                                record.get("email", "").lower(),
                                response.get("usersUci", []),
                            )
                        )
                        if (
                            "confidences" in match[0] and
                            match[0].get("confidences", [])
                        ):
                            record["ubaScore"] = (
                                match[0]["confidences"][-1].get(
                                    "confidenceScore", None
                                )
                            )
                            updated_users.append(
                                {
                                    "email": record.get("email"),
                                    "ubaScore": record.get("ubaScore")
                                }
                            )
                except Exception as e:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error occurred while "
                            f"{logger_msg}. Error: {e}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                batch_count += 1
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched scores "
            f"for {len(updated_users)} user(s) from the Netskope Tenant."
        )
        return updated_users

    def _update_devices(self, records: list[dict]) -> list[dict]:
        """Update device tags by fetching them from the Netskope tenant.

        Args:
            records (list): List of device records to update.

        Returns:
            list: List of updated device records with a new 'Tags' field.
        """
        tenant_name = self.tenant.parameters.get("tenantName", "").strip()
        url = f"{tenant_name}{URLS.get('V2_DEVICE_GET_TAGS')}"
        token = resolve_secret(self.tenant.parameters.get("v2token", ""))
        headers = {
            "Netskope-API-Token": token,
            "Content-Type": "application/json",
        }
        total_updated_record_counter = 0
        updated_records = []
        update_skip_count = 0
        for record in records:
            # Make a copy to avoid modifying the original record in case of failure
            updated_record = {}

            device_uid = record.get("Netskope Device UID")
            user_key = record.get("User Key")
            hostname = record.get("Hostname")
            updated_record["Device Serial Number"] = record.get(
                "Device Serial Number"
            )
            updated_record["Device ID"] = record.get("Device ID")
            updated_record["Netskope Device UID"] = device_uid
            updated_record["User Key"] = user_key
            updated_record["Hostname"] = hostname

            # Handle User Key as list (multi-user scenario)
            user_keys = user_key
            if isinstance(user_key, str):
                user_keys = [user_key] if user_key else []
            elif not isinstance(user_key, list):
                user_keys = []

            unique_user_keys = set()
            for uk in user_keys:
                if uk:
                    unique_user_keys.add(uk)
                else:
                    update_skip_count += 1

            if not device_uid or not unique_user_keys or not hostname:
                update_skip_count += 1
                continue

            user_keys_list = list(unique_user_keys)
            total_batches = (
                (len(user_keys_list) + TAG_DEVICE_BATCH_SIZE - 1) //
                TAG_DEVICE_BATCH_SIZE
            )

            if total_batches > 1:
                self.logger.debug(
                    f"{self.log_prefix}: Device '{device_uid}' has "
                    f"{len(user_keys_list)} user key(s). Processing "
                    f"{total_batches} batch(es) of {TAG_DEVICE_BATCH_SIZE}."
                )

            all_tags = set()
            successful_batches = 0
            failed_batches = 0

            for batch_num in range(total_batches):
                start_idx = batch_num * TAG_DEVICE_BATCH_SIZE
                end_idx = min(
                    start_idx + TAG_DEVICE_BATCH_SIZE,
                    len(user_keys_list)
                )
                user_keys_batch = user_keys_list[start_idx:end_idx]

                devices_payload = [
                    {
                        "nsdeviceuid": device_uid,
                        "userkey": user_key,
                        "hostname": hostname
                    }
                    for user_key in user_keys_batch
                ]
                payload = {"devices": devices_payload}
                logger_msg = (
                    f"fetching tags for device with UID '{device_uid}' "
                    f"(batch {batch_num + 1}/{total_batches} with "
                    f"{len(user_keys_batch)} user(s))"
                )

                try:
                    response = self.netskope_helper._api_call_helper(
                        url=url,
                        method="post",
                        headers=headers,
                        json=payload,
                        proxies=self.proxy,
                        message=f"Error occurred while {logger_msg}",
                        logger_msg=logger_msg,
                        error_codes=["CRE_1045", "CRE_1049"],
                    )

                    if response.get("success"):
                        tags = [
                            tag.get("name")
                            for tag in response.get("data", {}).get("data", [])
                            if tag.get("name")
                        ]
                        all_tags.update(tags)
                        successful_batches += 1
                    else:
                        self.logger.info(
                            message=(
                                f"{self.log_prefix}: Batch "
                                f"{batch_num + 1}/{total_batches} failed for device "
                                f"with UID '{device_uid}'."
                            ),
                            details=(
                                f"{str(response.get('error'))}"
                            )
                        )
                        failed_batches += 1
                        continue

                except NetskopeException as e:
                    self.logger.error(
                        f"{self.log_prefix}: {logger_msg} failed due to an "
                        f"exception. Error: {e}"
                    )
                    failed_batches += 1
                    continue
                except Exception as e:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Unexpected error while "
                            f"{logger_msg}. Error: {e}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    failed_batches += 1
                    continue

            log_msg = ""
            if failed_batches > 0:
                log_msg = (
                    f" Failed to fetch tags for {failed_batches} "
                    f"out of {total_batches} batch(es) for device "
                    f"with UID '{device_uid}'."
                )

            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched tags for "
                f"{successful_batches} batch(es).{log_msg}"
            )

            updated_record["Tags"] = list(all_tags)
            updated_records.append(updated_record)

            if list(all_tags):
                total_updated_record_counter += 1
        skip_msg = "."
        if update_skip_count > 0:
            skip_msg += (
                f" Skipped {update_skip_count} records due to missing "
                f"Netskope Device UID, User Key, or Hostname."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully updated {len(updated_records)}"
            f" record(s). Fetched tag(s) for {total_updated_record_counter} out "
            f"of {len(records)} record(s){skip_msg}"
        )
        return updated_records

    def _update_applications(self, records: list[dict]):
        """Update application scores.

        Args:
            records (list): List of applications to update.

        Returns:
            list: List of updated applications.
        """
        applications = {}
        for app in records:
            applications[app.get("applicationName", "").lower()] = app
        self._fetch_app_details(applications)
        self._fetch_app_domains(applications)
        self._fetch_app_tags(applications)
        apps = self._create_applications(applications)
        self.logger.info(
            f"{self.log_prefix}: Successfully updated {len(apps)} "
            "application records from the Netskope Tenant."
        )
        return apps

    def _fetch_devices(self):
        """Fetch devices from Netskope client status events."""
        client_status_events = self.data if (
            self.data_type == "events" and self.sub_type == "clientstatus"
        ) else []
        self.logger.info(
            f"{self.log_prefix}: Processing {len(client_status_events)} "
            "client status events."
        )
        devices = []
        skipped_count = 0
        for device_data in client_status_events:
            try:
                extracted_data = self._extract_entity_fields(
                    event=device_data,
                    entity_field_mapping=DEVICE_FIELD_MAPPING,
                    entity="Devices",
                )
                if extracted_data:
                    devices.extend(extracted_data)
                else:
                    skipped_count += 1
            except Exception as e:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"extracting device fields. Error: {e}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_count += 1
                continue
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(devices)}"
            f" device(s) and skipped {skipped_count} device(s) records"
            " from the Netskope Tenant."
        )
        return devices

    def update_records(self, entity: str, records: List[dict]):
        """Fetch user scores.

        Args:
            entity (str): Entity to update.
            records (list): List of records to update.

        Returns:
            list: List of updated records.
        """
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        update_logger_msg = (
            f"{self.log_prefix}: Updating {len(records)} "
            f"{entity} record(s) from the Netskope Tenant."
        )
        if entity == "Users":
            self.logger.info(update_logger_msg)
            return self._update_users(records)
        elif entity == "Applications":
            self.logger.info(update_logger_msg)
            return self._update_applications(records)
        elif entity == "Devices":
            # Add tags to devices
            self.logger.info(update_logger_msg)
            return self._update_devices(records)
        else:
            raise ValueError(f"Unsupported entity '{entity}'")

    def _get_tenant_and_headers(self) -> Tuple[str, Dict]:
        """Return the tenant base URL and the v2-token auth headers.

        The Add to Destination/DNS/Service Profile and Create Device
        Classification actions all authenticate the same way against the
        shared Netskope provider tenant. This resolves the tenant base
        URL and builds the ``Netskope-API-Token`` header once so the
        per-action helpers do not each repeat the same setup.

        Returns:
            Tuple[str, Dict]: ``(tenant_name, headers)`` where
                ``tenant_name`` is the stripped tenant base URL and
                ``headers`` carries the resolved v2 API token.
        """
        tenant_name = (
            self.tenant.parameters.get("tenantName", "").strip()
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        return tenant_name, headers

    def _get_destination_profiles(
        self,
        is_values_required: bool = False,
    ) -> Dict:
        """Fetch destination profiles from the Netskope Tenant.

        Iterates over the destinations list endpoint using
        offset/limit pagination and returns a mapping keyed by
        profile name. Each value carries the metadata fields
        required for de-duplication and capacity checks.

        Args:
            is_values_required (bool): When True request the
                profile ``values`` as well (needed to skip values
                that are already present). Defaults to False.

        Returns:
            Dict: Mapping of profile name to profile metadata
                (id, name, type, values_count, description[, values]).
        """
        tenant_name, headers = self._get_tenant_and_headers()
        url = f"{tenant_name}{URLS.get('V2_DESTINATION_PROFILE')}"
        profiles = {}
        offset = 0
        limit = 100
        logger_msg = "fetching destination profiles from the Netskope Tenant"
        self.logger.debug(
            f"{self.log_prefix}: {logger_msg.capitalize()}."
        )
        try:
            # Drive the loop off the page size rather than a returned
            # total: stop once a page returns fewer than ``limit``
            # items and advance the offset by the number actually
            # returned, so a missing/incorrect total cannot cause an
            # early stop or an infinite loop.
            while True:
                params = {
                    "fields": (
                        "id,name,type,values_count,description"
                        + (",values" if is_values_required else "")
                    ),
                    "offset": offset,
                    "limit": limit,
                }
                response = self.netskope_helper._api_call_helper(
                    url=url,
                    method="get",
                    error_codes=["CRE_1063", "CRE_1064"],
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    message=f"Error occurred while {logger_msg}",
                    logger_msg=logger_msg,
                )
                elements = response.get("elements", [])
                for profile in elements:
                    profiles[profile.get("name", "")] = profile
                if len(elements) < limit:
                    break
                offset += len(elements)
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched "
            f"{len(profiles)} destination profile(s)."
        )
        return profiles

    def _deploy_destination_profile(self, ids: list) -> bool:
        """Apply pending changes for the given destination profiles.

        Calls the destinations deploy endpoint so that profiles
        carrying undeployed (pending) changes become editable
        again before values are appended.

        Args:
            ids (list): Destination profile ids to deploy.

        Returns:
            bool: True when every requested id was applied,
                False otherwise.
        """
        tenant_name, headers = self._get_tenant_and_headers()
        url = f"{tenant_name}{URLS.get('V2_DESTINATION_PROFILE_DEPLOY')}"
        payload = {"ids": ids}
        logger_msg = (
            "applying pending changes for destination "
            f"profile(s) {ids}"
        )
        self.logger.debug(
            f"{self.log_prefix}: {logger_msg.capitalize()}."
        )
        try:
            response = self.netskope_helper._api_call_helper(
                url=url,
                method="post",
                error_codes=["CRE_1067", "CRE_1068"],
                headers=headers,
                json=payload,
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
                is_handle_error_required=False,
            )
            if response.status_code not in [200, 201]:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"{logger_msg}. Received exit code "
                        f"{response.status_code}."
                    ),
                    details=str(response.text),
                )
                return False
            deploy_json = handle_status_code(
                response,
                error_code="CRE_1068",
                custom_message=f"Error occurred while {logger_msg}",
                plugin=self.log_prefix,
                notify=False,
                log=True,
            )
            applied = []
            if isinstance(deploy_json, dict):
                applied = deploy_json.get("applied", [])
            success = all(str(i) in [str(a) for a in applied] for i in ids)
            if not success:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Pending changes were not "
                        f"applied for all destination profile(s) {ids}."
                    ),
                    details=repr(deploy_json),
                )
            return success
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)

    def _push_destination_profile(
        self,
        destination_values: list,
        existing_profile_name: str,
        new_profile_name: str,
        new_profile_description: str,
        match_type: str,
        apply_pending_changes: str = "No",
        operation: str = "append",
        exact_total_limit: Optional[int] = None,
    ) -> int:
        """Create or update values on a Netskope destination profile.

        When ``existing_profile_name`` is ``"create"`` a new profile
        is created with the resolved values. Otherwise, for an
        ``append`` operation the values are added (PATCH on the values
        endpoint) to the matching profile, skipping any value already
        present; for a ``replace`` operation the whole value list is
        overwritten in a single PATCH on the profile id endpoint.
        Capacity limits are respected best-effort by trimming overflow
        before the request, while still relying on the API to reject
        anything it cannot accept. A 409 pending-changes response
        triggers a deploy + retry only when ``apply_pending_changes``
        is ``"Yes"``; otherwise it is logged and skipped.

        Args:
            destination_values (list): Resolved, de-duplicated values
                to add to the profile.
            existing_profile_name (str): Selected profile name, or the
                literal ``"create"`` to create a new profile.
            new_profile_name (str): Name to use when creating a profile.
            new_profile_description (str): Description for a new profile.
            match_type (str): Match type for a new profile
                (insensitive/sensitive/regex).
            apply_pending_changes (str): ``"Yes"`` to auto-deploy
                pending changes on a 409, else ``"No"``.
            operation (str): ``append`` to keep the existing values and
                add to them, ``replace`` to overwrite the profile with
                the provided values.
            exact_total_limit (Optional[int]): Tenant-wide exact-match
                value limit from the action parameter; ``None`` falls
                back to the default constant.

        Returns:
            tuple: ``(shared_count, not_applied)`` where ``shared_count``
                is the count of values successfully shared to the profile
                and ``not_applied`` is the list of values that failed or
                were skipped (capacity overflow or a failed batch). Used
                by the bulk caller to attribute unshared values back to
                their originating action ids.
        """
        tenant_name, headers = self._get_tenant_and_headers()
        values = [v for v in destination_values if v]
        if not values:
            self.logger.info(
                f"{self.log_prefix}: No network targets to share "
                "after removing empty entries. Skipping action execution."
            )
            return 0, []
        try:
            existing_profiles = self._get_destination_profiles(
                is_values_required=True
            )
            if existing_profile_name == "create":
                # Re-running the action with the same parameters would
                # otherwise attempt to create a duplicate profile, which
                # the API rejects with an "already exists" error. If a
                # profile with the requested name already exists, share
                # the values to it instead of creating a new one.
                if new_profile_name not in existing_profiles:
                    return self._create_destination_profile(
                        tenant_name=tenant_name,
                        headers=headers,
                        profile_name=new_profile_name,
                        description=new_profile_description,
                        match_type=match_type,
                        values=values,
                        existing_profiles=existing_profiles,
                        exact_total_limit=exact_total_limit,
                    )
                self.logger.info(
                    f"{self.log_prefix}: Destination profile "
                    f"'{new_profile_name}' already exists on the "
                    "Netskope Tenant; adding values to the existing "
                    "profile instead of creating a new one."
                )
                target_profile = existing_profiles.get(new_profile_name)
            else:
                target_profile = existing_profiles.get(
                    existing_profile_name
                )
                if not target_profile:
                    error_message = (
                        f"Destination profile '{existing_profile_name}' "
                        "could not be found on the Netskope Tenant."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {error_message}",
                        resolution=(
                            "Verify the destination profile still exists "
                            "on the Netskope Tenant and re-run the "
                            "action."
                        ),
                    )
                    raise NetskopeException(error_message)
                self.logger.info(
                    f"{self.log_prefix}: Found destination "
                    f"profile '{existing_profile_name}' on "
                    "the Netskope Tenant."
                )
            if operation == "replace":
                return self._replace_destination_profile_values(
                    tenant_name=tenant_name,
                    headers=headers,
                    profile=target_profile,
                    values=values,
                    new_profile_description=new_profile_description,
                    match_type=match_type,
                    existing_profiles=existing_profiles,
                    apply_pending_changes=apply_pending_changes,
                    exact_total_limit=exact_total_limit,
                )
            return self._append_destination_profile_values(
                tenant_name=tenant_name,
                headers=headers,
                profile=target_profile,
                values=values,
                new_profile_description=new_profile_description,
                match_type=match_type,
                existing_profiles=existing_profiles,
                apply_pending_changes=apply_pending_changes,
                exact_total_limit=exact_total_limit,
            )
        except NetskopeException:
            raise
        except Exception as err:
            profile_name = (
                new_profile_name
                if existing_profile_name == "create"
                else existing_profile_name
            )
            error_message = (
                "Unexpected error occurred while adding Network Targets"
                f" to destination profile '{profile_name}'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)

    def _create_destination_profile(
        self,
        tenant_name: str,
        headers: dict,
        profile_name: str,
        description: str,
        match_type: str,
        values: list,
        existing_profiles: Dict,
        exact_total_limit: Optional[int] = None,
    ) -> int:
        """Create a new destination profile with the given values.

        Trims the value list to the available capacity for the
        requested match type before issuing the create request, then
        relies on the API to reject anything it still cannot accept.

        Args:
            tenant_name (str): Netskope tenant base URL.
            headers (dict): Request headers including the API token.
            profile_name (str): Name of the profile to create.
            description (str): Description for the new profile.
            match_type (str): Match type for the new profile.
            values (list): De-duplicated values to add.
            existing_profiles (Dict): Existing profiles used for the
                capacity computation.
            exact_total_limit (Optional[int]): Tenant-wide exact-match
                value limit override; ``None`` uses the default
                constant.

        Returns:
            tuple: ``(shared_count, not_applied)`` where ``shared_count``
                is the count of values successfully shared and
                ``not_applied`` is the list of values dropped because of
                capacity limits.
        """
        max_shareable, limit_label = self.netskope_helper._destination_profile_capacity(
            existing_profiles=existing_profiles,
            target_profile_name="",
            match_type=match_type,
            requested_count=len(values),
            exact_total_limit=exact_total_limit,
        )
        if max_shareable <= 0:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: The destination profile "
                    f"capacity for match type '{match_type}' is "
                    f"exhausted on the Netskope Tenant ({limit_label} "
                    "has been reached). Skipping creation of profile "
                    f"'{profile_name}'."
                ),
                resolution=(
                    "Remove unused values or profiles on the Netskope "
                    "Tenant to free up capacity, then re-run the action."
                ),
            )
            return 0, list(values)
        bounded_values = values[:max_shareable]
        capacity_overflow_values = values[max_shareable:]
        capacity_overflow = len(capacity_overflow_values)
        # The create POST body is also bound by the destination profile
        # API payload limit, so only the first chunk that fits is sent on
        # create; the remainder is appended on the values endpoint after
        # the profile id is known.
        budget = (
            DESTINATION_PROFILE_PAYLOAD_LIMIT
            - DESTINATION_PROFILE_PAYLOAD_SAFETY_BUFFER
        )
        base_overhead = len(
            json.dumps(
                {
                    "name": profile_name,
                    "description": description,
                    "type": match_type,
                    "values": [],
                }
            ).encode("utf-8")
        )
        post_chunk, post_overflow = (
            self.netskope_helper._split_values_within_budget(
                bounded_values, base_overhead, budget
            )
        )
        # A single value can never realistically exceed the budget; if
        # the metadata pushed the first value just over, still send it so
        # the profile is created with at least one value.
        if not post_chunk and bounded_values:
            post_chunk = [bounded_values[0]]
            post_overflow = bounded_values[1:]
        payload = {
            "name": profile_name,
            "description": description,
            "type": match_type,
            "values": post_chunk,
        }
        url = f"{tenant_name}{URLS.get('V2_DESTINATION_PROFILE')}"
        logger_msg = (
            f"creating destination profile '{profile_name}' on the "
            "Netskope Tenant"
        )
        self.logger.info(
            f"{self.log_prefix}: Creating destination profile "
            f"'{profile_name}' with {len(bounded_values)} "
            "provided network target(s) on the Netskope "
            "Tenant."
        )
        response = self.netskope_helper._api_call_helper(
            url=url,
            method="post",
            error_codes=["CRE_1065", "CRE_1066"],
            headers=headers,
            json=payload,
            proxies=self.proxy,
            message=f"Error occurred while {logger_msg}",
            logger_msg=logger_msg,
            is_handle_error_required=False,
        )
        if response.status_code not in [200, 201]:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} Received "
                    f"exit code {response.status_code}."
                ),
                details=str(response.text),
                resolution=(
                    "Verify the profile name is unique and the values "
                    "are valid for the selected match type, then "
                    "re-run the action."
                ),
            )
            raise NetskopeException(error_message)
        handle_status_code(
            response,
            error_code="CRE_1066",
            custom_message=f"Error occurred while {logger_msg}",
            plugin=self.log_prefix,
            notify=False,
            log=True,
        )
        # Append the values that did not fit the create POST (if any) to
        # the freshly created profile via the values endpoint.
        not_applied = list(capacity_overflow_values)
        applied_count = len(post_chunk)
        if post_overflow:
            profile_id = ""
            try:
                profile_id = (response.json() or {}).get("id", "")
            except Exception:
                profile_id = ""
            if not profile_id:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Could not determine the id "
                        f"of the newly created destination profile "
                        f"'{profile_name}', so {len(post_overflow)} "
                        "value(s) that did not fit the create request "
                        "could not be added."
                    ),
                    resolution=(
                        "Re-run the action to add the remaining values "
                        "to the now-existing destination profile."
                    ),
                )
                not_applied.extend(post_overflow)
            else:
                failed_idx = self._append_destination_value_batches(
                    tenant_name=tenant_name,
                    headers=headers,
                    profile_id=profile_id,
                    profile_name=profile_name,
                    values=post_overflow,
                    apply_pending_changes="No",
                )
                applied_count += len(post_overflow) - len(failed_idx)
                not_applied.extend(
                    post_overflow[i] for i in sorted(failed_idx)
                )
        overflow_msg = ""
        if capacity_overflow:
            overflow_msg = (
                f" Skipped {capacity_overflow} value(s) that exceeded "
                f"{limit_label} on the Netskope Tenant."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully created destination "
            f"profile '{profile_name}' with {applied_count} "
            f"value(s).{overflow_msg}"
        )
        return applied_count, not_applied

    def _append_destination_profile_values(
        self,
        tenant_name: str,
        headers: dict,
        profile: dict,
        values: list,
        new_profile_description: str,
        match_type: str,
        existing_profiles: Dict,
        apply_pending_changes: str,
        exact_total_limit: Optional[int] = None,
    ) -> int:
        """Append values to an existing destination profile.

        The whole value list (the profile's current values plus the
        provided values) is sent in a single PATCH on the profile id
        endpoint, together with the desired match ``type`` (always sent,
        required by this endpoint) and ``description`` (sent only when it
        differs from the fetched profile). Values already present on the
        profile are **not** removed from the provided set: a destination
        profile accepts duplicate values regardless of match type, so a
        provided value already on the profile is added again. The
        provided values are trimmed to the available capacity before the
        request. A 409 pending-changes response is deployed and the PATCH
        retried once when ``apply_pending_changes`` is ``"Yes"``;
        otherwise it is logged and skipped.

        Args:
            tenant_name (str): Netskope tenant base URL.
            headers (dict): Request headers including the API token.
            profile (dict): Target profile metadata (id, name, type,
                description, values[, values_count]).
            values (list): De-duplicated values to add to the profile.
            new_profile_description (str): Desired description; sent only
                if it differs from the existing one.
            match_type (str): Desired match type; always sent as it is
                required by the endpoint.
            existing_profiles (Dict): Existing profiles used for the
                capacity computation.
            apply_pending_changes (str): ``"Yes"`` to auto-deploy on a
                409, else ``"No"``.
            exact_total_limit (Optional[int]): Tenant-wide exact-match
                value limit override; ``None`` uses the default
                constant.

        Returns:
            tuple: ``(shared_count, not_applied)`` where ``shared_count``
                is the count of values successfully added and
                ``not_applied`` is the list of values dropped because of
                capacity limits, or the whole provided set when the PATCH
                itself is skipped/failed.
        """
        profile_id = profile.get("id", "")
        profile_name = profile.get("name", "")
        existing_type = profile.get("type", "")
        existing_description = profile.get("description", "")
        existing_values = list(profile.get("values", []) or [])
        # For an append that also switches the type to regex, the by-id
        # PATCH must re-send all existing values with the new type. If
        # the existing value count alone exceeds the regex total limit,
        # the PATCH will time out regardless of how many new values are
        # added — short-circuit before making any API call.
        if (
            match_type == "regex"
            and existing_type != "regex"
            and len(existing_values)
            > DESTINATION_PROFILE_REGEX_TOTAL_LIMIT
        ):
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Cannot change the "
                    f"match type of destination profile "
                    f"'{profile_name}' to 'regex' — the "
                    f"profile already holds "
                    f"{len(existing_values)} value(s), which "
                    "exceeds the regex total limit of "
                    f"{DESTINATION_PROFILE_REGEX_TOTAL_LIMIT}."
                    " Skipping action execution.."
                ),
                resolution=(
                    "Reduce the profile's values to below "
                    f"{DESTINATION_PROFILE_REGEX_TOTAL_LIMIT}"
                    " before changing its match type to "
                    "'regex', then re-run the action."
                ),
            )
            return 0, list(values)
        # The existing values stay on the profile, so the capacity
        # baseline keeps the profile's current usage and only the newly
        # provided values count as requested. Use match_type (the desired
        # type) so that a type switch (e.g. exact → regex) is checked
        # against the correct bucket; using existing_type would silently
        # pass new values that the API will reject.
        max_shareable, limit_label = self.netskope_helper._destination_profile_capacity(
            existing_profiles=existing_profiles,
            target_profile_name=profile_name,
            match_type=match_type,
            requested_count=len(values),
            exact_total_limit=exact_total_limit,
        )
        type_changed = bool(match_type) and match_type != existing_type
        desc_changed = bool(new_profile_description) and (
            new_profile_description != existing_description
        )
        if max_shareable > 0:
            bounded_new = values[:max_shareable]
            capacity_overflow_values = values[max_shareable:]
            if capacity_overflow_values:
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"{len(capacity_overflow_values)} of "
                    f"{len(values)} provided network target(s)"
                    f" exceed the capacity for destination "
                    f"profile '{profile_name}' ({limit_label})"
                    f"; only {len(bounded_new)} will be "
                    "applied."
                )
        else:
            bounded_new = []
            capacity_overflow_values = list(values)
        # Nothing new fits and the match type/description are unchanged:
        # there is nothing to send.
        if not bounded_new and not type_changed and not desc_changed:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: The destination profile "
                    f"capacity for '{profile_name}' (match type "
                    f"'{match_type}') is exhausted on the Netskope "
                    f"Tenant ({limit_label} has been reached). "
                    "Skipping adding values."
                ),
                resolution=(
                    "Remove unused values or profiles on the Netskope "
                    "Tenant to free up capacity, then re-run the action."
                ),
            )
            return 0, list(values)
        # The match type is always sent; the description only when it
        # differs from the fetched profile.
        metadata_body = {"type": match_type}
        if desc_changed:
            metadata_body["description"] = new_profile_description
        # The existing values are kept on the profile, so they lead the
        # value set the profile must end up holding; the provided
        # (capacity-bounded) values follow and are the only ones
        # attributed back to action ids.
        return self._write_destination_profile_values(
            tenant_name=tenant_name,
            headers=headers,
            profile_id=profile_id,
            profile_name=profile_name,
            metadata_body=metadata_body,
            existing_values=existing_values,
            new_values=bounded_new,
            capacity_overflow_values=capacity_overflow_values,
            apply_pending_changes=apply_pending_changes,
            action_phrase="adding values to destination profile",
            success_verb="added values to",
            limit_label=limit_label,
        )

    def _replace_destination_profile_values(
        self,
        tenant_name: str,
        headers: dict,
        profile: dict,
        values: list,
        new_profile_description: str,
        match_type: str,
        existing_profiles: Dict,
        apply_pending_changes: str,
        exact_total_limit: Optional[int] = None,
    ) -> int:
        """Replace all values on an existing destination profile.

        Overwrites the profile's value list in a single PATCH on the
        profile id endpoint, which is far cheaper than removing the
        existing values in capped batches. ``type`` is always sent (it
        is required by this endpoint); ``description`` is included only
        when it differs from the profile fetched from the API. The new
        value set is trimmed to the
        available capacity (the profile's current values are freed by
        the replace). A 409 pending-changes response is deployed and
        the PATCH retried once when ``apply_pending_changes`` is
        ``"Yes"``; otherwise it is logged and skipped.

        Args:
            tenant_name (str): Netskope tenant base URL.
            headers (dict): Request headers including the API token.
            profile (dict): Target profile metadata (id, name, type,
                description).
            values (list): De-duplicated values to set on the profile.
            new_profile_description (str): Desired description; sent
                only if it differs from the existing one.
            match_type (str): Desired match type; always sent as it is
                required by the endpoint.
            existing_profiles (Dict): Existing profiles used for the
                capacity computation.
            apply_pending_changes (str): ``"Yes"`` to auto-deploy on a
                409, else ``"No"``.
            exact_total_limit (Optional[int]): Tenant-wide exact-match
                value limit override; ``None`` uses the default
                constant.

        Returns:
            tuple: ``(shared_count, not_applied)`` where ``shared_count``
                is the count of values the profile was replaced with and
                ``not_applied`` is the list of values that could not be
                applied (capacity overflow, or the whole value set when
                the replace request itself is skipped/failed).
        """
        profile_id = profile.get("id", "")
        profile_name = profile.get("name", "")
        existing_type = profile.get("type", "")
        existing_description = profile.get("description", "")
        # Replacing frees the profile's current values, so treat its
        # usage as zero when checking capacity for the new value set.
        # Use match_type (the desired type after the replace), not
        # existing_type: if the replace also changes the type bucket
        # (exact ↔ regex), the capacity limits differ and using the old
        # type would silently pass a value set that the API rejects.
        capacity_profiles = dict(existing_profiles)
        target_copy = dict(capacity_profiles.get(profile_name, {}))
        target_copy["values_count"] = 0
        capacity_profiles[profile_name] = target_copy
        max_shareable, limit_label = self.netskope_helper._destination_profile_capacity(
            existing_profiles=capacity_profiles,
            target_profile_name=profile_name,
            match_type=match_type,
            requested_count=len(values),
            exact_total_limit=exact_total_limit,
        )
        if max_shareable <= 0:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: The destination profile "
                    f"capacity for '{profile_name}' (match type "
                    f"'{match_type}') is exhausted on the Netskope "
                    f"Tenant ({limit_label} has been reached). "
                    "Skipping value replacement."
                ),
                resolution=(
                    "Remove unused values or profiles on the Netskope "
                    "Tenant to free up capacity, then re-run the action."
                ),
            )
            return 0, list(values)
        bounded_values = values[:max_shareable]
        capacity_overflow_values = values[max_shareable:]
        if capacity_overflow_values:
            self.logger.info(
                f"{self.log_prefix}: "
                f"{len(capacity_overflow_values)} of "
                f"{len(values)} provided network target(s) "
                f"exceed the capacity for destination profile"
                f" '{profile_name}' ({limit_label}); only "
                f"{len(bounded_values)} will be applied."
            )
        # The match type is always sent; the description only when it
        # differs from the fetched profile.
        metadata_body = {"type": match_type}
        if (
            new_profile_description
            and new_profile_description != existing_description
        ):
            metadata_body["description"] = new_profile_description
        # Replace discards the profile's current values, so there are no
        # existing values to preserve; the whole (capacity-bounded)
        # provided set is what the profile must end up holding.
        return self._write_destination_profile_values(
            tenant_name=tenant_name,
            headers=headers,
            profile_id=profile_id,
            profile_name=profile_name,
            metadata_body=metadata_body,
            existing_values=[],
            new_values=bounded_values,
            capacity_overflow_values=capacity_overflow_values,
            apply_pending_changes=apply_pending_changes,
            action_phrase="replacing the values of destination profile",
            success_verb="replaced the values of",
            limit_label=limit_label,
        )

    def _write_destination_profile_values(
        self,
        tenant_name: str,
        headers: dict,
        profile_id: str,
        profile_name: str,
        metadata_body: dict,
        existing_values: list,
        new_values: list,
        capacity_overflow_values: list,
        apply_pending_changes: str,
        action_phrase: str,
        success_verb: str,
        limit_label: str,
    ) -> tuple:
        """Write a profile's value set, splitting at the payload budget.

        Shared by the append and replace operations. The value set the
        profile must end up holding is ``existing_values + new_values``
        (``existing_values`` is empty for replace). The leading chunk
        that fits the destination profile by-id PATCH payload budget —
        together with the ``metadata_body`` (``type`` always,
        ``description`` when changed) — is written with a single by-id
        PATCH (which **replaces** the value list); whatever did not fit is
        then added in batches of up to
        ``DESTINATION_PROFILE_VALUES_PER_APPEND`` (10) values on the values
        endpoint (``op: append``, which leaves the already-written values
        in place). When the whole set fits the budget this collapses to a
        single by-id PATCH.

        Only the provided (``new_values``) values are attributed back to
        action ids: a provided value is applied when it landed in the
        PATCH chunk or in a batch that appended successfully. Existing
        values that are re-sent only to preserve them are not attributed
        (see the metadata-update transient-state risk in the workflow
        doc).

        Args:
            tenant_name (str): Netskope tenant base URL.
            headers (dict): Request headers including the API token.
            profile_id (str): Id of the target profile.
            profile_name (str): Name of the target profile (logging).
            metadata_body (dict): ``type`` plus an optional
                ``description`` to apply via the by-id PATCH.
            existing_values (list): Values already on the profile that
                must be preserved (empty for replace).
            new_values (list): Capacity-bounded provided values; the only
                ones attributed back to action ids.
            capacity_overflow_values (list): Provided values dropped for
                capacity before this call; reported as not applied.
            apply_pending_changes (str): ``"Yes"`` to auto-deploy on a
                409, else ``"No"``.
            action_phrase (str): Present-participle phrase for in-progress
                / error logs, e.g. ``"adding values to destination
                profile"``.
            success_verb (str): Past-tense verb for the success summary,
                e.g. ``"added values to"`` / ``"replaced the values of"``.
            limit_label (str): Human-readable capacity limit description
                used in the capacity-overflow part of the summary.

        Returns:
            tuple: ``(applied_count, not_applied)`` where ``applied_count``
                is the number of provided values written and
                ``not_applied`` is the list of provided values that could
                not be written (capacity overflow, plus any payload batch
                that was skipped/failed, or the whole provided set when
                the by-id PATCH itself is skipped/failed).
        """
        budget = (
            DESTINATION_PROFILE_PAYLOAD_LIMIT
            - DESTINATION_PROFILE_PAYLOAD_SAFETY_BUFFER
        )
        combined = list(existing_values) + list(new_values)
        new_offset = len(existing_values)
        # The by-id PATCH body carries the metadata, so the first chunk
        # must fit within the budget once the metadata overhead is
        # accounted for.
        patch_overhead = len(
            json.dumps({**metadata_body, "values": []}).encode("utf-8")
        )
        patch_chunk, overflow = (
            self.netskope_helper._split_values_within_budget(
                combined, patch_overhead, budget
            )
        )
        # A single value can never realistically exceed the budget; if
        # the metadata pushed the first value just over, still send it in
        # the PATCH (the API rejects a values-less PATCH).
        if not patch_chunk and combined:
            patch_chunk = [combined[0]]
            overflow = combined[1:]
        by_id_path = URLS.get(
            "V2_DESTINATION_PROFILE_BY_ID"
        ).format(profile_id)
        by_id_url = f"{tenant_name}{by_id_path}"
        patch_logger_msg = f"{action_phrase} '{profile_name}'"
        if action_phrase.startswith("adding"):
            self.logger.info(
                f"{self.log_prefix}: Appending "
                f"{len(new_values)} provided network "
                f"target(s) to destination profile "
                f"'{profile_name}'."
            )
        else:
            self.logger.info(
                f"{self.log_prefix}: Replacing the values "
                f"of destination profile '{profile_name}' "
                f"with {len(new_values)} provided network "
                "target(s)."
            )
        if not self._send_destination_request(
            url=by_id_url,
            headers=headers,
            method="patch",
            body={**metadata_body, "values": patch_chunk},
            profile_id=profile_id,
            profile_name=profile_name,
            apply_pending_changes=apply_pending_changes,
            logger_msg=patch_logger_msg,
        ):
            # The by-id PATCH itself was skipped or failed, so nothing was
            # written: every provided value is reported not applied.
            return 0, list(capacity_overflow_values) + list(new_values)
        # Append whatever did not fit the PATCH on the values endpoint.
        failed_overflow_idx = set()
        if overflow:
            self.logger.info(
                f"{self.log_prefix}: Payload limit (9 MB) reached for "
                f"destination profile '{profile_name}' API call. Adding "
                f"{len(patch_chunk)} or the {len(combined)} values to the "
                "destinaton Profile in the initial API call. The remaining "
                f"{len(overflow)} value(s) will be added via the append "
                "values endpoint in batches of "
                f"{DESTINATION_PROFILE_VALUES_PER_APPEND}."
            )
            failed_overflow_idx = self._append_destination_value_batches(
                tenant_name=tenant_name,
                headers=headers,
                profile_id=profile_id,
                profile_name=profile_name,
                values=overflow,
                apply_pending_changes=apply_pending_changes,
            )
        # Attribute applied vs not-applied for the provided values only.
        patch_count = len(patch_chunk)
        not_applied_new = []
        for j, value in enumerate(new_values):
            combined_index = new_offset + j
            if combined_index < patch_count:
                # Written by the by-id PATCH.
                continue
            if (combined_index - patch_count) in failed_overflow_idx:
                not_applied_new.append(value)
        applied_count = len(new_values) - len(not_applied_new)
        not_applied = list(capacity_overflow_values) + not_applied_new
        overflow_msg = ""
        if capacity_overflow_values:
            overflow_msg = (
                f" Skipped {len(capacity_overflow_values)} value(s) that "
                f"exceeded {limit_label} on the Netskope Tenant."
            )
        payload_skip_msg = ""
        if not_applied_new:
            payload_skip_msg = (
                f" Could not add {len(not_applied_new)} value(s) to the "
                "destination profile; the append request was skipped or "
                "failed."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully {success_verb} destination "
            f"profile '{profile_name}' ({applied_count} provided "
            f"value(s) applied).{overflow_msg}{payload_skip_msg}"
        )
        return applied_count, not_applied

    def _append_destination_value_batches(
        self,
        tenant_name: str,
        headers: dict,
        profile_id: str,
        profile_name: str,
        values: list,
        apply_pending_changes: str,
    ) -> set:
        """Append values to a profile via the values endpoint in batches.

        The values endpoint accepts at most
        ``DESTINATION_PROFILE_VALUES_PER_APPEND`` (10) values per call, so
        ``values`` is split into batches of that many and each batch is
        appended with a ``PATCH`` to the values endpoint
        (``{"operation": {"op": "append", "values": [...]}}``), which
        leaves the profile's existing values in place. (The payload size
        budget applies only to the by-id PATCH / create POST that carry
        the match type and description, not to this append endpoint, which
        is bounded by a value count.) Each batch reuses the shared 409
        pending-changes deploy + retry handling. Best effort: a batch that
        is skipped or fails is recorded and the remaining batches are
        still attempted.

        Args:
            tenant_name (str): Netskope tenant base URL.
            headers (dict): Request headers including the API token.
            profile_id (str): Id of the target profile.
            profile_name (str): Name of the target profile (logging).
            values (list): Values to append, in order.
            apply_pending_changes (str): ``"Yes"`` to auto-deploy on a
                409, else ``"No"``.

        Returns:
            set: Indices (into ``values``) whose batch was skipped or
                failed to append; empty when every batch succeeded.
        """
        values_path = URLS.get(
            "V2_DESTINATION_PROFILE_VALUES"
        ).format(profile_id)
        values_url = f"{tenant_name}{values_path}"
        batch_size = DESTINATION_PROFILE_VALUES_PER_APPEND
        total_batches = (len(values) + batch_size - 1) // batch_size
        failed_idx = set()
        for batch_index, start in enumerate(
            range(0, len(values), batch_size), start=1
        ):
            batch = values[start:start + batch_size]
            logger_msg = (
                f"appending values to destination profile "
                f"'{profile_name}' (batch {batch_index} of "
                f"{total_batches})"
            )
            try:
                self.logger.info(
                    f"{self.log_prefix}: Appending "
                    f"{len(batch)} value(s) to destination "
                    f"profile '{profile_name}' "
                    f"(batch {batch_index} of "
                    f"{total_batches})."
                )
                if not self._send_destination_request(
                    url=values_url,
                    headers=headers,
                    method="patch",
                    body={
                        "operation": {
                            "op": "append",
                            "values": batch,
                        }
                    },
                    profile_id=profile_id,
                    profile_name=profile_name,
                    apply_pending_changes=apply_pending_changes,
                    logger_msg=logger_msg,
                ):
                    failed_idx.update(
                        range(start, start + len(batch))
                    )
                    continue
                self.logger.info(
                    f"{self.log_prefix}: Successfully "
                    f"appended {len(batch)} value(s) to "
                    f"destination profile '{profile_name}'"
                    f" (batch {batch_index} of "
                    f"{total_batches})."
                )
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected "
                        "error while appending values to "
                        f"destination profile '{profile_name}'"
                        f" (batch {batch_index} of "
                        f"{total_batches}). Error: {err}"
                    ),
                    details=re.sub(
                        r"token=([0-9a-zA-Z]*)",
                        "token=********&",
                        traceback.format_exc(),
                    ),
                    resolution=(
                        "Re-run the action to retry the "
                        "failed values."
                    ),
                )
                failed_idx.update(
                    range(start, start + len(batch))
                )
        return failed_idx

    def _send_destination_request(
        self,
        url: str,
        headers: dict,
        method: str,
        body: dict,
        profile_id: str,
        profile_name: str,
        apply_pending_changes: str,
        logger_msg: str,
    ) -> bool:
        """Send a destination profile write, handling pending changes.

        The single request primitive shared by the by-id PATCH and the
        values-endpoint append. A 409 pending-changes response triggers a
        deploy + retry once when ``apply_pending_changes`` is ``"Yes"``;
        otherwise it is logged and skipped.

        Args:
            url (str): Fully built request URL.
            headers (dict): Request headers including the API token.
            method (str): HTTP method (``"patch"``).
            body (dict): Request body.
            profile_id (str): Id of the target profile (used for the
                deploy call on a 409).
            profile_name (str): Name of the target profile (logging).
            apply_pending_changes (str): ``"Yes"`` to auto-deploy on a
                409, else ``"No"``.
            logger_msg (str): Present-participle phrase for error logs,
                e.g. ``"adding values to destination profile 'X'"``.

        Returns:
            bool: ``True`` on a 2xx response, ``False`` when the request
                is skipped (pending changes not applied) or fails.
        """
        for attempt in range(2):
            response = self.netskope_helper._api_call_helper(
                url=url,
                method=method,
                error_codes=["CRE_1065", "CRE_1066"],
                headers=headers,
                json=body,
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
                is_handle_error_required=False,
            )
            response_text = (
                response.text
                if hasattr(response, "text")
                else str(response)
            )
            if (
                response.status_code == 409
                and PENDING_CHANGES_DETECTED in response_text
            ):
                if apply_pending_changes == "Yes" and attempt == 0:
                    self.logger.info(
                        f"{self.log_prefix}: Pending changes detected "
                        f"for destination profile '{profile_name}'. "
                        "Applying pending changes and retrying."
                    )
                    if self._deploy_destination_profile([profile_id]):
                        continue
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Could not apply "
                            f"pending changes for destination profile "
                            f"'{profile_name}'. Skipping action execution."
                        ),
                        details=response_text,
                    )
                    return False
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Pending changes detected "
                        f"for destination profile '{profile_name}'. "
                        "Skipping action execution."
                    ),
                    resolution=(
                        "Set 'Apply Pending Changes' to 'Yes' in the "
                        "action configuration, or manually apply the "
                        "pending changes for destination profile "
                        f"'{profile_name}' from the Netskope Tenant "
                        "UI, then re-run the action."
                    ),
                    details=response_text,
                )
                return False
            if response.status_code not in [200, 201]:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"{logger_msg}. Received exit code "
                        f"{response.status_code}."
                    ),
                    details=response_text,
                    resolution=(
                        "Verify the values are valid for the profile "
                        "match type and the profile capacity is not "
                        "exceeded, then re-run the action."
                    ),
                )
                return False
            handle_status_code(
                response,
                error_code="CRE_1066",
                custom_message=f"Error occurred while {logger_msg}",
                plugin=self.log_prefix,
                notify=False,
                log=False,
            )
            return True
        return False

    def _get_dns_profiles(self) -> Dict:
        """Fetch DNS profiles from the Netskope Tenant.

        Paginates through ``GET /api/v2/profiles/dns`` requesting only
        the ``id`` and ``name`` fields and returns a mapping of profile
        name to profile id, suitable for building action dropdowns.

        Returns:
            Dict: Mapping of DNS profile name to its id.
        """
        tenant_name, headers = self._get_tenant_and_headers()
        url = f"{tenant_name}{URLS.get('V2_DNS_PROFILE')}"
        profiles = {}
        offset = 0
        limit = 150
        page_number = 1
        params = {
            "offset": offset,
            "limit": limit,
            # No space after the comma in the fields query parameter
            # else the Netskope API returns an error.
            "fields": "id,name",
        }
        logger_msg = "fetching DNS profiles from the Netskope Tenant"
        self.logger.debug(f"{self.log_prefix}: {logger_msg.capitalize()}.")
        try:
            # Drive the loop off the page size: stop once a page returns
            # fewer than ``limit`` items and advance the offset by the
            # count actually returned, so a missing total cannot cause an
            # early stop or an infinite loop.
            while True:
                page_msg = f"{logger_msg} for page {page_number}"
                response = self.netskope_helper._api_call_helper(
                    url=url,
                    method="get",
                    error_codes=["CRE_1063", "CRE_1064"],
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    message=f"Error occurred while {page_msg}",
                    logger_msg=page_msg,
                )
                dns_profiles = response.get("profiles", [])
                for dns_profile in dns_profiles:
                    profile_name = dns_profile.get("name", "")
                    profile_id = dns_profile.get("id")
                    if profile_name and profile_id:
                        profiles[profile_name] = profile_id
                if len(dns_profiles) < limit:
                    break
                offset += len(dns_profiles)
                params["offset"] = offset
                page_number += 1
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched {len(profiles)} "
            "DNS profile(s) from the Netskope Tenant."
        )
        return profiles

    def _get_dns_profile_by_name(self, name: str) -> Dict:
        """Fetch a single DNS profile by its name.

        Args:
            name (str): Name of the DNS profile to look up.

        Returns:
            Dict: The full DNS profile object as returned by the API,
            or an empty dict if no profile with that name exists.
        """
        tenant_name, headers = self._get_tenant_and_headers()
        url = f"{tenant_name}{URLS.get('V2_DNS_PROFILE')}"
        params = {
            "filter": f'name eq "{name}"',
            "offset": 0,
            "limit": 150,
            # No space after the comma in the fields query parameter
            # else the Netskope API returns an error.
            "fields": "id,name,description,domain_config,status",
        }
        logger_msg = (
            f"fetching DNS profile '{name}' from the Netskope Tenant"
        )
        self.logger.debug(
            f"{self.log_prefix}: {_capitalize_first(logger_msg)}."
        )
        try:
            response = self.netskope_helper._api_call_helper(
                url=url,
                method="get",
                error_codes=["CRE_1063", "CRE_1064"],
                headers=headers,
                params=params,
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
            )
            for profile in response.get("profiles", []):
                if profile.get("name") == name:
                    return profile
            return {}
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)

    def _get_security_categories(self) -> List[str]:
        """Fetch DNS security categories from the Netskope Tenant.

        Paginates through ``GET /api/v2/profiles/dns/domaincategories``,
        keeps only categories whose ``category_type`` is ``security``
        and expands each into ``"<name> (Block)"`` and
        ``"<name> (Sinkhole)"`` choices for the action dropdown.

        Returns:
            List[str]: Expanded security category choice strings.
        """
        tenant_name, headers = self._get_tenant_and_headers()
        url = f"{tenant_name}{URLS.get('V2_DNS_DOMAIN_CATEGORIES')}"
        categories = []
        offset = 0
        limit = 150
        page_number = 1
        logger_msg = (
            "fetching DNS security categories from the Netskope Tenant"
        )
        self.logger.debug(f"{self.log_prefix}: {logger_msg.capitalize()}.")
        try:
            # Drive the loop off the page size: stop once a page returns
            # fewer than ``limit`` items and advance the offset by the
            # count actually returned.
            while True:
                page_msg = f"{logger_msg} for page {page_number}"
                params = {
                    "offset": offset,
                    "limit": limit,
                    "sortby": "name",
                    "sortorder": "asc",
                }
                response = self.netskope_helper._api_call_helper(
                    url=url,
                    method="get",
                    error_codes=["CRE_1063", "CRE_1064"],
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    message=f"Error occurred while {page_msg}",
                    logger_msg=page_msg,
                )
                domain_categories = response.get("domaincategories", [])
                for category in domain_categories:
                    category_name = category.get("name", "")
                    category_type = category.get(
                        "category_type", ""
                    ).lower()
                    if category_name and category_type == "security":
                        categories.extend(
                            [
                                f"{category_name} (Block)",
                                f"{category_name} (Sinkhole)",
                            ]
                        )
                if len(domain_categories) < limit:
                    break
                offset += len(domain_categories)
                page_number += 1
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched "
            f"{len(categories)} DNS security category choice(s) "
            "from the Netskope Tenant."
        )
        return categories

    def _get_record_types(self) -> List[str]:
        """Fetch DNS record types from the Netskope Tenant.

        Paginates through ``GET /api/v2/profiles/dns/recordtypes`` and
        returns the list of record type names for the action dropdown.

        Returns:
            List[str]: List of DNS record type names.
        """
        tenant_name, headers = self._get_tenant_and_headers()
        url = f"{tenant_name}{URLS.get('V2_DNS_RECORD_TYPES')}"
        record_types = []
        offset = 0
        limit = 150
        page_number = 1
        logger_msg = (
            "fetching DNS record types from the Netskope Tenant"
        )
        self.logger.debug(f"{self.log_prefix}: {logger_msg.capitalize()}.")
        try:
            # Drive the loop off the page size: stop once a page returns
            # fewer than ``limit`` items and advance the offset by the
            # count actually returned.
            while True:
                page_msg = f"{logger_msg} for page {page_number}"
                params = {
                    "offset": offset,
                    "limit": limit,
                    "sortby": "name",
                    "sortorder": "asc",
                }
                response = self.netskope_helper._api_call_helper(
                    url=url,
                    method="get",
                    error_codes=["CRE_1063", "CRE_1064"],
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    message=f"Error occurred while {page_msg}",
                    logger_msg=page_msg,
                )
                elements = response.get("recordtypes", [])
                for record_type in elements:
                    record_type_name = record_type.get("name", "")
                    if record_type_name:
                        record_types.append(record_type_name)
                if len(elements) < limit:
                    break
                offset += len(elements)
                page_number += 1
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched "
            f"{len(record_types)} DNS record type(s) from the "
            "Netskope Tenant."
        )
        return record_types

    def _parse_security_categories(
        self, raw_categories: List[str]
    ) -> List[Dict]:
        """Parse '<name> (Block|Sinkhole)' strings into payload dicts.

        Args:
            raw_categories (List[str]): Selected category choice
                strings of the form ``"<name> (Block)"`` or
                ``"<name> (Sinkhole)"``.

        Returns:
            List[Dict]: A list of ``{"name": ..., "action": ...}``
            dicts, one per input string that matches the expected
            format. Strings that don't match are skipped silently.
        """
        pattern = re.compile(
            r"^(?P<name>.+?)\s*\((?P<action>Block|Sinkhole)\)$"
        )
        parsed: List[Dict] = []
        for category in raw_categories:
            match = pattern.match(category)
            if not match:
                continue
            parsed.append(
                {
                    "name": match.group("name").strip(),
                    "action": match.group("action"),
                }
            )
        return parsed

    def _push_dns_profile(
        self,
        domains: List[str],
        existing_profile_name: str,
        new_profile_name: str,
        action_type: str,
        action_params: Dict,
        operation: str = "append",
    ) -> int:
        """Share domains to a DNS profile on the Netskope Tenant.

        When ``existing_profile_name`` is ``"create"`` a new profile
        is created (POST) carrying the profile config and as many of
        the resolved ``domains`` as fit under the payload budget. When
        an existing profile is selected, a minimal-diff PATCH body is
        built and the new domains are packed into the matching list
        under the same budget. Domains that are not properly formatted
        (``REGEX_FOR_DOMAIN``) or exceed the RFC length limits are
        validated out and reported before sharing; domains dropped
        because they exceed the ``DNS_PROFILE_PAYLOAD_LIMIT`` are
        likewise reported and skipped.

        Args:
            domains (List[str]): Resolved, de-duplicated domain names
                to share to the profile.
            existing_profile_name (str): Selected profile name, or the
                literal ``"create"`` to create a new profile.
            new_profile_name (str): Name to use when creating a profile.
            action_type (str): ``add_to_allow_list`` or
                ``add_to_block_list``.
            action_params (Dict): Resolved action parameters.

        Returns:
            tuple: ``(shared_count, not_applied)`` where ``shared_count``
                is the count of domains successfully shared to the
                profile and ``not_applied`` is the list of domains that
                were not applied — those dropped as invalid/over-length
                and those skipped because the payload size budget was
                exhausted. Used by the bulk caller to attribute unshared
                domains back to their originating action ids.
        """
        tenant_name, headers = self._get_tenant_and_headers()
        # The DNS profile endpoint only accepts properly formatted
        # domains. Since values arrive directly from the action's
        # Static/Source field (not as typed indicators), validate each
        # against the domain format regex and the RFC length limits
        # before sharing; malformed entries are dropped and reported.
        valid_domains = []
        invalid_domains = []
        for domain in domains:
            if not domain:
                continue
            if (
                re.match(REGEX_FOR_DOMAIN, domain)
                and self.netskope_helper.is_valid_domain_length(domain)
            ):
                valid_domains.append(domain)
            else:
                invalid_domains.append(domain)
        if invalid_domains:
            self.logger.info(
                f"{self.log_prefix}: Skipping {len(invalid_domains)} "
                "value(s) as they were either not domains or were of "
                "invalid format, and therefore cannot be added to the "
                "DNS profile."
            )
        if not valid_domains:
            self.logger.info(
                f"{self.log_prefix}: No valid domains to share to the "
                "DNS profile. Skipping action execution."
            )
            return 0, list(invalid_domains)
        if action_type == "add_to_allow_list":
            list_key = "allow_list"
            list_key_label = "allowlist"
        elif action_type == "add_to_block_list":
            list_key = "block_list"
            list_key_label = "blocklist"
        else:
            error_message = (
                f"Invalid action type '{action_type}'. Valid values "
                "are 'add_to_allow_list' or 'add_to_block_list'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Re-run the action with a valid Action Type "
                    "selection."
                ),
            )
            raise NetskopeException(error_message)
        security_categories = self._parse_security_categories(
            action_params.get("dns_security_categories", [])
        )
        try:
            if existing_profile_name == "create":
                profile_name = new_profile_name
                existing_profile = self._get_dns_profile_by_name(
                    profile_name
                )
                # Re-running the action with the same parameters would
                # otherwise attempt to create a duplicate profile, which
                # the API rejects with an "already exists" error. If a
                # profile with the requested name already exists, share
                # the domains to it instead of creating a new one.
                if existing_profile:
                    self.logger.info(
                        f"{self.log_prefix}: DNS profile "
                        f"'{profile_name}' already exists on the "
                        "Netskope Tenant; adding domains to the "
                        "existing profile instead of creating a new one."
                    )
                    body = self.netskope_helper._build_dns_patch_body(
                        existing_profile=existing_profile,
                        action_params=action_params,
                        action_type=action_type,
                        operation=operation,
                        security_categories=security_categories,
                    )
                    method = "patch"
                    profile_path = URLS.get(
                        "V2_DNS_PROFILE_BY_ID"
                    ).format(existing_profile.get("id"))
                    url = f"{tenant_name}{profile_path}"
                    log_action = (
                        f"updating DNS profile '{profile_name}' on the "
                        "Netskope Tenant"
                    )
                else:
                    body = self.netskope_helper._build_dns_create_body(
                        profile_name=profile_name,
                        action_params=action_params,
                        action_type=action_type,
                        security_categories=security_categories,
                    )
                    method = "post"
                    url = f"{tenant_name}{URLS.get('V2_DNS_PROFILE')}"
                    log_action = (
                        f"creating DNS profile '{profile_name}' on the "
                        "Netskope Tenant"
                    )
            else:
                profile_name = existing_profile_name
                existing_profile = self._get_dns_profile_by_name(
                    profile_name
                )
                if not existing_profile:
                    error_message = (
                        f"DNS profile '{profile_name}' could not be "
                        "found on the Netskope Tenant."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {error_message}",
                        resolution=(
                            "Verify the DNS profile still exists on the "
                            "Netskope Tenant and re-run the action."
                        ),
                    )
                    raise NetskopeException(error_message)
                body = self.netskope_helper._build_dns_patch_body(
                    existing_profile=existing_profile,
                    action_params=action_params,
                    action_type=action_type,
                    operation=operation,
                    security_categories=security_categories,
                )
                method = "patch"
                profile_path = URLS.get(
                    "V2_DNS_PROFILE_BY_ID"
                ).format(existing_profile.get("id"))
                url = f"{tenant_name}{profile_path}"
                log_action = (
                    f"updating DNS profile '{profile_name}' on the "
                    "Netskope Tenant"
                )
            budget = (
                DNS_PROFILE_PAYLOAD_LIMIT
                - DNS_PROFILE_PAYLOAD_SAFETY_BUFFER
            )
            accepted, skipped = self.netskope_helper._pack_domains_within_budget(
                body=body,
                list_key=list_key,
                candidate_domains=valid_domains,
                budget_bytes=budget,
            )
            # In the patch flow, if the packer accepted zero candidates
            # and the trailing target entry has no domains, drop it so
            # the patch body never carries a meaningless empty entry.
            if method == "patch":
                list_entries = body.get("domain_config", {}).get(
                    list_key, []
                )
                if list_entries and not list_entries[-1].get(
                    "domain_names"
                ):
                    list_entries.pop()
            if not accepted:
                self.logger.info(
                    f"{self.log_prefix}: DNS profile API payload size "
                    f"limit reached for {list_key_label} before any "
                    f"domains could be added; skipping all "
                    f"{len(skipped)} domain(s)."
                )
                return 0, list(invalid_domains) + list(skipped)
            self.logger.info(
                f"{self.log_prefix}: Out of {len(valid_domains)} "
                f"domain(s), attempting to share {len(accepted)} "
                f"domain(s) to {list_key_label} of DNS profile "
                f"'{profile_name}'. Skipping {len(skipped)} domain(s) "
                "due to exceeding the DNS profile API payload size "
                f"limit of {DNS_PROFILE_PAYLOAD_LIMIT / (1024 * 1024)}"
                " MB."
            )
            self.netskope_helper._api_call_helper(
                url=url,
                method=method,
                error_codes=["CRE_1063", "CRE_1064"],
                headers=headers,
                json=body,
                proxies=self.proxy,
                message=f"Error occurred while {log_action}",
                logger_msg=log_action,
            )
        except NetskopeException:
            raise
        except Exception as err:
            profile_name = (
                new_profile_name
                if existing_profile_name == "create"
                else existing_profile_name
            )
            error_message = (
                "Unexpected error occurred while sharing domains to the DNS "
                f"profile '{profile_name}'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)
        self.logger.info(
            f"{self.log_prefix}: Successfully added {len(accepted)} "
            f"domain(s) to {list_key_label} of DNS profile "
            f"'{profile_name}' on the Netskope Tenant."
        )
        return len(accepted), list(invalid_domains) + list(skipped)

    def _get_service_profiles(
        self,
        custom_only: bool = True,
        name: str = None,
    ) -> Dict:
        """Fetch service profiles from the Netskope Tenant.

        Paginates through ``GET /api/v2/profiles/serviceobjects``
        requesting the ``id``, ``name``, ``type``, ``protocols`` and
        ``description`` fields and returns a mapping of profile name to
        its full metadata. When ``custom_only`` is True only profiles whose
        ``type`` equals ``CUSTOM`` (compared case-insensitively, since
        the list endpoint returns ``CUSTOM``/``PREDEFINED`` while the
        create endpoint returns lowercase) are kept, because only
        CUSTOM service profiles are editable. An optional ``name``
        narrows the listing to a single profile via the API's exact
        ``name eq`` filter.

        Args:
            custom_only (bool): When True, keep only ``CUSTOM`` (i.e.
                editable) service profiles. Defaults to True.
            name (str): When provided, fetch only the profile with this
                exact name. Defaults to None.

        Returns:
            Dict: Mapping of service profile name to its metadata
                (id, name, type, protocols).
        """
        tenant_name, headers = self._get_tenant_and_headers()
        url = f"{tenant_name}{V2_SERVICE_PROFILE}"
        profiles = {}
        offset = 0
        limit = SERVICE_PROFILE_PAGE_SIZE
        page_number = 1
        logger_msg = (
            "fetching service profiles from the Netskope Tenant"
        )
        if name:
            logger_msg = (
                f"fetching service profile '{name}' from the "
                "Netskope Tenant"
            )
        self.logger.debug(
            f"{self.log_prefix}: {_capitalize_first(logger_msg)}."
        )
        try:
            # Drive the loop off the page size: stop once a page returns
            # fewer than ``limit`` items and advance the offset by the
            # count actually returned.
            while True:
                page_msg = f"{logger_msg} for page {page_number}"
                params = {
                    "offset": offset,
                    "limit": limit,
                    # No space after the comma in the fields query
                    # parameter else the Netskope API returns an error.
                    "fields": "id,name,type,protocols,description",
                }
                if name:
                    params["filter"] = f'name eq "{name}"'
                response = self.netskope_helper._api_call_helper(
                    url=url,
                    method="get",
                    error_codes=["CRE_1063", "CRE_1064"],
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    message=f"Error occurred while {page_msg}",
                    logger_msg=page_msg,
                )
                services = response.get("services", [])
                for service in services:
                    profile_name = service.get("name", "")
                    profile_type = str(
                        service.get("type", "")
                    ).upper()
                    if not profile_name:
                        continue
                    if (
                        custom_only
                        and profile_type != SERVICE_PROFILE_TYPE_CUSTOM
                    ):
                        continue
                    profiles[profile_name] = service
                if len(services) < limit:
                    break
                offset += len(services)
                page_number += 1
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)
        if name and len(profiles) > 0:
            if len(profiles) > 0:
                self.logger.debug(
                    f"{self.log_prefix}: Successfully fetched Service "
                    f"Profile '{name}' from the Netskope Tenant."
                )
        elif not name:
            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched {len(profiles)} "
                "service profile(s) from the Netskope Tenant."
            )
        return profiles

    def _get_service_profile_by_name(self, name: str) -> Dict:
        """Fetch a single CUSTOM service profile by its name.

        Performs an exact ``name eq`` lookup against the service
        profile listing and returns the matching CUSTOM profile,
        including its existing ``protocols`` (needed to union ports
        for an Append operation). PREDEFINED profiles are excluded
        because they cannot be edited.

        Args:
            name (str): Name of the service profile to look up.

        Returns:
            Dict: The matching CUSTOM service profile object, or an
                empty dict if no editable profile with that name
                exists.
        """
        profiles = self._get_service_profiles(
            custom_only=True,
            name=name,
        )
        return profiles.get(name, {})

    def _push_service_profile(
        self,
        operation: str,
        profile_name: str,
        description: str,
        tcp: List[str],
        udp: List[str],
        tcp_udp: List[str],
        icmp: bool,
    ) -> tuple:
        """Create or update a service profile on the Netskope Tenant.

        When no editable (CUSTOM) profile named ``profile_name``
        exists, a new profile is created via ``POST`` carrying the
        assembled ``protocols``. Otherwise the existing profile is
        updated via ``PATCH`` on its id. For an ``append`` operation
        the new ports are unioned (de-duplicated, order preserved)
        with the profile's existing ports for each protocol; for a
        ``replace`` operation only the supplied ports are sent. Empty
        protocol arrays are omitted from the payload. The selected ICMP
        value is honoured on update for both operations (enabled adds
        ``icmp: true``, disabled omits it), so an ``append`` can turn an
        existing ICMP off as well as on. The ``description`` is also
        applied on update, sent only when a value is provided that
        differs from the profile's current description.

        PREDEFINED profiles cannot be updated: a ``PATCH`` against
        such an id returns HTTP 404. That case is detected explicitly
        (``is_handle_error_required=False``) and surfaced as a clear
        "predefined/not found" error.

        Args:
            operation (str): ``append`` to union with existing ports,
                ``replace`` to overwrite with only the new ports.
            profile_name (str): Target service profile name (existing
                CUSTOM profile to update, or the name to create).
            description (str): Description used when creating a profile.
            tcp (List[str]): TCP ports/ranges to add.
            udp (List[str]): UDP ports/ranges to add.
            tcp_udp (List[str]): TCP_UDP ports/ranges to add.
            icmp (bool): Whether ICMP is enabled for the profile.

        Returns:
            tuple: ``(applied_count, not_applied)`` where
                ``applied_count`` is the number of ports applied and
                ``not_applied`` is the list of ports that could not be
                applied. A service profile update is all-or-nothing — the
                API does not report a partial port rejection — so on
                success ``not_applied`` is empty and every requested port
                is counted as applied; a total failure raises and is
                attributed to the action ids by the caller.
        """
        tenant_name, headers = self._get_tenant_and_headers()
        new_ports = {
            "tcp": [p for p in (tcp or []) if p],
            "udp": [p for p in (udp or []) if p],
            "tcp_udp": [p for p in (tcp_udp or []) if p],
        }
        existing_profile = self._get_service_profile_by_name(
            profile_name
        )
        if existing_profile:
            profile_id = existing_profile.get("id")
            existing_protocols = existing_profile.get(
                "protocols", {}
            )
            protocols = {}
            for proto, ports in new_ports.items():
                if operation == "append":
                    merged = list(
                        existing_protocols.get(proto, [])
                    )
                    for port in ports:
                        if port not in merged:
                            merged.append(port)
                    if merged:
                        protocols[proto] = merged
                elif ports:
                    protocols[proto] = ports
            # The selected ICMP value is honoured for both Append and
            # Replace: enabling adds ``icmp: true`` and disabling omits
            # it from the protocols object (the PATCH replaces the whole
            # object), so an Append can now turn an existing ICMP off as
            # well as on, matching the user's selection.
            if icmp:
                protocols["icmp"] = True
            body = {"protocols": protocols}
            # The Description is applied on update too (it was previously
            # sent only on create); send it only when a value is provided
            # that differs from the profile's current description, so a
            # no-op re-run does not clobber it.
            existing_description = existing_profile.get("description", "")
            if description and description != existing_description:
                body["description"] = description
            method = "patch"
            profile_path = V2_SERVICE_PROFILE_BY_ID.format(profile_id)
            url = f"{tenant_name}{profile_path}"
            logger_msg = (
                f"updating service profile '{profile_name}' on the "
                "Netskope Tenant"
            )
        else:
            protocols = {
                proto: ports
                for proto, ports in new_ports.items()
                if ports
            }
            if icmp:
                protocols["icmp"] = True
            body = {
                "name": profile_name,
                "description": description,
                "protocols": protocols,
            }
            method = "post"
            url = f"{tenant_name}{V2_SERVICE_PROFILE}"
            logger_msg = (
                f"creating service profile '{profile_name}' on the "
                "Netskope Tenant"
            )
        self.logger.debug(
            f"{self.log_prefix}: {_capitalize_first(logger_msg)}."
        )
        try:
            response = self.netskope_helper._api_call_helper(
                url=url,
                method=method,
                error_codes=["CRE_1063", "CRE_1064"],
                headers=headers,
                json=body,
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
                is_handle_error_required=False,
            )
            if method == "patch" and response.status_code == 404:
                error_message = (
                    f"Service profile '{profile_name}' could not be "
                    "updated because it was not found or is a "
                    "PREDEFINED profile. Only CUSTOM service profiles "
                    "are editable."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    details=str(response.text),
                    resolution=(
                        "Select a CUSTOM service profile (PREDEFINED "
                        "profiles cannot be modified) or create a new "
                        "service profile, then re-run the action."
                    ),
                )
                raise NetskopeException(error_message)
            handle_status_code(
                response,
                error_code="CRE_1064",
                custom_message=f"Error occurred while {logger_msg}",
                plugin=self.log_prefix,
                notify=False,
                log=True,
            )
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)
        action_verb = "updated" if method == "patch" else "created"
        self.logger.info(
            f"{self.log_prefix}: Successfully {action_verb} service "
            f"profile '{profile_name}' on the Netskope Tenant."
        )
        applied_count = (
            len(new_ports["tcp"])
            + len(new_ports["udp"])
            + len(new_ports["tcp_udp"])
        )
        return applied_count, []

    def _get_device_classifications(self) -> Dict:
        """Fetch device classifications from the Netskope Tenant.

        Paginates through ``GET /api/v2/deviceclassification/tags`` and
        returns a mapping of device classification name to its id,
        suitable for building action dropdowns and for checking whether a
        classification already exists before creating it. The endpoint
        returns a bare JSON array of classification objects.

        Returns:
            Dict: Mapping of device classification name to its id.
        """
        tenant_name, headers = self._get_tenant_and_headers()
        url = (
            f"{tenant_name}"
            f"{URLS.get('V2_DEVICE_CLASSIFICATION_TAGS')}"
        )
        classifications = {}
        offset = 0
        limit = DEVICE_CLASSIFICATION_PAGE_SIZE
        page_number = 1
        logger_msg = (
            "fetching device classifications from the Netskope Tenant"
        )
        self.logger.debug(
            f"{self.log_prefix}: {logger_msg.capitalize()}."
        )
        try:
            while True:
                page_msg = f"{logger_msg} for page {page_number}"
                params = {"offset": offset, "limit": limit}
                response = self.netskope_helper._api_call_helper(
                    url=url,
                    method="get",
                    error_codes=["CRE_1063", "CRE_1064"],
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    message=f"Error occurred while {page_msg}",
                    logger_msg=page_msg,
                )
                tags = (
                    response
                    if isinstance(response, list)
                    else response.get("data", [])
                )
                if not tags:
                    break
                for tag in tags:
                    name = tag.get("name", "")
                    tag_id = tag.get("id")
                    if name and tag_id is not None:
                        classifications[name] = tag_id
                if len(tags) < limit:
                    break
                offset += limit
                page_number += 1
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched "
            f"{len(classifications)} device classification(s) from the "
            "Netskope Tenant."
        )
        return classifications

    def _get_device_classification_rules(self) -> List[Dict]:
        """Fetch device classification rules from the Netskope Tenant.

        Paginates through ``GET /api/v2/deviceclassification/rules`` and
        returns the full rule objects (including ``id``, ``name``,
        ``label``, ``os`` and ``conditions``). The conditions are needed
        to union the existing device tags for an Append operation, and
        the id is needed to target a rule for an update. The endpoint
        returns a bare JSON array of rule objects.

        Returns:
            List[Dict]: List of device classification rule objects.
        """
        tenant_name, headers = self._get_tenant_and_headers()
        url = (
            f"{tenant_name}"
            f"{URLS.get('V2_DEVICE_CLASSIFICATION_RULES')}"
        )
        rules = []
        offset = 0
        limit = DEVICE_CLASSIFICATION_PAGE_SIZE
        page_number = 1
        logger_msg = (
            "fetching device classification rules from the Netskope "
            "Tenant"
        )
        self.logger.debug(
            f"{self.log_prefix}: {logger_msg.capitalize()}."
        )
        try:
            while True:
                page_msg = f"{logger_msg} for page {page_number}"
                params = {"offset": offset, "limit": limit}
                response = self.netskope_helper._api_call_helper(
                    url=url,
                    method="get",
                    error_codes=["CRE_1063", "CRE_1064"],
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    message=f"Error occurred while {page_msg}",
                    logger_msg=page_msg,
                )
                page_rules = (
                    response
                    if isinstance(response, list)
                    else response.get("data", [])
                )
                if not page_rules:
                    break
                rules.extend(page_rules)
                if len(page_rules) < limit:
                    break
                offset += limit
                page_number += 1
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched {len(rules)} "
            "device classification rule(s) from the Netskope Tenant."
        )
        return rules

    def _create_device_classification(
        self,
        name: str,
        existing_classifications: Dict,
    ) -> None:
        """Create a device classification on the Netskope Tenant.

        Creates the classification via ``POST`` only when one with the
        same name does not already exist, so re-running the action with
        the same name reuses the existing classification instead of
        attempting a duplicate create (which the API rejects). The
        request body is a JSON array carrying a single classification
        object, as required by the endpoint.

        Args:
            name (str): Name of the device classification to create.
            existing_classifications (Dict): Mapping of existing
                classification name to id, used to skip creation when the
                classification already exists.
        """
        if name in existing_classifications:
            self.logger.info(
                f"{self.log_prefix}: Device classification '{name}' "
                "already exists on the Netskope Tenant; reusing it "
                "instead of creating a new one."
            )
            return
        tenant_name, headers = self._get_tenant_and_headers()
        url = (
            f"{tenant_name}"
            f"{URLS.get('V2_DEVICE_CLASSIFICATION_TAGS')}"
        )
        body = [
            {
                "name": name,
                "description": DEVICE_CLASSIFICATION_DEFAULT_DESCRIPTION,
            }
        ]
        logger_msg = (
            f"creating device classification '{name}' on the Netskope "
            "Tenant"
        )
        self.logger.debug(
            f"{self.log_prefix}: {_capitalize_first(logger_msg)}."
        )
        response = self.netskope_helper._api_call_helper(
            url=url,
            method="post",
            error_codes=["CRE_1063", "CRE_1064"],
            headers=headers,
            json=body,
            proxies=self.proxy,
            message=f"Error occurred while {logger_msg}",
            logger_msg=logger_msg,
        )
        if (
            isinstance(response, dict)
            and not response.get("status", True)
        ):
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=str(response),
                resolution=(
                    "Verify the device classification name is valid and "
                    "does not already exist, then re-run the action."
                ),
            )
            raise NetskopeException(error_message)
        self.logger.info(
            f"{self.log_prefix}: Successfully {logger_msg}."
        )

    def _send_classification_rule_request(
        self, method, url, body, headers, logger_msg
    ):
        """Send a device classification rule create/update request.

        Issues the ``POST`` (create) or ``PUT`` (update) request for a
        device classification rule and handles its responses: an HTTP
        409 (the same classification criteria already exist on another
        rule) is surfaced with the conflicting rule's message, and any
        other non-2xx status is routed through ``handle_status_code``.
        The rule endpoints return an empty body on success, so the
        error handler is only invoked for non-success status codes.
        Raises ``NetskopeException`` on any failure.

        Args:
            method (str): ``post`` to create a rule or ``put`` to update
                an existing rule by id.
            url (str): Fully-qualified rule endpoint URL.
            body (Union[dict, list]): Request body (a single-object
                array for create, a rule object for update).
            headers (dict): Request headers carrying the v2 API token.
            logger_msg (str): Present-participle description of the call
                used in error and conflict messages.
        """
        try:
            response = self.netskope_helper._api_call_helper(
                url=url,
                method=method,
                error_codes=["CRE_1063", "CRE_1064"],
                headers=headers,
                json=body,
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
                is_handle_error_required=False,
            )
            # The rule create/update endpoints return an empty body on
            # success (201/200), so only invoke the error handler for
            # non-success status codes to avoid parsing an empty body.
            if response.status_code == 409:
                try:
                    conflict_msg = response.json().get(
                        "message",
                        "A conflicting device classification rule"
                        " already exists.",
                    )
                except Exception:
                    conflict_msg = (
                        "A conflicting device classification rule"
                        " already exists."
                    )
                error_message = (
                    f"Error occurred while {logger_msg}."
                    f" {conflict_msg}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    resolution=(
                        "A device classification rule with the same"
                        " classification criteria already exists on"
                        " the Netskope Tenant. Modify the Tags,"
                        " Match Type, or Operating System to make"
                        " the rule criteria unique."
                    ),
                )
                raise NetskopeException(error_message)
            elif not 200 <= response.status_code < 300:
                handle_status_code(
                    response,
                    error_code="CRE_1064",
                    custom_message=f"Error occurred while {logger_msg}",
                    plugin=self.log_prefix,
                    notify=False,
                    log=True,
                )
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)

    def _move_rule_classification(
        self,
        rule_id,
        existing_rule,
        label,
        rule_name,
        os,
        tenant_name,
        headers,
    ):
        """Reassign an existing rule to a different classification.

        Used when a short-circuit (the rule is already full, every
        provided tag is already on the rule, or no device tag is left to
        apply) means the rule's device tags do not change, but the
        selected device classification differs from the rule's current
        one. A Netskope rule can belong to only one classification, so
        the rule is updated in place with its existing conditions left
        untouched and only its ``label`` (the classification) changed.
        Raises ``NetskopeException`` on failure.

        Args:
            rule_id (str): Id of the rule to update.
            existing_rule (dict): The rule object fetched from the
                tenant; its ``conditions`` are preserved verbatim.
            label (str): The new device classification name to move the
                rule to.
            rule_name (str): Rule name (used in the body and logs).
            os (str): Target operating system of the rule.
            tenant_name (str): Base tenant URL.
            headers (dict): Request headers carrying the v2 API token.
        """
        rule_path = URLS.get(
            "V2_DEVICE_CLASSIFICATION_RULE_BY_ID"
        ).format(rule_id)
        url = f"{tenant_name}{rule_path}"
        body = {
            "conditions": existing_rule.get("conditions", {}),
            "label": label,
            "name": rule_name,
            "os": os,
        }
        logger_msg = (
            f"moving device classification rule '{rule_name}' to"
            f" classification '{label}' on the Netskope Tenant"
        )
        self.logger.debug(
            f"{self.log_prefix}: {_capitalize_first(logger_msg)}."
        )
        self._send_classification_rule_request(
            "put", url, body, headers, logger_msg
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully moved device"
            f" classification rule '{rule_name}' to classification"
            f" '{label}' on the Netskope Tenant."
        )

    def _push_device_classification(
        self,
        operation: str,
        classification_value: str,
        new_classification_name: str,
        rule_value: str,
        new_rule_name: str,
        os: str,
        operator: str,
        group_operator: str,
        tags: List[str],
    ) -> tuple:
        """Create/update a device classification and its rule.

        Ensures the target device classification exists (creating it when
        'Create new Device Classification' was selected), resolves the
        provided device tag names to ids, builds the rule's condition tree
        and then creates the rule (``POST`` with a single-object array) or
        updates an existing rule (``PUT`` on its id). For an Append
        operation against an existing rule the new device tags are unioned
        with the rule's current tags; for Replace the rule's device tags
        are overwritten with only the new tags. When updating an existing
        rule, only its device tag checks are changed (via
        ``_replace_rule_tag_checks``) and every other condition branch is
        preserved; a brand-new rule gets a freshly built condition tree.
        The action fails (raises)
        if any provided device tag does not exist on the Netskope Tenant
        (tags are never created here).

        Args:
            operation (str): ``append`` to union with the existing rule's
                device tags, ``replace`` to overwrite them.
            classification_value (str): Selected classification name, or
                the literal ``"create"`` to create a new one.
            new_classification_name (str): Name used when creating a
                classification.
            rule_value (str): Packed ``name<sep>id`` of the selected rule,
                or a ``<sep>create`` value to create a new rule.
            new_rule_name (str): Name used when creating a rule.
            os (str): Target operating system for the rule.
            operator (str): ``and`` or ``or`` inner tag group logical
                operator (from Match Type).
            group_operator (str): ``and`` or ``or`` outer container
                operator joining multiple tag groups (from Group Match
                Type).
            tags (List[str]): Device tag names to reference in the rule.

        Returns:
            tuple: ``(applied_count, not_applied, action_status)`` where
                ``applied_count`` is the number of NEW device tags added
                to the rule (device tags already present on the rule are
                not counted), ``not_applied`` is the list of provided tag
                names that were skipped because of the rule's tag limit
                (tags beyond the first 5, the new tags that did not fit an
                existing rule, or every provided tag when the rule is
                already full) so the caller can attribute each back to its
                originating action id(s) via ``value_to_ids``, and
                ``action_status`` is ``"created"`` when a new rule was
                created or ``"updated"`` when an existing rule was
                targeted (including the self-heal case and the skip
                paths). Tags that do not exist on the Netskope Tenant
                still raise (the whole group fails). A failure to create
                the classification, resolve the tags or push the rule
                raises and is attributed to the action id(s) by the
                caller.
        """
        tenant_name, headers = self._get_tenant_and_headers()
        # Resolve the classification label, creating the classification
        # when 'Create new Device Classification' was selected.
        if classification_value == "create":
            label = new_classification_name
            existing_classifications = (
                self._get_device_classifications()
            )
            self._create_device_classification(
                label, existing_classifications
            )
        else:
            label = classification_value
        # Resolve the target rule: an existing rule is updated by id; a
        # new rule name is created, or updated if a rule with that name
        # and OS already exists so that re-runs do not duplicate it. When
        # the matched rule sits in a different classification, it is moved
        # to the selected one as part of the normal update (a rule belongs
        # to exactly one classification).
        rule_name, _, rule_id_token = rule_value.rpartition(
            CUSTOM_SEPARATOR_DEVICE_CLASSIFICATION
        )
        existing_rule = {}
        if rule_id_token == "create":
            rule_name = new_rule_name
            rule_id = None
            for rule in self._get_device_classification_rules():
                if rule.get("name", "") != rule_name:
                    # A different rule -- keep searching for the name.
                    continue
                # A rule with this name already exists on the tenant
                # (rule names are unique, so a create with an existing
                # name is rejected with a 409). Its OS cannot be changed
                # -- mirroring the Netskope UI -- so when the selected OS
                # differs from the existing rule's OS the action is
                # short-circuited with an error instead of issuing a POST
                # that the tenant rejects with a 409.
                existing_os = rule.get("os", "")
                if str(existing_os).lower() != os.lower():
                    error_message = (
                        "Cannot change the operating system for device"
                        f" classification rule '{rule_name}' from"
                        f" '{existing_os}' to '{os}'; hence skipping the"
                        " Create Device Classification action execution."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {error_message}",
                        resolution=(
                            "The operating system of an existing rule"
                            " cannot be changed. Provide the rule's"
                            f" current operating system '{existing_os}',"
                            " either use a different rule or create a new"
                            f" rule for with operating system {os}."
                        ),
                    )
                    raise NetskopeException(error_message)
                # Same name and OS -> reuse (update) the existing rule
                # instead of creating a duplicate.
                rule_id = rule.get("id")
                existing_rule = rule
                self.logger.info(
                    f"{self.log_prefix}: Device classification rule "
                    f"'{rule_name}' already exists on the Netskope "
                    "Tenant; updating it instead of creating a new "
                    "one."
                )
                break
        else:
            rule_id = rule_id_token
            for rule in self._get_device_classification_rules():
                if str(rule.get("id", "")) == str(rule_id):
                    existing_rule = rule
                    break
            if not existing_rule:
                error_message = (
                    f"Device classification rule '{rule_name}' could "
                    "not be found on the Netskope Tenant."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    resolution=(
                        "Verify the device classification rule still "
                        "exists on the Netskope Tenant and re-run the "
                        "action."
                    ),
                )
                raise NetskopeException(error_message)
            # Case 1: the operating system of an existing rule cannot be
            # changed (the Netskope UI does not allow it either), so a
            # mismatch is an error and the action is short-circuited for
            # this rule rather than attempting a forbidden OS change.
            existing_os = existing_rule.get("os", "")
            if str(existing_os).lower() != os.lower():
                error_message = (
                    "Cannot change the operating system for device"
                    f" classification rule '{rule_name}' from"
                    f" '{existing_os}' to '{os}'; hence skipping the"
                    " Create Device Classification action execution."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    resolution=(
                        "The operating system of an existing rule"
                        " cannot be changed. Select the rule's current"
                        f" operating system '{existing_os}' in the"
                        " action configuration, or create a new rule"
                        " for the desired operating system."
                    ),
                )
                raise NetskopeException(error_message)
        # A rule targeted by id (an existing rule, including the
        # self-heal case where a create resolves to an existing rule) is
        # updated; otherwise a brand-new rule is created. This status is
        # returned so the caller can log/report the right verb.
        action_status = "updated" if rule_id is not None else "created"
        # The selected device classification becomes the rule's label.
        # A Netskope rule can belong to only one classification, so when
        # an existing rule's current classification differs from the
        # selected one the rule must be moved to it even if its device
        # tags do not change (the short-circuit paths below).
        existing_label = (
            existing_rule.get("label", "") if existing_rule else ""
        )
        label_changed = bool(existing_rule) and existing_label != label
        # Tags that exceed DEVICE_CLASSIFICATION_TAGS_PER_GROUP per group
        # are split into additional condition groups instead of discarded.
        existing_tag_ids = []
        if existing_rule:
            existing_tag_ids = self.netskope_helper._extract_rule_tag_ids(
                existing_rule.get("conditions", {})
            )
        # Resolve all provided device tag names to ids. Tags that do not
        # exist on the Netskope Tenant cause the whole group to fail.
        tag_cache = self._fetch_all_tags()
        new_tag_ids, not_found = self.netskope_helper._resolve_classification_tag_ids(
            tags, tag_cache
        )
        if not_found:
            error_message = (
                "Some of the provided Tags do not exist on the "
                "Netskope Tenant. Hence skipping the Create Device "
                "Classification action execution."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=(
                    "Tags not found on the Netskope Tenant: "
                    f"{', '.join(not_found)}."
                ),
                resolution=(
                    "Create these device tags on the Netskope Tenant "
                    "or provide existing device tag names, then re-run "
                    "the action."
                ),
            )
            raise NetskopeException(error_message)
        # Map resolved tag ids back to the provided names for logging.
        id_to_name = {}
        for tag in tags:
            resolved_id = tag_cache.get(str(tag).strip().lower())
            if resolved_id is not None and resolved_id not in id_to_name:
                id_to_name[resolved_id] = str(tag).strip()
        # Append unions the new device tags with the rule's current tags;
        # tags that exceed DEVICE_CLASSIFICATION_TAGS_PER_GROUP per group
        # are split into additional condition groups instead of discarded.
        # Replace (or a brand-new rule) uses only the new tags.
        # ``added_tag_ids`` are the newly added tags only — tags already
        # present on the rule are never counted.
        if existing_rule and operation == "append":
            final_tag_ids = list(existing_tag_ids)
            added_tag_ids = []
            for tag_id in new_tag_ids:
                if tag_id in final_tag_ids:
                    # Already on the rule — not a newly added tag.
                    continue
                final_tag_ids.append(tag_id)
                added_tag_ids.append(tag_id)
            if new_tag_ids and not added_tag_ids:
                self.logger.info(
                    f"{self.log_prefix}: All the provided tags already "
                    "exist in the device classification rule "
                    f"'{rule_name}'. Hence skipping the action "
                    "execution. 0 new device tag(s) were added."
                )
                # The rule's device tags do not change, but if the
                # selected classification differs the rule is still
                # moved to it.
                if label_changed:
                    self._move_rule_classification(
                        rule_id,
                        existing_rule,
                        label,
                        rule_name,
                        os,
                        tenant_name,
                        headers,
                    )
                return (
                    0,
                    list(not_found),
                    action_status,
                )
        else:
            final_tag_ids = list(new_tag_ids)
            added_tag_ids = [
                tag_id
                for tag_id in new_tag_ids
                if tag_id not in existing_tag_ids
            ]
        if not final_tag_ids:
            self.logger.info(
                f"{self.log_prefix}: No device tags were provided to "
                f"apply to the device classification rule "
                f"'{rule_name}'. Skipping action execution."
            )
            # No device tag change, but if the selected classification
            # differs the rule is still moved to it. The rule's existing
            # conditions are sent verbatim, so a rule with no conditions
            # to preserve is left untouched (never wiped to empty).
            if label_changed and existing_rule.get("conditions"):
                self._move_rule_classification(
                    rule_id,
                    existing_rule,
                    label,
                    rule_name,
                    os,
                    tenant_name,
                    headers,
                )
            return (
                0,
                list(not_found),
                action_status,
            )
        # When updating an existing rule, touch ONLY its device tags:
        # swap the tag checks inside the existing conditions and leave
        # every other condition branch (min OS version, not-compromised,
        # ...) intact. A brand-new rule gets a freshly built tree.
        if existing_rule:
            conditions = self.netskope_helper._replace_rule_tag_checks(
                existing_rule.get("conditions", {}),
                final_tag_ids,
                operator,
                group_operator,
            )
        else:
            conditions = self.netskope_helper._build_rule_conditions(
                final_tag_ids, operator, group_operator
            )
        rule_body = {
            "conditions": conditions,
            "label": label,
            "name": rule_name,
            "os": os,
        }
        if rule_id is not None:
            method = "put"
            rule_path = URLS.get(
                "V2_DEVICE_CLASSIFICATION_RULE_BY_ID"
            ).format(rule_id)
            url = f"{tenant_name}{rule_path}"
            body = rule_body
            logger_msg = (
                f"updating device classification rule '{rule_name}'"
                f" in classification '{label}' on the Netskope"
                " Tenant"
            )
            final_logger = (
                f"updated device classification rule '{rule_name}'"
                f" in classification '{label}' on the Netskope"
                " Tenant"
            )
        else:
            method = "post"
            url = (
                f"{tenant_name}"
                f"{URLS.get('V2_DEVICE_CLASSIFICATION_RULES')}"
            )
            body = [rule_body]
            logger_msg = (
                f"creating device classification rule '{rule_name}'"
                f" in classification '{label}' on the Netskope"
                " Tenant"
            )
            final_logger = (
                f"created device classification rule '{rule_name}'"
                f" in classification '{label}' on the Netskope"
                " Tenant"
            )
        self.logger.debug(
            f"{self.log_prefix}: {_capitalize_first(logger_msg)}."
        )
        self._send_classification_rule_request(
            method, url, body, headers, logger_msg
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully {final_logger}."
            f" Added {len(added_tag_ids)} new device tag(s) to the"
            f" rule '{rule_name}'."
        )
        return (
            len(added_tag_ids),
            list(not_found),
            action_status,
        )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add user to group", value="add"),
            ActionWithoutParams(
                label="Remove user from group", value="remove"
            ),
            ActionWithoutParams(label="Update UCI score", value="impact"),
            ActionWithoutParams(label="UCI Reset", value="uci_reset"),
            ActionWithoutParams(
                label="Add host to Private App", value="private_app"
            ),
            ActionWithoutParams(
                label="Create or Update App Instance", value="app_instance"
            ),
            ActionWithoutParams(
                label="Tag/Untag Application", value="tag_app"
            ),
            ActionWithoutParams(
                label="Tag/Untag Device", value="tag_device"
            ),
            ActionWithoutParams(
                label="Add to Destination Profile",
                value="destination_profile",
            ),
            ActionWithoutParams(
                label="Add to DNS Profile", value="dns_profile"
            ),
            ActionWithoutParams(
                label="Add to Service Profile", value="service_profile"
            ),
            ActionWithoutParams(
                label="Create Device Classification",
                value="device_classification",
            ),
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def _get_all_groups(self) -> List:
        """Get list of all the groups.

        Args:
            log_in_status_check (bool, optional): Log in status check. \
                Defaults to False.
        Returns:
            List: List of all the groups.
        """
        all_groups = []
        start_at = 1
        url = (
            f"{self.tenant.parameters.get('tenantName', '').strip()}"
            f"{URLS.get('V2_SCIM_GROUPS')}"
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        logger_msg = "fetching groups from the Netskope Tenant"
        self.logger.debug(
            f"{self.log_prefix}: {logger_msg.capitalize()}."
        )
        while True:
            try:
                params = {"count": PAGE_SIZE, "startIndex": start_at}
                response = self.netskope_helper._api_call_helper(
                    url=url,
                    method="get",
                    error_codes=["CRE_1015", "CRE_1028"],
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    message=f"Error occurred while {logger_msg}",
                    logger_msg=logger_msg,
                )
                if not isinstance(response, dict):
                    groups = json.loads(response)
                groups_in_page = groups.get("Resources", [])
                if not groups_in_page:
                    break
                all_groups += groups_in_page
                start_at += PAGE_SIZE
            except NetskopeException:
                raise
            except Exception as err:
                error_message = f"Error occurred while {logger_msg}."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} "
                        f"Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched {len(all_groups)} "
            f"groups."
        )
        return all_groups

    def _get_all_users(self) -> List:
        """Get list of all the users.

        Returns:
            List: List of all the users.
        """
        all_users = []
        start_at = 1
        url = (
            f"{self.tenant.parameters.get('tenantName', '').strip()}"
            f"{URLS.get('V2_SCIM_USERS')}"
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        logger_msg = "fetching users from the Netskope Tenant"
        self.logger.debug(
            f"{self.log_prefix}: {logger_msg.capitalize()}."
        )
        while True:
            try:
                params = {"count": PAGE_SIZE, "startIndex": start_at}
                response = self.netskope_helper._api_call_helper(
                    url=url,
                    method="get",
                    error_codes=["CRE_1016", "CRE_1029"],
                    headers=headers,
                    params=params,
                    proxies=self.proxy,
                    message=f"Error occurred while {logger_msg}",
                    logger_msg=logger_msg,
                )
                if not isinstance(response, dict):
                    users = json.loads(response)
                users_in_page = users.get("Resources", [])
                if not users_in_page:
                    break
                all_users += users_in_page
                start_at += PAGE_SIZE
            except NetskopeException:
                raise
            except Exception as err:
                error_message = f"Error occurred while {logger_msg}."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} "
                        f"Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched {len(all_users)} "
            f"users."
        )
        return all_users

    def _find_user_by_email(self, users: List, email: str) -> Optional[Dict]:
        """Find user from list by email.

        Args:
            users (List): List of user dictionaries.
            email (str): Email to find.

        Returns:
            Optional[Dict]: User dictionary if found, None otherwise.
        """
        for user in users:
            for e in user.get("emails", []):
                if e.get("value", "").lower() == email.lower():
                    return user
        return None

    def _find_group_by_name(self, groups: List, name: str) -> Optional[Dict]:
        """Find group from list by name.

        Args:
            groups (List): List of groups dictionaries.
            name (str): Name to find.

        Returns:
            Optional[Dict]: Group dictionary if found, None otherwise.
        """
        for group in groups:
            if group.get("displayName", "") == name:
                return group
        return None

    def _remove_from_group(
        self, configuration: Dict, user_ids: List[Dict], group_id: str
    ):
        """Remove specified user from the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group ID of the group.

        Raises:
            NetskopeException: If the group does not exist on Netskope.
        """
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {
                    "op": "remove",
                    "path": "members",
                    "value": user_ids,
                }
            ],
        }
        url = (
            f"{self.tenant.parameters.get('tenantName', '').strip()}"
            f"{URLS.get('V2_SCIM_GROUPS')}/{group_id}"
        )
        logger_msg = "removing user(s) from group"
        try:
            response = self.netskope_helper._api_call_helper(
                url=url,
                method="patch",
                error_codes=["CRE_1017", "CRE_1030"],
                headers=headers,
                json=body,
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
                is_handle_error_required=False
            )
            if response.status_code == 404:
                err_msg = f"Group with id {group_id} does not exist"
                self.logger.error(
                    f"{self.log_prefix}: {err_msg} while {logger_msg}."
                )
                raise NetskopeException(err_msg)
            response = handle_status_code(
                response,
                error_code="CRE_1030",
                custom_message=f"Error occurred while {logger_msg}",
                plugin=self.log_prefix,
                notify=False,
                log=True,
            )
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)

    def _add_to_group(
        self,
        configuration: Dict,
        user_ids: List[Dict],
        group_id: str
    ):
        """Add specified user to the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): List of User ID payload.
            group_id (str): Group ID of the group.

        Raises:
            NetskopeException: If the group does not exist on Netskope.
        """
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {
                    "op": "add",
                    "path": "members",
                    "value": user_ids,
                }
            ],
        }
        url = (
            f"{self.tenant.parameters.get('tenantName', '').strip()}"
            f"{URLS.get('V2_SCIM_GROUPS')}/{group_id}"
        )
        logger_msg = "adding user(s) to group"
        try:
            response = self.netskope_helper._api_call_helper(
                url=url,
                method="patch",
                error_codes=["CRE_1018", "CRE_1031"],
                headers=headers,
                json=body,
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
                is_handle_error_required=False
            )
            if response.status_code == 404:
                err_msg = f"Group with id {group_id} does not exist"
                self.logger.error(
                    f"{self.log_prefix}: {err_msg} while {logger_msg}."
                )
                raise NetskopeException(err_msg)
            response = handle_status_code(
                response,
                error_code="CRE_1031",
                custom_message=f"Error occurred while {logger_msg}",
                plugin=self.log_prefix,
                notify=False,
                log=True,
            )
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)

    def _update_impact_score(
        self,
        user: str,
        score: int,
        source: str = "",
        reason: str = "",
    ):
        """Update the impact score of a user.

        Args:
            user (str): User ID of the user.
            score (int): Score of the user.
            source (str): Source of the score.
            reason (str): Reason for the score.

        Raises:
            NetskopeException: If the user does not exist on Netskope.
        """
        url = (
            f"{self.tenant.parameters.get('tenantName', '').strip()}"
            f"{URLS.get('V2_UCI_IMPACT')}"
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        data = {
            "user": user.strip(),
            "score": score,
            "timestamp": int(time.time()) * 1000,
            "source": source.strip(),
            "reason": reason.strip(),
        }
        logger_msg = "updating the impact score"
        try:
            return self.netskope_helper._api_call_helper(
                url=url,
                method="post",
                json=data,
                headers=headers,
                proxies=self.proxy,
                error_codes=["CRE_1028", "CRE_1029"],
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg
            )
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)

    def _reset_uci_score(
        self,
        user_list: list
    ):
        """Reset the impact score of a user.

        Args:
            user_list (list): List of User ID of the user.

        Raises:
            NetskopeException: If the user does not exist on Netskope.
        """
        url = (
            f"{self.tenant.parameters.get('tenantName', '').strip()}"
            f"{URLS.get('V2_UCI_RESET')}"
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        data = {
            "users": user_list,
        }
        logger_msg = "performing the 'UCI Reset' action on the users"
        try:
            response = self.netskope_helper._api_call_helper(
                url=url,
                headers=headers,
                method="post",
                json=data,
                proxies=self.proxy,
                error_codes=["CRE_1028", "CRE_1029"],
                message=(
                    f"Error occurred while {logger_msg}"
                ),
                logger_msg=logger_msg,
                is_handle_error_required=False
            )
            if response.status_code == 400:
                err_msg = "Some of the provided users' UCI not found"
                self.logger.error(
                    f"{self.log_prefix}: {err_msg} while {logger_msg}."
                )
                raise NetskopeException(err_msg)
            response = handle_status_code(
                response,
                error_code="CRE_1030",
                custom_message=f"Error occurred while {logger_msg}",
                plugin=self.log_prefix,
                notify=False,
                log=True,
            )
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)

    def _create_group(self, configuration: Dict, name: str) -> Dict:
        """Create a new group with name.

        Args:
            configuration (Dict): Configuration parameters.
            name (str): Name of the group to create.

        Returns:
            Dict: Newly created group dictionary.
        """
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        body = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": name,
            "meta": {"resourceType": "Group"},
            "externalId": None,
        }
        url = (
            f"{self.tenant.parameters.get('tenantName', '').strip()}"
            f"{URLS.get('V2_SCIM_GROUPS')}"
        )
        logger_msg = f"creating group '{name}'"
        self.logger.debug(
            f"{self.log_prefix}: {_capitalize_first(logger_msg)} on "
            "the Netskope Tenant."
        )
        try:
            response = self.netskope_helper._api_call_helper(
                url=url,
                method="post",
                error_codes=["CRE_1019", "CRE_1032"],
                headers=headers,
                json=body,
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
                is_handle_error_required=False
            )
            if response.status_code == 409:
                err_msg = f"Group {name} already exists."
                self.logger.error(
                    f"{self.log_prefix}: {err_msg} while {logger_msg}."
                )
                raise NetskopeException(err_msg)
            response = handle_status_code(
                response,
                error_code="CRE_1032",
                custom_message=f"Error occurred while {logger_msg}",
                plugin=self.log_prefix,
                notify=False,
                log=True,
            )
            if not isinstance(response, dict):
                response = json.loads(response)
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully created group '{name}' "
            "on the Netskope Tenant."
        )
        return response

    def get_types_to_pull(self, data_type):
        """Get the types of data to pull.

        Args:
            data_type (str): Type of data

        Returns:
            List of sub types to pull
        """
        sub_types = []
        # mappedEntities is currently not being passed in configuration
        # but will be present in configuration starting from CE v6.0.0
        # This will ensure the data pull call are only dependant on
        # the mapped entities.
        # Till then if the user wants to pull Devices they will have to
        # map application entity.
        # (IPE for this fix https://engjira.cdsys.local/browse/NCTE-25648)
        mapped_entities = self.mappedEntities if hasattr(self, "mappedEntities") else []
        if mapped_entities:
            for mapped_entity in mapped_entities:
                if data_type == "alerts" and mapped_entity.get("entity") == "Users":
                    sub_types.extend(["uba"])
                elif data_type == "events" and mapped_entity.get("entity") == "Applications":
                    sub_types.extend(["application"])
                elif data_type == "events" and mapped_entity.get("entity") == "Devices":
                    sub_types.extend(["clientstatus"])
        else:
            if data_type == "alerts":
                sub_types.extend(["uba"])
            elif data_type == "events":
                sub_types.extend(["application", "clientstatus"])
        return sub_types

    def get_target_fields(self, plugin_id, plugin_parameters):
        """Get available Target fields."""
        return []

    def validate(self, configuration: Dict):
        """Validate Netskope configuration.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        initial_range = configuration.get("initial_range")
        if initial_range is None:
            err_msg = (
                "Initial Range for Events is a "
                "required configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Provide a non empty Initial Range for Events (in hours)."
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(initial_range, int):
            err_msg = (
                "Invalid Initial Range for Events "
                "provided in configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Provide valid number in Initial Range for Events "
                    "(in hours)."
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif initial_range < 0 or initial_range > 8760:
            err_msg = (
                "Invalid Initial Range for Events provided in configuration"
                " parameters. Valid value should be in range 0 to 8760."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Provide valid number in Initial Range for Events "
                    "(in hours). Valid value should be in range 0 to 8760."
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        days = configuration.get("days")
        if days is None:
            err_msg = (
                "Initial Range for Alerts is a required "
                "configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Provide a non empty Initial Range for Alerts (in days)."
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(days, int):
            err_msg = (
                "Invalid Initial Range for Alerts provided in "
                "configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Provide valid number in Initial Range for Alerts "
                    "(in days)."
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif days < 0 or days > 365:
            err_msg = (
                "Invalid Initial Range for Alerts provided in configuration"
                " parameters. Valid value should be in range 0 to 365."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Provide valid number in Initial Range for Alerts "
                    "(in days). Valid value should be in range 0 to 365."
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate required fields in entity mappings
        is_valid, err_msg = self._validate_required_field_in_entity_mappings()
        if not is_valid:
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                    )
            )
            return ValidationResult(success=False, message=err_msg)

        try:
            helper = AlertsHelper()
            self.tenant = helper.get_tenant(configuration.get("tenant", ""))
            tenant_configuration = self.tenant.parameters
            token = resolve_secret(tenant_configuration.get("v2token", ""))
            if token is None:
                return ValidationResult(
                    success=False,
                    message=(
                        "V2 token is required in the tenant configuration "
                        "to configure Netskope CRE plugin. It can be "
                        "configured from Settings > Tenants."
                    ),
                )
            provider = plugin_provider_helper.get_provider(
                tenant_name=self.tenant.name
            )
            # mappedEntities is currently not being passed in configuration
            # but will be present in configuration starting from CE v6.0.0
            # This will ensure the plugin validates/creates client status
            # iterator if and only if Device entity is mapped.
            # Till then plugin will validate/create client status iterator
            # regardless of whether Device entity is mapped or not
            # (IPE for this fix https://engjira.cdsys.local/browse/NCTE-25648)
            mapped_entities = self.mappedEntities if hasattr(self, "mappedEntities") else []
            type_map = {
                "events": [],
                "alerts": [],
            }
            if mapped_entities:
                for mapped_entity in mapped_entities:
                    if mapped_entity.get("entity") == "Users":
                        type_map["alerts"].append("uba")
                    if mapped_entity.get("entity") == "Applications":
                        type_map["events"].append("application")
                    if mapped_entity.get("entity") == "Devices":
                        type_map["events"].append("clientstatus")
            else:
                type_map = {
                    "events": ["application", "clientstatus"],
                    "alerts": ["uba"],
                }
            modified_type_map = type_map.copy()
            clientstatus_requested = (
                "events" in modified_type_map
                and "clientstatus" in modified_type_map.get("events", [])
            )
            if clientstatus_requested:
                modified_type_map["events"] = [
                    event_type
                    for event_type in modified_type_map.get("events", [])
                    if event_type != "clientstatus"
                ]
            else:
                try:
                    provider.unregister_client_status_consumer(
                        "cre", self.name
                    )
                except Exception as e:
                    self.logger.error(
                        f"{self.log_prefix}: Error while releasing "
                        f"client_status subscription for CRE plugin "
                        f"'{self.name}': {e}"
                    )

            provider.permission_check(
                modified_type_map,
                plugin_name=self.plugin_name,
                configuration_name=self.name,
            )

            # Register only after all other validations pass — prevents a
            # stale True subscriber leaf when permission_check fails and the
            # plugin stays disabled.
            if clientstatus_requested:
                try:
                    provider.register_client_status_consumer("cre", self.name)
                except Exception as e:
                    return ValidationResult(success=False, message=str(e))

            logger_msg = (
                "Successfully validated the plugin "
                "configuration parameters."
            )
            self.logger.debug(
                f"{self.log_prefix}: {logger_msg}"
            )
            return ValidationResult(
                success=True, message=logger_msg
            )
        except ConnectionError:
            return ValidationResult(
                success=False,
                message="Could not connect to validate the credentials.",
            )
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def cleanup(self, action_type: str = "disable"):
        """
        Release this CRE plugin configuration's hold on the shared
        client_status iterator when the plugin is disabled or deleted.

        Resolves the associated tenant, fetches the Netskope provider, and
        calls ``unregister_client_status_consumer("cre", self.name, ...)``
        with ``deleted`` derived from ``action_type``:

          * ``action_type == "delete"`` -> ``deleted=True``: the leaf is
            removed from the subscriber registry entirely (config is gone).
          * ``action_type == "disable"`` (or anything else) ->
            ``deleted=False``: the leaf is set to False (config still
            exists but is opted out of client_status).

        If this call drops the last active subscriber, the provider will
        delete the shared iterator on the tenant.

        Errors are caught and logged rather than raised so a transient
        provider problem cannot block plugin disable/delete.

        Args:
            action_type (str): Cleanup action identifier passed by the
                framework — typically the value of
                ``ActionType.DELETE`` (``"delete"``) or
                ``ActionType.DISABLE`` (``"disable"``). Defaults to
                ``"disable"``, the safer of the two: the leaf is set to
                False (opted out) rather than removed, so the shared
                iterator is not torn down on an ambiguous call.

        Returns:
            None
        """
        try:
            helper = AlertsHelper()
            tenant_name = helper.get_tenant_crev2(self.name).name
            provider = plugin_provider_helper.get_provider(
                tenant_name=tenant_name
            )
            provider.unregister_client_status_consumer(
                "cre", self.name, deleted=(action_type == "delete")
            )
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Error while releasing client_status "
                f"subscription on CRE plugin '{self.name}' "
                f"(action_type={action_type}): {e}"
            )

    def _validate_required_field_in_entity_mappings(self):
        """Validate if required fields are present in entity mappings."""
        mapped_entities = (
            self.mappedEntities if hasattr(self, "mappedEntities") else []
        )

        required_fields_by_entity = {
            "Users": ["email"],
            "Applications": ["applicationName"],
            "Devices": [
                "Device ID",
                "Hostname",
                "Netskope Device UID",
                "Device Serial Number",
                "User Key",
            ],
        }

        error_messages = []

        if mapped_entities:
            for mapped_entity in mapped_entities:
                entity_name = mapped_entity.get("entity")
                if entity_name not in required_fields_by_entity:
                    continue

                mapped_source_fields = set()
                for field in mapped_entity.get("fields", []):
                    mapped_source_field = field.get("source", "")
                    if mapped_source_field:
                        mapped_source_fields.add(mapped_source_field)

                missing_fields = [
                    field
                    for field in required_fields_by_entity[entity_name]
                    if field not in mapped_source_fields
                ]

                if missing_fields:
                    formatted_fields = ", ".join(
                        f"'{field}'" for field in missing_fields
                    )
                    error_messages.append(
                        f"Missing required fields {formatted_fields}"
                        f" in entity mappings for {entity_name}."
                    )

        if error_messages:
            return False, " ".join(error_messages)

        return True, ""

    def _validate_parameters(
        self,
        field_name: str,
        field_value,
        field_type: type,
        parameter_type: Literal["configuration", "action"],
        allowed_values: Dict = None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
        validation_err_msg: str = "Validation error occurred. ",
        check_dollar: bool = False,
        is_source_field_allowed: bool = True,
    ) -> Union[ValidationResult, None]:
        """Validate a configuration or action parameter.

        Args:
            field_name (str): Parameter name.
            field_value: Parameter value.
            field_type (type): Expected type.
            parameter_type (Literal["configuration", "action"]):
                Type of parameter used in error messages.
            allowed_values (Dict, optional): Dict or list of allowed
                values.
            custom_validation_func (Callable, optional): Custom
                validation function.
            is_required (bool): Whether the field is required.
            validation_err_msg (str): Error message prefix.
            check_dollar (bool): Skip validation if source field.
            is_source_field_allowed (bool): Whether source fields
                are allowed.

        Returns:
            ValidationResult or None.
        """
        if (
            not is_source_field_allowed
            and isinstance(field_value, str)
            and "$" in field_value
        ):
            err_msg = (
                f"'{field_name}' can only contain the Static Field."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Ensure that Static is selected for the"
                    f" field '{field_name}' in the action"
                    " configuration."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        if (
            check_dollar
            and isinstance(field_value, str)
            and "$" in field_value
        ):
            self.logger.info(
                message=(
                    f"{self.log_prefix}: '{field_name}' contains"
                    " the Source Field hence validation for this"
                    " field will be performed while executing the"
                    " action."
                ),
            )
            return None

        if (
            is_required
            and not isinstance(field_value, (int, float))
            and not field_value
        ):
            err_msg = (
                f"'{field_name}' is a required"
                f" {parameter_type} parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: "
                    f"{validation_err_msg}{err_msg}"
                ),
                resolution=(
                    "Ensure that some value is provided for"
                    f" field {field_name}."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if is_required and not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid value provided for the {parameter_type}"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: "
                    f"{validation_err_msg}{err_msg}"
                ),
                resolution=(
                    "Ensure that a valid value is provided for"
                    f" {field_name} field."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if custom_validation_func and not custom_validation_func(
            field_value
        ):
            err_msg = (
                f"Invalid value provided for the {parameter_type}"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: "
                    f"{validation_err_msg}{err_msg}"
                ),
                resolution=(
                    "Ensure that a valid value is provided for"
                    f" {field_name} field."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if allowed_values and isinstance(field_value, str):
            if field_value not in allowed_values:
                if len(allowed_values) <= 5:
                    err_msg = (
                        f"Invalid value provided for the"
                        f" {parameter_type} parameter '{field_name}'."
                        " Allowed values are"
                        f" {', '.join(str(v) for v in allowed_values)}."
                    )
                else:
                    err_msg = (
                        f"Invalid value for '{field_name}' provided"
                        f" in the {parameter_type} parameters."
                    )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: "
                        f"{validation_err_msg}{err_msg}"
                    ),
                    resolution=(
                        "Ensure that a valid value is provided"
                        " from the allowed values."
                    ),
                )
                return ValidationResult(
                    success=False, message=err_msg
                )
        return None

    def validate_action(self, action: Action):
        """Validate Netskope configuration.

        Args:
            action (Action): Action object.

        Returns:
            ValidationResult: Validation result.
        """

        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        if action.value == "generate":
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "impact":
            try:
                self._process_params_for_impact_action(action.parameters)
            except NetskopeException as ex:
                return ValidationResult(success=False, message=str(ex))
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "uci_reset":
            try:
                self._process_params_for_reset_action(action.parameters)
            except NetskopeException as ex:
                return ValidationResult(success=False, message=str(ex))
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "tag_app":
            try:
                self._process_params_for_add_tag_action(action.parameters)
            except NetskopeException as ex:
                return ValidationResult(success=False, message=str(ex))
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "tag_device":
            try:
                self._process_params_for_tag_device_action(
                    action.parameters, is_validation=True
                )
            except NetskopeException as ex:
                return ValidationResult(success=False, message=str(ex))
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "app_instance":
            try:
                self._process_params_for_app_instance_action(action.parameters)
            except NetskopeException as ex:
                return ValidationResult(success=False, message=str(ex))
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "private_app":
            try:
                existing_private_apps = self._get_private_apps()
                existing_publishers = self._get_publishers()
            except Exception as e:
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"Exception occurred while validating action parameters.",
                    details=re.sub(
                        r"token=([0-9a-zA-Z]*)",
                        "token=********&",
                        traceback.format_exc(),
                    ),
                    error_code="CRE_1042",
                )
                return ValidationResult(success=False, message=str(e))

            skip_excess_hosts = action.parameters.get(
                "skip_excess_hosts", False
            )
            if skip_excess_hosts not in [True, False]:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Invalid value provided for the "
                        "action parameter 'Skip Excess Hosts'."
                    ),
                    resolution=(
                        "Select either 'Yes' or 'No' for 'Skip Excess "
                        "Hosts' from the Static field dropdown."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Skip Excess Hosts provided.",
                )

            tags = action.parameters.get("tags", "")
            # For a Static Tags field, validate every tag at save time and
            # fail the configuration if any tag is empty or exceeds the
            # maximum allowed length. For a Source field ("$" present) the
            # validation is deferred to action execution, where invalid
            # tags are skipped and the remaining valid tags are pushed.
            if tags and "$" not in tags:
                tags_to_validate = [
                    tag.strip() for tag in tags.split(",") if tag.strip()
                ]
                _, skipped_tags, skip_count = (
                    self.netskope_helper.validate_tags_for_private_app(
                        tags_to_push=tags_to_validate,
                        private_app_name=action.parameters.get(
                            "private_app_name", ""
                        ),
                    )
                )
                if skip_count > 0:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {skip_count} tag(s) "
                            "provided in the Tags field are empty or exceed "
                            "the maximum allowed character limit of "
                            f"{PRIVATE_APP_TAG_MAX_LENGTH}."
                        ),
                        details=f"Invalid Tags: {', '.join(skipped_tags)}",
                        resolution=(
                            "Provide tags that are non-empty and do not "
                            f"exceed {PRIVATE_APP_TAG_MAX_LENGTH} characters."
                        ),
                    )
                    return ValidationResult(
                        success=False,
                        message=(
                            "Each tag should be non-empty and less than or "
                            f"equal to {PRIVATE_APP_TAG_MAX_LENGTH} "
                            "characters."
                        ),
                    )

            host = action.parameters.get("host", "")
            # For a Static Host field, validate every comma-separated value
            # at save time and fail the configuration if any value is empty
            # or is not a valid IPv4 address, IPv4 CIDR block, hostname, or
            # domain. For a Source field ("$" present) the validation is
            # deferred to action execution, where invalid host values are
            # skipped and the remaining valid values are pushed.
            if host and "$" not in host:
                _, skipped_hosts, skip_host_count = (
                    self.netskope_helper.validate_hosts_for_private_app(
                        hosts_to_push=host.split(","),
                        private_app_name=action.parameters.get(
                            "private_app_name", ""
                        ),
                    )
                )
                if skip_host_count > 0:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {skip_host_count} value(s) "
                            "provided in the Host field are empty or are not "
                            "a valid IPv4 address, IPv4 CIDR block, hostname, "
                            "or domain."
                        ),
                        details=f"Invalid Host(s): {', '.join(skipped_hosts)}",
                        resolution=(
                            "Provide non-empty host values, each a valid "
                            "IPv4 address, IPv4 CIDR block, hostname, or "
                            "domain (max 253 characters with each label "
                            "between 1 and 63 characters)."
                        ),
                    )
                    return ValidationResult(
                        success=False,
                        message=(
                            "Each host should be a non-empty valid IPv4 "
                            "address, IPv4 CIDR block, hostname, or domain."
                        ),
                    )
            list_of_private_apps_list = list(existing_private_apps.keys())
            list_of_private_apps_list.append("create")
            if (
                action.parameters.get("private_app_name", "")
                not in list_of_private_apps_list
            ):
                return ValidationResult(
                    success=False, message="Invalid private app provided."
                )
            if action.parameters.get("private_app_name", "") == "create":
                if (action.parameters.get("name") or "").strip() == "":
                    return ValidationResult(
                        success=False,
                        message=(
                            "If you have selected 'Create new private app' "
                            "in Private App Name, New Private App Name "
                            "should not be empty."
                        ),
                    )

                if "$" in (action.parameters.get("name") or "").strip():
                    return ValidationResult(
                        success=False,
                        message=(
                            "'Create New Private App' contains Source "
                            "field value. Please provide "
                            "new private app name in Static field only."
                        ),
                    )

            protocols = action.parameters.get("protocol", [])
            if not protocols:
                return ValidationResult(
                    success=False,
                    message=(
                        "Protocol is a required field to "
                        "create a new private app."
                    ),
                )
            if not all(protocol in ["TCP", "UDP"] for protocol in protocols):
                return ValidationResult(
                    success=False,
                    message=(
                        "Invalid Protocol provided. "
                        "Valid values are TCP or UDP."
                    ),
                )
            tcp_port = action.parameters.get("tcp_ports") or ""
            tcp_port_list = [
                port.strip() for port in tcp_port.split(",") if port.strip()
            ]
            udp_port = action.parameters.get("udp_ports") or ""
            udp_port_list = [
                port.strip() for port in udp_port.split(",") if port.strip()
            ]

            if "TCP" in protocols:
                # Port values only matter when the protocol is selected, so
                # the Source-field check is scoped to this block.
                if "$" in tcp_port:
                    return ValidationResult(
                        success=False,
                        message=(
                            "'TCP Ports' contains a Source field value. "
                            "Please provide TCP port(s) in the Static "
                            "field only."
                        ),
                    )
                if not tcp_port_list:
                    return ValidationResult(
                        success=False,
                        message=(
                            "If you have selected 'TCP' in Protocols, "
                            "TCP Port should not be empty."
                        ),
                    )
                if not all(
                    self.netskope_helper._validate_port(port) for port in tcp_port_list
                ):
                    return ValidationResult(
                        success=False,
                        message=(
                            "Invalid TCP Port or Port Range provided."
                            " Valid values are between 0 and 65535."
                        ),
                    )
            if "UDP" in protocols:
                # Port values only matter when the protocol is selected, so
                # the Source-field check is scoped to this block.
                if "$" in udp_port:
                    return ValidationResult(
                        success=False,
                        message=(
                            "'UDP Ports' contains a Source field value. "
                            "Please provide UDP port(s) in the Static "
                            "field only."
                        ),
                    )
                if not udp_port_list:
                    return ValidationResult(
                        success=False,
                        message=(
                            "If you have selected 'UDP' in Protocols, "
                            "UDP Port should not be empty."
                        ),
                    )
                if not all(
                    self.netskope_helper._validate_port(port) for port in udp_port_list
                ):
                    return ValidationResult(
                        success=False,
                        message=(
                            "Invalid UDP Port or Port Range provided."
                            " Valid values are between 0 and 65535."
                        ),
                    )

            publishers = action.parameters.get("publishers", [])
            if publishers and not all(
                publisher in existing_publishers for publisher in publishers
            ):
                return ValidationResult(
                    success=False, message="Invalid publisher provided."
                )

            use_publisher_dns = action.parameters.get(
                "use_publisher_dns", False
            )
            if use_publisher_dns is None or use_publisher_dns not in [
                True,
                False,
            ]:
                return ValidationResult(
                    success=False,
                    message="Invalid Use Publisher DNS provided.",
                )

            default_url = action.parameters.get("default_url", "")
            if action.parameters.get("private_app_name", "") == "create":
                if not default_url:
                    return ValidationResult(
                        success=False,
                        message=(
                            "If you have selected 'Create new private app' "
                            "in Private App Name, "
                            "Default Host should not be empty."
                        ),
                    )
                if "$" in default_url:
                    return ValidationResult(
                        success=False,
                        message=(
                            "'Default Host' contains Source field value. "
                            "Please provide default host in Static field only."
                        ),
                    )
                if not re.compile(REGEX_HOST).match(default_url.strip()):
                    return ValidationResult(
                        success=False,
                        message="Invalid Default Host provided.",
                    )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value in ["add", "remove"]:
            groups = self._get_all_groups()
            if (
                action.parameters.get("group", "") != "create" and
                len(groups) <= 0
            ):
                return ValidationResult(
                    success=False, message="No groups available."
                )
            if action.parameters.get("group", "") != "create" and not any(
                map(
                    lambda g: g["id"] == action.parameters.get("group", ""),
                    groups,
                )
            ):
                return ValidationResult(
                    success=False, message="Invalid group ID provided."
                )
            if (
                action.value == "add"
                and action.parameters.get("group", "") == "create"
                and len(action.parameters.get("name", "").strip()) == 0
            ):
                return ValidationResult(
                    success=False, message="Group Name can not be empty."
                )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "destination_profile":
            try:
                existing_profiles = self._get_destination_profiles()
            except Exception as e:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"fetching destination profiles for action "
                        f"parameter validation. Error: {e}"
                    ),
                    details=re.sub(
                        r"token=([0-9a-zA-Z]*)",
                        "token=********&",
                        traceback.format_exc(),
                    ),
                )
                return ValidationResult(success=False, message=str(e))
            if validation_result := self._validate_parameters(
                field_name="Operation",
                field_value=action.parameters.get("operation", ""),
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=list(OPERATION_OPTIONS.keys()),
            ):
                return validation_result
            profile_name = action.parameters.get(
                "destination_profile_name", ""
            )
            valid_profiles = list(existing_profiles.keys())
            valid_profiles.append("create")
            if profile_name not in valid_profiles:
                err_msg = (
                    "Invalid value provided for the action"
                    " parameter 'Destination Profile'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Select a valid Destination Profile from the"
                        " dropdown or select 'Create new profile'."
                    ),
                )
                return ValidationResult(
                    success=False, message=err_msg
                )
            if profile_name == "create":
                new_name = (
                    action.parameters.get("new_profile_name") or ""
                ).strip()
                if validation_result := self._validate_parameters(
                    field_name="Create New Profile",
                    field_value=new_name,
                    field_type=str,
                    parameter_type="action",
                    is_source_field_allowed=False,
                ):
                    return validation_result
                if validation_result := self.netskope_helper._validate_max_length(
                    field_name="Create New Profile",
                    field_value=new_name,
                    max_length=MAX_DESTINATION_PROFILE_NAME_LENGTH,
                ):
                    return validation_result
                if validation_result := self.netskope_helper._validate_forbidden_chars(
                    field_name="Create New Profile",
                    field_value=new_name,
                    forbidden_chars=DESTINATION_PROFILE_NAME_FORBIDDEN_CHARS,
                ):
                    return validation_result
            new_description = (
                action.parameters.get("new_profile_description") or ""
            )
            if validation_result := self._validate_parameters(
                field_name="Profile Description",
                field_value=new_description,
                field_type=str,
                parameter_type="action",
                is_required=False,
                is_source_field_allowed=False,
            ):
                return validation_result
            if validation_result := self.netskope_helper._validate_max_length(
                field_name="Profile Description",
                field_value=new_description,
                max_length=MAX_DESTINATION_PROFILE_DESC_LENGTH,
            ):
                return validation_result
            if validation_result := self._validate_parameters(
                field_name="Match Type",
                field_value=action.parameters.get(
                    "profile_match_type", ""
                ),
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=list(MATCH_TYPE_OPTIONS.keys()),
            ):
                return validation_result
            if validation_result := self._validate_parameters(
                field_name="Apply Pending Changes",
                field_value=action.parameters.get(
                    "apply_pending_changes", ""
                ),
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=["Yes", "No"],
            ):
                return validation_result
            destination_values = (
                action.parameters.get("destination_values") or ""
            )
            if validation_result := self._validate_parameters(
                field_name="Network Targets",
                field_value=destination_values,
                field_type=str,
                parameter_type="action",
                check_dollar=True,
            ):
                return validation_result
            # Normalize to a stripped string so the shared validator's
            # fixed field_type check works whether the number field
            # arrives as an int or a string; the custom check tolerates
            # an empty value (falls back to the default) and otherwise
            # requires a positive integer.
            exact_total_limit = str(
                action.parameters.get("exact_match_total_limit", "")
            ).strip()
            if validation_result := self._validate_parameters(
                field_name="Tenant Exact-Match Value Limit",
                field_value=exact_total_limit,
                field_type=str,
                parameter_type="action",
                is_required=False,
                is_source_field_allowed=False,
                custom_validation_func=(
                    lambda v: v == "" or (v.isdigit() and int(v) > 0)
                ),
            ):
                return validation_result
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "dns_profile":
            try:
                existing_profiles = self._get_dns_profiles()
                security_categories = self._get_security_categories()
                record_types = self._get_record_types()
            except Exception as e:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"fetching DNS profile metadata for action "
                        f"parameter validation. Error: {e}"
                    ),
                    details=re.sub(
                        r"token=([0-9a-zA-Z]*)",
                        "token=********&",
                        traceback.format_exc(),
                    ),
                )
                return ValidationResult(success=False, message=str(e))
            if validation_result := self._validate_parameters(
                field_name="Operation",
                field_value=action.parameters.get("operation", ""),
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=list(OPERATION_OPTIONS.keys()),
            ):
                return validation_result
            if validation_result := self._validate_parameters(
                field_name="Action Type",
                field_value=action.parameters.get(
                    "dns_profile_action_type", ""
                ),
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=list(
                    DNS_PROFILE_ACTION_TYPE_OPTIONS.keys()
                ),
            ):
                return validation_result
            profile_value = action.parameters.get("dns_profile_name", "")
            valid_profiles = [
                f"{name}{CUSTOM_SEPARATOR}{profile_id}"
                for name, profile_id in existing_profiles.items()
            ]
            valid_profiles.append(
                f"Create new DNS Profile{CUSTOM_SEPARATOR}create"
            )
            if validation_result := self._validate_parameters(
                field_name="DNS Profile",
                field_value=profile_value,
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=valid_profiles,
            ):
                return validation_result
            if profile_value.endswith(f"{CUSTOM_SEPARATOR}create"):
                new_name = (
                    action.parameters.get("new_profile_name") or ""
                ).strip()
                if validation_result := self._validate_parameters(
                    field_name="Create New DNS Profile",
                    field_value=new_name,
                    field_type=str,
                    parameter_type="action",
                    is_source_field_allowed=False,
                ):
                    return validation_result
                if validation_result := self.netskope_helper._validate_max_length(
                    field_name="Create New DNS Profile",
                    field_value=new_name,
                    max_length=MAX_DNS_PROFILE_NAME_LENGTH,
                ):
                    return validation_result
                if validation_result := self.netskope_helper._validate_forbidden_chars(
                    field_name="Create New DNS Profile",
                    field_value=new_name,
                    forbidden_chars=DNS_PROFILE_FORBIDDEN_CHARS,
                ):
                    return validation_result
            new_description = (
                action.parameters.get("new_profile_description") or ""
            )
            if validation_result := self._validate_parameters(
                field_name="Profile Description",
                field_value=new_description,
                field_type=str,
                parameter_type="action",
                is_required=False,
                is_source_field_allowed=False,
            ):
                return validation_result
            if validation_result := self.netskope_helper._validate_max_length(
                field_name="Profile Description",
                field_value=new_description,
                max_length=MAX_DNS_PROFILE_DESC_LENGTH,
            ):
                return validation_result
            if validation_result := self.netskope_helper._validate_forbidden_chars(
                field_name="Profile Description",
                field_value=new_description,
                forbidden_chars=DNS_PROFILE_FORBIDDEN_CHARS,
            ):
                return validation_result
            categories = action.parameters.get(
                "dns_security_categories", []
            )
            if validation_result := self._validate_parameters(
                field_name="Categories",
                field_value=categories,
                field_type=list,
                parameter_type="action",
                is_required=False,
                is_source_field_allowed=False,
                custom_validation_func=lambda cats: (
                    isinstance(cats, list)
                    and all(
                        cat in security_categories for cat in cats
                    )
                ),
            ):
                return validation_result
            category_bases = {}
            for category in categories:
                base = category.rsplit(" (", 1)[0]
                category_bases.setdefault(base, set()).add(category)
            for base, variants in category_bases.items():
                if len(variants) > 1:
                    err_msg = (
                        f"Category '{base}' cannot be selected"
                        " with both '(Block)' and '(Sinkhole)'"
                        " actions."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            f"Select either the '(Block)' or"
                            f" '(Sinkhole)' variant of '{base}',"
                            " not both."
                        ),
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )
            has_sinkhole = any(
                category.endswith("(Sinkhole)") for category in categories
            )
            sinkhole_ip = (
                action.parameters.get("sinkhole_ip") or ""
            ).strip()
            if has_sinkhole:
                if validation_result := self._validate_parameters(
                    field_name="Sinkhole IP",
                    field_value=sinkhole_ip,
                    field_type=str,
                    parameter_type="action",
                    is_source_field_allowed=False,
                    custom_validation_func=self.netskope_helper._validate_ip_address,
                ):
                    return validation_result
            record_type_values = action.parameters.get(
                "dns_record_types", []
            )
            if validation_result := self._validate_parameters(
                field_name="Record Types",
                field_value=record_type_values,
                field_type=list,
                parameter_type="action",
                is_required=True,
                is_source_field_allowed=False,
                custom_validation_func=lambda rts: all(
                    rt in record_types for rt in rts
                ),
            ):
                return validation_result
            if (
                "All Record Types" in record_type_values
                and len(record_type_values) > 1
            ):
                err_msg = (
                    "'All Record Types' cannot be combined"
                    " with other record types."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Either select 'All Record Types' on its"
                        " own or select specific record types"
                        " without 'All Record Types'."
                    ),
                )
                return ValidationResult(
                    success=False, message=err_msg
                )
            if validation_result := self._validate_parameters(
                field_name="Block all except Allow list",
                field_value=action.parameters.get(
                    "block_all_except_allow_list", ""
                ),
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=list(
                    BLOCK_ALL_EXCEPT_ALLOW_LIST_OPTIONS.keys()
                ),
            ):
                return validation_result
            domain_names = action.parameters.get("domain_names") or ""
            if validation_result := self._validate_parameters(
                field_name="Domain Names",
                field_value=domain_names,
                field_type=str,
                parameter_type="action",
                check_dollar=True,
            ):
                return validation_result
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "service_profile":
            try:
                existing_profiles = self._get_service_profiles(
                    custom_only=True
                )
            except Exception as e:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"fetching service profiles for action "
                        f"parameter validation. Error: {e}"
                    ),
                    details=re.sub(
                        r"token=([0-9a-zA-Z]*)",
                        "token=********&",
                        traceback.format_exc(),
                    ),
                )
                return ValidationResult(success=False, message=str(e))
            if validation_result := self._validate_parameters(
                field_name="Operation",
                field_value=action.parameters.get("operation", ""),
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=list(
                    SERVICE_PROFILE_OPERATION_OPTIONS.keys()
                ),
            ):
                return validation_result
            icmp = action.parameters.get("icmp", False)
            if icmp not in [True, False]:
                return ValidationResult(
                    success=False,
                    message=(
                        "Invalid value provided for the choice"
                        " parameter 'ICMP'."
                    ),
                )
            profile_name = action.parameters.get(
                "service_profile_name", ""
            )
            valid_profiles = list(existing_profiles.keys())
            valid_profiles.append("create")
            if validation_result := self._validate_parameters(
                field_name="Service Profile",
                field_value=profile_name,
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=valid_profiles,
            ):
                return validation_result
            if profile_name == "create":
                new_name = (
                    action.parameters.get("new_profile_name") or ""
                ).strip()
                if validation_result := self._validate_parameters(
                    field_name="Service Profile Name",
                    field_value=new_name,
                    field_type=str,
                    parameter_type="action",
                    is_source_field_allowed=False,
                ):
                    return validation_result
                if validation_result := self.netskope_helper._validate_max_length(
                    field_name="Service Profile Name",
                    field_value=new_name,
                    max_length=MAX_SERVICE_PROFILE_NAME_LENGTH,
                ):
                    return validation_result
            new_description = (
                action.parameters.get("new_profile_description") or ""
            )
            if validation_result := self._validate_parameters(
                field_name="Description",
                field_value=new_description,
                field_type=str,
                parameter_type="action",
                is_required=False,
                is_source_field_allowed=False,
            ):
                return validation_result
            if validation_result := self.netskope_helper._validate_max_length(
                field_name="Description",
                field_value=new_description,
                max_length=MAX_SERVICE_PROFILE_DESC_LENGTH,
            ):
                return validation_result
            port_fields = {
                "tcp_ports": "TCP Ports",
                "udp_ports": "UDP Ports",
                "tcp_udp_ports": "TCP/UDP Ports",
            }
            has_any_ports = False
            for key, label in port_fields.items():
                raw_value = action.parameters.get(key) or ""
                if validation_result := self._validate_parameters(
                    field_name=label,
                    field_value=raw_value,
                    field_type=str,
                    parameter_type="action",
                    is_required=False,
                    check_dollar=True,
                    custom_validation_func=lambda v: all(
                        self.netskope_helper._validate_port(p)
                        for p in [
                            p.strip()
                            for p in v.split(",")
                            if p.strip()
                        ]
                    ),
                ):
                    return validation_result
                if raw_value.strip():
                    has_any_ports = True
            if not has_any_ports and not icmp:
                err_msg = (
                    "At least one of TCP Ports, UDP Ports,"
                    " TCP/UDP Ports, or ICMP is required."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide at least one port value or enable"
                        " ICMP in the action configuration."
                    ),
                )
                return ValidationResult(
                    success=False, message=err_msg
                )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "device_classification":
            try:
                existing_classifications = (
                    self._get_device_classifications()
                )
                existing_rules = self._get_device_classification_rules()
            except Exception as e:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        "fetching device classification metadata for "
                        f"action parameter validation. Error: {e}"
                    ),
                    details=traceback.format_exc(),
                )
                return ValidationResult(success=False, message=str(e))
            if validation_result := self._validate_parameters(
                field_name="Operation",
                field_value=action.parameters.get("operation", ""),
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=list(OPERATION_OPTIONS.keys()),
            ):
                return validation_result
            classification_value = action.parameters.get(
                "device_classification", ""
            )
            valid_classifications = list(
                existing_classifications.keys()
            )
            valid_classifications.append("create")
            if validation_result := self._validate_parameters(
                field_name="Device Classification",
                field_value=classification_value,
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=valid_classifications,
            ):
                return validation_result
            if classification_value == "create":
                new_name = (
                    action.parameters.get("new_classification_name")
                    or ""
                ).strip()
                if validation_result := self._validate_parameters(
                    field_name="Device Classification Name",
                    field_value=new_name,
                    field_type=str,
                    parameter_type="action",
                    is_source_field_allowed=False,
                ):
                    return validation_result
                if validation_result := self.netskope_helper._validate_max_length(
                    field_name="Device Classification Name",
                    field_value=new_name,
                    max_length=MAX_DEVICE_CLASSIFICATION_NAME_LENGTH,
                ):
                    return validation_result
            rule_value = action.parameters.get(
                "device_classification_rule", ""
            )
            valid_rules = [
                f"{rule.get('name', '')}"
                f"{CUSTOM_SEPARATOR_DEVICE_CLASSIFICATION}"
                f"{rule.get('id')}"
                for rule in existing_rules
                if rule.get("name") and rule.get("id") is not None
            ]
            valid_rules.append(
                f"Create new Device Classification Rule"
                f"{CUSTOM_SEPARATOR_DEVICE_CLASSIFICATION}create"
            )
            if validation_result := self._validate_parameters(
                field_name="Device Classification Rule",
                field_value=rule_value,
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=valid_rules,
            ):
                return validation_result
            if rule_value.endswith(
                f"{CUSTOM_SEPARATOR_DEVICE_CLASSIFICATION}create"
            ):
                new_rule = (
                    action.parameters.get("new_rule_name") or ""
                ).strip()
                if validation_result := self._validate_parameters(
                    field_name="Device Classification Rule Name",
                    field_value=new_rule,
                    field_type=str,
                    parameter_type="action",
                    is_source_field_allowed=False,
                ):
                    return validation_result
                if validation_result := self.netskope_helper._validate_max_length(
                    field_name="Device Classification Rule Name",
                    field_value=new_rule,
                    max_length=MAX_DEVICE_CLASSIFICATION_NAME_LENGTH,
                ):
                    return validation_result
                if CUSTOM_SEPARATOR_DEVICE_CLASSIFICATION in new_rule:
                    err_msg = (
                        "'Device Classification Rule Name' should"
                        " not contain"
                        f" '{CUSTOM_SEPARATOR_DEVICE_CLASSIFICATION}'."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Remove"
                            f" '{CUSTOM_SEPARATOR_DEVICE_CLASSIFICATION}'"
                            " from the 'Device Classification Rule"
                            " Name'."
                        ),
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )
            if validation_result := self._validate_parameters(
                field_name="Operating System",
                field_value=action.parameters.get("os", ""),
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=list(
                    DEVICE_CLASSIFICATION_OS_OPTIONS.keys()
                ),
            ):
                return validation_result
            if validation_result := self._validate_parameters(
                field_name="Match Type",
                field_value=action.parameters.get(
                    "logical_operator", ""
                ),
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=list(
                    DEVICE_CLASSIFICATION_OPERATOR_OPTIONS.keys()
                ),
            ):
                return validation_result
            if validation_result := self._validate_parameters(
                field_name="Group Match Type",
                field_value=action.parameters.get(
                    "group_operator", ""
                ),
                field_type=str,
                parameter_type="action",
                is_source_field_allowed=False,
                allowed_values=list(
                    DEVICE_CLASSIFICATION_OPERATOR_OPTIONS.keys()
                ),
            ):
                return validation_result
            # Tags are required. Static tags are validated to exist on
            # the Netskope Tenant at save; Source fields ("$") are
            # resolved and validated at execution time instead.
            raw_tags = (
                action.parameters.get("classification_tags") or ""
            )
            if validation_result := self._validate_parameters(
                field_name="Tags",
                field_value=raw_tags,
                field_type=str,
                parameter_type="action",
                check_dollar=True,
            ):
                return validation_result
            if "$" not in raw_tags:
                raw_segments = raw_tags.split(",")
                tag_list = [
                    tag.strip()
                    for tag in raw_segments
                    if tag.strip()
                ]
                if any(not tag.strip() for tag in raw_segments):
                    err_msg = (
                        "'Tags' should not contain empty values"
                        " between commas."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Provide a non-empty tag name between"
                            " each comma in the 'Tags' field."
                        ),
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )
                # Short-circuit: any tag that violates Netskope's
                # tag-creation constraints can never exist on the
                # tenant, so fail immediately without making an API
                # call to _fetch_all_tags.
                invalid_chars = [
                    tag for tag in tag_list
                    if not re.match(REGEX_TAG, tag)
                ]
                if invalid_chars:
                    err_msg = (
                        "One or more Tags contain invalid characters"
                        " and cannot exist on the Netskope Tenant."
                        " Tag names must contain only alphanumeric"
                        " characters, hyphens, and spaces."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Provide tag names that contain only"
                            " alphanumeric characters, hyphens, and"
                            " spaces."
                        ),
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )
                for tag in tag_list:
                    if validation_result := self.netskope_helper._validate_max_length(
                        field_name=f"Tag '{tag}'",
                        field_value=tag,
                        max_length=TAG_DEVICE_TAG_LENGTH,
                    ):
                        return validation_result
                try:
                    tag_cache = self._fetch_all_tags()
                except Exception as e:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error occurred while "
                            "fetching device tags for action parameter "
                            f"validation. Error: {e}"
                        ),
                        details=traceback.format_exc(),
                    )
                    return ValidationResult(
                        success=False, message=str(e)
                    )
                missing = [
                    tag
                    for tag in tag_list
                    if tag.lower() not in tag_cache
                ]
                if missing:
                    err_msg = (
                        "Some of the provided Tags do not exist on"
                        " the Netskope Tenant. Provide existing"
                        " device tags."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=(
                            "Tags not found on the Netskope Tenant: "
                            f"{', '.join(missing)}."
                        ),
                        resolution=(
                            "Ensure all provided tag names exist on"
                            " the Netskope Tenant before saving."
                        ),
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        return ValidationResult(
            success=False, message="Invalid action provided."
        )

    def _get_publishers(self) -> Dict:
        """Retrieve a dictionary of publishers.

        Returns:
            Dict: Dictionary of publishers.
        """
        dict_publishers = {}
        tenant_name = (
            self.tenant.parameters.get('tenantName', '').strip()
        )
        url = (
            f"{tenant_name}{URLS.get('V2_PUBLISHER')}"
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        params = {
            "fields": "publisher_id,publisher_name"
        }  # we need only 2 fields
        logger_msg = "fetching publishers from the Netskope Tenant"
        self.logger.debug(
            f"{self.log_prefix}: {logger_msg.capitalize()}."
        )
        try:
            response = self.netskope_helper._api_call_helper(
                url=url,
                method="get",
                error_codes=["CRE_1047", "CRE_1048"],
                headers=headers,
                params=params,
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
            )

            existing_publishers = response.get("data", {}).get(
                "publishers", []
            )
            # Private app from netskope.
            for x in existing_publishers:
                dict_publishers[x["publisher_name"]] = x.get("publisher_id", "")
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched {len(dict_publishers)} "
            f"publisher(s)."
        )
        return dict_publishers

    def _get_private_apps(
        self, get_hosts_of: Optional[str] = None
    ) -> Union[dict, tuple]:
        """Check private app present in Netskope \
            and create a new one if not found.

        Args:
            get_hosts_of (str): Private app name.

        Returns:
            Dict: Dictionary of private apps.
        """
        dict_of_private_apps = {}
        tenant_name = (
            self.tenant.parameters.get('tenantName', '').strip()
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        url = (
            f"{tenant_name}{URLS.get('V2_PRIVATE_APP')}"
        )
        # tags / protocols / publishers / use_publisher_dns are needed only
        # when resolving a group for a push (get_hosts_of set): the Append
        # path unions the new tags with the app's existing tags, and the
        # metadata-refresh path compares these fields against the action
        # params to skip no-op update calls. The dropdown/validate calls do
        # not need them.
        fields = "app_id,app_name,host"
        if get_hosts_of:
            fields += (
                ",tags,protocols,service_publisher_assignments,"
                "use_publisher_dns"
            )
        params = {"fields": fields}
        logger_msg = "fetching private apps on the Netskope Tenant"
        self.logger.debug(
            f"{self.log_prefix}: {logger_msg.capitalize()}."
        )
        try:
            response = self.netskope_helper._api_call_helper(
                url=url,
                method="get",
                error_codes=["CRE_1040", "CRE_1041"],
                headers=headers,
                params=params,
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
            )
            existing_private_apps = response.get("data", {}).get(
                "private_apps", []
            )
            # Private app from netskope.
            for x in existing_private_apps:
                dict_of_private_apps[x["app_name"]] = {
                    "id": x["app_id"],
                    "host_count": len(x["host"].split(",")),
                    "tags": self.netskope_helper._extract_private_app_tag_names(
                        x.get("tags", [])
                    ),
                } | (
                    {
                        "hosts": x["host"].split(","),
                        "protocols": x.get("protocols", []),
                        "publishers": x.get(
                            "service_publisher_assignments", []
                        ),
                        "use_publisher_dns": x.get(
                            "use_publisher_dns", False
                        ),
                    }
                    if get_hosts_of
                    and x["app_name"].startswith(
                        get_hosts_of.removesuffix("]")
                    )
                    else {}
                )
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched "
            f"{len(dict_of_private_apps)} private app(s)."
        )
        return dict_of_private_apps

    def get_action_params(self, action: Action) -> list:
        """Get fields required for an action.

        Args:
            action (Action): Action object.

        Returns:
            List: List of fields required for the action.
        """
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        if action.value == "generate":
            return []
        if action.value in ["add", "remove"]:
            groups = self._get_all_groups()
            groups = sorted(
                groups, key=lambda g: g.get("displayName", "").lower()
            )
            if action.value == "add":
                return [
                    {
                        "label": "User Email",
                        "key": "user",
                        "type": "text",
                        "default": "",
                        "mandatory": True,
                        "description": (
                            "Email address of the user to add to group. "
                            "It must exist in SCIM."
                        ),
                    },
                    {
                        "label": "Group",
                        "key": "group",
                        "type": "choice",
                        "choices": [
                            {
                                "key": g.get("displayName", ""),
                                "value": g.get("id", ""),
                            }
                            for g in groups
                        ]
                        + [{"key": "Create new group", "value": "create"}],
                        "default": (
                            groups[0]["id"] if len(groups) > 0 else "create"
                        ),
                        "mandatory": True,
                        "description": (
                            "Select an existing group from Static field "
                            "dropdown or select 'Create new group'."
                        ),
                    },
                    {
                        "label": "Group Name",
                        "key": "name",
                        "type": "text",
                        "default": "",
                        "mandatory": False,
                        "description": (
                            "Provide a SCIM group name if 'Create new group' "
                            "is selected in 'Group' field."
                        ),
                    },
                ]
            elif action.value == "remove":
                return [
                    {
                        "label": "User Email",
                        "key": "user",
                        "type": "text",
                        "default": "",
                        "mandatory": True,
                        "description": (
                            "Email address of the user to remove from group. "
                            "It must exist in SCIM."
                        ),
                    },
                    {
                        "label": "Group",
                        "key": "group",
                        "type": "choice",
                        "choices": [
                            {
                                "key": g.get("displayName", ""),
                                "value": g.get("id", ""),
                            }
                            for g in groups
                        ]
                        + [{"key": "No groups available", "value": "group"}],
                        "default": (
                            groups[0]["id"] if len(groups) > 0 else "group"
                        ),
                        "mandatory": True,
                        "description": (
                            "Select an existing group from Static field "
                            "dropdown."
                        ),
                    },
                ]
        elif action.value == "impact":
            return [
                {
                    "label": "User Email",
                    "key": "user",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Email of the user to trigger the score change."
                    ),
                },
                {
                    "label": "Score (Reduction)",
                    "key": "score",
                    "type": "number",
                    "default": "",
                    "mandatory": True,
                    "description": "Score to be reduced from UCI.",
                },
                {
                    "label": "Source",
                    "key": "source",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": "Name of the source reporting this.",
                },
                {
                    "label": "Reason",
                    "key": "reason",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Reason for this score change.",
                },
            ]
        elif action.value == "uci_reset":
            return [
                {
                    "label": "User Email",
                    "key": "user",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Select field for the User Email or provide "
                        "Static comma separated User Emails to reset "
                        "the UCI score."
                        "User's UCI score will be reset to 1000."
                    ),
                }
            ]
        elif action.value == "private_app":
            existing_private_apps = self._get_private_apps()
            existing_publishers = self._get_publishers()
            return [
                {
                    "label": "Skip Excess Hosts",
                    "key": "skip_excess_hosts",
                    "type": "choice",
                    "choices": [
                        {"key": "No", "value": False},
                        {"key": "Yes", "value": True},
                    ],
                    "default": False,
                    "mandatory": True,
                    "description": (
                        "A private app holds at most "
                        f"{MAX_HOSTS_PER_PRIVATE_APP} hosts. Select 'No' to "
                        "create roll-over sibling private apps until all "
                        "hosts are accommodated or the tenant's private app "
                        "limit is reached (the rest are skipped). Select "
                        "'Yes' to not create roll-over siblings and skip "
                        "any hosts beyond the existing capacity. Select "
                        "from the Static field dropdown only."
                    ),
                },
                {
                    "label": "Host",
                    "key": "host",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. 127.0.0.1",
                    "mandatory": True,
                    "description": (
                        "Host address to append to the private app. "
                        "Multiple comma-separated values are supported. "
                        "Example: host-1, host-2"
                    ),
                },
                {
                    "label": "Tags",
                    "key": "tags",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. tag-1, tag-2",
                    "mandatory": False,
                    "description": (
                        "Tags to set for the private app. "
                        "These tags will overwrite existing "
                        "tags available on your tenant. "
                        "Multiple comma-separated values are supported. "
                        "Example: tag-1, tag-2"
                    ),
                },
                {
                    "label": "Private App Name",
                    "key": "private_app_name",
                    "type": "choice",
                    "choices": [
                        {"key": key, "value": key}
                        for key in sorted(existing_private_apps.keys())
                    ]
                    + [{"key": "Create new private app", "value": "create"}],
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Select a private app from Static field dropdown."
                    ),
                },
                {
                    "label": "Create New Private App",
                    "key": "name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Create private app with given name. "
                        "Provide private app name in Static field "
                        "if you have selected 'Create new private app' "
                        "in Private App Name."
                    ),
                },
                {
                    "label": "Protocol",
                    "key": "protocol",
                    "type": "multichoice",
                    "choices": [
                        {"key": "UDP", "value": "UDP"},
                        {"key": "TCP", "value": "TCP"},
                    ],
                    "default": ["TCP", "UDP"],
                    "mandatory": False,
                    "description": (
                        "Select Protocol from Static field dropdown. "
                        "Valid values are TCP and UDP."
                    ),
                },
                {
                    "label": "TCP Ports",
                    "key": "tcp_ports",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Comma-separated ports or port ranges for "
                        "the TCP protocol. (e.g. 443, 8080-8090)"
                        "(Only enter if you have selected 'TCP' in Protocol.)"
                    ),
                },
                {
                    "label": "UDP Ports",
                    "key": "udp_ports",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Comma-separated ports or port ranges for "
                        "the UDP protocol. (e.g. 443, 8080-8090)"
                        "(Only enter if you have selected 'UDP' in Protocol.)"
                    ),
                },
                {
                    "label": "Publisher",
                    "key": "publishers",
                    "type": "multichoice",
                    "choices": [
                        {"key": key, "value": key}
                        for key in sorted(existing_publishers.keys())
                    ],
                    "default": (
                        []
                        if not existing_publishers.keys()
                        else [list(existing_publishers.keys())[0]]
                    ),
                    "mandatory": False,
                    "description": (
                        "Select Publishers from Static field dropdown only."
                    ),
                },
                {
                    "label": "Use Publisher DNS",
                    "key": "use_publisher_dns",
                    "type": "choice",
                    "choices": [
                        {"key": "No", "value": False},
                        {"key": "Yes", "value": True},
                    ],
                    "default": False,
                    "mandatory": True,
                    "description": (
                        "Select Yes or No from Static field dropdown "
                        "for Use Publishers DNS."
                    ),
                },
                {
                    "label": "Default Host",
                    "key": "default_url",
                    "type": "text",
                    "default": "cedefaultpush.io",
                    "mandatory": False,
                    "description": (
                        "The default Host to be used when "
                        "new private app is created. "
                        "Provide Default Host in Static field "
                        "if you have selected 'Create new private app' "
                        "in Private App Name."
                    ),
                },
            ]
        elif action.value == "tag_app":
            return [
                {
                    "label": "Tag Action",
                    "key": "tag_action",
                    "type": "choice",
                    "choices": [
                        {
                            "key": "Add",
                            "value": "append"
                        },
                        {
                            "key": "Remove",
                            "value": "remove"
                        }
                    ],
                    "default": "append",
                    "placeholder": "Add",
                    "mandatory": True,
                    "description": (
                        "Whether to Add/Remove tag(s) from "
                        "the application(s). Select Tag Action "
                        "from Static field dropdown only."
                    ),
                },
                {
                    "label": "Tags",
                    "key": "tags",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. tag-1, tag-2",
                    "mandatory": True,
                    "description": (
                        "Select field for the tags or provide Static comma "
                        "separated tag values."
                    ),
                },
                {
                    "label": "Application Names",
                    "key": "apps",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. Dropbox, Google Drive",
                    "mandatory": False,
                    "description": (
                        "Select field for the Application Names or provide "
                        "Static comma separated Application Names. "
                        "100 is the max allowed input size for Static values."
                    ),
                },
                {
                    "label": "Application IDs",
                    "key": "ids",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. 3324, 1233",
                    "mandatory": False,
                    "description": (
                        "Select field for the Application IDs or provide "
                        "Static comma separated Application IDs. "
                        "100 is the max allowed input size for Static values."
                    ),
                },
            ]
        elif action.value == "tag_device":
            return [
                {
                    "label": "Tag Action",
                    "key": "tag_device_action",
                    "type": "choice",
                    "choices": [
                        {
                            "key": "Add",
                            "value": "append"
                        },
                        {
                            "key": "Remove",
                            "value": "remove"
                        },
                        {
                            "key": "Replace",
                            "value": "replace"
                        }
                    ],
                    "default": "append",
                    "placeholder": "Add",
                    "mandatory": True,
                    "description": (
                        "Select whether to add, remove, or replace tags on the "
                        "devices. Select Tag Action from the static dropdown only. Note: "
                        "at max 5 tags are allowed per user-device pair on Netskope."
                    ),
                },
                {
                    "label": "Tags",
                    "key": "tags",
                    "type": "text",
                    "default": "",
                    "placeholder": "e.g. tag-1, tag-2",
                    "mandatory": False,
                    "description": (
                        "Select a source field for the tags or provide static "
                        "comma-separated tag values. Note: For Replace "
                        "action, if tags are not provided or empty, all tags "
                        "will be removed from the device."
                    ),
                },
                {
                    "label": "Netskope Device UID",
                    "key": "device_id",
                    "type": "text",
                    "default": "",
                    "placeholder": "e.g. uid-1",
                    "mandatory": True,
                    "description": (
                        "The Device UID of the device to which the tag action should be "
                        "performed. Select a source field or "
                        "provide a static value."
                    ),
                },
                {
                    "label": "User Key",
                    "key": "device_user_key",
                    "type": "text",
                    "default": "",
                    "placeholder": "e.g. user-1",
                    "mandatory": True,
                    "description": (
                        "The User Key of the user associated with the"
                        " device on which the tag action should be "
                        "performed. Select a source field or "
                        "provide a static value."
                    ),
                },
                {
                    "label": "Hostname",
                    "key": "hostname",
                    "type": "text",
                    "default": "",
                    "placeholder": "e.g. device-hostname",
                    "mandatory": True,
                    "description": (
                        "The hostname of the device on which the tag "
                        "action should be performed. Select a source "
                        "field or provide a static value."
                    ),
                },
            ]
        elif action.value == "app_instance":
            return [
                {
                    "label": "Instance ID",
                    "key": "instance_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "placeholder": "i.e. 123451234512",
                    "description": (
                        "For AWS, use the account ID. For Azure, use the "
                        "Subscription. For GCP, use the Project. The "
                        "`app + instance_id` combo must be new."
                    ),
                },
                {
                    "label": "Instance Name",
                    "key": "instance_name",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. MYAWS_GOSKOPE",
                    "mandatory": True,
                    "description": (
                        "Used to change instance name, and must be unique. "
                        "Name should be unique within `app + instance_id` or "
                        "`app + instance_name`."
                    ),
                },
                {
                    "label": "Application Name",
                    "key": "app_name",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. Dropbox",
                    "mandatory": True,
                    "description": "Name of the application.",
                },
                {
                    "label": "Tag",
                    "key": "tag",
                    "type": "choice",
                    "choices": [
                        {"key": "None", "value": "None"},
                        {"key": "Sanctioned", "value": "Sanctioned"},
                        {"key": "Unsanctioned", "value": "Unsanctioned"},
                    ],
                    "default": "None",
                    "mandatory": False,
                    "description": "Select Tag from Static field dropdown.",
                },
            ]
        elif action.value == "destination_profile":
            existing_profiles = self._get_destination_profiles()
            params = copy.deepcopy(DESTINATION_PROFILE_ACTION_PARAMS)
            profile_choices = [
                {"key": key, "value": key}
                for key in sorted(existing_profiles.keys())
            ] + [
                {"key": "Create new profile", "value": "create"}
            ]
            for param in params:
                if param["key"] == "destination_profile_name":
                    param["choices"] = profile_choices
            return params
        elif action.value == "dns_profile":
            existing_profiles = self._get_dns_profiles()
            security_categories = self._get_security_categories()
            record_types = self._get_record_types()
            profile_choices = [
                {
                    "key": name,
                    "value": f"{name}{CUSTOM_SEPARATOR}{profile_id}",
                }
                for name, profile_id in sorted(
                    existing_profiles.items(),
                    key=lambda item: item[0].lower(),
                )
            ] + [
                {
                    "key": "Create new DNS Profile",
                    "value": (
                        f"Create new DNS Profile"
                        f"{CUSTOM_SEPARATOR}create"
                    ),
                }
            ]
            params = copy.deepcopy(DNS_PROFILE_ACTION_PARAMS)
            for param in params:
                key = param["key"]
                if key == "dns_profile_name":
                    param["choices"] = profile_choices
                    param["default"] = (
                        profile_choices[0]["value"]
                        if profile_choices
                        else ""
                    )
                elif key == "dns_security_categories":
                    param["choices"] = [
                        {"key": category, "value": category}
                        for category in security_categories
                    ]
                elif key == "dns_record_types":
                    param["choices"] = [
                        {"key": record_type, "value": record_type}
                        for record_type in record_types
                    ]
                    param["default"] = (
                        [record_types[0]] if record_types else []
                    )
            return params
        elif action.value == "service_profile":
            existing_profiles = self._get_service_profiles(
                custom_only=True
            )
            params = copy.deepcopy(SERVICE_PROFILE_ACTION_PARAMS)
            profile_choices = [
                {"key": key, "value": key}
                for key in sorted(existing_profiles.keys())
            ] + [
                {
                    "key": "Create new service profile",
                    "value": "create",
                }
            ]
            for param in params:
                if param["key"] == "service_profile_name":
                    param["choices"] = profile_choices
            return params
        elif action.value == "device_classification":
            existing_classifications = (
                self._get_device_classifications()
            )
            existing_rules = self._get_device_classification_rules()
            classification_choices = [
                {"key": name, "value": name}
                for name in sorted(
                    existing_classifications.keys(),
                    key=lambda n: n.lower(),
                )
            ] + [
                {
                    "key": "Create new Device Classification",
                    "value": "create",
                }
            ]
            rule_choices = [
                {
                    "key": rule.get("name", ""),
                    "value": (
                        f"{rule.get('name', '')}"
                        f"{CUSTOM_SEPARATOR_DEVICE_CLASSIFICATION}"
                        f"{rule.get('id')}"
                    ),
                }
                for rule in sorted(
                    existing_rules,
                    key=lambda r: str(r.get("name", "")).lower(),
                )
                if rule.get("name") and rule.get("id") is not None
            ] + [
                {
                    "key": "Create new Device Classification Rule",
                    "value": (
                        f"Create new Device Classification Rule"
                        f"{CUSTOM_SEPARATOR_DEVICE_CLASSIFICATION}create"
                    ),
                }
            ]
            params = copy.deepcopy(DEVICE_CLASSIFICATION_ACTION_PARAMS)
            for param in params:
                key = param["key"]
                if key == "device_classification":
                    param["choices"] = classification_choices
                elif key == "device_classification_rule":
                    param["choices"] = rule_choices
            return params
        return []

    def _push_private_app(
        self,
        host: Union[str, list[str]],
        existing_private_app_name: str,
        new_private_app_name: str,
        protocol_type: list[str],
        tcp_ports: list[str],
        udp_ports: list[str],
        publishers: list[str],
        use_publisher_dns: bool,
        default_url: str,
        tags: list[str] = [],
        skip_excess_hosts: bool = False,
        host_to_tags: Optional[dict] = None,
        compact: bool = False,
    ):
        """Append host(s) to a private app group.

        Resolves the logical private app (the base app ``[X]`` plus any
        numbered roll-over siblings ``[X 2]`` ...), runs the shared setup
        (protocols, publishers, host/tag validation, group enumeration),
        then appends the hosts via ``_append_private_app_hosts`` (honouring
        the per-app host cap ``MAX_HOSTS_PER_PRIVATE_APP`` and
        ``skip_excess_hosts``). When ``compact`` is set (bulk sync only) the
        group is consolidated after the append to reclaim apps left
        partially filled by earlier reverts.

        Args:
            host (Union[str, list[str]]): The host(s) to be shared.
            existing_private_app_name (str): Selected app name, or
                ``create``.
            new_private_app_name (str): Name for a newly created app.
            protocol_type (List[str]): The list of protocol types.
            tcp_ports (List[int]): The list of TCP ports.
            udp_ports (List[int]): The list of UDP ports.
            publishers (List[str]): The list of publishers.
            use_publisher_dns (bool): Whether to use the publisher DNS.
            default_url (str): The default host.
            tags (List[str], optional): The list of tags. Defaults to [].
            skip_excess_hosts (bool, optional): When True, do not create \
                new roll-over sibling apps for hosts beyond the existing \
                capacity - the excess hosts are skipped. When False, new \
                siblings are created until all hosts fit or the tenant's \
                private app limit is reached. Defaults to False.
            host_to_tags (Optional[dict], optional): Pre-built and \
                pre-validated ``{host -> set(tag_name)}`` map used to scope \
                each app's tags to the records whose hosts land in it \
                (bulk path). When None (single/fallback), it is built from \
                ``tags`` and applied uniformly to all hosts. Defaults None.
            compact (bool, optional): When True (set by the bulk sync), \
                consolidate the app group after the append so apps left \
                partially filled by earlier reverts are re-packed and any \
                emptied trailing apps removed. Best-effort. Defaults False.

        Returns:
            tuple[set[str], dict[str, int]]: ``(not_placed, added_counts)``
                where ``not_placed`` is the set of host values that were
                NOT placed (invalid plus capacity-skipped), used by
                ``execute_actions`` to attribute failed action ids per
                record, and ``added_counts`` maps each private app name to
                the number of hosts added to it.
        """
        tenant_name = (
            self.tenant.parameters.get('tenantName', '').strip()
        )
        try:
            if existing_private_app_name == "create":
                base_name = new_private_app_name
            else:
                base_name = existing_private_app_name.removeprefix(
                    "["
                ).removesuffix("]")
            private_app_name = f"[{base_name}]"
            # Validate/filter the hosts first (no API calls): if nothing is
            # valid we can short-circuit before the fetch-apps /
            # fetch-publishers calls below, which would otherwise be wasted.
            if host and isinstance(host, str):
                host = list(map(lambda x: x.strip(), host.split(",")))
            if host_to_tags is None:
                # Single-record / fallback: validate the uniform tags and
                # map every valid host to the same tag-name set.
                valid_hosts, valid_tags, invalid_hosts = (
                    self._filter_private_app_hosts_tags(
                        host if host else [], tags, private_app_name
                    )
                )
                tag_names = {tag["tag_name"] for tag in valid_tags}
                host_to_tags = {
                    valid_host: set(tag_names) for valid_host in valid_hosts
                }
            else:
                # Bulk: tags were validated + attached per record upstream;
                # only the hosts need validating here.
                valid_hosts, _, invalid_hosts = (
                    self._filter_private_app_hosts_tags(
                        host if host else [], [], private_app_name
                    )
                )
            # De-duplicate while keeping a deterministic order.
            unique_hosts = list(dict.fromkeys(valid_hosts))
            if not unique_hosts:
                # Append has nothing to add - skip without the fetch-apps /
                # fetch-publishers calls below. Every record in this group
                # contributed only invalid/empty hosts, so returning them as
                # not-placed fails all those records.
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: No valid host to add to "
                        f"private app '{private_app_name}'; hence"
                        " skipping the action."
                    ),
                    resolution=(
                        "Provide at least one valid host (IPv4 "
                        "address, IPv4 CIDR block, hostname, or "
                        "domain)."
                    ),
                )
                return set(invalid_hosts), {}
            existing_private_apps = self._get_private_apps(
                get_hosts_of=private_app_name
            )
            protocols_list = self.netskope_helper._build_private_app_protocols(
                protocol_type, tcp_ports, udp_ports
            )
            publishers_list = self._resolve_private_app_publishers(
                publishers, private_app_name
            )
            members = self.netskope_helper._ordered_private_app_group(
                existing_private_apps, base_name
            )
            shared = {
                "tenant_name": tenant_name,
                "base_name": base_name,
                "private_app_name": private_app_name,
                "members": members,
                "host_to_tags": host_to_tags,
                "publishers_list": publishers_list,
                "use_publisher_dns": use_publisher_dns,
                "protocols_list": protocols_list,
                "default_url": default_url,
                "skip_excess_hosts": skip_excess_hosts,
            }
            capacity_skipped, added_counts = (
                self._append_private_app_hosts(unique_hosts, **shared)
            )
            # After the append, consolidate the group (bulk sync only): an
            # earlier revert may have left apps partially filled, so re-pack
            # the group to free up trailing apps. Best-effort - a compaction
            # failure is logged but never fails the action.
            if compact:
                self._compact_private_app_group(
                    tenant_name,
                    base_name,
                    private_app_name,
                    host_to_tags,
                    publishers_list,
                    use_publisher_dns,
                    protocols_list,
                    default_url,
                )
            # Hosts that were not placed: invalid (validation-filtered) plus
            # capacity-skipped (Skip Excess / tenant limit). The caller uses
            # this to attribute failed action ids per record, and
            # added_counts (app name -> hosts added) for the final summary.
            return (
                set(invalid_hosts) | set(capacity_skipped or []),
                added_counts,
            )
        except NetskopeException:
            raise
        except Exception as err:
            error_message = (
                "Error occurred while pushing data to private app."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
                error_code="CRE_1021",
            )
            raise NetskopeException(error_message)

    def _resolve_private_app_publishers(self, publishers, private_app_name):
        """Resolve publisher names to private app publisher entries.

        Unknown publishers are skipped and logged; if every provided
        publisher is unknown a NetskopeException is raised.

        Args:
            publishers (list[str]): Publisher names selected for the app.
            private_app_name (str): Target app name (used in logs).

        Returns:
            list[dict]: ``{publisher_id, publisher_name}`` entries.
        """
        existing_publishers = self._get_publishers()
        publishers_list = []
        skipped_publishers = []
        for publisher in publishers:
            if publisher in existing_publishers:
                publishers_list.append(
                    {
                        "publisher_id": existing_publishers[publisher],
                        "publisher_name": publisher,
                    }
                )
            else:
                skipped_publishers.append(publisher)
        if not publishers_list and skipped_publishers:
            self.logger.error(
                f"{self.log_prefix}: Unable to find the "
                f"provided publishers [{','.join(skipped_publishers)}]."
            )
            raise NetskopeException(
                f"{self.log_prefix}: Could not create new private app "
                "to share host."
            )
        if skipped_publishers:
            self.logger.error(
                f"{self.log_prefix}: Unable to find the following "
                f"publishers [{','.join(skipped_publishers)}]."
                " Hence ignoring them while creating "
                f"the private app '{private_app_name}'."
            )
        return publishers_list

    def _filter_private_app_hosts_tags(self, host, tags, private_app_name):
        """Validate and sanitize hosts and tags before sharing.

        Invalid hosts (empty or not a valid IPv4 address, IPv4 CIDR
        block, hostname, or domain) and invalid tags (empty or over the
        maximum length) are skipped and logged. Static values are
        already validated at save time; this mainly covers Source-field
        values resolved per record at execution.

        Args:
            host (list[str]): Hosts to validate.
            tags (list[str]): Tags to validate.
            private_app_name (str): Target app name (used in logs).

        Returns:
            tuple[list[str], list[dict], list[str]]: (valid_hosts,
                valid_tags, skipped_hosts) where ``skipped_hosts`` are the
                invalid (not-placed) host values, used for per-record
                failed-action-id attribution.
        """
        valid_hosts, skipped_hosts, skip_host_count = (
            self.netskope_helper.validate_hosts_for_private_app(
                hosts_to_push=host if host else [],
                private_app_name=private_app_name,
            )
        )
        if skip_host_count > 0:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Skipped adding "
                    f"{skip_host_count} host(s) to private app "
                    f"'{private_app_name}' as they were empty or were "
                    "not a valid IPv4 address, IPv4 CIDR block, "
                    "hostname, or domain."
                ),
                details=f"Skipped Host(s): {', '.join(skipped_hosts)}",
            )
        valid_tags, skipped_tags, skip_tag_count = (
            self.netskope_helper.validate_tags_for_private_app(
                tags_to_push=tags,
                private_app_name=private_app_name,
            )
        )
        if skip_tag_count > 0:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Skipped adding "
                    f"{skip_tag_count} tag(s) to private app "
                    f"'{private_app_name}' as they were empty or "
                    "exceeded the maximum allowed character limit of "
                    f"{PRIVATE_APP_TAG_MAX_LENGTH}."
                ),
                details=f"Skipped Tags: {', '.join(skipped_tags)}",
            )
        return valid_hosts, valid_tags, skipped_hosts

    def _create_private_app(
        self,
        app_name_to_create,
        default_url,
        publishers_list,
        use_publisher_dns,
        protocols_list,
    ):
        """Create a private app seeded with the default host.

        Args:
            app_name_to_create (str): Name to create the app with.
            default_url (str): Seed host for the new app.
            publishers_list (list[dict]): Resolved publisher entries.
            use_publisher_dns (bool): Whether to use the publisher DNS.
            protocols_list (list[dict]): Protocol entries for the app.

        Returns:
            tuple[str, str]: (app_id, app_name) of the created app.

        Raises:
            NetskopeException: If the app could not be created.
        """
        tenant_name = (
            self.tenant.parameters.get('tenantName', '').strip()
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        data = {
            "app_name": app_name_to_create,
            "host": default_url,
            "publishers": publishers_list,
            "use_publisher_dns": use_publisher_dns,
        }
        if protocols_list:
            data["protocols"] = protocols_list
        logger_msg = (
            f"creating private app '{app_name_to_create}' on the "
            "Netskope Tenant"
        )
        self.logger.debug(
            f"{self.log_prefix}: {_capitalize_first(logger_msg)}."
        )
        url = f"{tenant_name}{URLS.get('V2_PRIVATE_APP')}"
        response = self.netskope_helper._api_call_helper(
            url=url,
            method="post",
            error_codes=["CRE_1043", "CRE_1044"],
            headers=headers,
            json=data,
            proxies=self.proxy,
            message=f"Error occurred while {logger_msg}",
            logger_msg=logger_msg,
            is_handle_error_required=False,
        )
        if response.status_code not in [200, 201]:
            err_msg = f"Error occurred while {logger_msg}. "
            self.logger.error(
                message=err_msg,
                details=str(response.text),
            )
            raise NetskopeException(
                "Could not create new private app to share host.",
            )
        create_private_app_json = handle_status_code(
            response,
            error_code="CRE_1044",
            custom_message=f"Error occurred while {logger_msg}.",
            plugin=self.log_prefix,
            notify=False,
            log=True,
        )
        if create_private_app_json.get("status", "") != "success":
            response_message = create_private_app_json.get("message", "")
            # The tenant's max private app count returns HTTP 200 with a
            # status=error body; treat it as a non-fatal stop signal so the
            # roll-over can skip the remaining hosts instead of failing.
            if "maximum number" in response_message.lower():
                raise PrivateAppLimitReachedError(response_message)
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while "
                    "creating private app. "
                    f"Received exit code {response.status_code}."
                ),
                details=repr(create_private_app_json),
            )
            raise NetskopeException(
                "Could not create new private app to share the host."
            )
        return (
            create_private_app_json["data"]["app_id"],
            create_private_app_json["data"]["app_name"],
        )

    def _delete_private_app(self, tenant_name, app_id, app_name):
        """Delete a private app by id.

        Args:
            tenant_name (str): Tenant base URL.
            app_id (str): Id of the app to delete.
            app_name (str): Name of the app (used in logs).

        Returns:
            bool: True if the app was deleted, False otherwise.
        """
        logger_msg = f"deleting the surplus private app '{app_name}'"
        url = (
            f"{tenant_name}"
            f"{URLS.get('V2_PRIVATE_APP_PATCH').format(app_id)}"
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        try:
            response = self.netskope_helper._api_call_helper(
                url=url,
                method="delete",
                error_codes=["CRE_1069", "CRE_1070"],
                headers=headers,
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
                is_handle_error_required=False,
            )
            if response.status_code in [200, 201, 204]:
                self.logger.info(
                    f"{self.log_prefix}: Successfully deleted the surplus "
                    f"private app '{app_name}'."
                )
                return True
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unable to delete the surplus "
                    f"private app '{app_name}'. Received exit code "
                    f"{response.status_code}."
                ),
                details=str(response.text),
            )
            return False
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while "
                    f"{logger_msg}. Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            return False

    def _remove_surplus_private_app(
        self,
        tenant_name,
        member,
        publishers_list,
        use_publisher_dns,
        protocols_list,
        default_url,
    ):
        """Remove a private app left empty after a Replace re-pack.

        Tries to delete the app; if the tenant rejects the delete (for
        example because the app is still referenced by a policy) the app
        is reset to the default host instead so it no longer holds stale
        data (a private app must keep at least one host, so the default
        host placeholder is used rather than an empty host list).

        Args:
            tenant_name (str): Tenant base URL.
            member (dict): ``{name, id, number}`` of the surplus app.
            publishers_list (list[dict]): Resolved publisher entries.
            use_publisher_dns (bool): Whether to use the publisher DNS.
            protocols_list (list[dict]): Protocol entries for the app.
            default_url (str): Default host placeholder to reset the app to.

        Returns:
            bool: True if the app was deleted or reset.
        """
        if self._delete_private_app(
            tenant_name, member["id"], member["name"]
        ):
            return True
        self.logger.info(
            f"{self.log_prefix}: Could not delete the surplus private app "
            f"'{member['name']}'. Resetting it to the default host instead."
        )
        data = {
            "host": default_url,
            "publishers": publishers_list,
            "use_publisher_dns": use_publisher_dns,
        }
        if protocols_list:
            data["protocols"] = protocols_list
        try:
            self._patch_private_app(
                tenant_name, member["id"], data, member["name"]
            )
            return True
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unable to reset the surplus "
                    f"private app '{member['name']}'. It may still hold "
                    f"stale hosts. Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            return False

    def _create_overflow_siblings(
        self,
        tenant_name,
        base_name,
        members,
        overflow_hosts,
        skip_excess_hosts,
        default_url,
        host_to_tags,
        publishers_list,
        use_publisher_dns,
        protocols_list,
    ):
        """Place overflow hosts into newly created roll-over sibling apps.

        Used by both Append and Replace for the hosts that do not fit in
        the existing group apps. New siblings are numbered past the highest
        existing member (or named ``[base]`` when the group is empty),
        ``MAX_HOSTS_PER_PRIVATE_APP`` hosts each.

        Returns:
            tuple[list[str], dict[str, int]]: ``(not_placed, added_counts)``
                where ``not_placed`` is the list of hosts that could NOT be
                placed - the hosts beyond the base app when
                ``skip_excess_hosts`` is set (the base app is the primary
                app, not a roll-over sibling, so it is still created), or
                the remainder once the tenant's private app limit is
                reached - and ``added_counts`` maps each newly created app
                name to the number of hosts added to it.
        """
        if not overflow_hosts:
            return [], {}
        added_counts = {}
        chunks = [
            overflow_hosts[index: index + MAX_HOSTS_PER_PRIVATE_APP]
            for index in range(
                0, len(overflow_hosts), MAX_HOSTS_PER_PRIVATE_APP
            )
        ]
        next_number = (
            max(member["number"] for member in members) + 1
            if members
            else 2
        )
        # When the group is empty the first app created is the base app
        # (the primary app, not a roll-over sibling); it is created even
        # when skip_excess_hosts is set. Only additional siblings are
        # gated by skip_excess_hosts.
        base_needed = not members
        for index, chunk in enumerate(chunks):
            is_base = base_needed and index == 0
            if skip_excess_hosts and not is_base:
                remaining = [
                    host for batch in chunks[index:] for host in batch
                ]
                self.logger.info(
                    f"{self.log_prefix}: 'Skip Excess Hosts' is enabled; "
                    f"skipping {len(remaining)} excess host(s) that "
                    f"exceed the capacity of the existing private app(s) "
                    f"for '[{base_name}]'."
                )
                return remaining, added_counts
            if is_base:
                sibling_name = base_name
                self.logger.info(
                    f"{self.log_prefix}: Creating private app "
                    f"'[{sibling_name}]' with {len(chunk)} host(s) on the "
                    "Netskope Tenant."
                )
            else:
                sibling_name = f"{base_name} {next_number}"
                next_number += 1
                self.logger.info(
                    f"{self.log_prefix}: Creating new private app "
                    f"'[{sibling_name}]' to accommodate {len(chunk)} excess "
                    "host(s) that exceed the capacity of the existing "
                    f"private app(s) for '[{base_name}]'."
                )
            try:
                created_app_id, created_app_name = self._create_private_app(
                    sibling_name,
                    default_url,
                    publishers_list,
                    use_publisher_dns,
                    protocols_list,
                )
            except PrivateAppLimitReachedError as err:
                remaining = [
                    host for batch in chunks[index:] for host in batch
                ]
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Reached the tenant's maximum "
                        "private app limit while creating roll-over "
                        f"siblings for '[{base_name}]'. Skipping "
                        f"{len(remaining)} host(s) that could not be "
                        "accommodated."
                    ),
                    details=str(err),
                )
                return remaining, added_counts
            self._patch_private_app(
                tenant_name,
                created_app_id,
                self.netskope_helper._private_app_body(
                    chunk,
                    host_to_tags,
                    publishers_list,
                    use_publisher_dns,
                    protocols_list,
                ),
                created_app_name,
            )
            added_counts[created_app_name] = (
                added_counts.get(created_app_name, 0) + len(chunk)
            )
        return [], added_counts

    def _append_private_app_hosts(
        self,
        unique_hosts,
        tenant_name,
        base_name,
        private_app_name,
        members,
        host_to_tags,
        publishers_list,
        use_publisher_dns,
        protocols_list,
        default_url,
        skip_excess_hosts,
    ):
        """Union new hosts into a logical private app, rolling over by 500.

        New hosts (those not already present in any group member) fill the
        existing siblings' remaining room in order; the rest roll over into
        new sibling apps (unless ``skip_excess_hosts`` skips them, or the
        tenant's private app limit is reached). Existing hosts are never
        moved or removed. When filling an existing app the new batch's tags
        are unioned with that app's current tags (so prior tags are kept).
        """
        existing_set = set()
        for member in members:
            existing_set.update(member["hosts"])
        new_to_add = [
            host for host in unique_hosts if host not in existing_set
        ]
        if not new_to_add:
            # Nothing new to add. Refresh every group member's metadata
            # (publishers, protocols); keep each app's existing tags via
            # base_tags (no new hosts means no new batch tags to add). Skip
            # the API call entirely for members whose metadata already
            # matches the action params - it would be a no-op PATCH.
            if members:
                self.logger.info(
                    f"{self.log_prefix}: All {len(unique_hosts)} provided "
                    f"host(s) are already present in private app "
                    f"'{private_app_name}'; no new hosts to add. Refreshing "
                    "its publishers, protocols, tags, and use-publisher-DNS "
                    "values."
                )
                for member in members:
                    # Every host here is already in the app (that's why
                    # there's nothing new to add), but the records can still
                    # carry tags - and a tag may be new even when the host
                    # isn't. So the tag set this app would end up with is its
                    # existing tags plus any the records attached to its
                    # hosts; comparing that to its current tags tells us
                    # whether the update is needed.
                    target_tag_names = set(member["tags"])
                    for host in member["hosts"]:
                        target_tag_names |= host_to_tags.get(host, set())
                    if not self.netskope_helper._private_app_metadata_changed(
                        member,
                        publishers_list,
                        use_publisher_dns,
                        protocols_list,
                        target_tag_names,
                    ):
                        self.logger.debug(
                            f"{self.log_prefix}: No metadata changes for "
                            f"private app '{member['name']}'; skipping the "
                            "update API call."
                        )
                        continue
                    self._patch_private_app(
                        tenant_name,
                        member["id"],
                        self.netskope_helper._private_app_body(
                            member["hosts"],
                            host_to_tags,
                            publishers_list,
                            use_publisher_dns,
                            protocols_list,
                            base_tags=member["tags"],
                        ),
                        member["name"],
                    )
            else:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: No private app with the name "
                        f"'{private_app_name}' was found on the Netskope "
                        "Tenant; skipping the action execution."
                    ),
                    resolution=(
                        "Verify the private app still exists on the "
                        "Netskope Tenant, or provide at least one valid "
                        "host so a new private app can be created."
                    ),
                )
            # Nothing was capacity-skipped or added on this path. When the
            # app does not exist, every record here contributed only
            # invalid/empty hosts (a valid host would have created the app),
            # so they are already attributed as failed via the invalid-host
            # set in _push_private_app.
            return [], {}
        # Some of the provided hosts are already in the group and are not
        # re-added; report how many so it is clear what happened to them.
        already_present = len(unique_hosts) - len(new_to_add)
        if already_present:
            self.logger.info(
                f"{self.log_prefix}: {already_present} of the "
                f"{len(unique_hosts)} provided host(s) were not added to "
                f"private app '{private_app_name}' as they are already "
                "present in it."
            )
        # When Skip Excess Hosts is enabled no new sibling apps are
        # created, so the only capacity is the room left in the existing
        # group members. If they are already full there is nowhere to put
        # any new host - report skipping all of them directly instead of
        # going through the roll-over path and reporting a "0 appended"
        # success below.
        if skip_excess_hosts and members:
            available_room = sum(
                max(0, MAX_HOSTS_PER_PRIVATE_APP - len(member["hosts"]))
                for member in members
            )
            if available_room <= 0:
                self.logger.info(
                    f"{self.log_prefix}: Private app '{private_app_name}' "
                    f"is already at its maximum capacity of "
                    f"{MAX_HOSTS_PER_PRIVATE_APP} host(s) per app and "
                    "'Skip Excess Hosts' is enabled; hence skipping all "
                    f"{len(unique_hosts)} unique host(s)."
                )
                return new_to_add, {}
        # Track how many new hosts were added to each private app.
        added_counts = {}
        # The Default Host is only a placeholder (seeded at creation, or left
        # behind by a revert that reset an emptied app); once real hosts are
        # added to an app it is dropped so it does not linger alongside them.
        default_host = (default_url or "").strip()
        # Fill the existing siblings' remaining room first.
        pointer = 0
        for member in members:
            if pointer >= len(new_to_add):
                break
            current_hosts = list(member["hosts"])
            if default_host:
                current_hosts = [
                    host for host in current_hosts if host != default_host
                ]
            room = MAX_HOSTS_PER_PRIVATE_APP - len(current_hosts)
            if room <= 0:
                self.logger.info(
                    f"{self.log_prefix}: Private app '{member['name']}' is "
                    f"already full ({MAX_HOSTS_PER_PRIVATE_APP} host(s)); "
                    "adding the remaining host(s) to the next app."
                )
                continue
            take = new_to_add[pointer: pointer + room]
            # Union this batch's tags with the existing app's tags so the
            # filled app keeps its prior tags and gains the new ones. The
            # Default Host placeholder (if any) is dropped from current_hosts
            # above since at least one real host is being added here.
            self._patch_private_app(
                tenant_name,
                member["id"],
                self.netskope_helper._private_app_body(
                    current_hosts + take,
                    host_to_tags,
                    publishers_list,
                    use_publisher_dns,
                    protocols_list,
                    base_tags=member["tags"],
                ),
                member["name"],
            )
            added_counts[member["name"]] = len(take)
            pointer += len(take)
        # Any remaining new hosts roll over into new sibling apps.
        skipped, overflow_counts = self._create_overflow_siblings(
            tenant_name,
            base_name,
            members,
            new_to_add[pointer:],
            skip_excess_hosts,
            default_url,
            host_to_tags,
            publishers_list,
            use_publisher_dns,
            protocols_list,
        )
        added_counts.update(overflow_counts)
        placed = len(new_to_add) - len(skipped)
        skip_note = (
            f" {len(skipped)} excess host(s) were skipped."
            if skipped
            else ""
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully appended {placed} new "
            f"host(s) to private app '{private_app_name}'.{skip_note}"
        )
        # The capacity-skipped hosts (Skip Excess / tenant limit) are
        # returned so the caller can attribute failed action ids, along
        # with the per-app added-host counts for the final summary.
        return skipped, added_counts

    def _compact_private_app_group(
        self,
        tenant_name,
        base_name,
        private_app_name,
        host_to_tags,
        publishers_list,
        use_publisher_dns,
        protocols_list,
        default_url,
    ):
        """Consolidate a private app group after an append (bulk sync only).

        A revert removes hosts in place, which can leave a group with
        partially filled apps (for example ``[X]``=500, ``[X 2]``=260,
        ``[X 3]``=200) or with the base app reset to the Default Host
        placeholder while a sibling still holds real hosts. This re-packs the
        group's real hosts into the fewest apps (``MAX_HOSTS_PER_PRIVATE_APP``
        each), **filling the existing slots in order from the base first** and
        deleting the trailing slots left unused. No real host is dropped -
        only redistributed - and the group is only ever shrunk, so this never
        creates a new app. Compaction runs only when it would free a slot (a
        surplus or a placeholder slot), to avoid needless churn.

        The base (and any lower-numbered slot still needed to hold the
        re-packed hosts) is **reused** even when it currently holds only the
        Default Host placeholder - the real hosts overwrite the placeholder.
        Only the **trailing surplus** slots are removed: a slot that held real
        hosts (now moved up) is reset to the Default Host if its delete is
        rejected (so it keeps no stale duplicates), while a trailing slot
        holding only the placeholder is just deleted (on a delete failure it
        is left as-is). The Default Host placeholder value is never merged into
        another app. A lone group app is left untouched.

        It is a best-effort cleanup: any error is logged but never raised,
        so a compaction failure does not fail the action.

        Tags and metadata follow the hosts: each rewritten slot is given the
        publishers / protocols / use-publisher-DNS from the current action,
        and its tags are the union of the tags of the source app(s) of the
        hosts that land in it (so a moved host's tags are carried into its new
        app) plus the current sync's tags (``host_to_tags``).

        Args:
            tenant_name (str): Tenant base URL.
            base_name (str): Logical app name without brackets.
            private_app_name (str): The base app name ``[base]`` (for logs).
            host_to_tags (dict[str, set[str]]): host -> contributing tag
                names from the current sync.
            publishers_list (list[dict]): Resolved publisher entries.
            use_publisher_dns (bool): Whether to use the publisher DNS.
            protocols_list (list[dict]): Protocol entries for the apps.
            default_url (str): Default Host placeholder.
        """
        try:
            # Re-fetch the group fresh - the append just mutated it.
            existing_private_apps = self._get_private_apps(
                get_hosts_of=private_app_name
            )
            members = self.netskope_helper._ordered_private_app_group(
                existing_private_apps, base_name
            )
            if len(members) <= 1:
                # A single app (or none) cannot be consolidated, and a lone
                # placeholder app is left as the group's anchor.
                return
            default_host = (default_url or "").strip()
            # Collect every real host across the group in member order
            # (base-first), de-duplicated, while remembering the tags carried
            # by each host's source app so they follow the host when it moves.
            # The Default Host placeholder value is never collected, so it is
            # never merged into another app.
            all_hosts = []
            seen = set()
            host_to_source_tags = {}
            for member in members:
                for host in member["hosts"]:
                    if not host or host == default_host:
                        continue
                    host_to_source_tags.setdefault(host, set()).update(
                        member["tags"]
                    )
                    if host not in seen:
                        seen.add(host)
                        all_hosts.append(host)
            if not all_hosts:
                # The group holds only placeholder host(s); there is nothing
                # real to consolidate, so the apps (and the anchor) are left
                # as-is.
                return
            target_count = (
                len(all_hosts) + MAX_HOSTS_PER_PRIVATE_APP - 1
            ) // MAX_HOSTS_PER_PRIVATE_APP
            if len(members) <= target_count:
                # The group already uses the minimum number of apps; there is
                # no surplus or placeholder slot to reclaim, so skip to avoid
                # churn. (A placeholder slot holds no real host, so when one
                # exists len(members) always exceeds target_count.)
                return
            chunks = [
                all_hosts[index: index + MAX_HOSTS_PER_PRIVATE_APP]
                for index in range(
                    0, len(all_hosts), MAX_HOSTS_PER_PRIVATE_APP
                )
            ]
            self.logger.info(
                f"{self.log_prefix}: Compacting private app group "
                f"'{private_app_name}' from {len(members)} app(s) to "
                f"{len(chunks)} app(s)."
            )
            # Re-pack the hosts into the existing app slots in order, filling
            # the base (and lower-numbered siblings) first - reusing a slot
            # even when it currently holds only the Default Host placeholder.
            # Each rewritten slot carries the tags of the source app(s) of the
            # hosts that land in it (base_tags) plus the current sync's tags
            # (host_to_tags), so tags follow the hosts as they move.
            for index, chunk in enumerate(chunks):
                member = members[index]
                if chunk == member["hosts"]:
                    # Slot already holds exactly these hosts (so the same
                    # source tags); skip the redundant PATCH.
                    continue
                chunk_source_tags = set()
                for host in chunk:
                    chunk_source_tags |= host_to_source_tags.get(host, set())
                self._patch_private_app(
                    tenant_name,
                    member["id"],
                    self.netskope_helper._private_app_body(
                        chunk,
                        host_to_tags,
                        publishers_list,
                        use_publisher_dns,
                        protocols_list,
                        base_tags=chunk_source_tags,
                    ),
                    member["name"],
                )
            # Remove the trailing surplus slots left unused after the re-pack.
            # A slot that held real hosts (now moved up) is reset to the
            # Default Host if its delete is rejected, so it keeps no stale
            # duplicate hosts; a slot holding only the placeholder is just
            # deleted (on a delete failure it is left as-is).
            for member in members[len(chunks):]:
                if default_host and member["hosts"] == [default_host]:
                    self._delete_private_app(
                        tenant_name, member["id"], member["name"]
                    )
                else:
                    self._remove_surplus_private_app(
                        tenant_name,
                        member,
                        publishers_list,
                        use_publisher_dns,
                        protocols_list,
                        default_url,
                    )
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while consolidating "
                    f"private app group '{private_app_name}'. The hosts were "
                    "added successfully; only the cleanup of partially "
                    f"filled apps was skipped. Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )

    def _tag_application(
        self,
        tags: list[str],
        apps: list[str],
        ids: list[int],
        cci_tag_action: str
    ):
        """Tag the application(s) on Netskope.

        Args:
            tags (list[str]): List of tags to be attached to \
                the application(s).
            apps (list[str]): List of application names to be tagged.
            ids (list[int]): List of application IDs to be tagged.
            cci_tag_action (str): Action to be performed on the tags.
        """
        tenant_name = (
            self.tenant.parameters.get('tenantName', '').strip()
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        for tag in tags:
            log_message = (
                f"tagging {', '.join(apps if apps else ids)} application(s) "
                f"with the tag '{tag}'"
            )
            if cci_tag_action == "remove":
                log_message = (
                    f"untagging {', '.join(apps if apps else ids)} "
                    f"application(s) with the tag '{tag}'"
                )
            try:
                self.logger.debug(
                    f"{self.log_prefix}: {_capitalize_first(log_message)}."
                )
                data = (
                    {"tag": tag}
                    | ({"apps": apps} if apps else {})
                    | ({"ids": ids} if ids else {})
                )
                url = (
                    f"{tenant_name}{URLS.get('V2_CCI_TAG_CREATE')}"
                )
                if cci_tag_action == "append":
                    log_msg = f"creating tag '{tag}'"
                    add_tags_response = self.netskope_helper._api_call_helper(
                        url=url,
                        method="post",
                        error_codes=["CRE_1043", "CRE_1046"],
                        headers=headers,
                        json=data,
                        proxies=self.proxy,
                        message=f"Error occurred while {log_msg}",
                        logger_msg=log_msg,
                    )
                    if (
                        add_tags_response.get("message", "") ==
                        ERROR_APP_DOES_NOT_EXIST
                    ):
                        err_msg = (
                            f"Error occurred while {log_message}. "
                            "Invalid Application Name/ID provided."
                        )
                        self.logger.error(f"{self.log_prefix}: {err_msg}")
                        raise NetskopeException(err_msg)
                    elif (
                        add_tags_response.get("status_code") == 400 and
                        TAG_EXISTS in add_tags_response.get("error", "")
                    ):
                        # either the tag is one of the pre-defined ones or
                        # the tag already exists;
                        # try updating the existing record
                        data["action"] = cci_tag_action
                        url = (
                            f"{tenant_name}"
                            f"{URLS.get('V2_CCI_TAG_UPDATE').format(tag)}"
                        )
                        update_tags_response = self.netskope_helper._api_call_helper(
                            url=url,
                            method="patch",
                            error_codes=["CRE_1043", "CRE_1047"],
                            headers=headers,
                            json=data,
                            proxies=self.proxy,
                            message=f"Error occurred while {log_message}",
                            logger_msg=log_message,
                        )
                        if (
                            update_tags_response.get("message", "") ==
                            ERROR_APP_DOES_NOT_EXIST
                        ):
                            error_msg = (
                                f"Error occurred while "
                                f"{log_message}. "
                                "Invalid Application Name/ID provided."
                            )
                            self.logger.error(
                                f"{self.log_prefix}: {error_msg}"
                            )
                            raise NetskopeException(error_msg)
                        elif (
                            TAG_NOT_FOUND in update_tags_response.get(
                                "error", ""
                            )
                        ):
                            error_msg = (
                                f"Error occurred while "
                                f"{log_message}. "
                                f"Tag '{tag}' does not exists."
                            )
                            self.logger.error(
                                message=f"{self.log_prefix}: {error_msg}",
                                resolution=(
                                    "Make sure provided tag exists "
                                    "on the Netskope Tenant for "
                                    "adding the tag to the application(s)."
                                )
                            )
                            raise NetskopeException(error_msg)
                        elif update_tags_response.get("status", "") != SUCCESS:
                            error_msg = (
                                "Error occurred while "
                                f"{log_message}."
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {error_msg}"
                                ),
                                details=json.dumps(update_tags_response),
                            )
                            raise NetskopeException(error_msg)
                    elif add_tags_response.get("status", "") != SUCCESS:
                        err_msg = (
                            f"Error occurred while {log_msg}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=json.dumps(add_tags_response),
                        )
                        raise NetskopeException(err_msg)
                else:
                    # For Removing the tags, tag creation should not be done
                    url = (
                        f"{tenant_name}"
                        f"{URLS.get('V2_CCI_TAG_UPDATE').format(tag)}"
                    )
                    data["action"] = cci_tag_action
                    update_tags_response = self.netskope_helper._api_call_helper(
                        url=url,
                        method="patch",
                        error_codes=["CRE_1043", "CRE_1047"],
                        headers=headers,
                        json=data,
                        proxies=self.proxy,
                        message=f"Error occurred while {log_message}",
                        logger_msg=log_message,
                    )
                    if (
                        update_tags_response.get("message", "") ==
                        ERROR_APP_DOES_NOT_EXIST
                    ):
                        error_msg = (
                            f"Error occurred while "
                            f"{log_message}. "
                            "Invalid Application Name/ID provided."
                        )
                        self.logger.error(
                            f"{self.log_prefix}: {error_msg}"
                        )
                        raise NetskopeException(error_msg)
                    elif (
                        TAG_NOT_FOUND in update_tags_response.get(
                            "error", ""
                        )
                    ):
                        error_msg = (
                            f"Error occurred while "
                            f"{log_message}. "
                            f"Tag '{tag}' does not exists."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {error_msg}",
                            resolution=(
                                "Make sure provided tag exists "
                                "on the Netskope Tenant for "
                                "removing the tag from the application(s)."
                            )
                        )
                        raise NetskopeException(error_msg)
                    elif update_tags_response.get("status", "") != SUCCESS:
                        error_msg = (
                            "Error occurred while "
                            f"{log_message}."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {error_msg}"
                            ),
                            details=json.dumps(update_tags_response),
                        )
                        raise NetskopeException(error_msg)
            except NetskopeException:
                raise
            except Exception as err:
                error_message = f"Error occurred while {log_message}."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} "
                        f"Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise NetskopeException(error_message)
            log_msg = (
                f"Successfully tagged the '{tag}' tag to "
                "the application(s) on the Netskope Tenant."
            )
            if cci_tag_action == "remove":
                log_msg = (
                    f"Successfully untagged the '{tag}' tag from "
                    "the application(s) on the Netskope Tenant."
                )
            self.logger.debug(
                f"{self.log_prefix}: {log_msg}"
            )

    def _fetch_all_tags(self):
        """Fetch all tags from Netskope tenant with pagination.
        
        Returns:
            dict: Dictionary mapping tag_name to tag_id, or None if fetch fails.
        """
        tenant_name = self.tenant.parameters.get('tenantName', '').strip().strip('/')
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }

        tag_cache = {}
        offset = 0
        total_fetched = 0

        try:
            self.logger.info(
                f"{self.log_prefix}: Fetching all tags from Netskope."
            )

            while True:
                log_message = f"fetching tags (offset: {offset}, limit: {TAG_CACHE_PAGE_SIZE})"
                self.logger.debug(f"{self.log_prefix}: {log_message.capitalize()}.")

                url = f"{tenant_name}{URLS.get('V2_DEVICE_GET_TAGS')}"
                payload = {
                    "devices": [],
                    "offset": offset,
                    "limit": TAG_CACHE_PAGE_SIZE
                }

                response = self.netskope_helper._api_call_helper(
                    url=url,
                    method="post",
                    error_codes=["CRE_1045", "CRE_1049"],
                    headers=headers,
                    json=payload,
                    proxies=self.proxy,
                    message=f"Error occurred while {log_message}",
                    logger_msg=log_message,
                )

                if not response.get("success"):
                    err_msg = (
                        "Error occurred while fetching all tags "
                        "from Netskope."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {err_msg}"
                        ),
                        details=str(response.get("error", {}))
                    )
                    raise NetskopeException(err_msg)

                data = response.get("data", {})
                tags = data.get("data", []) if data and isinstance(data, dict) else []

                for tag_info in tags:
                    if isinstance(tag_info, dict):
                        # as the Netskope API is case insensitive ,
                        # we are normalizing the tags and then storing it
                        tag_name = tag_info.get("name").lower()
                        tag_id = tag_info.get("id")
                        if tag_name and tag_id:
                            tag_cache[tag_name] = tag_id

                total_fetched += len(tags)

                total_count = data.get("total_count", 0)
                self.logger.debug(
                    f"{self.log_prefix}: Fetched {len(tags)} tag(s) in current page. "
                    f"Total fetched: {total_fetched}/{total_count}."
                )

                if total_fetched >= total_count or len(tags) < TAG_CACHE_PAGE_SIZE:
                    break

                offset += TAG_CACHE_PAGE_SIZE

            self.logger.info(
                f"{self.log_prefix}: Successfully fetched {len(tag_cache)} tag(s)"
                " from Netskope tenant"
            )
            return tag_cache

        except Exception as e:
            err_msg = (
                "An Unexpected error occurred while "
                "fetching all tags from Netskope."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {e}"
                ),
                details=str(traceback.format_exc())
            )
            raise NetskopeException(err_msg)

    def _query_and_create_tags_with_cache(
        self,
        tags: list[str],
        action: str,
        tag_cache: dict = None
    ):
        """Query for tags using cache and create them if they don't exist.

        Args:
            tags (list[str]): List of tags to query and create.
            action (str): Action type - 'append', 'remove', or 'replace'.
            tag_cache (dict): Cache mapping tag_name to tag_id.

        Returns:
            tuple: (tag_ids list[str], updated_tag_cache dict)

        Raises:
            NetskopeException: If any tag creation/validation fails.
        """
        tenant_name = self.tenant.parameters.get('tenantName', '').strip().strip('/')
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }

        tag_ids = []
        updated_cache = tag_cache.copy()
        failed_tags = []
        non_empty_tags_list = []
        for tag in tags:
            if not tag:
                continue
            else:
                non_empty_tags_list.append(tag)

            if not re.match(REGEX_TAG, tag):
                err_msg = (
                    f"Invalid tag '{tag}' provided. Tag name must contain "
                    "only alphanumeric characters, hyphens, and spaces. This"
                    f" tag will be skipped for {str(action)} action"
                )
                self.logger.info(f"{self.log_prefix}: {err_msg}.")
                failed_tags.append(tag)
                continue

            if len(tag) > TAG_DEVICE_TAG_LENGTH:
                err_msg = (
                    f"Invalid tag '{tag}' provided. Tag length cannot "
                    f"exceed {TAG_DEVICE_TAG_LENGTH} characters. This"
                    f"tag will be skipped for {str(action)} action"
                )
                self.logger.info(f"{self.log_prefix}: {err_msg}.")
                failed_tags.append(tag)
                continue

            normalized_tag = tag.lower()
            if normalized_tag in updated_cache:
                tag_ids.append(updated_cache[normalized_tag])
                self.logger.debug(
                    f"{self.log_prefix}: Tag '{tag}' found in tag lookup"
                    f" list with ID '{updated_cache[normalized_tag]}'."
                )
            elif action in ["append", "replace"]:
                log_message = f"creating tag '{tag}'"
                self.logger.debug(
                    f"{self.log_prefix}: {_capitalize_first(log_message)}."
                )

                try:
                    url = f"{tenant_name}{URLS.get('V2_DEVICE_TAG')}"
                    create_response = self.netskope_helper._api_call_helper(
                        url=url,
                        method="post",
                        error_codes=["CRE_1045", "CRE_1049"],
                        headers=headers,
                        json={"name": tag, "description": "Tag created by Cloud Exchange"},
                        proxies=self.proxy,
                        message=f"Error occurred while {log_message}",
                        logger_msg=log_message,
                    )

                    if not create_response.get("success"):
                        err_msg = (
                            f"Error occurred while {log_message}. This"
                            f"tag will be skipped for {str(action)} action"
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}.",
                            details=json.dumps(create_response.get("error", {}))
                        )
                        failed_tags.append(tag)
                    elif tag_info := create_response.get("data", {}):
                        tag_id = tag_info.get("id")
                        if tag_id:
                            tag_ids.append(tag_id)
                            updated_cache[normalized_tag] = tag_id
                            self.logger.debug(
                                f"{self.log_prefix}: Successfully created "
                                f"tag '{tag}' with ID '{tag_id}'."
                            )
                        else:
                            failed_tags.append(tag)
                    else:
                        failed_tags.append(tag)
                except Exception:
                    failed_tags.append(tag)
            elif action == "remove":
                err_msg = (
                    f"Provided tag '{tag}' not found on Netskope "
                    "when trying to untag device. "
                    "Please provide valid tags."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}"
                )
                failed_tags.append(tag)

        if failed_tags:
            msg = (
                f"Failed to process {len(failed_tags)} tag(s) either "
                "due to being invalid or of unsupported type for "
                f"{action} action. Following tag(s) {failed_tags} will be "
                "skipped."
            )
            self.logger.info(
                f"{self.log_prefix}: {msg}"
            )

        if not tag_ids:
            if action == "replace" and not non_empty_tags_list:
                self.logger.debug(
                    f"{self.log_prefix}: No tags provided for "
                    "replace action. All tags will be removed from "
                    "the device(s)."
                )
                return tag_ids, updated_cache
            else:
                err_msg = (
                    f"No tag ids found for {str(tags)} tag(s) to"
                    f" perform {action} tag(s) action on Device(s)."
                )
                raise NetskopeException(err_msg)

        return tag_ids, updated_cache

    def _get_tag_id(
        self,
        tag_name: str,
        response: dict
    ):
        """Check Tag Query Response for given tag

        Args:
            tag_name str: tag name to search for in response
            response dict: Response received from Netskope
        
        Returns:
            tag_id str: tag id if it exists, else None
        """
        if not response.get("success"):
            return None
        data = response.get("data", {}).get("data", [])
        try:
            for tag_info in data:
                if tag_info.get("name").lower() == tag_name.lower():
                    return tag_info.get("id")
        except Exception:
            pass
        return None

    def _tag_devices(
        self,
        tag_ids: list[str],
        devices: list[dict],
        cci_tag_action: str
    ):
        """Tag the device(s) on Netskope.

        Args:
            tags (list[str]): List of tags to be attached to \
                the device(s).
            device_ids (list[str]): List of device IDs to be tagged.
            device_user_keys (list[str]): List of device user keys to be tagged.
            cci_tag_action (str): Action to be performed on the tags.
        """
        tenant_name = (
            self.tenant.parameters.get('tenantName', '').strip()
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }

        if cci_tag_action == "append":
            log_message = "adding tags to devices"
            url = f"{tenant_name}{URLS.get('V2_DEVICE_BULK_ADD_TAGS')}"
        else:  # remove
            log_message = "removing tags from devices"
            url = f"{tenant_name}{URLS.get('V2_DEVICE_BULK_REMOVE_TAGS')}"

        data = {"tags": tag_ids, "devices": devices}

        self.logger.debug(f"{self.log_prefix}: {log_message.capitalize()}.")
        response = self.netskope_helper._api_call_helper(
            url=url,
            method="post",
            error_codes=["CRE_1045", "CRE_1049"],
            headers=headers,
            json=data,
            proxies=self.proxy,
            message=f"Error occurred while {log_message}",
            logger_msg=log_message,
        )
        if not response.get("success"):
            err_msg = f"Error occurred while {log_message}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=json.dumps(response),
            )
            raise NetskopeException(err_msg)

        log_msg = (
            f"Successfully {'added' if cci_tag_action == 'append' else 'removed'} "     # noqa
            f"tags for {len(devices)} device record(s) on the Netskope Tenant."
        )
        self.logger.debug(
            f"{self.log_prefix}: {log_msg}"
        )

    def _replace_device_tags(
        self,
        tag_ids: list[int],
        devices: list[dict],
    ):
        """Replace all tags on devices with the provided tags.

        Args:
            tag_ids (list[int]): List of tag IDs to replace on the devices.
            devices (list[dict]): List of device dicts with nsdeviceuid and
                userkey.
        """
        tenant_name = (
            self.tenant.parameters.get('tenantName', '').strip().strip('/')
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }

        log_message = f"replacing tags on {len(devices)} device record(s)"
        url = f"{tenant_name}{URLS.get('V2_DEVICE_BULK_REPLACE_TAGS')}"

        data = {"tags": tag_ids, "devices": devices}

        self.logger.debug(f"{self.log_prefix}: {log_message.capitalize()}.")
        response = self.netskope_helper._api_call_helper(
            url=url,
            method="post",
            error_codes=["CRE_1045", "CRE_1049"],
            headers=headers,
            json=data,
            proxies=self.proxy,
            message=f"Error occurred while {log_message}",
            logger_msg=log_message,
        )
        if not response.get("success"):
            err_msg = f"Error occurred while {log_message}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=json.dumps(response),
            )
            raise NetskopeException(err_msg)

        self.logger.debug(
            f"{self.log_prefix}: Successfully replaced tags for "
            f"{len(devices)} device record(s) on the Netskope Tenant."
        )

    def _create_app_instance(
        self,
        instance_id: str,
        instance_name: str,
        app: str,
        tags: list[str],
        auth_token: str,
    ):
        """Create an app instance.

        Args:
            instance_id (str): Instance ID.
            instance_name (str): Instance name.
            app (str): App name.
            tags (str): Tag.
            auth_token (str): Auth token.
        """
        tenant_name = (
            self.tenant.parameters.get('tenantName', '').strip()
        )
        url = (
            f"{tenant_name}{URLS.get('V1_APP_INSTANCE')}"
        )
        params = {
            "op": "list",
            "app": app,
            "instance_id": instance_id,
            "instance_name": instance_name,
        }
        logger_msg = f"listing app instances for application: {app}"
        try:
            list_instances_response = self.netskope_helper._api_call_helper(
                url=url,
                method="post",
                error_codes=["CRE_1045", "CRE_1049"],
                params=params,
                data={"token": auth_token},
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
            )
            if (
                list_instances_response.get("status", "").lower() !=
                SUCCESS.lower()
            ):
                err_msg = (
                    f"Error occurred while {logger_msg}"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg}."
                    ),
                    details=json.dumps(list_instances_response),
                )
                raise NetskopeException(err_msg)
            if len(list_instances_response.get("data", [])):
                op = "update"
            else:
                op = "add"
            params = {"op": op}
            url = (
                f"{tenant_name}{URLS.get('V1_APP_INSTANCE')}"
            )
            custom_message = (
                f"{'updating' if op == 'update' else 'adding'} app instance"
            )
            data = {
                "instances": [
                    {
                        "instance_id": instance_id,
                        "instance_name": instance_name,
                        "app": app,
                        "tags": tags,
                    }
                ],
                "token": auth_token,
            }
            create_instances_response = self.netskope_helper._api_call_helper(
                url=url,
                method="post",
                error_codes=["CRE_1044", "CRE_1048"],
                params=params,
                json=data,
                proxies=self.proxy,
                message=(
                    f"Error occurred while {custom_message} on "
                    "the Netskope Tenant"
                ),
                logger_msg=custom_message,
            )
            if create_instances_response.get("errors", []):
                if len(create_instances_response.get("errors", [])) > 0:
                    errs = ", ".join(
                        create_instances_response.get("errors", [])
                    )
                    err_msg = (
                        f"Error occurred while {custom_message} "
                        "app instance on the Netskope Tenant."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} ",
                        details=errs,
                    )
                    raise NetskopeException(err_msg)
            elif (
                create_instances_response.get("status", "").lower() !=
                SUCCESS.lower()
            ):
                err_msg = (
                    f"Error occurred while {custom_message} on "
                    "the Netskope Tenant."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg}"
                    ),
                    details=json.dumps(create_instances_response),
                )
                raise NetskopeException(err_msg)
        except NetskopeException:
            raise
        except Exception as err:
            error_message = (
                f"Error occurred while {custom_message} on "
                "the Netskope Tenant."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)

    def _process_params_for_app_instance_action(
        self, params: dict
    ) -> tuple[str, str, str, list[str]]:
        """Process parameters for app instance action.

        Args:
            params (dict): Params dictionary.

        Returns:
            tuple[str, str, str, list[str]]: Processed params.
        """
        tag = str(params.get("tag") or "")
        skip_tag_validation = isinstance(tag, str) and tag.startswith("$")
        instance_id = str(params.get("instance_id") or "")
        skip_instance_id_validation = isinstance(
            instance_id, str
        ) and instance_id.startswith("$")
        instance_name = str(params.get("instance_name") or "")
        skip_instance_name_validation = isinstance(
            instance_name, str
        ) and instance_name.startswith("$")
        app_name = str(params.get("app_name") or "")
        skip_app_name_validation = isinstance(
            app_name, str
        ) and app_name.startswith("$")

        if (
            tag.strip() not in ["Unsanctioned", "Sanctioned", "None", ""]
        ):
            raise NetskopeException(
                "Invalid value for Tag provided. It must be empty or one of "
                "the following: None, Sanctioned, Unsanctioned."
            )

        if not skip_app_name_validation and not app_name.strip():
            raise NetskopeException(
                "Empty value for Application Name provided."
            )

        if not skip_instance_name_validation and not instance_name.strip():
            raise NetskopeException("Empty value for Instance Name provided.")

        if not skip_instance_id_validation and not instance_id.strip():
            raise NetskopeException("Empty value for Instance ID provided.")

        if tag.strip() in ["Sanctioned", "Unsanctioned"]:
            tags = [tag.strip()]
        else:
            tags = []

        instance_id = instance_id.strip()
        instance_name = instance_name.strip()
        app_name = app_name.strip()

        return (
            instance_id,
            instance_name,
            app_name,
            tags,
        )

    def _process_params_for_impact_action(
        self, params: dict
    ) -> tuple[str, str, str, str]:
        """Process parameters for impact action.

        Args:
            params (dict): Params dictionary.

        Returns:
            tuple[str, str, str, str]: Processed params.
        """
        user = str(params.get("user") or "")
        score = params.get("score")
        source = str(params.get("source") or "")
        reason = str(params.get("reason") or "")

        skip_user_validation = isinstance(user, str) and user.startswith("$")
        skip_score_validation = isinstance(score, str) and score.startswith(
            "$"
        )
        skip_source_validation = isinstance(source, str) and source.startswith(
            "$"
        )
        skip_reason_validation = isinstance(reason, str) and reason.startswith(
            "$"
        )

        if not skip_user_validation:
            user = user.strip()
            if len(user.split(",")) > 1:
                err_msg = (
                    "Invalid value for User Email provided. "
                    "Multiple comma separated emails are not allowed."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide a valid User Email. "
                        "Multiple comma separated emails are not allowed."
                    )
                )
                raise NetskopeException(err_msg)
            if not re.match(REGEX_EMAIL, user):
                err_msg = (
                    "Invalid value for User Email provided. "
                    "It must be a valid email address."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide a valid User Email."
                    )
                )
                raise NetskopeException(err_msg)

        if not skip_score_validation:
            try:
                score = int(score)
            except Exception:
                err_msg = (
                    "Invalid value for Score (Reduction) provided. "
                    "It must be an integer."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide a valid integer value for Score (Reduction)."
                    )
                )
                raise NetskopeException(err_msg)
            if not 1 <= score <= 1000:
                err_msg = (
                    "Invalid value for Score (Reduction) provided. "
                    "It must be between 1 and 1000."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide a valid integer value for Score (Reduction) "
                        "between 1 and 1000."
                    )
                )
                raise NetskopeException(err_msg)

        if not skip_source_validation:
            source = source.strip()
            if not source:
                err_msg = (
                    "Invalid value for Source provided. It must not be empty."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide a valid Source for the "
                        "Update UCI Score action."
                    )
                )
                raise NetskopeException(err_msg)

        if not skip_reason_validation:
            reason = reason.strip()
            if not reason:
                err_msg = (
                    "Invalid value for Reason provided. It must not be empty."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide a valid Reason for the "
                        "Update UCI Score action."
                    )
                )
                raise NetskopeException(err_msg)

        return (
            user,
            score,
            source,
            reason,
        )

    def _process_params_for_reset_action(
        self, params: dict,
        bulk_action: bool = False,
    ) -> list[str]:
        """Process parameters for reset action.

        Args:
            params (dict): Params dictionary.

        Returns:
            list[str]: Processed params.
        """
        user = str(params.get("user") or "")
        skip_user_validation = isinstance(user, str) and user.startswith("$")
        skipped_user_count = 0
        valid_users = []
        if not skip_user_validation:
            users = user.split(",")
            for user in users:
                user = user.strip()
                if not re.match(REGEX_EMAIL, user):
                    if bulk_action:
                        skipped_user_count += 1
                        continue
                    err_msg = (
                        f"Invalid User Email '{user}' provided. "
                        "It must be a valid email address."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Provide a valid User Email."
                        )
                    )
                    raise NetskopeException(err_msg)
                valid_users.append(user)

        return valid_users, skipped_user_count

    def _process_params_for_add_tag_action(
        self,
        params: dict,
        is_execute: bool = False
    ) -> tuple:
        """Process parameters for add tag action.

        Args:
            params (dict): Params dictionary.

        Returns:
            tuple: Processed params.
        """

        def convert_to_list(value: Union[str, list[str]]) -> list[str]:
            """Convert to list.

            Args:
                value (Union[str, list[str]]): Value to be converted.

            Returns:
                list[str]: List of values.
            """
            if isinstance(value, list):
                return value
            if isinstance(value, str):
                return list(
                    filter(
                        lambda x: len(x) != 0,
                        map(lambda x: x.strip(), value.split(",")),
                    )
                )
            return []

        tags = params.get("tags") or ""
        skip_tag_validation = isinstance(tags, str) and tags.startswith("$")
        tags = convert_to_list(tags)
        apps = params.get("apps") or ""
        skip_apps_validation = isinstance(apps, str) and apps.startswith("$")
        apps = convert_to_list(apps)
        ids = params.get("ids") or ""
        skip_ids_validation = isinstance(ids, str) and ids.startswith("$")
        ids = convert_to_list(ids)

        tag_action = params.get("tag_action") or "append"
        if isinstance(tag_action, str) and tag_action.startswith("$"):
            err_msg = (
                "Select Tag Action "
                "from Static field dropdown only."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Select Tag Action "
                    "from Static field dropdown only."
                )
            )
            raise NetskopeException(err_msg)
        if tag_action not in ["append", "remove"]:
            err_msg = (
                "Invalid value for Tag Action provided. "
                "It must be either 'Add' or 'Remove'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Select 'Add' or 'Remove' for Tag Action "
                    "from Static field dropdown."
                )
            )
            raise NetskopeException(err_msg)

        if not tags and not skip_tag_validation:
            err_msg = (
                "Invalid value for tags provided. Tags can not be empty."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Provide valid Tags for the action. "
                    "Empty Tags are not allowed."
                )
            )
            raise NetskopeException(err_msg)

        if not skip_tag_validation and not is_execute:
            for tag in tags:
                tag = tag.strip()
                if len(tag) > TAG_APP_TAG_LENGTH:
                    err_msg = (
                        "Invalid value for Tags provided. "
                        "Each tag length can not exceed "
                        f"{TAG_APP_TAG_LENGTH} characters."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Provide each tag of length "
                            "less than or equal to "
                            f"{TAG_APP_TAG_LENGTH} characters."
                        )
                    )
                    raise NetskopeException(err_msg)

        if (not apps and not ids) and not (
            skip_apps_validation or skip_ids_validation
        ):
            err_msg = (
                "Invalid value for Application Names/IDs provided. "
                "Application Names and IDs can not be empty."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Provide valid Application Names or IDs for the action. "
                    "Empty Application Names and IDs are not allowed."
                )
            )
            raise NetskopeException(err_msg)

        if apps and ids:
            err_msg = (
                "Invalid value for Application Names/IDs provided. "
                "Application Names and IDs both can not be "
                "provided at the same time."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Provide either of valid Application Names "
                    "or IDs for the Tag/Untag Application action."
                )
            )
            raise NetskopeException(err_msg)

        try:
            ids = list(map(int, ids))
        except ValueError as ex:
            if not skip_ids_validation:
                err_msg = (
                    "Invalid value for Application IDs provided. "
                    "One of the ID is not a valid integer."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide valid Application IDs in integer format."
                    )
                )
                raise NetskopeException(err_msg) from ex

        return tags, apps, ids, tag_action

    def _process_params_for_tag_device_action(
        self,
        params: dict,
        is_execute: bool = False,
        is_validation: bool = False
    ) -> tuple:
        """Process parameters for tag device action.

        Args:
            params (dict): Params dictionary.

        Returns:
            tuple: Processed params.
        """

        def convert_to_list(
            value: Union[str, list[str]],
            static_input_len_validation: bool = False,
            field_name: str = "",
            is_validation: bool = False,
            action_name: str = "",
            action_label: str = ""
        ) -> list[str]:
            """Convert to list.

            Args:
                value (Union[str, list[str]]): Value to be converted.

            Returns:
                list[str]: List of values.
            """
            list_values = []
            if isinstance(value, list):
                list_values = value
            if isinstance(value, str):
                list_values = [v.strip() for v in value.split(",")]
                if (
                    is_validation and any(not v for v in list_values)
                ):
                    log_and_raise = False
                    if (
                        action_name == "replace" and len(list_values) > 1
                    ) or action_name != "replace":
                        log_and_raise = True

                    if log_and_raise:
                        if (len(list_values) == 1) and (not list_values[0]):
                            err_msg = (
                                f"Invalid value for tags provided. Tags cannot be empty for "
                                f"'{action_label}' action."
                            )
                        else:
                            err_msg = (
                                f"Static field '{field_name}' "
                                "can not have empty comma separated values."
                            )
                        raise NetskopeException(err_msg)
                if is_validation and static_input_len_validation and len(list_values) > 1:
                    err_msg = (
                        f"Static field '{field_name}'"
                        "can not have multiple comma separated values."
                    )
                    raise NetskopeException(err_msg)
            return list_values

        tags = params.get("tags") or ""
        tag_action = params.get("tag_device_action") or "append"
        tag_action_label = TAG_ACTION_LABEL_MAP.get(tag_action, "Replace")
        skip_tag_validation = isinstance(tags, str) and tags.startswith("$")
        tags = convert_to_list(
            action_name=tag_action,
            value=tags,
            field_name="Tags",
            is_validation=is_validation,
            action_label=tag_action_label
        )

        device_id = params.get("device_id") or ""
        skip_device_id_validation = isinstance(device_id, str) and device_id.startswith("$")
        convert_to_list(
            value=device_id,
            static_input_len_validation=True,
            field_name="Netskope Device UID",
            is_validation=is_validation
        )

        device_user_key = params.get("device_user_key") or ""
        skip_device_user_key_validation = isinstance(device_user_key, str) and device_user_key.startswith("$")
        device_user_key = convert_to_list(
            value=device_user_key,
            field_name="User Key",
            is_validation=is_validation
        )

        hostname = params.get("hostname") or ""
        skip_hostname_validation = isinstance(hostname, str) and hostname.startswith("$")   # noqa
        convert_to_list(
            value=hostname,
            field_name="Hostname",
            static_input_len_validation=True,
            is_validation=is_validation
        )

        if isinstance(tag_action, str) and tag_action.startswith("$"):
            err_msg = (
                "Select Tag Action "
                "from Static field dropdown only."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise NetskopeException(err_msg)
        if tag_action not in ["append", "remove", "replace"]:
            err_msg = (
                "Invalid value for Tag Action provided. "
                "It must be either 'Add', 'Remove', or 'Replace'."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise NetskopeException(err_msg)
        if not tags and not skip_tag_validation and tag_action in ["append", "remove"]:
            err_msg = (
                f"Invalid value for tags provided. Tags cannot be empty for "
                f"'{tag_action_label}' action."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise NetskopeException(err_msg)

        if not skip_tag_validation and not is_execute:
            for tag in tags:
                if not re.match(REGEX_TAG, tag):
                    err_msg = (
                        "Invalid value for Tags provided. "
                        "Tag name must contain only alphanumeric characters, hyphens, and spaces."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    raise NetskopeException(err_msg)
                if len(tag) > TAG_DEVICE_TAG_LENGTH:
                    err_msg = (
                        "Invalid value for Tags provided. "
                        "Each tag length can not exceed "
                        f"{TAG_DEVICE_TAG_LENGTH} characters."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    raise NetskopeException(err_msg)

        if not device_id and not skip_device_id_validation:
            err_msg = (
                "Netskope Device UID is a required parameter "
                f"for {tag_action_label} action."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise NetskopeException(err_msg)
        if not device_user_key and not skip_device_user_key_validation:
            err_msg = (
                "User Key is a required parameter "
                f"for {tag_action_label} action."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise NetskopeException(err_msg)
        if not hostname and not skip_hostname_validation:
            err_msg = (
                "Hostname is a required parameter "
                f"for {tag_action_label} action."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise NetskopeException(err_msg)

        return tags, device_id, device_user_key, hostname, tag_action

    def revert_action(self, action: Action):
        """Revert an action for a single excluded record.

        The framework calls this once per record that no longer matches the
        business rule. For the 'Add host to Private App' action this removes
        that record's host(s) from the private app group in place: the
        host(s) are dropped from whichever group member(s) contain them, and
        the record's tags are stripped from those member(s) too.

        Removal is in place - hosts are never moved between apps here (the
        bulk sync's compaction pass reclaims any apps a revert leaves
        partially filled). A member left with no hosts is deleted when it is
        a roll-over sibling, or reset to the Default Host when it is the base
        app (a private app must keep at least one host); when no Default Host
        is configured the emptied base app is deleted instead.

        Args:
            action (Action): Action to be reverted (carries the record's
                resolved parameters).

        Raises:
            NotImplementedError: For action types that do not support a
                per-record revert.
            NetskopeException: On an unrecoverable error while removing the
                host(s).
        """
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        # Mirror execute_action: keep the multi-value fields intact so the
        # full set of the record's hosts (and its tags) is available rather
        # than collapsed to a single latest value.
        action.parameters = get_latest_values(
            action.parameters,
            exclude_keys=["host", "tags", "protocol", "publishers"],
        )
        if action.value != "private_app":
            raise NotImplementedError(
                f"Revert action is not supported for '{action.value}' "
                "action in Netskope Risk Exchange plugin."
            )
        tenant_name = self.tenant.parameters.get("tenantName", "").strip()
        existing_private_app_name = action.parameters.get(
            "private_app_name", ""
        )
        new_private_app_name = action.parameters.get("name", "")
        if existing_private_app_name == "create":
            base_name = new_private_app_name
        else:
            base_name = existing_private_app_name.removeprefix(
                "["
            ).removesuffix("]")
        private_app_name = f"[{base_name}]"
        try:
            # Normalise the record's host(s) to remove - a Source field (a
            # list) or a Static field (a comma-separated string) - via the
            # shared _normalize_csv_values helper (trims, drops empties,
            # de-duplicates), as execute_actions and the profile actions do.
            hosts_to_remove = set(
                self.netskope_helper._normalize_csv_values(
                    action.parameters.get("host")
                )
            )
            if not hosts_to_remove:
                self.logger.info(
                    f"{self.log_prefix}: No host found in the record for "
                    f"private app '{private_app_name}'; hence skipping the "
                    "revert action."
                )
                return
            # Short-circuit: a host that fails the same validation used by the
            # add-host action could never have been added to the app, so
            # fetching the app to remove it would be a wasted API call. Keep
            # only the valid hosts; if none are valid, skip before the
            # fetch-apps call below.
            valid_hosts, _, _ = (
                self.netskope_helper.validate_hosts_for_private_app(
                    hosts_to_push=list(hosts_to_remove),
                    private_app_name=private_app_name,
                )
            )
            if not valid_hosts:
                self.logger.info(
                    f"{self.log_prefix}: No valid host found in the reverted "
                    f"record for private app '{private_app_name}'; hence "
                    "skipping the revert action for this record."
                )
                return
            hosts_to_remove = set(valid_hosts)
            # Resolve the record's tags so they can be stripped from the
            # member(s) the host(s) are removed from.
            raw_tags = action.parameters.get("tags") or []
            if isinstance(raw_tags, str):
                raw_tags = [
                    tag.strip()
                    for tag in raw_tags.split(",")
                    if tag.strip()
                ]
            record_valid_tags, _, _ = (
                self.netskope_helper.validate_tags_for_private_app(
                    raw_tags, private_app_name
                )
            )
            record_tag_names = {
                tag["tag_name"] for tag in record_valid_tags
            }
            self.logger.info(
                f"{self.log_prefix}: Attempting to remove "
                f"{len(hosts_to_remove)} host(s) of the reverted record from "
                f"private app '{private_app_name}'."
            )
            existing_private_apps = self._get_private_apps(
                get_hosts_of=private_app_name
            )
            members = self.netskope_helper._ordered_private_app_group(
                existing_private_apps, base_name
            )
            if not members:
                self.logger.info(
                    f"{self.log_prefix}: No private app with the name "
                    f"'{private_app_name}' was found on the Netskope Tenant; "
                    "hence skipping the revert action."
                )
                return
            # Resolve the metadata once so the host-removal PATCH keeps the
            # app's ports/publishers/DNS aligned (and does not wipe them).
            tcp_port = action.parameters.get("tcp_ports", "") or ""
            udp_port = action.parameters.get("udp_ports", "") or ""
            protocols_list = (
                self.netskope_helper._build_private_app_protocols(
                    action.parameters.get("protocol", []),
                    [p.strip() for p in tcp_port.split(",") if p.strip()],
                    [p.strip() for p in udp_port.split(",") if p.strip()],
                )
            )
            publishers_list = self._resolve_private_app_publishers(
                action.parameters.get("publishers", []), private_app_name
            )
            use_publisher_dns = action.parameters.get(
                "use_publisher_dns", False
            )
            default_url = action.parameters.get("default_url", "").strip()
            removed_hosts = set()
            for member in members:
                remaining = [
                    host
                    for host in member["hosts"]
                    if host not in hosts_to_remove
                ]
                if len(remaining) == len(member["hosts"]):
                    # This member held none of the reverted host(s).
                    continue
                removed_hosts.update(
                    host
                    for host in member["hosts"]
                    if host in hosts_to_remove
                )
                # Strip the reverted record's tags from this member (a tag
                # also contributed by a still-active record may be removed -
                # documented known behavior).
                new_tag_names = [
                    tag
                    for tag in member["tags"]
                    if tag not in record_tag_names
                ]
                if remaining:
                    data = {
                        "host": ",".join(remaining),
                        "tags": [
                            {"tag_name": name}
                            for name in sorted(new_tag_names)
                        ],
                        "publishers": publishers_list,
                        "use_publisher_dns": use_publisher_dns,
                    }
                    if protocols_list:
                        data["protocols"] = protocols_list
                    self._patch_private_app(
                        tenant_name, member["id"], data, member["name"]
                    )
                elif member["number"] != 1:
                    # Emptied roll-over sibling: delete it (reset to the
                    # Default Host if the delete is rejected).
                    self._remove_surplus_private_app(
                        tenant_name,
                        member,
                        publishers_list,
                        use_publisher_dns,
                        protocols_list,
                        default_url,
                    )
                elif default_url:
                    # Emptied base app: a private app must keep at least one
                    # host, so reset it to the Default Host placeholder.
                    self.logger.info(
                        f"{self.log_prefix}: Removing the last host(s) from "
                        f"the base private app '{member['name']}'; resetting "
                        f"it to the Default Host '{default_url}'."
                    )
                    reset_body = {
                        "host": default_url,
                        "tags": [
                            {"tag_name": name}
                            for name in sorted(new_tag_names)
                        ],
                        "publishers": publishers_list,
                        "use_publisher_dns": use_publisher_dns,
                    }
                    if protocols_list:
                        reset_body["protocols"] = protocols_list
                    self._patch_private_app(
                        tenant_name,
                        member["id"],
                        reset_body,
                        member["name"],
                    )
                else:
                    # Base app emptied and no Default Host configured - it
                    # cannot be reset to an empty host list, so delete it.
                    self.logger.info(
                        f"{self.log_prefix}: Removing the last host(s) from "
                        f"the base private app '{member['name']}' with no "
                        "Default Host configured; hence deleting the app."
                    )
                    self._delete_private_app(
                        tenant_name, member["id"], member["name"]
                    )
            if not removed_hosts:
                self.logger.info(
                    f"{self.log_prefix}: None of the reverted record's "
                    f"host(s) were found in private app '{private_app_name}'; "
                    "hence nothing was removed."
                )
                return
            self.logger.info(
                f"{self.log_prefix}: Successfully removed "
                f"{len(removed_hosts)} host(s) of the reverted record from "
                f"private app '{private_app_name}'."
            )
        except NetskopeException:
            raise
        except Exception as err:
            error_message = (
                "Error occurred while removing the reverted record's "
                f"host(s) from private app '{private_app_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message} Error: {err}",
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)

    def _patch_private_app(
        self, tenant: str, app_id: str, data: dict, app_name: str = ""
    ):
        """Patch an existing private app.

        Args:
            tenant (str): Tenant base URL.
            app_id (str): Existing app id.
            data (dict): Request body.
            app_name (str, optional): Name of the private app being \
                patched, included in log messages for context. Defaults \
                to "".

        Raises:
            NetskopeException: Error in the response.
            NetskopeException: Non-2xx status code.
        """
        logger_msg = (
            f"adding host to private app '{app_name}'"
            if app_name
            else "adding host to private app"
        )
        self.logger.debug(
            f"{self.log_prefix}: {_capitalize_first(logger_msg)}."
        )
        url = (
            f"{tenant}{URLS.get('V2_PRIVATE_APP_PATCH').format(app_id)}"
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        try:
            append_privateapp_response = self.netskope_helper._api_call_helper(
                url=url,
                method="patch",
                error_codes=["CRE_1045", "CRE_1046"],
                headers=headers,
                json=data,
                proxies=self.proxy,
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg,
                is_handle_error_required=False
            )
            if append_privateapp_response.status_code not in [
                200,
                201,
            ]:
                err_msg = (
                    f"Error occurred while {logger_msg}. "
                )
                self.logger.error(
                    message=err_msg,
                    details=str(append_privateapp_response.text),
                )
                raise NetskopeException(
                    "Could not share host."
                )

            append_privateapp_response = handle_status_code(
                append_privateapp_response,
                error_code="CRE_1046",
                custom_message=f"Error occurred while {logger_msg}",
                plugin=self.log_prefix,
                notify=False,
                log=True,
            )
            if append_privateapp_response.get("status", "") != "success":
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"{logger_msg}."
                    ),
                    details=repr(append_privateapp_response),
                )
                raise NetskopeException(
                    "Could not add host to private app."
                )

            self.logger.info(
                f"{self.log_prefix}: Successfully updated the private app"
                f" {app_name}."
            )
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
            )
            raise NetskopeException(error_message)
        return

    def _execute_private_app_action(
        self,
        action_dict: dict,
        host_to_tags: Optional[dict] = None,
        compact: bool = False,
    ):
        """Execute action on the given parameters.

        Args:
            action_dict (dict): Action parameters.
            host_to_tags (Optional[dict]): Pre-built ``{host -> set(tag
                name)}`` map for per-batch tag scoping (bulk path). When
                None, tags are taken uniformly from ``action_dict``.
            compact (bool): When True (bulk sync), consolidate the app group
                after the append to reclaim apps left partially filled by
                earlier reverts. Defaults to False.

        Returns:
            tuple[set[str], dict[str, int]]: ``(not_placed, added_counts)``
                forwarded from ``_push_private_app`` - the not-placed host
                set and the per-app added-host counts.
        """
        protocols = action_dict.get("protocol", [])
        tcp_port = action_dict.get("tcp_ports", "") or ""
        tcp_port_list = [
            port.strip() for port in tcp_port.split(",") if port.strip()
        ]
        udp_port = action_dict.get("udp_ports", "") or ""
        udp_port_list = [
            port.strip() for port in udp_port.split(",") if port.strip()
        ]
        use_publisher_dns = action_dict.get("use_publisher_dns", False)
        if not action_dict.get("host", ""):
            err_msg = (
                "Empty Host found in the record. "
                "Host can not be empty."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Make sure Host field in records "
                    "is not empty."
                )
            )
            raise NetskopeException(err_msg)
        tags = action_dict.get("tags", [])
        if tags and isinstance(tags, str):
            tags = [tag.strip() for tag in tags.split(",")]
        # Tag length/format validation happens inside _push_private_app via
        # validate_tags_for_private_app: invalid tags (empty or exceeding the
        # maximum length) are skipped and the remaining valid tags are still
        # pushed. Static tags are already validated at save time.

        return self._push_private_app(
            action_dict.get("host", ""),
            existing_private_app_name=action_dict.get("private_app_name", ""),
            new_private_app_name=action_dict.get("name", ""),
            protocol_type=protocols,
            tcp_ports=tcp_port_list,
            udp_ports=udp_port_list,
            publishers=action_dict.get("publishers", []),
            use_publisher_dns=use_publisher_dns,
            default_url=action_dict.get("default_url", "").strip(),
            tags=tags,
            skip_excess_hosts=action_dict.get("skip_excess_hosts", False),
            host_to_tags=host_to_tags,
            compact=compact,
        )

    def revert_uci_update_impact(self, anomaly_id: str):
        """Revert the UCI update impact using the anomaly id."""
        url = (
            f"{self.tenant.parameters.get('tenantName', '').strip()}"
            f"{URLS.get('V2_REVERT_UCI_IMPACT')}".format(anomaly_id)
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        data = {
            "reason": "Marking as Allowed from Netskope CE",
        }
        logger_msg = f"marking the anomaly ID {anomaly_id} as allowed"
        try:
            self.netskope_helper._api_call_helper(
                url=url,
                method="post",
                json=data,
                headers=headers,
                proxies=self.proxy,
                error_codes=["CRE_1028", "CRE_1029"],
                message=f"Error occurred while {logger_msg}",
                logger_msg=logger_msg
            )
        except NetskopeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)

    def _bulk_add_remove_tag_device(
            self, actions: List[Action], action_label: str
    ) -> List[str]:
        """Tag devices in bulk.

        Args:
            actions (List[Action]): List of actions.
            action_label (str): Action label.
        
        Returns:
            List[str]: List of failed action IDs.
        """

        try:
            failed_action_ids = []
            tag_groups = {}
            tag_cache = self._fetch_all_tags()
            action_value = (
                actions[0].get("params").parameters.get("tag_device_action")
            )
            action_value = "Add" if action_value == "append" else "Remove"
            device_bulk_call_count = 0
            for action_dict in actions:
                action_id, action = action_dict.get("id"), action_dict.get("params")
                try:
                    (
                        tags,
                        device_id,
                        device_user_key,
                        hostname,
                        cci_tag_action,
                    ) = self._process_params_for_tag_device_action(
                        action.parameters, True
                    )

                    user_keys = device_user_key
                    action_value = "Add" if cci_tag_action == "append" else "Remove"
                    if isinstance(device_user_key, str):
                        user_keys = [device_user_key] if device_user_key else []
                    elif not isinstance(device_user_key, list):
                        user_keys = []

                    unique_user_keys = set()
                    for uk in user_keys:
                        if uk:
                            unique_user_keys.add(uk)

                    if not unique_user_keys or not device_id or not hostname:
                        failed_action_ids.append(action_id)
                        continue

                    for user_key in unique_user_keys:
                        device = {
                            "nsdeviceuid": device_id,
                            "userkey": user_key,
                            "hostname": hostname
                        }

                        for tag in tags:
                            tag_key = (tag, cci_tag_action)
                            if tag_key not in tag_groups:
                                tag_groups[tag_key] = {
                                    'devices': [],
                                    'action_id_to_devices': {}
                                }

                            tag_groups[tag_key]['devices'].append(device)
                            if action_id not in tag_groups[tag_key][
                                'action_id_to_devices'
                            ]:
                                tag_groups[tag_key][
                                    'action_id_to_devices'
                                ][action_id] = []
                            tag_groups[tag_key][
                                'action_id_to_devices'
                            ][action_id].append(device)

                except Exception as e:
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while processing "
                        f"action '{action_label}' for record with ID '{action_id}'. "   # noqa
                        f"Error: {e}"
                    )
                    failed_action_ids.append(action_id)
            log_msg = ""
            skipped_records = len(failed_action_ids)
            if skipped_records > 0:
                log_msg = (
                    f" {skipped_records} record(s) will be skipped "
                    "either due to being invalid or missing "
                    "'Netskope Device UID', 'User Key' or"
                    " 'Hostname' field values."
                )
            self.logger.info(
                f"{self.log_prefix}: Performing '{action_value}' Tag(s)"
                f" action on {len(actions)-skipped_records} "
                f"record(s).{log_msg if log_msg else ''}"
            )
            for (tag, cci_tag_action), group_data in tag_groups.items():  # noqa
                devices = group_data['devices']
                action_id_to_devices = group_data['action_id_to_devices']

                try:
                    tag_ids, tag_cache = self._query_and_create_tags_with_cache(  # noqa
                        [tag], action=cci_tag_action, tag_cache=tag_cache
                    )

                    unique_devices = []
                    seen_devices = set()
                    for device in devices:
                        device_key = (device.get("nsdeviceuid"), device.get("userkey"))  # noqa
                        if device_key not in seen_devices:
                            unique_devices.append(device)
                            seen_devices.add(device_key)

                    total_batches = (len(unique_devices) + TAG_DEVICE_BATCH_SIZE - 1) // TAG_DEVICE_BATCH_SIZE    # noqa  
                    for batch_num in range(total_batches):
                        start_idx = batch_num * TAG_DEVICE_BATCH_SIZE
                        end_idx = min(start_idx + TAG_DEVICE_BATCH_SIZE, len(unique_devices))   # noqa
                        device_batch = unique_devices[start_idx:end_idx]

                        batch_action_ids = []
                        batch_device_keys = set(
                            (d.get("nsdeviceuid"), d.get("userkey"))  # noqa
                            for d in device_batch
                        )
                        for action_id, action_devices in action_id_to_devices.items():   # noqa
                            for action_device in action_devices:
                                action_device_key = (
                                    action_device.get("nsdeviceuid"),
                                    action_device.get("userkey")
                                )
                                if action_device_key in batch_device_keys:
                                    batch_action_ids.append(action_id)
                                    break

                        try:
                            self.logger.info(
                                f"{self.log_prefix}: Processing batch {batch_num + 1}/{total_batches} "     # noqa
                                f"of {len(device_batch)} device record(s) for tag '{tag}'."
                            )
                            if device_bulk_call_count > 0:
                                self.logger.debug(
                                    f"{self.log_prefix}: Sleeping "
                                    f"{DEVICE_BULK_TAG_INTER_BATCH_SLEEP}s before next "
                                    "device bulk tag API call to respect rate limit."
                                )
                                time.sleep(DEVICE_BULK_TAG_INTER_BATCH_SLEEP)
                            device_bulk_call_count += 1
                            self._tag_devices(tag_ids, device_batch, cci_tag_action)    # noqa

                            self.logger.info(
                                f"{self.log_prefix}: Successfully {'tagged' if cci_tag_action == 'append' else 'untagged'} "    # noqa
                                f"batch {batch_num + 1}/{total_batches} ({len(device_batch)} device record(s)) with tag '{tag}'."   # noqa
                            )

                        except Exception as batch_e:
                            device_bulk_call_count += 1
                            self.logger.error(
                                f"{self.log_prefix}: Failed to {'tag' if cci_tag_action == 'append' else 'untag'} "     # noqa
                                f"batch {batch_num + 1}/{total_batches} ({len(device_batch)} device record(s)) with tag '{tag}'. "      # noqa
                                f"Error: {batch_e}"
                            )
                            failed_action_ids.extend(batch_action_ids)

                except Exception as group_e:
                    self.logger.error(
                        f"{self.log_prefix}: Failed to execute action "
                        f"'{action_label}' for tag '{tag}'. Error: {group_e}"
                    )
                    failed_action_ids.extend(list(action_id_to_devices.keys()))
        except Exception as group_e:
            failed_action_ids = []
            self.logger.error(
                f"{self.log_prefix}: Failed to execute action '{action_label}'. "
                f"Error: {group_e}"
            )
            for action_dict in actions:
                action_id = action_dict.get("id")
                failed_action_ids.append(action_id)
            return failed_action_ids

        return failed_action_ids

    def _bulk_replace_device_tags(
        self,
        actions: List[Action],
        action_label: str
    ) -> List[str]:
        """Replace tags on devices in bulk using optimized tag-set grouping.

        This method optimizes API calls by:
        1. Grouping devices with identical tag sets together
        2. Batching devices (max 100 per API call)
        3. Enforcing 5-tag limit per device

        Args:
            actions (List[Action]): List of actions.
            action_label (str): Action label.

        Returns:
            List[str]: List of failed action IDs.
        """
        failed_action_ids = []
        device_to_tags = {}
        tag_cache = self._fetch_all_tags()
        device_bulk_call_count = 0
        for action_dict in actions:
            action_id = action_dict.get("id")
            action = action_dict.get("params")
            try:
                (
                    tags,
                    device_id,
                    device_user_key,
                    hostname,
                    _,
                ) = self._process_params_for_tag_device_action(
                    action.parameters, True
                )

                user_keys = device_user_key
                if isinstance(device_user_key, str):
                    user_keys = [device_user_key] if device_user_key else []
                elif not isinstance(device_user_key, list):
                    user_keys = []

                unique_user_keys = set()
                for uk in user_keys:
                    if uk:
                        unique_user_keys.add(uk)

                if not unique_user_keys or not device_id or not hostname:
                    failed_action_ids.append(action_id)
                    continue

                for user_key in unique_user_keys:
                    device_key = (device_id, user_key, hostname)
                    if device_key not in device_to_tags:
                        device_to_tags[device_key] = {
                            'tags': set(),
                            'action_ids': set()
                        }
                    device_to_tags[device_key]['tags'].update(tags)
                    device_to_tags[device_key]['action_ids'].add(action_id)

            except Exception as e:
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while processing "
                    f"action '{action_label}' for record with ID '{action_id}'. "
                    f"Error: {e}"
                )
                failed_action_ids.append(action_id)
        log_msg = ""
        skipped_records = len(failed_action_ids)
        if skipped_records > 0:
            log_msg = (
                f" {skipped_records} record(s) will be skipped "
                "either due to being invalid or missing "
                "'Netskope Device UID', 'User Key' or "
                "'Hostname' field values."
            )
        self.logger.info(
            f"{self.log_prefix}: Performing 'Replace' Tag(s) "
            f"action on {len(actions)-skipped_records} "
            f"record(s).{log_msg if log_msg else ''}"
        )

        tag_set_groups = {}

        for (device_id, user_key, hostname), group_data in device_to_tags.items():
            tags = sorted(list(group_data['tags']))  # Sort for consistent grouping
            action_ids = group_data['action_ids']

            # 5-tag limit
            if len(tags) > MAX_TAGS_PER_DEVICE:
                skipped_tags = tags[MAX_TAGS_PER_DEVICE:]
                tags = tags[:MAX_TAGS_PER_DEVICE]
                self.logger.info(
                    f"{self.log_prefix}: Device '{device_id}' (userkey: "
                    f"'{user_key}', Hostname: '{hostname}') has more than {MAX_TAGS_PER_DEVICE} tags. "
                    f"Only the first {MAX_TAGS_PER_DEVICE} sorted tags will be "
                    f"applied: {tags}. Skipped tags: {skipped_tags}"
                )

            tag_set_key = tuple(tags)
            if tag_set_key not in tag_set_groups:
                tag_set_groups[tag_set_key] = {
                    'devices': [],
                    'action_ids': set()
                }

            device = {
                "nsdeviceuid": device_id,
                "userkey": user_key,
                "hostname": hostname
            }
            tag_set_groups[tag_set_key]['devices'].append(device)
            tag_set_groups[tag_set_key]['action_ids'].update(action_ids)

        self.logger.debug(
            f"{self.log_prefix}: Grouped {len(device_to_tags)} device "
            f"record(s) into {len(tag_set_groups)} tag set group(s)."
        )

        for tags_tuple, group_data in tag_set_groups.items():
            tags = list(tags_tuple)
            devices = group_data['devices']
            action_ids = list(group_data['action_ids'])

            try:
                tag_ids, tag_cache = self._query_and_create_tags_with_cache(
                    tags, action="replace", tag_cache=tag_cache
                )

                # Batch TAG_DEVICE_BATCH_SIZE per API call)
                total_batches = (
                    (len(devices) + TAG_DEVICE_BATCH_SIZE - 1) // TAG_DEVICE_BATCH_SIZE
                )

                self.logger.info(
                    f"{self.log_prefix}: Replacing tags {tags} on "
                    f"{len(devices)} device record(s) in "
                    f"{total_batches} batch(es)."
                )

                for batch_num in range(total_batches):
                    start_idx = batch_num * TAG_DEVICE_BATCH_SIZE
                    end_idx = min(
                        start_idx + TAG_DEVICE_BATCH_SIZE, len(devices)
                    )
                    device_batch = devices[start_idx:end_idx]

                    try:
                        self.logger.info(
                            f"{self.log_prefix}: Processing batch "
                            f"{batch_num + 1}/{total_batches} with "
                            f"{len(device_batch)} device records(s) for tags {tags}."
                        )
                        if device_bulk_call_count > 0:
                            self.logger.debug(
                                f"{self.log_prefix}: Sleeping "
                                f"{DEVICE_BULK_TAG_INTER_BATCH_SLEEP}s before next "
                                "device bulk tag API call to respect rate limit."
                            )
                            time.sleep(DEVICE_BULK_TAG_INTER_BATCH_SLEEP)
                        device_bulk_call_count += 1
                        self._replace_device_tags(tag_ids, device_batch)

                        self.logger.info(
                            f"{self.log_prefix}: Successfully replaced tags "
                            f"on batch {batch_num + 1}/{total_batches} "
                            f"({len(device_batch)} device records) with tags {tags}."
                        )

                    except Exception as batch_e:
                        device_bulk_call_count += 1
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Failed to replace tags on "
                                f"batch {batch_num + 1}/{total_batches} "
                                f"({len(device_batch)} records). Error: {batch_e}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        batch_device_keys = set(
                            (d.get("nsdeviceuid"), d.get("userkey"))
                            for d in device_batch
                        )
                        for device_key, dev_data in device_to_tags.items():
                            if device_key in batch_device_keys:
                                failed_action_ids.extend(
                                    list(dev_data['action_ids'])
                                )

            except Exception as group_e:
                self.logger.error(
                    f"{self.log_prefix}: Failed to process tag set group "
                    f"with tags {tags}. Error: {group_e}"
                )
                failed_action_ids.extend(action_ids)

        return failed_action_ids

    def execute_action(self, action: Action, revert: bool = False):
        """Execute action on the user.

        Args:
            action (Action): Action object.
        """
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        # The 'Add host to Private App' action consumes the full set of
        # values from its Source/Static fields, so its multi-value
        # parameters must NOT be collapsed to a single latest value here.
        action.parameters = get_latest_values(
            action.parameters,
            exclude_keys=[
                "host",
                "tags",
                "protocol",
                "publishers",
            ],
        )
        self.logger.info(
            f"{self.log_prefix}: Executing '{action.label}' "
            f"{'revert action.' if revert else 'action'}."
        )
        if revert:
            if action.value == "impact":
                anomaly_id = action.parameters.get("anomaly_id", "")
                if not anomaly_id:
                    err_msg = (
                        "Unable to find the Anomaly ID, hence "
                        "Revert UCI Impact action will be skipped."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    raise NetskopeException(err_msg)
                self.revert_uci_update_impact(anomaly_id)
                self.logger.info(
                    f"{self.log_prefix}: Successfully executed revert action"
                    f" for '{action.label}' and marked Anomaly ID "
                    f"'{anomaly_id}' as allowed."
                )
                return

            raise NotImplementedError(
                f"Revert action is not supported for "
                f"'{action.value}' action in Netskope Risk Exchange plugin."
            )

        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action.label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action.label}' action."
            )
            return
        elif action.value == "impact":
            user, score, source, reason = (
                self._process_params_for_impact_action(action.parameters)
            )
            response = self._update_impact_score(
                user,
                score,
                source,
                reason,
            )
            if response.get("anomalyId"):
                action.parameters["anomaly_id"] = response.get("anomalyId")
            self.logger.info(
                f"{self.log_prefix}: UCI score updated for user {user} "
                "successfully."
            )
            return
        elif action.value == "uci_reset":
            user_list, skipped_users = (
                self._process_params_for_reset_action(action.parameters, True)
            )
            if skipped_users > 0:
                err_msg = (
                    f"Skipped {skipped_users} user email(s) "
                    "due to invalid email address."
                )
                self.logger.info(f"{self.log_prefix}: {err_msg}")
            if not user_list:
                err_msg = (
                    "Invalid user email(s) provided in "
                    "configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide valid user email(s) in "
                        "UCI Reset action."
                    )
                )
                raise NetskopeException(err_msg)
            self._reset_uci_score(
                user_list
            )
            self.logger.info(
                f"{self.log_prefix}: UCI score reset successfully "
                f"for user {', '.join(user_list)}'."
            )
            return
        elif action.value in ["add", "remove"]:
            user = action.parameters.get("user", "")
            users = self._get_all_users()
            match = self._find_user_by_email(users, user)
            if match is None:
                err_message = (
                    f"User with email {user} not found on the Netskope "
                    "Tenant via SCIM."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_message}",
                    resolution=(
                        f"Make sure user with email {user} is available "
                        "on the Netskope Tenant via SCIM."
                    )
                )
                raise NetskopeException(err_message)
            if action.value == "add":
                group_id = action.parameters.get("group", "")
                if group_id == "create":
                    groups = self._get_all_groups()
                    group_name = action.parameters.get("name", "").strip()
                    group_match = self._find_group_by_name(groups, group_name)
                    if group_match is None:  # create group
                        group = self._create_group(
                            self.configuration, group_name
                        )
                        group_id = group.get("id", "")
                    else:
                        group_id = group_match.get("id", "")
                self._add_to_group(
                    self.configuration,
                    [{"value": match.get("id", "")}],
                    group_id
                )
                self.logger.info(
                    f"{self.log_prefix}: Added {user} to group with "
                    f"ID {group_id} successfully."
                )
            if action.value == "remove":
                self._remove_from_group(
                    self.configuration,
                    [{"value": match.get("id", "")}],
                    action.parameters.get("group", ""),
                )
                self.logger.info(
                    f"{self.log_prefix}: Removed {user} from group with ID "
                    f"{action.parameters.get('group', '')} successfully."
                )
        elif action.value == "private_app":
            self._execute_private_app_action(action.parameters)
        elif action.value == "tag_app":
            # Append for adding the tags, remove for removing the tags
            (
                tags,
                apps,
                ids,
                cci_tag_action
            ) = self._process_params_for_add_tag_action(
                action.parameters, True
            )
            self._tag_application(tags, apps, ids, cci_tag_action)
            logger_msg = (
                f"Added tag(s) {','.join(tags)} to "
                "application(s) successfully"
            )
            if cci_tag_action == "remove":
                logger_msg = (
                    f"Removed tag(s) {','.join(tags)} from "
                    "application(s) successfully"
                )
            self.logger.info(
                f"{self.log_prefix}: {logger_msg}."
            )
        elif action.value == "app_instance":
            instance_id, instance_name, app, tags = (
                self._process_params_for_app_instance_action(action.parameters)
            )

            token = resolve_secret(self.tenant.parameters.get("token", ""))

            self._create_app_instance(
                instance_id, instance_name, app, tags, token
            )

            self.logger.info(
                f"{self.log_prefix}: Created/updated app instance "
                f"{instance_name} successfully."
            )
        # The Add to Destination/DNS/Service Profile and Create Device
        # Classification actions are handled exclusively through
        # ``execute_actions`` (bulk). The plugin requires CE 6.1.0+, where
        # bulk execution is always used, so no single-record branch is
        # implemented for them here.

    def execute_actions(self, actions, revert: bool = False):
        """Execute actions in bulk.

        Args:
            actions (List[Action]): List of Action objects.
        """
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        first_action = actions[0].get("params")
        action_label = first_action.label
        if revert:
            err_msg = ""
            if first_action.value != "impact":
                err_msg = (
                    f"Batch revert action for '{action_label}' is not "
                    f"supported in the Netskope Risk Exchange plugin."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise NotImplementedError(err_msg)
        if first_action.value != "impact":
            self.logger.info(
                f"{self.log_prefix}: Executing '{action_label}' action "
                f"for {len(actions)} record(s)."
            )
        failed_action_ids = []
        if first_action.value == "private_app":
            # Group records by target app name, keeping (action_id, params)
            # so each host can be mapped back to the contributing records.
            private_apps = {}
            for action_dict in actions:
                id, action = action_dict.get("id"), action_dict.get("params")
                selected = action.parameters.get("private_app_name", "")
                app_name = (
                    selected
                    if selected != "create"
                    else action.parameters.get("name", "")
                )
                private_apps.setdefault(app_name, []).append(
                    (id, action.parameters)
                )
            # Tracks how many hosts were added to each private app across
            # all groups; surfaced in the final summary log's details.
            hosts_per_app = {}
            for app_name, batched_actions in private_apps.items():
                batch_action_ids = [aid for aid, _ in batched_actions]
                try:
                    params = batched_actions[0][1].copy()
                    # One pass over the group's records builds: the unioned
                    # host list; the per-batch tag map (host -> contributing
                    # tag names) for tag scoping; and the per-record host
                    # sets for failed-action-id attribution.
                    union_hosts = []
                    host_to_tags = {}
                    record_to_hosts = {}
                    for aid, record_params in batched_actions:
                        # Use ``or []`` (not just a get default) so a tags
                        # value of None - not only a missing key - is
                        # normalised to an empty list before iterating.
                        raw_tags = record_params.get("tags") or []
                        if isinstance(raw_tags, str):
                            raw_tags = [
                                tag.strip()
                                for tag in raw_tags.split(",")
                                if tag.strip()
                            ]
                        record_valid_tags, _, _ = (
                            self.netskope_helper.validate_tags_for_private_app(
                                raw_tags, app_name
                            )
                        )
                        record_tag_names = {
                            tag["tag_name"] for tag in record_valid_tags
                        }
                        # Host accepts a Source field (a list) or a Static
                        # field (a comma-separated string); the shared
                        # _normalize_csv_values helper handles both - trimming,
                        # dropping empties, and de-duplicating - so each host
                        # is processed individually (as the profile actions).
                        record_hosts = (
                            self.netskope_helper._normalize_csv_values(
                                record_params.get("host")
                            )
                        )
                        host_set = set()
                        for host_value in record_hosts:
                            union_hosts.append(host_value)
                            host_set.add(host_value)
                            host_to_tags.setdefault(
                                host_value, set()
                            ).update(record_tag_names)
                        record_to_hosts[aid] = host_set
                    params["host"] = union_hosts
                    params = get_latest_values(
                        params,
                        exclude_keys=["host", "tags", "protocol", "publishers"],
                    )
                    # compact=True: after appending this group's hosts,
                    # consolidate the app group so apps left partially filled
                    # by earlier reverts are re-packed once per sync.
                    not_placed, added_counts = (
                        self._execute_private_app_action(
                            params, host_to_tags, compact=True
                        )
                    )
                    not_placed = not_placed or set()
                    # Accumulate the per-app added-host counts for the final
                    # summary log.
                    for name, count in (added_counts or {}).items():
                        hosts_per_app[name] = (
                            hosts_per_app.get(name, 0) + count
                        )
                    # A record fails only when EVERY host it contributed was
                    # not placed (invalid or capacity-skipped). A 0-host
                    # record is a vacuous subset -> it fails too.
                    for aid, host_set in record_to_hosts.items():
                        if host_set.issubset(not_placed):
                            failed_action_ids.append(aid)
                except Exception as e:
                    failed_action_ids.extend(batch_action_ids)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error occurred while adding "
                            f"hosts to private apps. Error: {str(e)}"
                        ),
                        details=re.sub(
                            r"token=([0-9a-zA-Z]*)",
                            "token=********&",
                            traceback.format_exc(),
                        ),
                    )

            total_hosts_added = sum(hosts_per_app.values())
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Completed the '{action_label}' "
                    f"action: added {total_hosts_added} host(s) across "
                    f"{len(hosts_per_app)} private app(s). Expand log to"
                    " view hosts added per Private App."
                ),
                details=(
                    "Hosts added per private app: "
                    f"{hosts_per_app}"
                ),
            )
            return ActionResult(
                success=True,
                message="Successfully added hosts to private apps.",
                failed_action_ids=list(dict.fromkeys(failed_action_ids)),
            )
        elif first_action.value in ["add", "remove"]:
            skip_count = 0
            bulk_payload = []
            action_parameters = first_action.parameters
            all_users = self._get_all_users()
            if first_action.value == "add":
                group_id = action_parameters.get("group", "")
                if group_id == "create":
                    groups = self._get_all_groups()
                    group_name = action_parameters.get("name", "").strip()
                    group_match = self._find_group_by_name(groups, group_name)
                    if group_match is None:  # create group
                        group = self._create_group(
                            self.configuration, group_name
                        )
                        group_id = group.get("id", "")
                        group_name = group.get("displayName", "")
                    else:
                        group_name = group_match.get("displayName", "")
                        group_id = group_match.get("id", "")

                batch_user_to_action_id = {}
                for action_dict in actions:
                    id, action = action_dict.get("id"), action_dict.get("params")
                    params = get_latest_values(action.parameters)
                    user = params.get("user", "")
                    match = self._find_user_by_email(all_users, user)
                    if match is None:
                        self.logger.info(
                            f"{self.log_prefix}: User with email {user} "
                            f"not found on the Netskope Tenant via SCIM. "
                            "Hence skipping execution of action "
                            f"'{action_label}' on '{user}'."
                        )
                        skip_count += 1
                        failed_action_ids.append(id)
                        continue

                    user_id = match.get("id", "")
                    bulk_payload.append(
                        {"value": user_id}
                    )
                    batch_user_to_action_id[user_id] = id

                total_users = 0
                if bulk_payload:
                    batch = 1
                    for index in range(
                        0, len(bulk_payload), ADD_REMOVE_USER_BATCH_SIZE
                    ):
                        batch_users = bulk_payload[
                            index: index + ADD_REMOVE_USER_BATCH_SIZE
                        ]
                        try:
                            self._add_to_group(
                                self.configuration,
                                batch_users,
                                group_id
                            )
                            total_users += len(batch_users)
                            self.logger.info(
                                f"{self.log_prefix}: Successfully added "
                                f"{len(batch_users)} user(s) to the group "
                                f"with ID '{group_id}' for batch {batch}. "
                                f"Total users added: {total_users}."
                            )
                            batch += 1
                        except Exception as e:
                            for batch_user in batch_users:
                                user_id = batch_user.get("value", "")
                                if user_id in batch_user_to_action_id:
                                    failed_action_ids.append(
                                        batch_user_to_action_id[user_id]
                                    )
                            self.logger.error(
                                f"{self.log_prefix}: Failed to add "
                                f"{len(batch_users)} user(s) to the group "
                                f"with ID '{group_id}' for batch {batch}. "
                                f"Error: {e} Continuing with next batch."
                            )
                            batch += 1

                if skip_count > 0:
                    self.logger.info(
                        f"{self.log_prefix}: Skipped adding {skip_count} "
                        f"user(s) to the group with ID '{group_id}' as they "
                        "were not found on the Netskope Tenant."
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully added "
                    f"{len(bulk_payload)} user(s) to the group with "
                    f"ID '{group_id}'."
                )
                return ActionResult(
                    success=True,
                    message="Successfully added users to group.",
                    failed_action_ids=failed_action_ids
                )
            elif first_action.value == "remove":
                group_id = action_parameters.get("group", "")
                batch_user_to_action_id = {}
                for action_dict in actions:
                    id, action = action_dict.get("id"), action_dict.get("params")
                    params = get_latest_values(action.parameters)
                    user = params.get("user", "")
                    match = self._find_user_by_email(all_users, user)
                    if match is None:
                        self.logger.info(
                            f"{self.log_prefix}: User with email {user} "
                            f"not found on the Netskope Tenant via SCIM. "
                            "Hence skipping execution of action "
                            f"'{action_label}' on '{user}'."
                        )
                        skip_count += 1
                        failed_action_ids.append(id)
                        continue

                    user_id = match.get("id", "")
                    bulk_payload.append(
                        {"value": user_id}
                    )
                    batch_user_to_action_id[user_id] = id

                total_removed = 0
                if bulk_payload:
                    batch = 1
                    for index in range(
                        0, len(bulk_payload), ADD_REMOVE_USER_BATCH_SIZE
                    ):
                        batch_users = bulk_payload[
                            index: index + ADD_REMOVE_USER_BATCH_SIZE
                        ]
                        try:
                            self._remove_from_group(
                                self.configuration,
                                batch_users,
                                group_id
                            )
                            total_removed += len(batch_users)
                            self.logger.info(
                                f"{self.log_prefix}: Successfully removed "
                                f"{len(batch_users)} user(s) from the group "
                                f"with ID '{group_id}' for batch {batch}. "
                                f"Total users removed: {total_removed}."
                            )
                            batch += 1
                        except Exception as e:
                            for batch_user in batch_users:
                                user_id = batch_user.get("value", "")
                                if user_id in batch_user_to_action_id:
                                    failed_action_ids.append(
                                        batch_user_to_action_id[user_id]
                                    )
                            self.logger.error(
                                f"{self.log_prefix}: Failed to remove "
                                f"{len(batch_users)} user(s) from the group "
                                f"with ID '{group_id}' for batch {batch}. "
                                f"Error: {e} Continuing with next batch."
                            )
                            batch += 1

                if skip_count > 0:
                    self.logger.info(
                        f"{self.log_prefix}: Skipped removing {skip_count} "
                        f"user(s) from the group with ID '{group_id}' "
                        "as they were not found on the Netskope Tenant."
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully removed "
                    f"{len(bulk_payload)} user(s) from the group with ID "
                    f"'{group_id}'."
                )
                return ActionResult(
                    success=True,
                    message="Successfully removed users from the group.",
                    failed_action_ids=failed_action_ids
                )
        elif first_action.value == "tag_app":
            tags_ids_apps = {}
            item_to_action_map = {}
            for action_dict in actions:
                id, action = action_dict.get("id"), action_dict.get("params")
                try:
                    (
                        tags,
                        apps,
                        ids,
                        cci_tag_action
                    ) = self._process_params_for_add_tag_action(
                        action.parameters,
                        True
                    )

                    for tag in tags:
                        if tag not in tags_ids_apps:
                            tags_ids_apps[tag] = {
                                "apps": [],
                                "ids": [],
                            }

                        if apps:
                            tags_ids_apps[tag]["apps"] = (
                                list(set(tags_ids_apps[tag]["apps"]) | set(apps))
                            )
                        if ids:
                            tags_ids_apps[tag]["ids"] = (
                                list(set(tags_ids_apps[tag]["ids"]) | set(ids))
                            )

                        for app in apps:
                            item_to_action_map[app] = id
                        for item_id in ids:
                            item_to_action_map[item_id] = id
                except Exception as e:
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while processing "
                        f"action '{action_label}' for record with ID '{id}'. "
                        f"Error: {e}"
                    )
                    failed_action_ids.append(id)

            skipped_tags_info, batch_failed_ids = self._bulk_tag_application(
                tags_ids_apps,
                cci_tag_action,
                item_to_action_map
            )
            failed_action_ids.extend(batch_failed_ids)

            log_msg_add_remove = (
                "tagged" if cci_tag_action == "append" else "untagged"
            )
            for tag, counts in skipped_tags_info.items():
                self.logger.info(
                    f"{self.log_prefix}: Successfully {log_msg_add_remove} "
                    f"{counts['tagged']} and skipped {counts['skipped']} "
                    f"application(s) with tag '{tag}'."
                )
            return ActionResult(
                success=True,
                message=f"Successfully {log_msg_add_remove} applications.",
                failed_action_ids=failed_action_ids
            )
        elif first_action.value == "tag_device":
            cci_tag_action = first_action.parameters.get(
                "tag_device_action", "append"
            )
            if cci_tag_action == "replace":
                # Use device-to-tags mapping for replace action
                failed_action_ids = self._bulk_replace_device_tags(
                    actions, action_label
                )
                return ActionResult(
                    success=True,
                    message="Successfully replaced tags on devices.",
                    failed_action_ids=list(set(failed_action_ids)),
                )
            else:
                # Use tag-to-devices mapping for add/remove actions
                log_msg_add_remove = (
                    "tagged" if cci_tag_action == "append" else "untagged"
                )
                failed_action_ids = self._bulk_add_remove_tag_device(
                    actions, action_label
                )
                return ActionResult(
                    success=True,
                    message=f"Successfully {log_msg_add_remove} devices.",
                    failed_action_ids=list(set(failed_action_ids)),
                )
        elif first_action.value == "app_instance":
            bulk_app_instance_payload = {
                "update": [],
                "add": []
            }
            skip_count = 0
            tenant_name = (
                self.tenant.parameters.get('tenantName', '').strip()
            )
            token = resolve_secret(self.tenant.parameters.get("token", ""))
            logger_msg = "listing app instances"
            for action_dict in actions:
                id, action = action_dict.get("id"), action_dict.get("params")
                try:
                    params = get_latest_values(action.parameters)
                    instance_id, instance_name, app, tags = (
                        self._process_params_for_app_instance_action(
                            params
                        )
                    )
                    url = (
                        f"{tenant_name}{URLS.get('V1_APP_INSTANCE')}"
                    )
                    params = {
                        "op": "list",
                        "app": app,
                        "instance_id": instance_id,
                        "instance_name": instance_name,
                    }
                    list_instances_response = self.netskope_helper._api_call_helper(
                        url=url,
                        method="post",
                        error_codes=["CRE_1045", "CRE_1049"],
                        params=params,
                        data={"token": token},
                        proxies=self.proxy,
                        message=f"Error occurred while {logger_msg}",
                        logger_msg=logger_msg,
                    )
                    if (
                        list_instances_response.get("status", "").lower() !=
                        SUCCESS.lower()
                    ):
                        skip_count += 1
                        failed_action_ids.append(id)
                        err_msg = (
                            f"Error occurred while {logger_msg} "
                            "from the Netskope Tenant."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg} ",
                            details=json.dumps(list_instances_response),
                        )
                        continue
                    if list_instances_response.get("data", []):
                        bulk_app_instance_payload.get("update", []).append(
                            {
                                "instance_id": instance_id,
                                "instance_name": instance_name,
                                "app": app,
                                "tags": tags,
                                "action_id": id
                            }
                        )
                    else:
                        bulk_app_instance_payload.get("add", []).append(
                            {
                                "instance_id": instance_id,
                                "instance_name": instance_name,
                                "app": app,
                                "tags": tags,
                                "action_id": id
                            }
                        )
                except Exception as err:
                    error_message = f"Error occurred while {logger_msg}."
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {error_message} "
                            f"Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1
                    failed_action_ids.append(id)
                    continue

            if skip_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped creating/updating "
                    f"{skip_count} app instance(s) as some error occurred."
                )
            _, bulk_failed_ids = self._create_update_app_instance_bulk(
                bulk_app_instance_payload,
                tenant_name,
                token,
            )
            failed_action_ids.extend(bulk_failed_ids)
            return ActionResult(
                success=True,
                message="Successfully created/updated app instance(s).",
                failed_action_ids=failed_action_ids
            )
        elif first_action.value == "uci_reset":
            user_list = []
            total_skipped_users = 0
            for action_dict in actions:
                id, action = action_dict.get("id"), action_dict.get("params")
                params = get_latest_values(action.parameters)
                try:
                    users, skipped_users = (
                        self._process_params_for_reset_action(
                            params, True,
                        )
                    )
                    user_list.extend(users)
                    total_skipped_users += skipped_users

                    if skipped_users > 0:
                        failed_action_ids.append(id)
                except Exception as err:
                    error_message = (
                        "Error occurred while processing user email(s)."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {error_message} "
                            f"Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    failed_action_ids.append(id)
            if total_skipped_users > 0:
                err_msg = (
                    f"Skipped {total_skipped_users} user email(s) "
                    "due to invalid email address."
                )
                self.logger.info(f"{self.log_prefix}: {err_msg}")
            if not user_list:
                err_msg = (
                    "Invalid user email(s) provided in "
                    "configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Make sure provided email(s) are valid "
                        "for the UCI Reset action."
                    )
                )
                raise NetskopeException(err_msg)
            self._reset_uci_score(user_list)
            self.logger.info(
                f"{self.log_prefix}: UCI score reset for {len(user_list)} "
                "user(s) successfully."
            )
            return ActionResult(
                success=True,
                message="Successfully reset UCI score for users.",
                failed_action_ids=failed_action_ids
            )
        elif first_action.value == "destination_profile":
            profile_groups = {}
            for action_dict in actions:
                id, action = (
                    action_dict.get("id"),
                    action_dict.get("params"),
                )
                params = action.parameters
                selected_profile = params.get(
                    "destination_profile_name", ""
                )
                # new_profile_name only matters when creating a profile; for
                # an existing profile it is left at its (possibly per-record
                # source) default, so excluding it from the key keeps all
                # records targeting the same existing profile in one group.
                group_key = (
                    selected_profile,
                    params.get("new_profile_name", "")
                    if selected_profile == "create"
                    else "",
                )
                group = profile_groups.setdefault(
                    group_key,
                    {
                        "params": params,
                        "values": [],
                        "ids": [],
                        "value_to_ids": {},
                    },
                )
                group["ids"].append(id)
                normalized = self.netskope_helper._normalize_csv_values(
                    params.get("destination_values", "")
                )
                group["values"].extend(normalized)
                # Track which action id(s) each value came from so that a
                # value that fails or is skipped can be attributed back
                # to the originating action(s) as a failed action id.
                for value in normalized:
                    group["value_to_ids"].setdefault(value, set()).add(id)
            for group in profile_groups.values():
                params = group["params"]
                batch_ids = group["ids"]
                value_to_ids = group["value_to_ids"]
                values = self.netskope_helper._normalize_csv_values(group["values"])
                # Optional per-action override for the tenant-wide
                # exact-match value limit; empty/invalid falls back to
                # the default constant inside the capacity helper.
                raw_limit = params.get("exact_match_total_limit", "")
                try:
                    exact_total_limit = (
                        int(raw_limit)
                        if str(raw_limit).strip() != ""
                        else None
                    )
                except (TypeError, ValueError):
                    exact_total_limit = None
                try:
                    shared, not_applied = (
                        self._push_destination_profile(
                            destination_values=values,
                            existing_profile_name=params.get(
                                "destination_profile_name", ""
                            ),
                            new_profile_name=params.get(
                                "new_profile_name", ""
                            ),
                            new_profile_description=params.get(
                                "new_profile_description", ""
                            ),
                            match_type=params.get(
                                "profile_match_type", ""
                            ),
                            apply_pending_changes=params.get(
                                "apply_pending_changes", "No"
                            ),
                            operation=params.get("operation", "append"),
                            exact_total_limit=exact_total_limit,
                        )
                    )
                    self.netskope_helper._attribute_failed_ids(
                        not_applied, value_to_ids, failed_action_ids
                    )
                    if params.get("operation", "append") == "replace":
                        summary = (
                            f"Successfully replaced the destination "
                            f"profile's values with {shared} network "
                            "target(s)."
                        )
                    else:
                        summary = (
                            f"Successfully added {shared} network "
                            "target(s) to the destination profile."
                        )
                    self.logger.info(f"{self.log_prefix}: {summary}")
                except Exception as e:
                    failed_action_ids.extend(batch_ids)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error occurred while "
                            "adding network targets to the "
                            f"destination profile. Error: {e}"
                        ),
                        details=re.sub(
                            r"token=([0-9a-zA-Z]*)",
                            "token=********&",
                            traceback.format_exc(),
                        ),
                    )
            return ActionResult(
                success=True,
                message=(
                    "Successfully added network targets to "
                    "destination profiles."
                ),
                failed_action_ids=list(set(failed_action_ids)),
            )
        elif first_action.value == "dns_profile":
            profile_groups = {}
            for action_dict in actions:
                id, action = (
                    action_dict.get("id"),
                    action_dict.get("params"),
                )
                params = action.parameters
                profile_value = params.get("dns_profile_name", "")
                # new_profile_name only matters when creating a profile (the
                # packed dropdown id is "create"); for an existing profile it
                # keeps a per-record source default, so exclude it from the
                # key to keep same-profile records in one group.
                is_create = (
                    profile_value.partition(CUSTOM_SEPARATOR)[2] == "create"
                )
                group_key = (
                    profile_value,
                    params.get("new_profile_name", "") if is_create else "",
                )
                group = profile_groups.setdefault(
                    group_key,
                    {
                        "params": params,
                        "domains": [],
                        "ids": [],
                        "value_to_ids": {},
                    },
                )
                group["ids"].append(id)
                normalized = self.netskope_helper._normalize_csv_values(
                    params.get("domain_names", "")
                )
                group["domains"].extend(normalized)
                # Track which action id(s) each domain came from so that a
                # domain that fails or is skipped (invalid/over-length or
                # dropped under the payload budget) can be attributed back
                # to the originating action(s) as a failed action id.
                for value in normalized:
                    group["value_to_ids"].setdefault(value, set()).add(id)
            for group in profile_groups.values():
                params = group["params"]
                batch_ids = group["ids"]
                value_to_ids = group["value_to_ids"]
                domains = self.netskope_helper._normalize_csv_values(group["domains"])
                profile_value = params.get("dns_profile_name", "")
                # Safe to split on the first separator: a DNS profile
                # name cannot contain "(" or ")" (rejected by both the
                # Netskope DNS profile API and the plugin's save-time
                # validation), so the "()" separator never collides with
                # the name.
                profile_name, _, profile_id = profile_value.partition(
                    CUSTOM_SEPARATOR
                )
                existing_profile_name = (
                    "create" if profile_id == "create" else profile_name
                )
                try:
                    shared, not_applied = self._push_dns_profile(
                        domains=domains,
                        existing_profile_name=existing_profile_name,
                        new_profile_name=params.get(
                            "new_profile_name", ""
                        ),
                        action_type=params.get(
                            "dns_profile_action_type", ""
                        ),
                        action_params=params,
                        operation=params.get("operation", "append"),
                    )
                    self.netskope_helper._attribute_failed_ids(
                        not_applied, value_to_ids, failed_action_ids
                    )
                    if params.get("operation", "append") == "replace":
                        summary = (
                            f"Successfully replaced the DNS profile's "
                            f"domains for the selected record type(s) "
                            f"with {shared} domain(s)."
                        )
                    else:
                        summary = (
                            f"Successfully added {shared} domain(s) to "
                            "the DNS profile."
                        )
                    self.logger.info(f"{self.log_prefix}: {summary}")
                except Exception as e:
                    failed_action_ids.extend(batch_ids)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error occurred while "
                            "adding domains to the DNS profile. "
                            f"Error: {e}"
                        ),
                        details=re.sub(
                            r"token=([0-9a-zA-Z]*)",
                            "token=********&",
                            traceback.format_exc(),
                        ),
                    )
            return ActionResult(
                success=True,
                message="Successfully added domains to DNS profiles.",
                failed_action_ids=list(set(failed_action_ids)),
            )
        elif first_action.value == "service_profile":
            profile_groups = {}
            for action_dict in actions:
                id, action = (
                    action_dict.get("id"),
                    action_dict.get("params"),
                )
                params = action.parameters
                selected_profile = params.get("service_profile_name", "")
                # new_profile_name only matters when creating a profile; for
                # an existing profile it keeps a per-record source default,
                # so exclude it to keep same-profile records in one group.
                group_key = (
                    selected_profile,
                    params.get("new_profile_name", "")
                    if selected_profile == "create"
                    else "",
                )
                group = profile_groups.setdefault(
                    group_key,
                    {
                        "params": params,
                        "tcp": [],
                        "udp": [],
                        "tcp_udp": [],
                        "ids": [],
                        "value_to_ids": {},
                    },
                )
                group["ids"].append(id)
                # Track which action id(s) each port came from so that a
                # port that fails or is skipped can be attributed back to
                # the originating action(s) as a failed action id.
                for proto_key in ("tcp_ports", "udp_ports", "tcp_udp_ports"):
                    normalized = self.netskope_helper._normalize_csv_values(
                        params.get(proto_key, "")
                    )
                    group[proto_key.replace("_ports", "")].extend(
                        normalized
                    )
                    for value in normalized:
                        group["value_to_ids"].setdefault(
                            value, set()
                        ).add(id)
            for group in profile_groups.values():
                params = group["params"]
                batch_ids = group["ids"]
                value_to_ids = group["value_to_ids"]
                profile_name = params.get("service_profile_name", "")
                if profile_name == "create":
                    profile_name = params.get("new_profile_name", "")
                try:
                    _, not_applied = self._push_service_profile(
                        operation=params.get("operation", "append"),
                        profile_name=profile_name,
                        description=params.get(
                            "new_profile_description", ""
                        ),
                        tcp=self.netskope_helper._normalize_csv_values(group["tcp"]),
                        udp=self.netskope_helper._normalize_csv_values(group["udp"]),
                        tcp_udp=self.netskope_helper._normalize_csv_values(
                            group["tcp_udp"]
                        ),
                        icmp=bool(params.get("icmp", False)),
                    )
                    self.netskope_helper._attribute_failed_ids(
                        not_applied, value_to_ids, failed_action_ids
                    )
                    if params.get("operation", "append") == "replace":
                        summary = (
                            f"Successfully replaced the ports on the "
                            f"service profile '{profile_name}'."
                        )
                    else:
                        summary = (
                            f"Successfully added ports to the service "
                            f"profile '{profile_name}'."
                        )
                    self.logger.info(f"{self.log_prefix}: {summary}")
                except Exception as e:
                    failed_action_ids.extend(batch_ids)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error occurred while "
                            "adding ports to the service profile "
                            f"'{profile_name}'. Error: {e}"
                        ),
                        details=re.sub(
                            r"token=([0-9a-zA-Z]*)",
                            "token=********&",
                            traceback.format_exc(),
                        ),
                    )
            return ActionResult(
                success=True,
                message="Successfully added ports to service profiles.",
                failed_action_ids=list(set(failed_action_ids)),
            )
        elif first_action.value == "device_classification":
            rule_groups = {}
            for action_dict in actions:
                id, action = (
                    action_dict.get("id"),
                    action_dict.get("params"),
                )
                params = action.parameters
                classification_value = params.get(
                    "device_classification", ""
                )
                rule_value = params.get("device_classification_rule", "")
                # The create-name fields only matter when their dropdown is
                # set to "create"; otherwise they keep a per-record source
                # default, so exclude them from the key.
                creating_classification = classification_value == "create"
                creating_rule = (
                    rule_value.rpartition(
                        CUSTOM_SEPARATOR_DEVICE_CLASSIFICATION
                    )[2] == "create"
                )
                group_key = (
                    params.get("operation", ""),
                    classification_value,
                    params.get("new_classification_name", "")
                    if creating_classification
                    else "",
                    rule_value,
                    params.get("new_rule_name", "")
                    if creating_rule
                    else "",
                    params.get("os", ""),
                    params.get("logical_operator", ""),
                    params.get("group_operator", ""),
                )
                group = rule_groups.setdefault(
                    group_key,
                    {
                        "params": params,
                        "tags": [],
                        "ids": [],
                        "value_to_ids": {},
                    },
                )
                group["ids"].append(id)
                normalized = self.netskope_helper._normalize_csv_values(
                    params.get("classification_tags", "")
                )
                group["tags"].extend(normalized)
                # Track which action id(s) each device tag came from so a
                # tag that is skipped (no matching tag on the tenant) can
                # be attributed back to the originating action(s).
                for value in normalized:
                    group["value_to_ids"].setdefault(
                        value, set()
                    ).add(id)
            rule_action_statuses = set()
            for group in rule_groups.values():
                params = group["params"]
                batch_ids = group["ids"]
                value_to_ids = group["value_to_ids"]
                tags = self.netskope_helper._normalize_csv_values(group["tags"])
                try:
                    _, not_applied, action_status = (
                        self._push_device_classification(
                            operation=params.get("operation", "append"),
                            classification_value=params.get(
                                "device_classification", ""
                            ),
                            new_classification_name=params.get(
                                "new_classification_name", ""
                            ),
                            rule_value=params.get(
                                "device_classification_rule", ""
                            ),
                            new_rule_name=params.get("new_rule_name", ""),
                            os=params.get("os", ""),
                            operator=params.get(
                                "logical_operator", "and"
                            ),
                            group_operator=params.get(
                                "group_operator", "and"
                            ),
                            tags=tags,
                        )
                    )
                    rule_action_statuses.add(action_status)
                    self.netskope_helper._attribute_failed_ids(
                        not_applied, value_to_ids, failed_action_ids
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully {action_status} "
                        "the device classification rule."
                    )
                except Exception as e:
                    failed_action_ids.extend(batch_ids)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error occurred while "
                            "creating or updating the device "
                            f"classification rule. Error: {e}"
                        ),
                        details=str(traceback.format_exc()),
                    )
            # Build the aggregate verb from what actually happened across
            # the groups: only-created, only-updated, or a mix of both.
            if rule_action_statuses == {"created"}:
                status_verb = "created"
            elif rule_action_statuses == {"updated"}:
                status_verb = "updated"
            elif rule_action_statuses:
                status_verb = "created and updated"
            else:
                status_verb = "created or updated"
            return ActionResult(
                success=True,
                message=(
                    f"Successfully {status_verb} device classification "
                    "rule(s)."
                ),
                failed_action_ids=list(set(failed_action_ids)),
            )
        elif first_action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action "
                f"'{action_label}' on {len(actions)} records."
                "Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return
        else:
            raise NotImplementedError

    def _create_update_app_instance_bulk(
        self,
        bulk_payload: dict,
        tenant_name: str,
        auth_token: str,
    ):
        """Create or update app instances.

        Args:
            bulk_payload (dict): Payload for bulk create or update
            tenant_name (str): Tenant name
            auth_token (str): Auth token.
        """
        op_counter = 1
        success = True
        batch_failed_action_ids = []
        for op, payload in bulk_payload.items():
            batch = 1
            create_update_msg = 'updating' if op == 'update' else 'adding'
            total_app_instances = 0
            for index in range(0, len(payload), APP_INSTANCE_BATCH_SIZE):
                batch_app_instances = payload[
                    index: index + APP_INSTANCE_BATCH_SIZE
                ]
                batch_action_ids = [
                    item.pop("action_id") for item in batch_app_instances
                ]
                if op_counter > 1 or batch > 1:
                    self.logger.info(
                        f"{self.log_prefix}: Batch {batch} for "
                        f"{create_update_msg} app instance will be executed "
                        "in 60 seconds as App Instance API only allows 1 "
                        "request per minute."
                    )
                    time.sleep(60)
                url = (
                    f"{tenant_name}{URLS.get('V1_APP_INSTANCE')}"
                )
                params = {"op": op}
                logger_msg = (
                    f"{create_update_msg} app instance for batch {batch}"
                )
                try:
                    create_instance_response = self.netskope_helper._api_call_helper(
                        url=url,
                        method="post",
                        error_codes=["CRE_1044", "CRE_1048"],
                        params=params,
                        json={
                            "instances": batch_app_instances,
                            "token": auth_token,
                        },
                        proxies=self.proxy,
                        message=f"Error occurred while {logger_msg}",
                        logger_msg=logger_msg,
                    )
                    if create_instance_response.get("errors", []):
                        if len(create_instance_response.get("errors", [])) > 0:
                            batch_failed_action_ids.extend(batch_action_ids)
                            errs = ", ".join(
                                create_instance_response.get("errors", [])
                            )
                            err_msg = (
                                f"Error occurred while {create_update_msg} "
                                "app instance on the Netskope Tenant "
                                f"for batch {batch}."
                            )
                            self.logger.error(
                                message=f"{self.log_prefix}: {err_msg} ",
                                details=errs,
                            )
                            success = False
                            continue
                    elif (
                        create_instance_response.get("status", "").lower() !=
                        SUCCESS.lower()
                    ):
                        batch_failed_action_ids.extend(batch_action_ids)
                        err_msg = (
                            f"Error occurred while {create_update_msg} "
                            "app instance on the Netskope Tenant "
                            f"for batch {batch}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg} ",
                            details=json.dumps(create_instance_response),
                        )
                        success = False
                        continue
                    success = True
                except Exception as err:
                    batch_failed_action_ids.extend(batch_action_ids)
                    error_message = f"Error occurred while {logger_msg}."
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {error_message} "
                            f"Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    success = False
                    continue
                if success:
                    total_app_instances += len(batch_app_instances)
                    added_msg = 'updated' if op == 'update' else 'added'
                    self.logger.info(
                        f"{self.log_prefix}: Successfully "
                        f"{added_msg} {len(batch_app_instances)} "
                        f"app instance(s) for batch {batch}. "
                        f"Total {added_msg} app instances: "
                        f"{total_app_instances}."
                    )
                batch += 1
            if op_counter and payload:
                op_counter += 1
        return success, batch_failed_action_ids

    def _bulk_tag_application(
        self,
        tags_ids_apps: dict,
        cci_tag_action: str,
        item_to_action_map: dict
    ):
        """Bulk tag application.

        Args:
            tags_ids_apps (dict): Dictionary of tags and ids/apps.
            cci_tag_action (str): Action to perform.
            item_to_action_map (dict): Dictionary of items and action ids.
        """
        tenant_name = self.tenant.parameters.get("tenantName", "").strip()
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }
        tags_apps_info = {}
        batch_failed_action_ids = []
        for tag, values in tags_ids_apps.items():
            apps = values.get("apps", [])
            ids = values.get("ids", [])
            total = apps + ids
            batch_count = 0
            tagged_count = 0
            skip_tag_count = 0
            if len(tag) > TAG_APP_TAG_LENGTH:
                self.logger.info(
                    f"{self.log_prefix}: Skipping "
                    f"{'tagging' if cci_tag_action == 'append' else 'untagging'} "
                    f"application(s) with the tag '{tag}' "
                    "as the tag name contains more than "
                    f"{TAG_APP_TAG_LENGTH} characters."
                )
                tags_apps_info[tag] = {
                    "skipped": len(total),
                    "tagged": 0,
                }
                tag_action_ids = list(
                    set([
                        item_to_action_map.get(item)
                        for item in total
                        if item_to_action_map.get(item)
                    ])
                )
                batch_failed_action_ids.extend(tag_action_ids)
                continue

            for i in range(0, len(total), TAG_APP_BATCH_SIZE):
                batch_count += 1
                batch = total[i: i + TAG_APP_BATCH_SIZE]

                batch_action_ids = list(
                    set([
                        item_to_action_map.get(item)
                        for item in batch
                        if item_to_action_map.get(item)
                    ])
                )

                data = (
                    {"tag": tag}
                    | ({"apps": batch} if apps else {})
                    | ({"ids": batch} if ids else {})
                )
                data["action"] = cci_tag_action
                url = (
                    f"{tenant_name}{URLS.get('V2_CCI_TAG_CREATE')}"
                )
                log_message = (
                    f"tagging application(s) "
                    f"with the tag '{tag}' for batch {batch_count}"
                )
                if cci_tag_action == "remove":
                    log_message = (
                        f"untagging application(s) "
                        f"with the tag '{tag}' for batch {batch_count}"
                    )
                try:
                    if cci_tag_action == "append":
                        logger_msg = (
                            f"creating the tag '{tag}' for tagging "
                            f"application(s) for batch {batch_count}"
                        )
                        add_tags_response = self.netskope_helper._api_call_helper(
                            url=url,
                            method="post",
                            error_codes=["CRE_1043", "CRE_1046"],
                            json=data,
                            headers=headers,
                            proxies=self.proxy,
                            message=f"Error occurred while {logger_msg}",
                            logger_msg=logger_msg,
                        )
                        if (
                            add_tags_response.get("message", "") ==
                            ERROR_APP_DOES_NOT_EXIST
                        ):
                            err_msg = (
                                f"Error occurred while {log_message}. "
                                "Invalid Application Name/ID provided."
                            )
                            self.logger.error(f"{self.log_prefix}: {err_msg}")
                            skip_tag_count += len(batch)
                            batch_failed_action_ids.extend(batch_action_ids)
                            continue
                        elif (
                            add_tags_response.get("status_code") == 400 and
                            TAG_EXISTS in add_tags_response.get("error", "")
                        ):
                            # either the tag is one of the pre-defined ones or
                            # the tag already exists;
                            # try updating the existing record
                            url = (
                                f"{tenant_name}"
                                f"{URLS.get('V2_CCI_TAG_UPDATE').format(tag)}"
                            )
                            update_tags_response = self.netskope_helper._api_call_helper(
                                url=url,
                                method="patch",
                                error_codes=["CRE_1043", "CRE_1047"],
                                json=data,
                                headers=headers,
                                proxies=self.proxy,
                                message=(
                                    f"Error occurred while {log_message}"
                                ),
                                logger_msg=log_message,
                            )
                            if (
                                update_tags_response.get("message", "") ==
                                ERROR_APP_DOES_NOT_EXIST
                            ):
                                error_msg = (
                                    f"Error occurred while "
                                    f"{log_message}. "
                                    "Invalid Application Name/ID provided."
                                )
                                self.logger.error(
                                    f"{self.log_prefix}: {error_msg}"
                                )
                                skip_tag_count += len(batch)
                                batch_failed_action_ids.extend(
                                    batch_action_ids
                                )
                                continue
                            elif (
                                TAG_NOT_FOUND in update_tags_response.get(
                                    "error", ""
                                )
                            ):
                                error_msg = (
                                    f"Error occurred while "
                                    f"{log_message}. "
                                    f"Tag '{tag}' does not exists."
                                )
                                self.logger.error(
                                    message=f"{self.log_prefix}: {error_msg}",
                                    resolution=(
                                        "Make sure provided tag exists "
                                        "on the Netskope Tenant for "
                                        "adding the tag to the application(s)."
                                    )
                                )
                                skip_tag_count += len(batch)
                                batch_failed_action_ids.extend(
                                    batch_action_ids
                                )
                                continue
                            elif update_tags_response.get("status", "") != SUCCESS:
                                error_msg = (
                                    "Error occurred while "
                                    f"{log_message}."
                                )
                                self.logger.error(
                                    message=(
                                        f"{self.log_prefix}: {error_msg}"
                                    ),
                                    details=json.dumps(update_tags_response),
                                )
                                skip_tag_count += len(batch)
                                batch_failed_action_ids.extend(
                                    batch_action_ids
                                )
                                continue
                        elif add_tags_response.get("status", "") != SUCCESS:
                            err_msg = (
                                f"Error occurred while {logger_msg}."
                            )
                            self.logger.error(
                                message=f"{self.log_prefix}: {err_msg}",
                                details=json.dumps(add_tags_response),
                            )
                            skip_tag_count += len(batch)
                            batch_failed_action_ids.extend(batch_action_ids)
                            continue
                    else:
                        url = (
                            f"{tenant_name}"
                            f"{URLS.get('V2_CCI_TAG_UPDATE').format(tag)}"
                        )
                        update_tags_response = self.netskope_helper._api_call_helper(
                            url=url,
                            method="patch",
                            error_codes=["CRE_1043", "CRE_1047"],
                            headers=headers,
                            json=data,
                            proxies=self.proxy,
                            message=f"Error occurred while {log_message}",
                            logger_msg=log_message,
                        )
                        if (
                            update_tags_response.get("message", "") ==
                            ERROR_APP_DOES_NOT_EXIST
                        ):
                            error_msg = (
                                f"Error occurred while "
                                f"{log_message}. "
                                "Invalid Application Name/ID provided."
                            )
                            self.logger.error(
                                f"{self.log_prefix}: {error_msg}"
                            )
                            skip_tag_count += len(batch)
                            batch_failed_action_ids.extend(batch_action_ids)
                            continue
                        elif (
                            TAG_NOT_FOUND in update_tags_response.get(
                                "error", ""
                            )
                        ):
                            error_msg = (
                                f"Error occurred while "
                                f"{log_message}. "
                                f"Tag '{tag}' does not exists."
                            )
                            self.logger.error(
                                message=f"{self.log_prefix}: {error_msg}",
                                resolution=(
                                    "Make sure provided tag exists "
                                    "on the Netskope Tenant for "
                                    "removing the tag from the application(s)."
                                )
                            )
                            skip_tag_count += len(batch)
                            batch_failed_action_ids.extend(batch_action_ids)
                            continue
                        elif update_tags_response.get("status", "") != SUCCESS:
                            error_msg = (
                                "Error occurred while "
                                f"{log_message}."
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {error_msg}"
                                ),
                                details=json.dumps(update_tags_response),
                            )
                            skip_tag_count += len(batch)
                            batch_failed_action_ids.extend(batch_action_ids)
                            continue
                except Exception as err:
                    batch_failed_action_ids.extend(batch_action_ids)
                    error_message = f"Error occurred while {logger_msg}."
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {error_message} "
                            f"Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skip_tag_count += len(batch)
                    continue

                tagged_count += len(batch)
                logger_msg = (
                    "Successfully tagged "
                    f"{len(batch)} application(s) with tag '{tag}' "
                    f"for batch {batch_count}. "
                    f"Total tagged applications: {tagged_count}."
                )
                if cci_tag_action == "remove":
                    logger_msg = (
                        "Successfully "
                        f"untagged the tag '{tag}' from {len(batch)} "
                        f"application(s) for batch {batch_count}. "
                        f"Total untagged applications: {tagged_count}."
                    )
                self.logger.debug(
                    f"{self.log_prefix}: {logger_msg}"
                )
            tags_apps_info[tag] = {
                "skipped": skip_tag_count,
                "tagged": tagged_count
            }
        return tags_apps_info, batch_failed_action_ids
