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

import json
import re
import time
import traceback
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union

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
    TAG_DEVICE_BATCH_SIZE,
    TAG_EXISTS,
    DEVICE_FIELD_MAPPING,
    MAX_TAGS_PER_DEVICE,
    TAG_CACHE_PAGE_SIZE,
)
from .utils.helper import NetskopePluginHelper, NetskopeException

plugin_provider_helper = PluginProviderHelper()


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
                        required=True,
                    ),
                    EntityField(name="ubaScore", type=EntityFieldType.NUMBER),
                    EntityField(
                        name="policyName", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="cci", type=EntityFieldType.NUMBER
                    ),
                    EntityField(
                        name="ccl", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="deviceClassification", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="policyAction", type=EntityFieldType.LIST
                    ),
                    EntityField(
                        name="severity", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="destinationIP", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="sourceRegion", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="sourceIP", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="userIP", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="policyID", type=EntityFieldType.STRING
                    ),
                ],
            ),
            Entity(
                name="Applications",
                fields=[
                    EntityField(
                        name="applicationId", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="applicationName",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(name="vendor", type=EntityFieldType.STRING),
                    EntityField(name="source", type=EntityFieldType.STRING),
                    EntityField(name="cci", type=EntityFieldType.NUMBER),
                    EntityField(name="ccl", type=EntityFieldType.STRING),
                    EntityField(
                        name="categoryName", type=EntityFieldType.STRING
                    ),
                    EntityField(name="users", type=EntityFieldType.LIST),
                    EntityField(name="deepLink", type=EntityFieldType.STRING),
                    EntityField(name="customTags", type=EntityFieldType.LIST),
                    EntityField(
                        name="discoveryDomains", type=EntityFieldType.LIST
                    ),
                    EntityField(
                        name="steeringDomains", type=EntityFieldType.LIST
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
                    ),
                    EntityField(
                        name="Hostname",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Netskope Device UID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Mac Addresses",
                        type=EntityFieldType.LIST
                    ),
                    EntityField(
                        name="Last Connected from Private IP",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Last Connected from Public IP",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Device Serial Number",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Operating System",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Operating System Version",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Device Make",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Device Model",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Last Updated Timestamp",
                        type=EntityFieldType.DATETIME
                    ),
                    EntityField(
                        name="Management ID",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Steering Config",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Region",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="User Name",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="User Key",
                        type=EntityFieldType.LIST,
                        required=True,
                    ),
                    EntityField(
                        name="Device Classification Status",
                        type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Tags",
                        type=EntityFieldType.LIST
                    ),
                ],
            )
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
        for record in records:
            # Make a copy to avoid modifying the original record in case of failure
            updated_record = {}

            device_uid = record.get("Netskope Device UID")
            user_key = record.get("User Key")
            updated_record["Device Serial Number"] = record.get(
                "Device Serial Number"
            )
            updated_record["Device ID"] = record.get("Device ID")
            updated_record["Netskope Device UID"] = device_uid
            updated_record["User Key"] = user_key

            # Handle User Key as list (multi-user scenario)
            user_keys = user_key
            if isinstance(user_key, str):
                user_keys = [user_key] if user_key else []
            elif not isinstance(user_key, list):
                user_keys = []

            unique_user_keys = set()
            for uk in user_keys:
                unique_user_keys.add(uk)

            if not device_uid or not unique_user_keys:
                self.logger.info(
                    f"{self.log_prefix}: Missing Netskope Device UID or "
                    f"User Key for device '{record.get('Device ID')}'. "
                    "Skipping update."
                )
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
                    {"nsdeviceuid": device_uid, "userkey": user_key}
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

        self.logger.info(
            f"{self.log_prefix}: Successfully updated {len(updated_records)}"
            f" record(s). Fetched tag(s) for {total_updated_record_counter} out "
            f"of {len(records)} record(s)."
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
            f"{self.log_prefix}: {logger_msg.capitalize()} on "
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
            if "events" in modified_type_map and "clientstatus" in modified_type_map.get("events", []):
                try:
                    provider.client_status_validation()
                    modified_type_map["events"] = [
                        event_type
                        for event_type in modified_type_map.get("events", [])
                        if event_type != "clientstatus"
                    ]
                except Exception as e:
                    return ValidationResult(success=False, message=str(e))

            provider.permission_check(
                modified_type_map,
                plugin_name=self.plugin_name,
                configuration_name=self.name,
            )

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

    def _validate_port(self, port):
        """Validate the port or port range.

        Args:
            port: Port number as int/str or port range as 'lower-upper' string

        Returns:
            bool: True if port or port range is valid, False otherwise
        """
        # Handle port range (e.g., '1000-2000')
        if isinstance(port, str) and '-' in port:
            try:
                lower, upper = port.split('-')
                lower_port = int(lower.strip())
                upper_port = int(upper.strip())
                # Check if ports are within valid range
                if not (0 <= lower_port <= 65535 and 0 <= upper_port <= 65535):
                    return False
                # Check if lower is less than upper and they are not equal
                if lower_port >= upper_port:
                    return False
                return True
            except (ValueError, AttributeError):
                return False

        # Handle single port
        try:
            port = int(port)
            return 0 <= port <= 65535
        except (ValueError, TypeError):
            return False

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
                    details=traceback.format_exc(),
                    error_code="CRE_1042",
                )
                return ValidationResult(success=False, message=str(e))

            tags = action.parameters.get("tags", "")
            if tags and "$" not in tags:
                for tag in tags.split(","):
                    if len(tag.strip()) > 30:
                        return ValidationResult(
                            success=False,
                            message=(
                                "Each tag should be less than or equal "
                                "to 30 characters."
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
            if (
                action.parameters.get("private_app_name", "") == "create"
                and not protocols
            ):
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
                if not tcp_port_list:
                    return ValidationResult(
                        success=False,
                        message=(
                            "If you have selected 'TCP' in Protocols, "
                            "TCP Port should not be empty."
                        ),
                    )
                if not all(
                    self._validate_port(port) for port in tcp_port_list
                ):
                    return ValidationResult(
                        success=False,
                        message=(
                            "Invalid TCP Port or Port Range provided."
                            " Valid values are between 0 and 65535."
                        ),
                    )
            if "UDP" in protocols:
                if not udp_port_list:
                    return ValidationResult(
                        success=False,
                        message=(
                            "If you have selected 'UDP' in Protocols, "
                            "UDP Port should not be empty."
                        ),
                    )
                if not all(
                    self._validate_port(port) for port in udp_port_list
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
                details=str(traceback.format_exc()),
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
        params = {"fields": "app_id,app_name,host"}  # we need only 3 fields
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
                } | (
                    {"hosts": x["host"].split(",")}
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
                details=str(traceback.format_exc()),
            )
            raise NetskopeException(error_message)
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched "
            f"{len(dict_of_private_apps)} private app(s)."
        )
        return dict_of_private_apps

    def _get_private_app(
        self,
        prefix: str,
        has_host: Optional[str] = None,
    ) -> Union[dict, tuple]:
        """Check private app present in Netskope and \
            create a new one if not found.

        Args:
            prefix (str): Private app name.
            has_host (str): Private app name.

        Returns:
            Dict: Dictionary of private apps.
        """
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
        params = {"fields": "app_id,app_name,host"}  # we need only 3 fields
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
            for app in existing_private_apps:
                split_hosts = app.get("host", "").split(",")
                if not app["app_name"].startswith(prefix.removesuffix("]")):
                    continue
                if has_host not in split_hosts:
                    continue
                return app
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
        return None

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
    ):
        """Push a private app to Netskope with the provided indicators, \
            app names, protocols, and publishers.

        Args:
            host (Union[str, list[str]]): The host to be pushed.
            existing_private_app_name (str): The name of an \
                existing private app.
            new_private_app_name (str): The name of a new private app.
            protocol_type (List[str]): The list of protocol types.
            tcp_ports (List[int]): The list of TCP ports.
            udp_ports (List[int]): The list of UDP ports.
            publishers (List[str]): The list of publishers.
            use_publisher_dns (bool): A boolean indicating whether \
                to use the publisher DNS.
            default_url (str): The default host.
            tags (List[str], optional): The list of tags. Defaults to [].
        """
        tenant_name = (
            self.tenant.parameters.get('tenantName', '').strip()
        )
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token", "")
            )
        }

        try:
            if existing_private_app_name == "create":
                private_app_name = f"[{new_private_app_name}]"
            else:
                private_app_name = existing_private_app_name
            existing_private_apps = self._get_private_apps(
                get_hosts_of=private_app_name
            )
            final_name = private_app_name
            counter = 2
            while True:
                if final_name not in existing_private_apps:
                    existing_private_app_name = final_name.removeprefix(
                        "["
                    ).removesuffix("]")
                    break
                if (
                    existing_private_apps[final_name].get("host_count", 0)
                    < MAX_HOSTS_PER_PRIVATE_APP
                ):
                    break
                final_name = f"[{private_app_name.removeprefix('[').removesuffix(']')} {counter}]"
                counter += 1
            private_app_name = final_name
            existing_publishers = self._get_publishers()
            protocols_list = []
            for protocol in protocol_type:
                if protocol == "TCP":
                    protocols_list.append(
                        {"type": "tcp", "ports": ",".join(tcp_ports)}
                    )
                if protocol == "UDP":
                    protocols_list.append(
                        {"type": "udp", "ports": ",".join(udp_ports)}
                    )

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
            # Check if the private app already exists
            if private_app_name not in existing_private_apps:
                # Creating URL List
                self.logger.debug(
                    f"{self.log_prefix}: Private app '{private_app_name}' "
                    "does not exist. Creating a new private app."
                )

                if existing_private_app_name == "create":
                    app_name_to_create = new_private_app_name
                else:
                    app_name_to_create = existing_private_app_name

                data = {
                    "app_name": app_name_to_create,
                    "host": default_url,
                    "publishers": publishers_list,
                    "use_publisher_dns": use_publisher_dns,
                }
                if protocols_list:
                    data["protocols"] = protocols_list
                logger_msg = "creating private app on the Netskope Tenant"
                url = (
                    f"{tenant_name}{URLS.get('V2_PRIVATE_APP')}"
                )
                response = self.netskope_helper._api_call_helper(
                    url=url,
                    method="post",
                    error_codes=["CRE_1043", "CRE_1044"],
                    headers=headers,
                    json=data,
                    proxies=self.proxy,
                    message=f"Error occurred while {logger_msg}",
                    logger_msg=logger_msg,
                    is_handle_error_required=False
                )

                if response.status_code not in [
                    200,
                    201,
                ]:
                    err_msg = (
                        f"Error occurred while {logger_msg}. "
                    )
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

                existing_private_apps[
                    create_private_app_json["data"]["app_name"]
                ] = {
                    "id": create_private_app_json["data"]["app_id"],
                    "host_count": 0,
                    "hosts": [],
                }

            if host and isinstance(host, str):
                host = list(map(lambda x: x.strip(), host.split(",")))
            data = {
                "host": ",".join(
                    list(
                        set(
                            existing_private_apps[private_app_name].get(
                                "hosts", []
                            )
                        ).union(host)
                    )
                ),
                "tags": (
                    list(map(lambda t: {"tag_name": t}, tags)) if tags else []
                ),
                "publishers": publishers_list,
                "use_publisher_dns": use_publisher_dns,
            }
            if protocols_list:
                data["protocols"] = protocols_list
            return self._patch_private_app(
                tenant_name,
                existing_private_apps[private_app_name].get("id", ""),
                data,
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
                    f"{self.log_prefix}: {log_message.capitalize()}."
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
                            f"{self.log_prefix}: {err_msg}."
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
                    f"tag will be skipped for {str(action)} action"
                )
                self.logger.info(f"{self.log_prefix}: {err_msg}")
                failed_tags.append(tag)
                continue

            if len(tag) > TAG_DEVICE_TAG_LENGTH:
                err_msg = (
                    f"Invalid tag '{tag}' provided. Tag length cannot "
                    f"exceed {TAG_DEVICE_TAG_LENGTH} characters. This"
                    f"tag will be skipped for {str(action)} action"
                )
                self.logger.info(f"{self.log_prefix}: {err_msg}")
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
                self.logger.debug(f"{self.log_prefix}: {log_message.capitalize()}.")

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
                            message=f"{self.log_prefix}: {err_msg}",
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
            f"Successfully {'added' if cci_tag_action == 'append' else 'removed'} "
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
            action_name: str = ""
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
                    if action_name == "replace" and len(list_values) > 1:
                        log_and_raise = True
                    elif action_name != "replace":
                        log_and_raise = True

                    if log_and_raise:
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

        skip_tag_validation = isinstance(tags, str) and tags.startswith("$")
        tags = convert_to_list(
            action_name=tag_action,
            value=tags,
            field_name="Tags",
            is_validation=is_validation
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
                f"'{tag_action}' action."
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

        if (not device_id and not device_user_key) and not (
            skip_device_id_validation or skip_device_user_key_validation
        ):
            err_msg = (
                "Invalid value for Netskope Device UID/User Key provided. "
                "Provide either Netskope Device UID or User Key."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise NetskopeException(err_msg)

        return tags, device_id, device_user_key, tag_action

    def revert_action(self, action: Action):
        """Revert the action.

        Args:
            action (Action): Action to be reverted.
        """
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        action.parameters = get_latest_values(
            action.parameters, exclude_keys=["tags", "protocol", "publishers"]
        )
        if action.value == "private_app":
            action_dict = action.parameters
            existing_private_app_name = action_dict.get("private_app_name", "")
            new_private_app_name = action_dict.get("name", "")
            host = action_dict.get("host", "")
            if existing_private_app_name == "create":
                private_app_name = f"[{new_private_app_name}]"
            else:
                private_app_name = existing_private_app_name
            if not host:
                self.logger.info(
                    f"{self.log_prefix}: Host value not found in the "
                    f"record for private app {private_app_name}. "
                    "Hence, skipped execution of revert action."
                )
                return
            self.logger.info(
                f"{self.log_prefix}: Attempting to remove the host {host} "
                f"from private app {private_app_name}."
            )
            app = self._get_private_app(
                prefix=private_app_name, has_host=action_dict.get("host", "")
            )
            if not app:
                self.logger.info(
                    f"{self.log_prefix}: Host {host} not found "
                    f"in {private_app_name}. "
                    "Hence, skipped execution of revert action."
                )
                return
            data = {
                "host": ",".join(
                    list(filter(
                        lambda x: x != host, app.get("host", "").split(",")
                    ))
                )
            }
            return self._patch_private_app(
                self.tenant.parameters.get('tenantName').strip(),
                app.get("app_id", ""),
                data,
            )
        raise NotImplementedError()

    def _patch_private_app(self, tenant: str, app_id: str, data: dict):
        """Patch an existing private app.

        Args:
            tenant (str): Tenant base URL.
            app_id (str): Existing app id.
            data (dict): Request body.

        Raises:
            NetskopeException: Error in the response.
            NetskopeException: Non-2xx status code.
        """
        logger_msg = "adding host to private app"
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
                f"{self.log_prefix}: Successfully updated the private app for "
                f"configuration {self.plugin_name}."
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
        return

    def _execute_private_app_action(self, action_dict: dict):
        """Execute action on the given parameters.

        Args:
            action_dict (dict): Action parameters.
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
            tags = list(map(lambda x: x.strip(), tags.split(",")))
            for tag in tags:
                if len(tag) > 30:
                    err_msg = (
                        "Found tag length greater than 30 characters. "
                        "Tag length should be less than or "
                        "equal to 30 characters."
                    )
                    self.logger.error(
                        message=err_msg,
                        details=str(tag),
                        resolution=(
                            "Make sure tag length is less than or "
                            "equal to 30 characters."
                        )
                    )
                    raise NetskopeException(err_msg)

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

    def _bulk_add_remove_tag_device(self, actions: List[Action], action_label: str) -> List[str]:
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
            action_value = None
            for action_dict in actions:
                action_id, action = action_dict.get("id"), action_dict.get("params")
                try:
                    (
                        tags,
                        device_id,
                        device_user_key,
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

                    if not unique_user_keys or not device_id:
                        failed_action_ids.append(action_id)
                        continue

                    for user_key in unique_user_keys:
                        device = {"nsdeviceuid": device_id, "userkey": user_key}

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
                        f"action '{action_label}' for record with ID '{action_id}'. "
                        f"Error: {e}."
                    )
                    failed_action_ids.append(action_id)
            log_msg = ""
            skipped_records = len(failed_action_ids)
            if skipped_records > 0:
                log_msg = (
                    f" {skipped_records} record(s) will be skipped "
                    "either due to being invalid or missing "
                    "'Netskope Device UID' or 'User Key' field values."
                )
            self.logger.info(
                f"{self.log_prefix}: Performing '{action_value}' Tag(s)"
                f" action on {len(actions)-skipped_records} "
                f"record(s).{log_msg if log_msg else ''}"
            )
            for (tag, cci_tag_action), group_data in tag_groups.items():
                devices = group_data['devices']
                action_id_to_devices = group_data['action_id_to_devices']

                try:
                    tag_ids, tag_cache = self._query_and_create_tags_with_cache(
                        [tag], action=cci_tag_action, tag_cache=tag_cache
                    )

                    unique_devices = []
                    seen_devices = set()
                    for device in devices:
                        device_key = (device.get("nsdeviceuid"), device.get("userkey"))
                        if device_key not in seen_devices:
                            unique_devices.append(device)
                            seen_devices.add(device_key)

                    total_batches = (len(unique_devices) + TAG_DEVICE_BATCH_SIZE - 1) // TAG_DEVICE_BATCH_SIZE
                    for batch_num in range(total_batches):
                        start_idx = batch_num * TAG_DEVICE_BATCH_SIZE
                        end_idx = min(start_idx + TAG_DEVICE_BATCH_SIZE, len(unique_devices))
                        device_batch = unique_devices[start_idx:end_idx]
                        
                        batch_action_ids = []
                        batch_device_keys = set(
                            (d.get("nsdeviceuid"), d.get("userkey"))
                            for d in device_batch
                        )
                        for action_id, action_devices in action_id_to_devices.items():
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
                                f"{self.log_prefix}: Processing batch {batch_num + 1}/{total_batches} "
                                f"of {len(device_batch)} device record(s) for tag '{tag}'."
                            )
                            self._tag_devices(tag_ids, device_batch, cci_tag_action)
                            
                            self.logger.info(
                                f"{self.log_prefix}: Successfully {'tagged' if cci_tag_action == 'append' else 'untagged'} "
                                f"batch {batch_num + 1}/{total_batches} ({len(device_batch)} device record(s)) with tag '{tag}'."
                            )
                        
                        except Exception as batch_e:
                            self.logger.error(
                                f"{self.log_prefix}: Failed to {'tag' if cci_tag_action == 'append' else 'untag'} "
                                f"batch {batch_num + 1}/{total_batches} ({len(device_batch)} device record(s)) with tag '{tag}'. "
                                f"Error: {batch_e}"
                            )
                            failed_action_ids.extend(batch_action_ids)

                except Exception as group_e:
                    self.logger.error(
                        f"{self.log_prefix}: Failed to execute action '{action_label}' for tag '{tag}'. "
                        f"Error: {group_e}"
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
        for action_dict in actions:
            action_id = action_dict.get("id")
            action = action_dict.get("params")
            try:
                (
                    tags,
                    device_id,
                    device_user_key,
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

                if not unique_user_keys or not device_id:
                    failed_action_ids.append(action_id)
                    continue

                for user_key in unique_user_keys:
                    device_key = (device_id, user_key)
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
                    f"Error: {e}."
                )
                failed_action_ids.append(action_id)
        log_msg = ""
        skipped_records = len(failed_action_ids)
        if skipped_records > 0:
            log_msg = (
                f" {skipped_records} record(s) will be skipped "
                "either due to being invalid or missing "
                "'Netskope Device UID' or 'User Key' field values."
            )
        self.logger.info(
            f"{self.log_prefix}: Performing 'Replace' Tag(s) "
            f"action on {len(actions)-skipped_records} "
            f"record(s).{log_msg if log_msg else ''}"
        )

        tag_set_groups = {}

        for (device_id, user_key), group_data in device_to_tags.items():
            tags = sorted(list(group_data['tags']))  # Sort for consistent grouping
            action_ids = group_data['action_ids']

            # 5-tag limit
            if len(tags) > MAX_TAGS_PER_DEVICE:
                skipped_tags = tags[MAX_TAGS_PER_DEVICE:]
                tags = tags[:MAX_TAGS_PER_DEVICE]
                self.logger.info(
                    f"{self.log_prefix}: Device '{device_id}' (userkey: "
                    f"'{user_key}') has more than {MAX_TAGS_PER_DEVICE} tags. "
                    f"Only the first {MAX_TAGS_PER_DEVICE} sorted tags will be "
                    f"applied: {tags}. Skipped tags: {skipped_tags}"
                )

            tag_set_key = tuple(tags)
            if tag_set_key not in tag_set_groups:
                tag_set_groups[tag_set_key] = {
                    'devices': [],
                    'action_ids': set()
                }

            device = {"nsdeviceuid": device_id, "userkey": user_key}
            tag_set_groups[tag_set_key]['devices'].append(device)
            tag_set_groups[tag_set_key]['action_ids'].update(action_ids)

        self.logger.debug(
            f"{self.log_prefix}: Grouped {len(device_to_tags)} device record(s) into "
            f"{len(tag_set_groups)} tag set group(s)."
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
                    f"{len(devices)} device record(s) in {total_batches} batch(es)."
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

                        self._replace_device_tags(tag_ids, device_batch)

                        self.logger.info(
                            f"{self.log_prefix}: Successfully replaced tags "
                            f"on batch {batch_num + 1}/{total_batches} "
                            f"({len(device_batch)} device records) with tags {tags}."
                        )

                    except Exception as batch_e:
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

    def execute_action(self, action: Action):
        """Execute action on the user.

        Args:
            action (Action): Action object.
        """
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        action.parameters = get_latest_values(
            action.parameters,
            exclude_keys=["host", "tags", "protocol", "publishers"],
        )
        self.logger.info(
            f"{self.log_prefix}: Executing '{action.label}' action."
        )
        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action.label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action.label}' action."
            )
            return
        elif action.value == "impact":
            if 'performRevert' in Action.model_fields and action.performRevert:
                anomaly_id = action.parameters.get("anomaly_id", "")
                if not anomaly_id:
                    err_msg = (
                        "Unable to find the Anomaly ID, hence "
                        "Revert UCI Impact Action will be skipped."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    raise NetskopeException(err_msg)
                self.revert_uci_update_impact(anomaly_id)
                self.logger.info(
                    f"{self.log_prefix}: Successfully marked anomaly ID "
                    f"{anomaly_id} as allowed."
                )
                return

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

    def execute_actions(self, actions):
        """Execute actions in bulk.

        Args:
            actions (List[Action]): List of Action objects.
        """
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        first_action = actions[0].get("params")
        action_label = first_action.label
        self.logger.info(
            f"{self.log_prefix}: Executing '{action_label}' action "
            f"for {len(actions)} records."
        )
        failed_action_ids = []
        if first_action.value == "private_app":
            private_apps = {}
            action_id_to_app_mapping = {}
            for action_dict in actions:
                id, action = action_dict.get("id"), action_dict.get("params")
                app_name = (
                    action.parameters.get("private_app_name", "")
                    if action.parameters.get("private_app_name", "") != "create"
                    else action.parameters.get("name", "")
                )
                private_apps.setdefault(app_name, []).append(action.parameters)
                action_id_to_app_mapping[id] = app_name
            for app_name, batched_actions in private_apps.items():
                batch_action_ids = [
                    action_id for action_id, mapped_app_name in action_id_to_app_mapping.items()
                    if mapped_app_name == app_name
                ]
                try:
                    first_action = batched_actions[0]
                    params = first_action.copy()
                    params["host"] = [
                        host_item
                        for action in batched_actions
                        for host_item in (
                            action["host"] if isinstance(action["host"], list)
                            else [action["host"]]
                        )
                        if host_item
                    ]
                    params = get_latest_values(
                        params,
                        exclude_keys=["host", "tags", "protocol", "publishers"],
                    )
                    self._execute_private_app_action(params)
                except Exception as e:
                    failed_action_ids.extend(batch_action_ids)
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while adding "
                        f"hosts to private apps. Error: {str(e)}"
                    )

            return ActionResult(
                success=True,
                message="Successfully added hosts to private apps.",
                failed_action_ids=failed_action_ids
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
                                f"Error: {e}. Continuing with next batch."
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
                                f"Error: {e}. Continuing with next batch."
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
                        f"Error: {e}."
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

    # TODO: Implement cleanup method to delete client status iterator