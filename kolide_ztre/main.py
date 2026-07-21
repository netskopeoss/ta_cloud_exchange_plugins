"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Netskope CRE Kolide Plugin.
"""

import traceback
from typing import Callable, Dict, List, Optional, Tuple, Type

import jwt

from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.crev2.plugin_base import (
    ActionResult,
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType,
)

from .utils.constants import (
    ACTION,
    ACTION_MANAGE_GROUP,
    ACTION_NO_ACTION,
    BASE_URL,
    CONFIGURATION,
    CUSTOM_SEPARATOR,
    DEVICE_FIELD_MAPPING,
    DEVICE_GROUP_MEMBERSHIP_BATCH_SIZE,
    EMPTY_ERROR_MESSAGE,
    GROUP_ACTION_TYPE_ADD,
    GROUP_ACTION_TYPE_REMOVE,
    DEVICES_ENDPOINT,
    DEVICES_ENTITY,
    DEVICE_GROUPS_ENDPOINT,
    DEPROVISIONED_PEOPLE_ENDPOINT,
    INVALID_VALUE_ERROR_MESSAGE,
    ISSUES_ENDPOINT,
    MODULE_NAME,
    PAGE_SIZE,
    PEOPLE_ENDPOINT,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    SSF_CAEP_COMPLIANCE_EVENT,
    SSF_STORAGE_POLL_TOKEN,
    SSF_STORAGE_STREAM_ID,
    SSF_STREAM_NAME,
    SUPPORTED_ACTIONS,
    TYPE_ERROR_MESSAGE,
    USER_FIELD_MAPPING,
    USERS_ENTITY,
    VALIDATION_ERROR_MESSAGE,
    WHOAMI_ENDPOINT,
)
from .utils.exceptions import (
    KolidePluginException,
    SSFStreamNotFoundError,
)
from .utils.helper import KolidePluginHelper


class KolidePlugin(PluginBase):
    """Kolide CRE ZTRE plugin class."""

    def __init__(self, name, *args, **kwargs):
        """Initialize the Kolide plugin.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        # Display name of the SSF compliance stream created on Kolide,
        # scoped to this plugin configuration's name so multiple configs
        # on one tenant get distinct streams.
        self.ssf_stream_name = f"{SSF_STREAM_NAME} ({self.name})"
        self.provide_action_id = True
        self.helper = KolidePluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from the manifest metadata.

        Returns:
            tuple: Two-tuple of (plugin_name, plugin_version).
        """
        try:
            metadata = KolidePlugin.metadata
            return (
                metadata.get("name", PLUGIN_NAME),
                metadata.get("version", PLUGIN_VERSION),
            )
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    # ------------------------------------------------------------------
    # Entity definitions
    # ------------------------------------------------------------------

    def get_entities(self) -> list:
        """Return the list of entities exposed by this plugin.

        Entity fields are populated dynamically based on the plugin
        configuration toggles: the ``Is Deleted`` User field is exposed
        only when ``fetch_deprovisioned_people`` is enabled; the
        ``Open Issues Count`` and ``Issue Title`` Device fields only
        when ``fetch_open_issues`` is enabled; and the
        ``Compliance Status`` and ``User Email`` Device fields only when
        ``fetch_compliance_status`` is enabled.

        Returns:
            list[Entity]: Users and Devices entities with their fields.
        """
        fetch_deprovisioned = (
            self.configuration.get(
                "fetch_deprovisioned_people", "yes"
            ) == "yes"
        )
        fetch_issues = (
            self.configuration.get("fetch_open_issues", "yes") == "yes"
        )
        fetch_compliance = (
            self.configuration.get(
                "fetch_compliance_status", "yes"
            ) == "yes"
        )

        user_fields = [
            EntityField(
                name="Email",
                type=EntityFieldType.STRING,
                description=(
                    "User's email address. This field can be"
                    " used to merge User records with other CRE"
                    " plugins."
                ),
                required=True,
            ),
            EntityField(
                name="User ID",
                type=EntityFieldType.STRING,
                description="Unique Kolide identifier of the user.",
            ),
            EntityField(
                name="Name",
                type=EntityFieldType.STRING,
                description="Full name of the user.",
            ),
            EntityField(
                name="Created At",
                type=EntityFieldType.DATETIME,
                description=(
                    "Timestamp when the user was created in"
                    " Kolide."
                ),
            ),
            EntityField(
                name="Last Authenticated At",
                type=EntityFieldType.DATETIME,
                description=(
                    "Timestamp when the user last authenticated"
                    " to Kolide."
                ),
            ),
            EntityField(
                name="Has Registered Device",
                type=EntityFieldType.BOOLEAN,
                description=(
                    "Whether the user has at least one"
                    " registered device."
                ),
            ),
            EntityField(
                name="Usernames",
                type=EntityFieldType.LIST,
                description=(
                    "Usernames associated with the user."
                ),
            ),
        ]
        if fetch_deprovisioned:
            user_fields.append(
                EntityField(
                    name="Is Deleted",
                    type=EntityFieldType.BOOLEAN,
                    description=(
                        "Whether the user is deprovisioned"
                        " (deleted or disabled) in Kolide."
                    ),
                )
            )

        device_fields = [
            EntityField(
                name="Device ID",
                type=EntityFieldType.STRING,
                description=(
                    "Unique Kolide identifier of the device."
                ),
                required=True,
            ),
            EntityField(
                name="Name",
                type=EntityFieldType.STRING,
                description="Name of the device.",
            ),
            EntityField(
                name="Device Serial Number",
                type=EntityFieldType.STRING,
                description=(
                    "Hardware serial number of the device. This"
                    " field can be used to merge Device records"
                    " with other CRE plugins."
                ),
                required=True,
            ),
            EntityField(
                name="Hardware UUID",
                type=EntityFieldType.STRING,
                description="Hardware UUID of the device.",
            ),
            EntityField(
                name="Hardware Model",
                type=EntityFieldType.STRING,
                description="Hardware model of the device.",
            ),
            EntityField(
                name="Operating System",
                type=EntityFieldType.STRING,
                description=(
                    "Operating system running on the device."
                ),
            ),
            EntityField(
                name="Device Type",
                type=EntityFieldType.STRING,
                description="Type of the device.",
            ),
            EntityField(
                name="Form Factor",
                type=EntityFieldType.STRING,
                description=(
                    "Physical form factor of the device"
                    " (e.g. laptop, desktop)."
                ),
            ),
            EntityField(
                name="Registered At",
                type=EntityFieldType.DATETIME,
                description=(
                    "Timestamp when the device was registered"
                    " in Kolide."
                ),
            ),
            EntityField(
                name="Last Authenticated At",
                type=EntityFieldType.DATETIME,
                description=(
                    "Timestamp when the device last"
                    " authenticated to Kolide."
                ),
            ),
            EntityField(
                name="Last Seen At",
                type=EntityFieldType.DATETIME,
                description=(
                    "Timestamp when the device was last seen by"
                    " Kolide."
                ),
            ),
            EntityField(
                name="Auth State",
                type=EntityFieldType.STRING,
                description=(
                    "Current authentication state of the"
                    " device."
                ),
            ),
            EntityField(
                name="Will Block At",
                type=EntityFieldType.DATETIME,
                description=(
                    "Timestamp when the device will be blocked"
                    " if it remains non-compliant."
                ),
            ),
            EntityField(
                name="User ID",
                type=EntityFieldType.REFERENCE,
                description=(
                    "User ID of the device's registered owner."
                    " This field is used to reference CRE Kolide"
                    " plugin's User entity"
                ),
            ),
            EntityField(
                name="Authentication Mode",
                type=EntityFieldType.STRING,
                description=(
                    "Authentication mode configured for the"
                    " device."
                ),
            ),
        ]
        if fetch_issues:
            device_fields.extend(
                [
                    EntityField(
                        name="Open Issues Count",
                        type=EntityFieldType.NUMBER,
                        description=(
                            "Number of open, non-exempted compliance"
                            " issues on the device."
                        ),
                    ),
                    EntityField(
                        name="Exempted Issues Count",
                        type=EntityFieldType.NUMBER,
                        description=(
                            "Number of open, exempted compliance issues"
                            " on the device."
                        ),
                    ),
                    EntityField(
                        name="Issue Title",
                        type=EntityFieldType.LIST,
                        description=(
                            "Titles of the open compliance issues on"
                            " the device."
                        ),
                    ),
                ]
            )
        if fetch_compliance:
            device_fields.extend(
                [
                    EntityField(
                        name="Compliance Status",
                        type=EntityFieldType.STRING,
                        description=(
                            "Device compliance status from the Kolide"
                            " SSF (Shared Signals Framework) stream."
                        ),
                    ),
                    EntityField(
                        name="User Email",
                        type=EntityFieldType.STRING,
                        description=(
                            "Email address of the device's registered"
                            " owner. This field can be used to merge"
                            " Kolide device records with user records"
                            " from other CRE plugins."
                        ),
                    ),
                ]
            )

        return [
            Entity(
                name="Users",
                fields=user_fields,
            ),
            Entity(
                name="Devices",
                fields=device_fields,
            ),
        ]

    def _get_storage(self):
        storage = self.storage if self.storage is not None else {}
        return storage

    # ------------------------------------------------------------------
    # Fetch helpers (used by both fetch_records and update_records)
    # ------------------------------------------------------------------

    def _fetch_all_issues(
        self, headers: Dict
    ) -> Tuple[Dict[str, int], Dict[str, int], Dict[str, List[str]]]:
        """Fetch all open (unresolved) issues and build per-device maps.

        Args:
            headers (Dict): Authentication and version headers.

        Returns:
            Tuple[Dict[str, int], Dict[str, int], Dict[str, List[str]]]:
                A three-tuple of ``(device_issue_counts,
                device_exempted_counts, device_issue_titles)`` mapping
                device_id -> open non-exempted issue count, device_id ->
                open exempted issue count, and device_id -> list of all
                open issue titles (exempted titles suffixed
                ``(Exempted)``) respectively.
        """
        url = ISSUES_ENDPOINT.format(base_url=BASE_URL)
        all_issues = self.helper.fetch_paginated_list(
            endpoint_url=url,
            headers=headers,
            logger_msg="fetching all issues",
            item_label="open issue(s)",
        )
        device_issue_counts: Dict[str, int] = {}
        device_exempted_counts: Dict[str, int] = {}
        device_issue_titles: Dict[str, List[str]] = {}
        for issue in all_issues:
            if issue.get("resolved_at") is not None:
                continue
            device_id = issue.get("device_information", {}).get("identifier")
            if not device_id:
                continue
            exempted = issue.get("exempted")
            if exempted:
                device_exempted_counts[device_id] = (
                    device_exempted_counts.get(device_id, 0) + 1
                )
            else:
                device_issue_counts[device_id] = (
                    device_issue_counts.get(device_id, 0) + 1
                )
            title = issue.get("title")
            if title:
                if exempted:
                    title = f"{title} (Exempted)"
                device_issue_titles.setdefault(device_id, []).append(
                    title
                )
        return (
            device_issue_counts,
            device_exempted_counts,
            device_issue_titles,
        )

    # ------------------------------------------------------------------
    # fetch_records
    # ------------------------------------------------------------------

    def fetch_records(self, entity: str) -> list:
        """Fetch all records for the given entity type from Kolide.

        Args:
            entity (str): Entity name – one of ``USERS_ENTITY`` or
                ``DEVICES_ENTITY``.

        Returns:
            list[dict]: List of normalised record dictionaries.

        Raises:
            KolidePluginException: On any API or unexpected error.
        """
        if entity not in [USERS_ENTITY, DEVICES_ENTITY]:
            err_msg = (
                f"Invalid entity type '{entity}'."
                f" Supported: {USERS_ENTITY}, {DEVICES_ENTITY}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Ensure the entity is one of "
                    f"'{USERS_ENTITY}' or '{DEVICES_ENTITY}'."
                ),
            )
            raise KolidePluginException(err_msg)

        try:
            (api_token,) = self.helper.get_configuration_parameters(
                self.configuration
            )
            headers = self.helper.get_auth_headers(api_token)

            if entity == USERS_ENTITY:
                return self._fetch_user_records(headers)
            else:
                return self._fetch_device_records(headers)

        except KolidePluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while fetching"
                f" {entity} records."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            raise KolidePluginException(err_msg)

    def _fetch_user_records(self, headers: Dict) -> list:
        """Fetch and normalise all Users from Kolide.

        Combines **active** users from the People endpoint (``Is Deleted``
        = ``False``) with **deprovisioned** users from the Deprovisioned
        People endpoint (``Is Deleted`` = ``True``). The People endpoint
        returns only active users and the Deprovisioned People endpoint
        returns only deleted/disabled users, so the two sets are disjoint
        and require no de-duplication. The deprovisioned fetch is gated by
        the ``fetch_deprovisioned_people`` configuration toggle; when it
        is ``no``, only active users are returned.

        Args:
            headers (Dict): Authentication and version headers.

        Returns:
            list[dict]: Combined list of user record dictionaries.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching {USERS_ENTITY} records"
            f" from {PLATFORM_NAME}."
        )

        all_records = self._fetch_people_from_endpoint(
            headers=headers,
            endpoint_url=PEOPLE_ENDPOINT.format(base_url=BASE_URL),
            is_deleted=False,
            source_label="active",
        )

        fetch_deprovisioned = (
            self.configuration.get(
                "fetch_deprovisioned_people", "yes"
            ) == "yes"
        )
        if fetch_deprovisioned:
            all_records.extend(
                self._fetch_people_from_endpoint(
                    headers=headers,
                    endpoint_url=DEPROVISIONED_PEOPLE_ENDPOINT.format(
                        base_url=BASE_URL
                    ),
                    is_deleted=True,
                    source_label="deprovisioned",
                )
            )
        else:
            self.logger.info(
                f"{self.log_prefix}: Skipping deprovisioned people fetch"
                " as 'Fetch Deprovisioned People' is disabled in plugin"
                " configuration."
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched"
            f" {len(all_records)} {USERS_ENTITY} record(s) from"
            f" {PLATFORM_NAME}."
        )
        return all_records

    def _fetch_people_from_endpoint(
        self,
        headers: Dict,
        endpoint_url: str,
        is_deleted: bool,
        source_label: str,
    ) -> list:
        """Fetch and normalise users from a people-style endpoint.

        Paginates ``endpoint_url`` (cursor-based), maps each person via
        ``USER_FIELD_MAPPING``, stamps the ``Is Deleted`` field, and
        returns the record list. Records missing an ``email`` are
        skipped and counted. Shared by the active (People) and
        deprovisioned (Deprovisioned People) fetches, which differ only
        by URL, ``is_deleted`` value, and log wording.

        Args:
            headers (Dict): Authentication and version headers.
            endpoint_url (str): Full URL of the people-style endpoint.
            is_deleted (bool): Value stamped on each record's
                ``Is Deleted`` field (``False`` for active users,
                ``True`` for deprovisioned users).
            source_label (str): Short label ("active" / "deprovisioned")
                used in log messages.

        Returns:
            list[dict]: Normalised user record dictionaries.
        """
        records = []
        skip_count = 0
        page = 1
        total = 0
        cursor = None

        while True:
            params = {"per_page": PAGE_SIZE}
            if cursor:
                params["cursor"] = cursor
            response = self.helper.api_helper(
                logger_msg=(
                    f"fetching {source_label} users in page {page}"
                ),
                url=endpoint_url,
                method="GET",
                params=params,
                headers=headers,
                is_validation=False,
            )
            page_data = response.get("data", [])
            page_count = 0
            for person in page_data:
                person_id = person.get("id")
                if not person.get("email"):
                    skip_count += 1
                    continue
                record: Dict = {}
                for field_name, mapping in USER_FIELD_MAPPING.items():
                    val = self.helper._extract_field_from_event(
                        mapping["key"],
                        person,
                        mapping.get("default"),
                        mapping.get("transformation"),
                    )
                    self.helper.add_field(record, field_name, val)
                self.helper.add_field(record, "User ID", person_id)
                self.helper.add_field(record, "Is Deleted", is_deleted)
                records.append(record)
                page_count += 1

            total += page_count
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched"
                f" {page_count} {source_label} User record(s) in"
                f" page {page}. Total {source_label} records"
                f" fetched: {total}."
            )

            next_cursor = response.get("pagination", {}).get(
                "next_cursor"
            )
            if not next_cursor:
                break
            cursor = next_cursor
            page += 1

        skip_msg = ""
        if skip_count:
            skip_msg = (
                f" Skipped {skip_count} {source_label} User record(s)"
                " due to missing Email."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {total}"
            f" {source_label} User record(s) from"
            f" {PLATFORM_NAME}.{skip_msg}"
        )
        return records

    def _fetch_device_records(self, headers: Dict) -> list:
        """Fetch and normalise all Devices from the Kolide Devices endpoint.

        Args:
            headers (Dict): Authentication and version headers.

        Returns:
            list[dict]: List of device record dictionaries.
        """
        all_records = []
        skip_count = 0
        page = 1
        total = 0
        cursor = None

        self.logger.info(
            f"{self.log_prefix}: Fetching {DEVICES_ENTITY} records"
            f" from {PLATFORM_NAME}."
        )

        while True:
            params = {"per_page": PAGE_SIZE}
            if cursor:
                params["cursor"] = cursor
            url = DEVICES_ENDPOINT.format(base_url=BASE_URL)
            response = self.helper.api_helper(
                logger_msg=f"fetching devices in page {page}",
                url=url,
                method="GET",
                params=params,
                headers=headers,
                is_validation=False,
            )
            page_data = response.get("data", [])
            page_count = 0
            for device in page_data:
                device_id = device.get("id")
                if not device_id:
                    skip_count += 1
                    continue
                record: Dict = {}
                for field_name, mapping in DEVICE_FIELD_MAPPING.items():
                    val = self.helper._extract_field_from_event(
                        mapping["key"],
                        device,
                        mapping.get("default"),
                        mapping.get("transformation"),
                    )
                    self.helper.add_field(record, field_name, val)
                self.helper.add_field(record, "Device ID", device_id)
                all_records.append(record)
                page_count += 1

            total += page_count
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched"
                f" {page_count} Device record(s) in page {page}."
                f" Total records fetched: {total}."
            )

            next_cursor = response.get("pagination", {}).get(
                "next_cursor"
            )
            if not next_cursor:
                break
            cursor = next_cursor
            page += 1

        skip_msg = ""
        if skip_count:
            skip_msg = (
                f" Skipped {skip_count} Device record(s) due to"
                " missing ID."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {total} Device"
            f" record(s) from {PLATFORM_NAME}.{skip_msg}"
        )
        return all_records

    # ------------------------------------------------------------------
    # update_records
    # ------------------------------------------------------------------

    def update_records(self, entity: str, records: list) -> list:
        """Enrich existing records with live data from Kolide.

        For Users: no-op — Users (active and deprovisioned) are fully
        fetched and labelled during ``fetch_records``, so this returns an
        empty list.

        For Devices: attaches the current open issue count, issue titles,
        and (when enabled) SSF compliance status and owner email to each
        device record.

        Args:
            entity (str): Entity name - ``USERS_ENTITY`` or
                ``DEVICES_ENTITY``.
            records (list[dict]): Existing records from the CE store.

        Returns:
            list[dict]: Updated records.  Always returns a list (never
                ``None``); returns ``[]`` for Users and when *records*
                is empty.

        Raises:
            KolidePluginException: On entity validation failure.
        """
        if entity not in [USERS_ENTITY, DEVICES_ENTITY]:
            err_msg = (
                f"Invalid entity type '{entity}'."
                f" Supported: {USERS_ENTITY}, {DEVICES_ENTITY}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Ensure the entity is one of "
                    f"'{USERS_ENTITY}' or '{DEVICES_ENTITY}'."
                ),
            )
            raise KolidePluginException(err_msg)

        # Users are fully populated during fetch_records (both active and
        # deprovisioned users are fetched and labelled there), so the
        # update phase is a no-op for Users. Returning an empty list
        # applies no updates and never drops records (the framework only
        # upserts what is returned).
        if entity == USERS_ENTITY:
            return []

        if not records:
            self.logger.info(
                f"{self.log_prefix}: No {entity} records to update."
                " Skipping."
            )
            return []
        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} "
            f"{entity} record(s) from {PLATFORM_NAME}."
        )

        (api_token,) = self.helper.get_configuration_parameters(
            self.configuration
        )
        headers = self.helper.get_auth_headers(api_token)

        fetch_issues = (
            self.configuration.get("fetch_open_issues", "yes") == "yes"
        )
        fetch_compliance = (
            self.configuration.get(
                "fetch_compliance_status", "yes"
            ) == "yes"
        )

        device_issue_counts: Optional[Dict[str, int]] = None
        device_exempted_counts: Optional[Dict[str, int]] = None
        device_issue_titles: Optional[Dict[str, List[str]]] = None
        if fetch_issues:
            device_issue_counts = {}
            device_exempted_counts = {}
            device_issue_titles = {}
            try:
                (
                    device_issue_counts,
                    device_exempted_counts,
                    device_issue_titles,
                ) = self._fetch_all_issues(headers)
            except KolidePluginException as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error fetching issues for"
                        f" device update. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error fetching"
                        f" issues for device update. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
        else:
            self.logger.info(
                f"{self.log_prefix}: Skipping open issues fetch for devices"
                " as 'Fetch Open Issues' is disabled in plugin configuration."
            )

        compliance_map: Optional[Dict[str, str]] = None
        user_email_map: Optional[Dict[str, str]] = None
        if fetch_compliance:
            try:
                compliance_map, user_email_map = (
                    self._fetch_ssf_compliance_statuses(api_token)
                )
            except KolidePluginException as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error fetching SSF"
                        f" compliance statuses. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error"
                        " fetching SSF compliance statuses."
                        f" Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
        else:
            self.logger.info(
                f"{self.log_prefix}: Skipping compliance status fetch"
                " for devices since 'Fetch Compliance Status' is disabled"
                " in plugin configuration."
            )
        return self._update_device_records(
            records,
            device_issue_counts,
            device_exempted_counts,
            device_issue_titles,
            compliance_map,
            user_email_map,
        )

    def _get_or_create_ssf_stream(
        self, api_token: str
    ) -> Tuple[str, str]:
        """Return (stream_id, poll_bearer_token) from storage or create new.

        Creates a new SSF stream via Kolide and persists the credentials
        in plugin storage when none are found.  The stream-creation logic
        lives in ``helper.create_ssf_stream`` so it can be replaced
        independently if the token-acquisition mechanism changes.

        Args:
            api_token (str): Kolide API bearer token.

        Returns:
            Tuple[str, str]: ``(stream_id, poll_bearer_token)``.
        """
        storage = self._get_storage()
        stream_id = storage.get(SSF_STORAGE_STREAM_ID, "")
        poll_bearer_token = storage.get(SSF_STORAGE_POLL_TOKEN, "")
        if stream_id and poll_bearer_token:
            return stream_id, poll_bearer_token

        self.logger.debug(
            f"{self.log_prefix}: No SSF stream credentials found in"
            " plugin storage. Creating a new SSF poll stream."
        )
        stream_id, poll_bearer_token = self.helper.create_ssf_stream(
            api_token=api_token,
            stream_name=self.ssf_stream_name,
            event_subscriptions=[SSF_CAEP_COMPLIANCE_EVENT],
        )
        storage[SSF_STORAGE_STREAM_ID] = stream_id
        storage[SSF_STORAGE_POLL_TOKEN] = poll_bearer_token
        self.logger.info(
            f"{self.log_prefix}: Successfully created Poll SSF Stream"
            f" {self.ssf_stream_name}. ({stream_id!r})"
        )
        return stream_id, poll_bearer_token

    def _recreate_ssf_stream(
        self, api_token: str
    ) -> Tuple[str, str]:
        """Recreate the SSF compliance stream after it is found missing.

        Called only when a poll returns HTTP 404 (the stream no longer
        exists on Kolide). A replacement is created reusing the standard
        stream name (``self.ssf_stream_name``) - the name is free because
        the old stream is gone - and the cached credentials are overwritten
        only AFTER the new stream is created. A failed create therefore
        leaves the previous credentials intact for an idempotent retry
        on the next cycle, rather than clearing storage into a half
        state.

        Known limitation: recreating starts a brand-new event stream, so
        any compliance-change events that occurred while the old stream
        was missing are NOT backfilled - there is an unavoidable data
        gap until each affected device next changes compliance state.

        Args:
            api_token (str): Kolide API bearer token.

        Returns:
            Tuple[str, str]: ``(stream_id, poll_bearer_token)`` of the
                newly created stream.
        """
        storage = self._get_storage()
        old_stream_id = storage.get(SSF_STORAGE_STREAM_ID, "")

        self.logger.info(
            f"{self.log_prefix}: Recreating the SSF compliance stream"
            f" (previous stream {old_stream_id!r} was not found)."
            " Compliance changes that occurred while the stream was"
            " missing will not be backfilled."
        )

        # Create the replacement FIRST; if this raises, the previous
        # credentials are left untouched so the next cycle can retry.
        stream_id, poll_bearer_token = self.helper.create_ssf_stream(
            api_token=api_token,
            stream_name=self.ssf_stream_name,
            event_subscriptions=[SSF_CAEP_COMPLIANCE_EVENT],
        )

        # Best-effort clean-up of the old stream (usually already gone,
        # since the poll returned 404); never blocks the new stream.
        if old_stream_id and old_stream_id != stream_id:
            self.helper.delete_ssf_stream(
                api_token=api_token, stream_id=old_stream_id
            )

        storage[SSF_STORAGE_STREAM_ID] = stream_id
        storage[SSF_STORAGE_POLL_TOKEN] = poll_bearer_token
        self.logger.info(
            f"{self.log_prefix}: Successfully recreated the SSF"
            f" compliance stream {self.ssf_stream_name!r}."
            f" ({stream_id!r})"
        )
        return stream_id, poll_bearer_token

    def _fetch_ssf_compliance_statuses(
        self, api_token: str
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Poll the SSF stream and return compliance and user-email maps.

        Decodes each Security Event Token (JWT), extracts the device ID,
        current compliance status, and (when the user subject format is
        ``"email"``) the user email from the CAEP compliance-change event.
        Acknowledges all received events and returns both maps.
        Events with no device sub or no compliance status are skipped.

        Args:
            api_token (str): Kolide API bearer token.

        Returns:
            Tuple[Dict[str, str], Dict[str, str]]:
                ``(compliance_map, user_email_map)`` where each key is a
                device_id string.  ``compliance_map`` maps to the
                current_status (e.g. ``"compliant"``);
                ``user_email_map`` maps to the user email address and is
                only populated when ``sub_id.user.format == "email"``.
        """
        stream_id, poll_bearer_token = self._get_or_create_ssf_stream(
            api_token
        )
        try:
            sets = self.helper.poll_ssf_events(
                stream_id=stream_id,
                api_token=api_token,
                poll_bearer_token=poll_bearer_token,
            )
        except SSFStreamNotFoundError as exp:
            # The stream no longer exists on Kolide (404). Recreate it
            # once and retry the poll. A second failure - or any other
            # error (transient 5xx / network), which is NOT caught here -
            # propagates to the caller, which skips compliance
            # enrichment for this cycle.
            self.logger.error(
                message=(
                    f"{self.log_prefix}: SSF compliance stream"
                    f" {stream_id!r} was not found. Recreating it and"
                    f" retrying the poll once. Error: {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "If the retry also fails, verify the API Token has"
                    " permission to manage SSF streams and that the"
                    " Kolide API is reachable."
                ),
            )
            stream_id, poll_bearer_token = self._recreate_ssf_stream(
                api_token
            )
            sets = self.helper.poll_ssf_events(
                stream_id=stream_id,
                api_token=api_token,
                poll_bearer_token=poll_bearer_token,
            )
        self.logger.info(
            f"{self.log_prefix}: Received {len(sets)} SSF event(s)"
            " from the compliance stream."
        )
        compliance_map: Dict[str, str] = {}
        user_email_map: Dict[str, str] = {}
        # Only events processed without error are acknowledged; an event
        # that raises while decoding is left unacknowledged so Kolide
        # re-delivers it on the next poll for another attempt.
        processed_jtis: List[str] = []
        for jti, jwt_str in sets.items():
            try:
                payload = jwt.decode(
                    jwt_str,
                    options={"verify_signature": False},
                    algorithms=["RS256"],
                )
                sub_id = payload.get("sub_id", {})
                device_id = str(
                    sub_id.get("device", {}).get("sub", "")
                ).strip()
                if not device_id:
                    processed_jtis.append(jti)
                    continue
                event_data = payload.get("events", {}).get(
                    SSF_CAEP_COMPLIANCE_EVENT, {}
                )
                current_status = event_data.get("current_status", "")
                if current_status:
                    compliance_map[device_id] = current_status
                user_subject = sub_id.get("user", {})
                if user_subject.get("format") == "email":
                    email = (
                        user_subject.get("email", "") or ""
                    ).strip()
                    if email:
                        user_email_map[device_id] = email
                processed_jtis.append(jti)
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to decode SSF"
                        f" event {jti!r}. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
        self.helper.acknowledge_ssf_events(
            stream_id=stream_id,
            api_token=api_token,
            poll_bearer_token=poll_bearer_token,
            jtis=processed_jtis,
        )
        return compliance_map, user_email_map

    def _update_device_records(
        self,
        records: list,
        device_issue_counts: Optional[Dict[str, int]] = None,
        device_exempted_counts: Optional[Dict[str, int]] = None,
        device_issue_titles: Optional[Dict[str, List[str]]] = None,
        compliance_map: Optional[Dict[str, str]] = None,
        user_email_map: Optional[Dict[str, str]] = None,
    ) -> list:
        """Enrich Device records with issue counts, compliance status,
        and user email.

        Args:
            records (list[dict]): Existing device records.
            device_issue_counts (Dict[str, int] | None): Mapping of
                device_id -> open non-exempted issue count. When
                ``None``, ``Open Issues Count`` is not updated.
            device_exempted_counts (Dict[str, int] | None): Mapping of
                device_id -> open exempted issue count. When ``None``,
                ``Exempted Issues Count`` is not updated.
            device_issue_titles (Dict[str, List[str]] | None): Mapping of
                device_id -> open issue titles. When ``None``,
                ``Issue Title`` is not updated.
            compliance_map (Dict[str, str] | None): Mapping of
                device_id -> compliance status from the SSF stream.
                When ``None``, ``Compliance Status`` is not updated.
            user_email_map (Dict[str, str] | None): Mapping of
                device_id -> user email extracted from the SSF event's
                ``sub_id.user`` when its format is ``"email"``.
                When ``None``, ``User Email`` is not updated.

        Returns:
            list[dict]: Updated device records.
        """

        updated_records = []
        skipped = 0
        issues_updated = 0
        compliance_updated = 0
        for record in records:
            device_id = record.get("Device ID")
            if not device_id:
                skipped += 1
                continue
            enriched = {
                "Device ID": device_id,
                "Device Serial Number": record.get("Device Serial Number"),
            }
            if device_issue_counts is not None:
                enriched["Open Issues Count"] = device_issue_counts.get(
                    device_id, 0
                )
                enriched["Issue Title"] = device_issue_titles.get(
                    device_id, []
                )
                issues_updated += 1
            if device_exempted_counts is not None:
                enriched["Exempted Issues Count"] = (
                    device_exempted_counts.get(device_id, 0)
                )
            if compliance_map is not None:
                status = compliance_map.get(device_id)
                if status is not None:
                    enriched["Compliance Status"] = status
                    compliance_updated += 1
            if user_email_map is not None:
                email = user_email_map.get(device_id)
                if email is not None:
                    enriched["User Email"] = email
            updated_records.append(enriched)

        skipped_suffix = (
            f" Skipped {skipped} Device record(s) with empty"
            " 'Device ID'."
            if skipped > 0
            else ""
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully updated open issue count"
            f" for {issues_updated} Device record(s) and compliance"
            f" status for {compliance_updated} Device record(s)."
            f"{skipped_suffix}"
        )
        return updated_records

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def get_actions(self) -> list:
        """Return the list of supported actions for this plugin.

        Returns:
            list[ActionWithoutParams]: Supported action descriptors.
        """
        return [
            ActionWithoutParams(
                label="Manage Device Groups",
                value=ACTION_MANAGE_GROUP,
            ),
            ActionWithoutParams(
                label="No Action",
                value=ACTION_NO_ACTION,
            ),
        ]

    def get_action_params(self, action: Action) -> list:
        """Return the UI parameter descriptors for a given action.

        Args:
            action (Action): The selected action.

        Returns:
            list[dict]: Parameter field descriptors for the CE UI.
        """
        if action.value == ACTION_NO_ACTION:
            return []

        if action.value == ACTION_MANAGE_GROUP:
            (api_token,) = self.helper.get_configuration_parameters(
                self.configuration
            )
            headers = self.helper.get_auth_headers(api_token)
            url = DEVICE_GROUPS_ENDPOINT.format(base_url=BASE_URL)
            groups = self.helper.fetch_paginated_list(
                endpoint_url=url,
                headers=headers,
                logger_msg="fetching device groups from Kolide",
                item_label="device group(s)",
            )
            groups_sorted = sorted(
                groups,
                key=lambda g: g.get("name", "").lower(),
            )
            # Pack "<name><CUSTOM_SEPARATOR><id>" into the value so the
            # group id is available at execution time (via rpartition)
            # without an extra group-lookup API call. Kolide has no
            # group-create API, so the id can always be carried here.
            choices = [
                {
                    "key": g["name"],
                    "value": (
                        f"{g['name']}{CUSTOM_SEPARATOR}{g['id']}"
                    ),
                }
                for g in groups_sorted
                if g.get("name") and g.get("id")
            ]
            if not choices:
                err_msg = (
                    "No device groups found on Kolide. Create at"
                    " least one device group before configuring"
                    " this action."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Create a device group on the Kolide and then"
                        " retry configuring this action."
                    ),
                )
                raise KolidePluginException(err_msg)

            device_ids_param = {
                "label": "Device IDs",
                "key": "device_ids",
                "type": "text",
                "mandatory": True,
                "default": "",
                "description": (
                    "Device IDs to add to or remove from the group."
                    " Select kolide device id source field or provide"
                    " comma-separated device ids."
                ),
            }
            return [
                {
                    "label": "Action Type",
                    "key": "action_type",
                    "type": "choice",
                    "choices": [
                        {
                            "key": "Add to Group",
                            "value": GROUP_ACTION_TYPE_ADD,
                        },
                        {
                            "key": "Remove from Group",
                            "value": GROUP_ACTION_TYPE_REMOVE,
                        },
                    ],
                    "default": GROUP_ACTION_TYPE_ADD,
                    "mandatory": True,
                    "description": (
                        "Whether to add devices to the group or"
                        " remove them from it."
                    ),
                },
                {
                    "label": "Device Group Name",
                    "key": "device_group_name",
                    "type": "choice",
                    "choices": choices,
                    "default": choices[0]["value"],
                    "mandatory": True,
                    "description": (
                        "Select the Kolide device group to manage."
                    ),
                },
                device_ids_param,
            ]

        return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate the parameters of a selected action.

        Args:
            action (Action): Action object including parameters.

        Returns:
            ValidationResult: Success or failure with a message.
        """
        action_value = action.value
        if action_value not in SUPPORTED_ACTIONS:
            err_msg = (
                f"Unsupported action '{action_value}'."
                " Supported actions are: 'Manage Device Group',"
                " 'No Action'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if action_value == ACTION_NO_ACTION:
            return ValidationResult(
                success=True, message="Validation successful."
            )

        if action_value == ACTION_MANAGE_GROUP:
            action_type = action.parameters.get("action_type", "")
            if isinstance(action_type, list):
                action_type = action_type[0] if action_type else ""
            if validation_failure := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Action Type",
                field_value=action_type,
                field_type=str,
                allowed_values=[
                    GROUP_ACTION_TYPE_ADD,
                    GROUP_ACTION_TYPE_REMOVE,
                ],
            ):
                return validation_failure

            # Device Group Name is a static dropdown whose value packs the
            # group id (see get_action_params); it is never a Source field,
            # and the packed value / group name may legitimately contain a
            # "$", so check_dollar must stay off here.
            group_name = action.parameters.get(
                "device_group_name", ""
            )
            if isinstance(group_name, list):
                group_name = group_name[0] if group_name else ""
            if validation_failure := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Device Group Name",
                field_value=group_name,
                field_type=str,
            ):
                return validation_failure

            device_ids_val = action.parameters.get("device_ids", "")
            if isinstance(device_ids_val, list):
                device_ids_val = (
                    device_ids_val[0] if device_ids_val else ""
                )
            if validation_failure := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Device IDs",
                field_value=device_ids_val,
                field_type=str,
                check_dollar=True,
                custom_validation_func=lambda value: all(
                    part.strip() for part in value.split(",")
                ),
            ):
                return validation_failure

        return ValidationResult(
            success=True, message="Validation successful."
        )

    def _validate_parameters(
        self,
        parameter_type: str,
        field_name: str,
        field_value,
        field_type: Type,
        check_dollar: bool = False,
        allowed_values: Optional[List] = None,
        custom_validation_func: Optional[Callable] = None,
    ) -> Optional[ValidationResult]:
        """Validate a single configuration or action parameter value.

        Args:
            parameter_type (str): Either ``CONFIGURATION`` or ``ACTION``;
                reported in the error message so the operator knows which
                form the field belongs to.
            field_name (str): Human-readable field name for messages.
            field_value: The parameter value to check.
            field_type (Type): Expected Python type of the value.
            check_dollar (bool): When True, a value containing ``$`` is
                treated as a Source field and validation is deferred to
                execution time (returns ``None``).
            allowed_values (Optional[List]): When provided, the value must
                be one of these entries.
            custom_validation_func (Optional[Callable]): When provided, the
                value is passed to this callable; a falsy return fails
                validation with the invalid-value error.

        Returns:
            ValidationResult if validation fails, else ``None``.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()
        if (
            check_dollar
            and isinstance(field_value, str)
            and "$" in field_value
        ):
            info_msg = (
                f"'{field_name}' contains the Source Field hence"
                " validation for this field will be performed while"
                " executing the action."
            )
            self.logger.info(
                message=f"{self.log_prefix}: {info_msg}"
            )
            return None
        if not field_value:
            err_msg = EMPTY_ERROR_MESSAGE.format(
                field_name=field_name, parameter_type=parameter_type
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    f"Please provide some value for field {field_name}."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(field_value, field_type) or (
            custom_validation_func
            and not custom_validation_func(field_value)
        ):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name, parameter_type=parameter_type
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    f"Please provide a valid value for {field_name} field."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if allowed_values and field_value not in allowed_values:
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name, parameter_type=parameter_type
            )
            err_msg += INVALID_VALUE_ERROR_MESSAGE.format(
                allowed_values=[
                    str(allowed_value).capitalize()
                    for allowed_value in allowed_values
                ]
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    "Please provide a valid value from the allowed"
                    " values."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        return None

    # ------------------------------------------------------------------
    # execute_actions
    # ------------------------------------------------------------------

    def execute_actions(self, actions: List[Action]):
        """Execute a batch of actions against Kolide.

        Groups add-to-group and remove-from-group actions by target
        group name so that all device IDs for the same group are sent
        in batches of DEVICE_GROUP_MEMBERSHIP_BATCH_SIZE rather than
        one device at a time.

        Args:
            actions (List[Action]): Actions supplied by the CE framework
                as ``{"id": ..., "params": Action}`` dicts.

        Returns:
            ActionResult: Reports per-action failures to the framework.
        """
        action_label_map = {
            action.value: action.label for action in self.get_actions()
        }
        first_action_value = (
            actions[0].get("params").value if actions else None
        )
        if first_action_value == ACTION_NO_ACTION:
            action_label = action_label_map.get(
                ACTION_NO_ACTION, "No Action"
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action "
                f"'{action_label}' on {len(actions)} records. Note: No"
                " processing will be done from plugin for the "
                f"'{action_label}' action."
            )
            return ActionResult(
                success=True,
                message="Action execution completed.",
                failed_action_ids=[],
            )

        (api_token,) = self.helper.get_configuration_parameters(
            self.configuration
        )
        headers = self.helper.get_auth_headers(api_token)

        failed_action_ids = []
        skipped_empty_count = 0

        # group_name -> {"device_ids": [...], "action_ids": [...]}
        add_groups: Dict[str, Dict] = {}
        remove_groups: Dict[str, Dict] = {}

        # ---- First pass: bucket all group actions ----
        for action in actions:
            action_id = action.get("id")
            action_obj = action.get("params")

            action_value = action_obj.value

            if action_value == ACTION_MANAGE_GROUP:
                # The dropdown value is packed as
                # "<name><CUSTOM_SEPARATOR><id>"; rpartition recovers the
                # id even when the group name itself contains the
                # separator characters.
                packed_group = (
                    action_obj.parameters.get("device_group_name", "")
                    or ""
                ).strip()
                group_name, sep, group_id = packed_group.rpartition(
                    CUSTOM_SEPARATOR
                )
                if not sep or not group_name or not group_id:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Action"
                            f" '{action_value}' has no valid Device"
                            " Group selection; skipping."
                        )
                    )
                    failed_action_ids.append(action_id)
                    continue

                action_type = (
                    action_obj.parameters.get("action_type", "")
                    or ""
                ).strip()
                if action_type not in (
                    GROUP_ACTION_TYPE_ADD,
                    GROUP_ACTION_TYPE_REMOVE,
                ):
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Action"
                            f" '{action_value}' has invalid Action"
                            f" Type '{action_type}'; skipping."
                        )
                    )
                    failed_action_ids.append(action_id)
                    continue

                device_ids = self._resolve_action_device_ids(
                    action_obj
                )
                if not device_ids:
                    skipped_empty_count += 1
                    failed_action_ids.append(action_id)
                    continue

                group_map = (
                    add_groups
                    if action_type == GROUP_ACTION_TYPE_ADD
                    else remove_groups
                )
                if group_id not in group_map:
                    group_map[group_id] = {
                        "group_name": group_name,
                        "device_ids": [],
                        "action_ids": [],
                        # device_id -> set(action_id) that requested it,
                        # used to attribute not-added devices back to
                        # their originating actions.
                        "device_to_action_ids": {},
                    }
                entry = group_map[group_id]
                entry["device_ids"].extend(device_ids)
                entry["action_ids"].append(action_id)
                for device_id in device_ids:
                    entry["device_to_action_ids"].setdefault(
                        device_id, set()
                    ).add(action_id)

            else:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unsupported action"
                        f" '{action_value}'."
                    )
                )
                failed_action_ids.append(action_id)

        if skipped_empty_count:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skipped_empty_count}"
                " record(s) as they had empty Device ID values."
            )

        # ---- Second pass: bulk-add per group ----
        for group_id, data in add_groups.items():
            group_name = data["group_name"]
            try:
                added_ids = self._execute_add_to_group_bulk(
                    group_id, group_name, data["device_ids"], headers
                )
            except KolidePluginException as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while adding"
                        f" device to '{group_name}' failed. Error: {exp}"
                    )
                )
                failed_action_ids.extend(data["action_ids"])
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred while"
                        f" adding device to group '{group_name}'. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
                failed_action_ids.extend(data["action_ids"])
            else:
                # The API omits devices it did not add. Fail every
                # action that requested a device which was not added.
                not_added = [
                    device_id
                    for device_id in data["device_to_action_ids"]
                    if device_id not in added_ids
                ]
                for device_id in not_added:
                    failed_action_ids.extend(
                        data["device_to_action_ids"][device_id]
                    )
                failed_msg = ""
                if not_added:
                    failed_msg = (
                        f" Failed to add {len(not_added)} device(s) to"
                        f" group '{group_name}'."
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully added"
                    f" {len(added_ids)} device(s) to group"
                    f" '{group_name}'.{failed_msg}"
                )

        # ---- Third pass: bulk-remove per group ----
        for group_id, data in remove_groups.items():
            group_name = data["group_name"]
            try:
                removed_ids = self._execute_remove_from_group_bulk(
                    group_id, group_name, data["device_ids"], headers
                )
            except KolidePluginException as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while removing"
                        f" device group from '{group_name}'. Error: {exp}"
                    )
                )
                failed_action_ids.extend(data["action_ids"])
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error removing"
                        f" from group '{group_name}'. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
                failed_action_ids.extend(data["action_ids"])
            else:
                # A device the API did not remove (including a 404
                # "not a member") is absent from removed_ids. Fail every
                # action that requested a device which was not removed.
                not_removed = [
                    device_id
                    for device_id in data["device_to_action_ids"]
                    if device_id not in removed_ids
                ]
                for device_id in not_removed:
                    failed_action_ids.extend(
                        data["device_to_action_ids"][device_id]
                    )
                failed_msg = ""
                if not_removed:
                    failed_msg = (
                        f" Failed to remove {len(not_removed)}"
                        f" device(s) from group '{group_name}'."
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully removed"
                    f" {len(removed_ids)} device(s) from group"
                    f" '{group_name}'.{failed_msg}"
                )

        return ActionResult(
            success=True,
            message="Action execution completed.",
            failed_action_ids=list(
                dict.fromkeys(failed_action_ids)
            ),
        )

    def _resolve_action_device_ids(self, action) -> List[str]:
        """Return the device ID list for a group action.

        Parses the ``device_ids`` action parameter (static CSV or
        Source field list).  Returns an empty list when the parameter
        is absent, None, or resolves to no non-blank values; the caller
        is responsible for skipping the action in that case.

        Args:
            action: Action object carrying ``parameters``.

        Returns:
            list[str]: List of device ID strings, possibly empty.
        """
        raw = action.parameters.get("device_ids", "")
        if isinstance(raw, list):
            device_ids = [
                str(d).strip() for d in raw if str(d).strip()
            ]
        else:
            raw = (raw or "").strip()
            device_ids = [
                d.strip() for d in raw.split(",") if d.strip()
            ]

        return device_ids

    def _execute_add_to_group_bulk(
        self,
        group_id: str,
        group_name: str,
        device_ids: List[str],
        headers: Dict,
    ) -> set:
        """Add devices to a Kolide device group in batches.

        Deduplicates the provided list, then adds all devices in batches
        of DEVICE_GROUP_MEMBERSHIP_BATCH_SIZE. The group id is taken
        straight from the packed action value, so no group-lookup API
        call is needed.

        Args:
            group_id (str): ID of the target device group.
            group_name (str): Display name of the target device group,
                used only in logs.
            device_ids (List[str]): Devices to add (duplicates allowed;
                will be deduped before sending).
            headers (Dict): Authentication and version headers.

        Returns:
            set: Device IDs (as strings) the API confirmed were added
                across all batches. Devices absent from this set were
                not added (including every device in a batch whose
                request failed and was skipped) and are attributed back
                to their actions by the caller.
        """
        unique_ids = list(dict.fromkeys(device_ids))
        added_ids = set()

        for batch_number, i in enumerate(
            range(
                0, len(unique_ids), DEVICE_GROUP_MEMBERSHIP_BATCH_SIZE
            ),
            start=1,
        ):
            batch = unique_ids[
                i: i + DEVICE_GROUP_MEMBERSHIP_BATCH_SIZE
            ]
            self.logger.info(
                f"{self.log_prefix}: Adding {len(batch)} device(s) in"
                f" batch {batch_number} to group '{group_name}'."
            )
            try:
                added_ids.update(
                    self.helper.add_devices_to_group(
                        group_id,
                        batch,
                        headers,
                        group_name=group_name,
                        batch_number=batch_number,
                    )
                )
            except KolidePluginException:
                continue
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred"
                        f" while adding {len(batch)} device(s) in batch"
                        f" {batch_number} to group '{group_name}'."
                        f" Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
                continue

        return added_ids

    def _execute_remove_from_group_bulk(
        self,
        group_id: str,
        group_name: str,
        device_ids: List[str],
        headers: Dict,
    ) -> set:
        """Remove devices from a Kolide device group one at a time.

        Deduplicates the device list, then issues a separate DELETE per
        device (the Kolide API does not support bulk removal). The group
        id is taken straight from the packed action value, so no
        group-lookup API call is needed. A device that could not be
        removed (e.g. it is not a member of the group, which the API
        reports as a 404) is skipped and omitted from the returned set.

        Args:
            group_id (str): ID of the target device group.
            group_name (str): Display name of the target device group,
                used only in logs.
            device_ids (List[str]): Devices to remove (duplicates
                allowed; will be deduped before sending).
            headers (Dict): Authentication and version headers.

        Returns:
            set: Device IDs (as strings) the API confirmed were removed.
                Devices absent from this set were not removed and are
                attributed back to their actions by the caller.
        """
        unique_ids = list(dict.fromkeys(device_ids))
        removed_ids = set()

        for device_id in unique_ids:
            self.logger.info(
                f"{self.log_prefix}: Removing device with ID {device_id!r}"
                f" from group '{group_name}'."
            )
            try:
                if self.helper.remove_device_from_group(
                    group_id,
                    device_id,
                    headers,
                    group_name=group_name,
                ):
                    removed_ids.add(device_id)
            except KolidePluginException:
                continue
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred"
                        f" while removing device with ID {device_id!r}"
                        f" from group '{group_name}'. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
                continue

        self.logger.info(
            f"{self.log_prefix}: Successfully removed {len(removed_ids)}"
            f" of {len(unique_ids)} device(s) from group"
            f" '{group_name}'."
        )
        return removed_ids

    # ------------------------------------------------------------------
    # validate
    # ------------------------------------------------------------------

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the plugin configuration.

        Checks that the ``api_token`` field is present and a string,
        then performs a live connectivity check against the Kolide API.

        Args:
            configuration (dict): Plugin configuration dictionary.

        Returns:
            ValidationResult: Success or failure with a message.
        """
        (api_token,) = self.helper.get_configuration_parameters(
            configuration
        )
        if validation_failure := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="API Token",
            field_value=api_token,
            field_type=str,
        ):
            return validation_failure

        for key, label in [
            ("fetch_deprovisioned_people", "Fetch Deprovisioned People"),
            ("fetch_open_issues", "Fetch Open Issues"),
            ("fetch_compliance_status", "Fetch Compliance Status"),
        ]:
            if validation_failure := self._validate_parameters(
                parameter_type=CONFIGURATION,
                field_name=label,
                field_value=configuration.get(key, "yes"),
                field_type=str,
                allowed_values=["yes", "no"],
            ):
                return validation_failure

        auth_result = self._validate_auth_params(configuration)
        if not auth_result.success:
            return auth_result

        # Provision the SSF compliance stream at save time when polling
        # is enabled, so any permission/connectivity problem surfaces
        # now and the credentials are cached for the first update cycle.
        # When it is disabled we deliberately leave any previously
        # created stream metadata untouched in storage, so re-enabling
        # later reuses the same stream instead of orphaning it.
        fetch_compliance = (
            configuration.get("fetch_compliance_status", "yes") == "yes"
        )
        if fetch_compliance:
            return self._provision_ssf_stream(
                configuration, auth_result
            )
        return auth_result

    def _validate_auth_params(
        self, configuration: dict
    ) -> ValidationResult:
        """Verify the API token by calling the /whoami endpoint.

        Args:
            configuration (dict): Plugin configuration dictionary.

        Returns:
            ValidationResult: Success when the token is accepted,
                failure otherwise.
        """
        try:
            (api_token,) = self.helper.get_configuration_parameters(configuration)
            headers = self.helper.get_auth_headers(api_token)
            url = WHOAMI_ENDPOINT.format(base_url=BASE_URL)
            self.helper.api_helper(
                logger_msg="validating API token",
                url=url,
                method="GET",
                headers=headers,
                is_validation=True,
            )
            self.logger.debug(
                f"{self.log_prefix}: Validation completed successfully."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        except KolidePluginException as exp:
            return ValidationResult(
                success=False, message=str(exp)
            )
        except Exception as exp:
            err_msg = (
                "Unexpected error during validation."
                " Check the logs for details."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False, message=err_msg
            )

    def _provision_ssf_stream(
        self,
        configuration: dict,
        success_result: ValidationResult,
    ) -> ValidationResult:
        """Create the SSF compliance stream during validation.

        Called only when 'Fetch Compliance Status' is enabled. Reuses an
        existing stream when its credentials are already cached in
        plugin storage (idempotent), otherwise creates one and persists
        the credentials. Storage writes made here survive to later runs
        because the framework passes the configuration's storage dict to
        the plugin by reference and saves it after validation.

        Args:
            configuration (dict): Plugin configuration dictionary.
            success_result (ValidationResult): Result to return when
                provisioning succeeds (the already-computed auth
                validation result).

        Returns:
            ValidationResult: ``success_result`` on success, else a
                failure result describing the stream-creation error.
        """
        try:
            (api_token,) = self.helper.get_configuration_parameters(
                configuration
            )
            self._get_or_create_ssf_stream(api_token)
            return success_result
        except KolidePluginException as exp:
            err_msg = (
                "Failed to create the Kolide SSF compliance stream."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error while creating the Kolide SSF"
                " compliance stream."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)

    def cleanup(self, action_type: str = "disable") -> None:
        """Delete the Kolide SSF compliance stream on plugin delete.

        The framework calls this hook when the plugin configuration is
        disabled or deleted. The SSF stream (and its cached credentials
        in storage) is removed only on **delete**; on **disable** the
        stream and its metadata are left intact so re-enabling the
        configuration reuses the same stream instead of orphaning it.

        A missing stream id (compliance status fetch was never enabled)
        is a no-op. All errors are caught and logged rather than raised so a
        transient Kolide problem cannot block plugin disable/delete.

        Args:
            action_type (str): Cleanup action identifier passed by the
                framework - ``ActionType.DELETE`` (``"delete"``) or
                ``ActionType.DISABLE`` (``"disable"``). Defaults to
                ``"disable"``, the safer of the two (the stream is
                kept).

        Returns:
            None
        """
        if action_type != "delete":
            # Do not delete the SSF Stream on plugin disable.
            # As a part of minor BUG NCTE-240 we will raise NotImplementedError
            # in this if branch so that the code short circuits and
            # does not empty the storage object
            raise NotImplementedError

        try:
            storage = self._get_storage()
            stream_id = storage.get(SSF_STORAGE_STREAM_ID, "")
            if not stream_id:
                self.logger.debug(
                    f"{self.log_prefix}: No SSF compliance stream found"
                    " in storage during cleanup; nothing to delete."
                )
                return
            (api_token,) = self.helper.get_configuration_parameters(
                self.configuration
            )
            self.helper.delete_ssf_stream(
                api_token=api_token, stream_id=stream_id
            )
            # Drop the cached credentials now that the stream is gone
            # (harmless even though the configuration record is being
            # removed alongside this cleanup).
            storage.pop(SSF_STORAGE_STREAM_ID, None)
            storage.pop(SSF_STORAGE_POLL_TOKEN, None)
            self.logger.info(
                f"{self.log_prefix}: Deleted the SSF compliance stream"
                f" ({stream_id!r}) during plugin cleanup."
            )
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error while deleting the SSF"
                    " compliance stream during plugin cleanup"
                    f" (action_type={action_type}). Error: {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "From the Kolide platform, delete the SSF stream"
                    f" {self.ssf_stream_name!r} created by the plugin."
                )
            )
