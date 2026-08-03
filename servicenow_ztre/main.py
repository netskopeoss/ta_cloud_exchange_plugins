"""
BSD 3-Clause License.

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

CRE ServiceNow plugin.
"""

import datetime
import json
import traceback
from base64 import b64decode, b64encode
from typing import Callable, Dict, List, Optional, Set, Tuple, Type
from urllib.parse import urlparse

from pydantic import ValidationError

from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.crev2.plugin_base import (
    ActionResult,
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    ACTION,
    ACTION_NO_ACTION,
    ACTION_SHARE_APPLICATION_DATA,
    ACTION_TAG_APPLICATION,
    ACTION_TAG_DEVICE,
    ACTION_TYPE_ADD,
    ACTION_TYPE_REMOVE,
    ACTION_USER_DELEGATION,
    ACTION_USER_GROUP,
    ACTION_USER_ROLE,
    APPLICATION_FIELD_MAPPING,
    APPLICATIONS_ENTITY,
    BATCH_REQUEST_ID,
    COMPANY_LOOKUP_SUBREQUEST_LIMIT,
    CONFIGURATION,
    CREATE_NEW_GROUP,
    CUSTOM_SEPARATOR,
    DATETIME_FORMATS,
    DEFAULT_TAG_KEY,
    DELEGATION_DATETIME_FORMAT,
    DELEGATION_DURATION_ERROR_MESSAGE,
    DELEGATION_EXTEND_DURATION_NO,
    DELEGATION_EXTEND_DURATION_OPTIONS,
    DELEGATION_EXTEND_DURATION_YES,
    DELEGATION_LOOKUP_FIELDS,
    DELEGATION_MAX_DURATION_DAYS,
    DELEGATION_OP_CREATED,
    DELEGATION_OP_REMOVED,
    DELEGATION_OP_UPDATED,
    DELEGATION_OPS,
    DELEGATION_SETTINGS_OPTIONS,
    DELEGATION_SETTINGS_VALUES,
    DEVICE_FIELD_MAPPING,
    DEVICES_ENTITY,
    DISCOVERY_SOURCE_FIELD,
    EMPTY_CSV_ERROR_MESSAGE,
    EMPTY_ERROR_MESSAGE,
    ENRICHMENT_BATCH_SIZE,
    ENRICHMENT_IN_CHUNK_SIZE,
    ENRICHMENT_SUBREQUEST_LIMIT,
    ENTITY_RECORD_LABELS,
    GROUP_NAME_MAX_LENGTH,
    INVALID_URL_ERROR_MESSAGE,
    INVALID_VALUE_ERROR_MESSAGE,
    LIMIT,
    MODULE_NAME,
    NETSKOPE_DISCOVERY_SOURCE,
    OPERATOR_OPTIONS,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    PULL_APPLICATION_TAGS,
    PULL_DEVICE_TAGS,
    PULL_INACTIVE_USERS,
    PULL_OPTION_LABELS,
    PULL_OPTIONS_VALUES,
    PULL_USER_DELEGATION,
    PULL_USER_GROUPS,
    PULL_USER_ROLES,
    RESOLVE_IN_CHUNK_SIZE,
    SERVICENOW_BATCH_SIZE,
    SHARE_TABLE_BUSINESS_APP,
    SHARE_TABLE_CORE_COMPANY,
    SHARE_TABLE_OPTIONS,
    STATIC_FIELD_ERROR_MESSAGE,
    SUPPORTED_ACTIONS,
    SUPPORTED_ENTITIES,
    TAG_ACTION_TYPE_OPTIONS,
    TAG_KEY_MAX_LENGTH,
    TAG_STATS_ALREADY_EXISTS,
    TAG_STATS_DOES_NOT_EXIST,
    TYPE_ERROR_MESSAGE,
    URLS,
    USER_FIELD_MAPPING,
    USER_GROUP_ACTION_TYPE_OPTIONS,
    USER_ROLE_ACTION_TYPE_OPTIONS,
    USERS_ENTITY,
    VALIDATION_ERROR_MESSAGE,
    VALIDATION_TABLE_KEYS,
)
from .utils.helper import (
    ServiceNowQuery,
    ServiceNowZTREPluginException,
    ServiceNowZTREPluginHelper,
    build_lookup_url,
    chunk_list,
    describe_targets,
    is_sys_id,
    is_positive_int,
    is_valid_csv_value,
    make_query_list,
    normalize_choice_values,
    normalize_csv_values,
    outcome_bucket,
    outcome_counts,
    unpack_choice_value,
)


class ServiceNowZTREPlugin(PluginBase):
    """CRE ServiceNow plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Service Now plugin initializer.

        Args:
            name (str): Plugin configuration name.
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
        self.provide_action_id = True
        self.servicenow_helper = ServiceNowZTREPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = ServiceNowZTREPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    # ------------------------------------------------------------------
    # Entity definitions
    # ------------------------------------------------------------------

    def get_entities(self) -> List[Entity]:
        """Get available entities.

        Users, Devices and Applications are always returned. Enrichment
        fields (User Roles, User Groups, User Delegation, Tags) are added
        only when the matching Pull Additional Details value is
        selected, so the
        declared schema stays in lock-step with what update_records
        actually populates.

        Returns:
            List[Entity]: Users, Devices and Applications entities.
        """
        selected = self.configuration.get("pull_options", PULL_OPTIONS_VALUES)

        user_fields = [
            EntityField(
                name="User ID",
                type=EntityFieldType.STRING,
                description="Unique ServiceNow sys_id of the user.",
                required=True,
            ),
            EntityField(
                name="Email",
                type=EntityFieldType.STRING,
                description=(
                    "User's email address. Can be used to merge User "
                    "records with other CRE plugins."
                ),
                required=True
            ),
            EntityField(
                name="User Name",
                type=EntityFieldType.STRING,
                description="ServiceNow user name of the user.",
            ),
            EntityField(
                name="Name",
                type=EntityFieldType.STRING,
                description="Full name of the user.",
            ),
            EntityField(
                name="Failed login attempts",
                type=EntityFieldType.NUMBER,
                description="Number of failed login attempts.",
            ),
            EntityField(
                name="Password needs reset",
                type=EntityFieldType.BOOLEAN,
                description="Whether the user's password needs a reset.",
            ),
            EntityField(
                name="Last login time",
                type=EntityFieldType.DATETIME,
                description="Timestamp of the user's last login.",
            ),
            EntityField(
                name="VIP",
                type=EntityFieldType.BOOLEAN,
                description="Whether the user is flagged as VIP.",
            ),
            EntityField(
                name="Business impact",
                type=EntityFieldType.NUMBER,
                description="Business criticality of the user.",
            ),
            EntityField(
                name="Internal Integration User",
                type=EntityFieldType.BOOLEAN,
                description="Whether the user is an integration account.",
            ),
            EntityField(
                name="Web service access only",
                type=EntityFieldType.BOOLEAN,
                description="Whether the user has web-service-only access.",
            ),
            EntityField(
                name="Identity type",
                type=EntityFieldType.STRING,
                description="Identity type of the user.",
            ),
            EntityField(
                name="Federated ID",
                type=EntityFieldType.STRING,
                description="Federated identifier of the user.",
            ),
            EntityField(
                name="Manager",
                type=EntityFieldType.STRING,
                description="Email of the user's manager.",
            ),
            EntityField(
                name="Company",
                type=EntityFieldType.STRING,
                description="Company the user belongs to.",
            ),
            EntityField(
                name="Department",
                type=EntityFieldType.STRING,
                description="Department the user belongs to.",
            ),
            EntityField(
                name="Source",
                type=EntityFieldType.STRING,
                description="Data source of the user record.",
            ),
        ]
        if PULL_INACTIVE_USERS in selected:
            user_fields.append(
                EntityField(
                    name="Is Active",
                    type=EntityFieldType.BOOLEAN,
                    description="Whether the user account is active.",
                )
            )
        if PULL_USER_ROLES in selected:
            user_fields.append(
                EntityField(
                    name="User Roles",
                    type=EntityFieldType.LIST,
                    description="Roles assigned to the user.",
                )
            )
        if PULL_USER_GROUPS in selected:
            user_fields.append(
                EntityField(
                    name="User Groups",
                    type=EntityFieldType.LIST,
                    description="Groups the user is a member of.",
                )
            )
        if PULL_USER_DELEGATION in selected:
            user_fields.append(
                EntityField(
                    name="User Delegation",
                    type=EntityFieldType.LIST,
                    description="Emails of the user's delegates.",
                )
            )

        device_fields = [
            EntityField(
                name="Device ID",
                type=EntityFieldType.STRING,
                description="Unique ServiceNow sys_id of the device.",
                required=True,
            ),
            EntityField(
                name="Device Name",
                type=EntityFieldType.STRING,
                description="Name of the device.",
            ),
            EntityField(
                name="Serial Number",
                type=EntityFieldType.STRING,
                description=(
                    "Hardware serial number. Can be used to merge Device "
                    "records with other CRE plugins."
                ),
                required=True,
            ),
            EntityField(
                name="IP Address",
                type=EntityFieldType.STRING,
                description="IP address of the device.",
            ),
            EntityField(
                name="MAC Address",
                type=EntityFieldType.STRING,
                description="MAC address of the device.",
            ),
            EntityField(
                name="FQDN",
                type=EntityFieldType.STRING,
                description="Fully qualified domain name of the device.",
            ),
            EntityField(
                name="DNS Domain",
                type=EntityFieldType.STRING,
                description="DNS domain of the device.",
            ),
            EntityField(
                name="Life Cycle Stage",
                type=EntityFieldType.STRING,
                description="Life-cycle stage of the device.",
            ),
            EntityField(
                name="Life Cycle Stage Status",
                type=EntityFieldType.STRING,
                description="Life-cycle stage status of the device.",
            ),
            EntityField(
                name="Attested",
                type=EntityFieldType.BOOLEAN,
                description="Whether the device is attested.",
            ),
            EntityField(
                name="Attestation Status",
                type=EntityFieldType.STRING,
                description="Attestation status of the device.",
            ),
            EntityField(
                name="Attestation Score",
                type=EntityFieldType.NUMBER,
                description="Attestation score of the device.",
            ),
            EntityField(
                name="Requires verification",
                type=EntityFieldType.BOOLEAN,
                description="Whether the device requires verification.",
            ),
            EntityField(
                name="Is Virtual",
                type=EntityFieldType.BOOLEAN,
                description="Whether the device is virtual.",
            ),
            EntityField(
                name="Fault Count",
                type=EntityFieldType.NUMBER,
                description="Number of faults on the device.",
            ),
            EntityField(
                name="Environment",
                type=EntityFieldType.STRING,
                description="Environment of the device.",
            ),
            EntityField(
                name="Discovery Source",
                type=EntityFieldType.STRING,
                description="Discovery source of the device.",
            ),
            EntityField(
                name="Device Asset Tag",
                type=EntityFieldType.STRING,
                description="Asset tag of the device.",
            ),
            EntityField(
                name="Assigned To",
                type=EntityFieldType.REFERENCE,
                description=(
                    "Email of the user the device is assigned to. "
                    "This field is used to reference the Users entity."
                ),
            ),
            EntityField(
                name="Managed By",
                type=EntityFieldType.STRING,
                description="User who manages the device.",
            ),
            EntityField(
                name="Most Frequent Login User",
                type=EntityFieldType.STRING,
                description="User who most frequently logs into the device.",
            ),
            EntityField(
                name="Owned By",
                type=EntityFieldType.STRING,
                description="User who owns the device.",
            ),
        ]
        if PULL_DEVICE_TAGS in selected:
            device_fields.append(
                EntityField(
                    name="Tags",
                    type=EntityFieldType.LIST,
                    description="Key/value tags applied to the device.",
                )
            )

        app_fields = [
            EntityField(
                name="Application ID",
                type=EntityFieldType.STRING,
                description="Unique ServiceNow sys_id of the application.",
                required=True,
            ),
            EntityField(
                name="Application Name",
                type=EntityFieldType.STRING,
                description="Name of the application.",
                required=True,
            ),
            EntityField(
                name="Asset Tag",
                type=EntityFieldType.STRING,
                description="Asset tag of the application.",
            ),
            EntityField(
                name="Description",
                type=EntityFieldType.STRING,
                description="Short description of the application.",
            ),
            EntityField(
                name="Comments",
                type=EntityFieldType.STRING,
                description="Free-text comments on the application.",
            ),
            EntityField(
                name="Application URL",
                type=EntityFieldType.STRING,
                description="URL of the application.",
            ),
            EntityField(
                name="IP Address",
                type=EntityFieldType.STRING,
                description="IP Address of the application.",
            ),
            EntityField(
                name="Vendor",
                type=EntityFieldType.STRING,
                description="Vendor of the application.",
            ),
            EntityField(
                name="Manufacturer",
                type=EntityFieldType.STRING,
                description="Manufacturer of the application.",
            ),
            EntityField(
                name="Category",
                type=EntityFieldType.STRING,
                description="Category of the application.",
            ),
            EntityField(
                name="Subcategory",
                type=EntityFieldType.STRING,
                description="Subcategory of the application.",
            ),
            EntityField(
                name="Business Criticality",
                type=EntityFieldType.STRING,
                description="Business criticality of the application.",
            ),
            EntityField(
                name="Data Classification",
                type=EntityFieldType.STRING,
                description="Data classification of the application.",
            ),
            EntityField(
                name="Operational Status",
                type=EntityFieldType.STRING,
                description="Operational status of the application.",
            ),
            EntityField(
                name="Install Status",
                type=EntityFieldType.STRING,
                description="Install status of the application.",
            ),
            EntityField(
                name="Life Cycle Stage",
                type=EntityFieldType.STRING,
                description="Life-cycle stage of the application.",
            ),
            EntityField(
                name="Life Cycle Stage Status",
                type=EntityFieldType.STRING,
                description="Life-cycle stage status of the application.",
            ),
            EntityField(
                name="Product Support Status",
                type=EntityFieldType.STRING,
                description="Product support status of the application.",
            ),
            EntityField(
                name="Certified",
                type=EntityFieldType.BOOLEAN,
                description="Whether the application is certified.",
            ),
            EntityField(
                name="Attested",
                type=EntityFieldType.BOOLEAN,
                description="Whether the application is attested.",
            ),
            EntityField(
                name="Attestation Status",
                type=EntityFieldType.STRING,
                description="Attestation status of the application.",
            ),
            EntityField(
                name="Attestation Score",
                type=EntityFieldType.NUMBER,
                description="Attestation score of the application.",
            ),
            EntityField(
                name="Environment",
                type=EntityFieldType.STRING,
                description="Environment of the application.",
            ),
            EntityField(
                name="Application Type",
                type=EntityFieldType.STRING,
                description="Type of the application.",
            ),
            EntityField(
                name="Next Assessment Date",
                type=EntityFieldType.DATETIME,
                description="Next assessment date of the application.",
            ),
            EntityField(
                name="Active",
                type=EntityFieldType.BOOLEAN,
                description="Whether the application is active.",
            ),
            EntityField(
                name="Owned By",
                type=EntityFieldType.STRING,
                description="User who owns the application.",
            ),
            EntityField(
                name="Managed By",
                type=EntityFieldType.STRING,
                description="User who manages the application.",
            ),
            EntityField(
                name="IT Application Owner",
                type=EntityFieldType.STRING,
                description="IT owner of the application.",
            ),
            EntityField(
                name="Application Portfolio Manager",
                type=EntityFieldType.STRING,
                description="Portfolio manager of the application.",
            ),
            EntityField(
                name="Support Group",
                type=EntityFieldType.STRING,
                description="Support group of the application.",
            ),
            EntityField(
                name="Company",
                type=EntityFieldType.STRING,
                description="Company the application belongs to.",
            ),
            EntityField(
                name="User Base",
                type=EntityFieldType.STRING,
                description="User base of the application.",
            ),
            EntityField(
                name="Active User Count",
                type=EntityFieldType.NUMBER,
                description="Active user count of the application.",
            ),
            EntityField(
                name="Discovery Source",
                type=EntityFieldType.STRING,
                description="Discovery source of the application.",
            ),
            EntityField(
                name="Last Updated",
                type=EntityFieldType.DATETIME,
                description="Timestamp when the application was updated.",
            ),
        ]
        if PULL_APPLICATION_TAGS in selected:
            app_fields.append(
                EntityField(
                    name="Tags",
                    type=EntityFieldType.LIST,
                    description="Key/value tags applied to the application.",
                )
            )

        return [
            Entity(name=USERS_ENTITY, fields=user_fields),
            Entity(name=DEVICES_ENTITY, fields=device_fields),
            Entity(name=APPLICATIONS_ENTITY, fields=app_fields),
        ]

    # ------------------------------------------------------------------
    # Extraction / normalization helpers
    # ------------------------------------------------------------------

    def _get_raw_value(self, record: Dict, key: str, use: str):
        """Read a single field from a display_value=all record.

        Args:
            record (Dict): The API record.
            key (str): The sysparm_fields token (flat / dot-walked).
            use (str): "value" (raw) or "display" (label).

        Returns:
            The extracted primitive string, or None when absent/empty.
        """
        raw = record.get(key)
        if raw is None:
            return None
        if isinstance(raw, dict):
            picked = raw.get("display_value") if use == "display" \
                else raw.get("value")
        else:
            picked = raw
        if picked is None or picked == "":
            return None
        return picked

    def _str_to_datetime(self, value: str):
        """Parse a ServiceNow date/date-time string to a datetime.

        Args:
            value (str): The date/date-time string.

        Returns:
            datetime.datetime or None when it cannot be parsed.
        """
        for fmt in DATETIME_FORMATS:
            try:
                return datetime.datetime.strptime(value, fmt)
            except (ValueError, TypeError):
                continue
        self.logger.debug(
            f"{self.log_prefix}: Unable to parse datetime value "
            f"'{value}'."
        )
        return None

    def _coerce_value(self, value, field_type: str):
        """Coerce a raw string to the declared field type.

        ServiceNow returns booleans as the strings "true"/"false" and
        integers as digit strings, so they are coerced here.

        Args:
            value: The raw value (string) to coerce.
            field_type (str): "string", "integer", "boolean" or
                "datetime".

        Returns:
            The coerced value, or None when coercion is not possible.
        """
        if value is None:
            return None
        if field_type == "boolean":
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() == "true"
        if field_type == "integer":
            try:
                return int(value)
            except (ValueError, TypeError):
                return None
        if field_type == "datetime":
            return self._str_to_datetime(value)
        return str(value)

    def _extract_record(self, record: Dict, mapping: Dict) -> Dict:
        """Build a normalized CE record from a mapping.

        Args:
            record (Dict): Raw API record (display_value=all shape).
            mapping (Dict): One of the *_FIELD_MAPPING dicts.

        Returns:
            Dict: Normalized record keyed by CE field name.
        """
        extracted = {}
        for field_name, spec in mapping.items():
            raw = self._get_raw_value(record, spec["key"], spec["use"])
            if raw is None and spec.get("fallback"):
                raw = self._get_raw_value(
                    record, spec["fallback"], spec["use"]
                )
            self._add_field(
                extracted,
                field_name,
                self._coerce_value(raw, spec["type"]),
            )
        return extracted

    def _add_field(self, record: Dict, field_name: str, value) -> None:
        """Store a field, normalizing empty containers/strings to None.

        Numeric zero is preserved (only empty strings and empty
        containers become None), matching the MongoDB-safety convention.

        Args:
            record (Dict): Record being built.
            field_name (str): CE field name.
            value: Value to store.
        """
        if isinstance(value, (dict, list, str)) and len(value) == 0:
            value = None
        record[field_name] = value

    # ------------------------------------------------------------------
    # Pagination helpers
    # ------------------------------------------------------------------

    def _paginate_table(
        self,
        url_path: str,
        headers: Dict,
        instance_url: str,
        fields: str,
        query: str,
        logger_msg: str,
        display_value_all: bool = True,
        start_offset: int = 0,
        limit: int = LIMIT,
        sub_id: Optional[str] = None,
        batch_index: Optional[int] = None,
    ):
        """Offset-paginate a Table API endpoint, yielding rows per page.

        Used for the primary entity pulls. Yields one page at a time
        instead of returning the full list so callers can extract and
        log each page as it arrives - see `_fetch_paginated_records`
        and `_fetch_all_rows`, which build on this.

        Args:
            url_path (str): Path-only endpoint from URLS.
            headers (Dict): Request headers (Basic Auth).
            instance_url (str): ServiceNow instance URL.
            fields (str): Comma-separated sysparm_fields (no spaces).
            query (str): sysparm_query filter (may be empty).
            logger_msg (str): Human-readable log context.
            display_value_all (bool): Request value + display_value.
            start_offset (int): sysparm_offset to begin at. Non-zero
                lets a caller resume paging where an earlier request
                stopped - e.g. the enrichment truncation follow-up
                continuing past the rows a batch sub-request already
                returned, instead of re-fetching from the start.
            limit (int): sysparm_limit page size (defaults to LIMIT).
            sub_id (Optional[str]): Batch sub-request id to name in the
                log line when this call is resuming a truncated
                enrichment sub-request. Omitted for the plain entity
                pulls.
            batch_index (Optional[int]): Batch chunk index to pair with
                sub_id in the log line. Omitted for the plain entity
                pulls.

        Yields:
            List[Dict]: The raw rows for one page.
        """
        endpoint = f"{instance_url}{url_path}"
        offset = start_offset
        page = (start_offset // limit) + 1 if limit else 1
        context = (
            f" for subrequest {sub_id} in batch {batch_index}"
            if sub_id is not None and batch_index is not None
            else ""
        )
        while True:
            params = {
                "sysparm_limit": limit,
                "sysparm_offset": offset,
                "sysparm_fields": fields,
                "sysparm_exclude_reference_link": "true",
            }
            if query:
                params["sysparm_query"] = query
            if display_value_all:
                params["sysparm_display_value"] = "all"
            response = self.servicenow_helper.api_helper(
                url=endpoint,
                method="GET",
                params=params,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"fetching {logger_msg} for page {page}{context}"
                ),
            )
            page_rows = response.get("result", []) or []
            yield page_rows
            if len(page_rows) < limit:
                break
            offset += limit
            page += 1

    def _fetch_all_rows(
        self,
        url_path: str,
        headers: Dict,
        instance_url: str,
        fields: str,
        query: str,
        logger_msg: str,
        display_value_all: bool = True,
    ) -> List[Dict]:
        """Collect every row from `_paginate_table`, logging per page.

        Use when the caller has no per-row extraction step (e.g.
        building an action dropdown) and just wants every row. Callers
        that also extract a record per row should use
        `_fetch_paginated_records` instead, so the "fetched" count in
        the log reflects what was actually kept, not just what the API
        returned.

        Args: same as `_paginate_table`.

        Returns:
            List[Dict]: All raw rows across every page.
        """
        rows = []
        for page, page_rows in enumerate(
            self._paginate_table(
                url_path=url_path,
                headers=headers,
                instance_url=instance_url,
                fields=fields,
                query=query,
                logger_msg=logger_msg,
                display_value_all=display_value_all,
            ),
            start=1,
        ):
            rows.extend(page_rows)
            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched "
                f"{len(page_rows)} {logger_msg} in page {page}. "
                f"Total fetched: {len(rows)}."
            )
        return rows

    def _fetch_paginated_records(
        self,
        url_path: str,
        headers: Dict,
        instance_url: str,
        mapping: Dict,
        id_field: str,
        entity: str,
        query: str,
        echo_field: Optional[str] = None,
    ) -> List[Dict]:
        """Paginate, extract and log an entity pull one page at a time.

        Extracting per page - rather than accumulating raw rows and
        extracting once at the end - keeps the "fetched" count in the
        per-page log accurate to records actually kept (had a valid
        id), not just how many rows the API returned that page.

        Args:
            url_path (str): Path-only endpoint from URLS.
            headers (Dict): Request headers (Basic Auth).
            instance_url (str): ServiceNow instance URL.
            mapping (Dict): Field mapping for the entity.
            id_field (str): CE field name of the unique id.
            entity (str): Entity name. Every log line below names the
                records through ENTITY_RECORD_LABELS[entity] rather than
                taking a separate label parameter, so the per-page and
                end-of-pull lines cannot disagree about what to call
                them.
            query (str): sysparm_query filter (may be empty).
            echo_field (Optional[str]): Raw discovery-source field. When
                given, it is added to sysparm_fields and rows this
                plugin itself shared to ServiceNow are dropped as they
                are read, then reported once at the end of the pull.

        Returns:
            List[Dict]: Normalized records across every page.
        """
        records = []
        skip_count = 0
        echo_count = 0
        logger_msg = ENTITY_RECORD_LABELS[entity]
        fields = self._build_fields(mapping)
        if echo_field and echo_field not in fields.split(","):
            fields += f",{echo_field}"
        for page, page_rows in enumerate(
            self._paginate_table(
                url_path=url_path,
                headers=headers,
                instance_url=instance_url,
                fields=fields,
                query=query,
                logger_msg=logger_msg,
            ),
            start=1,
        ):
            page_records, page_skipped, page_echoed = (
                self._records_from_rows(
                    page_rows, mapping, id_field, echo_field
                )
            )
            records.extend(page_records)
            skip_count += page_skipped
            echo_count += page_echoed
            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched and "
                f"processed {len(page_records)} of {len(page_rows)} "
                f"{logger_msg} in page {page}. Total processed: "
                f"{len(records)}."
            )
        skip_msg = ""
        if skip_count:
            skip_msg = (
                f" Skipped fetching {skip_count} {logger_msg} "
                "with a missing sys_id."
            )
        if echo_count:
            skip_msg += (
                f" Skipped re-pulling {echo_count} {logger_msg} "
                "shared from Netskope Cloud Exchange."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(records)} "
            f"{logger_msg} from {PLATFORM_NAME}.{skip_msg}"
        )
        return records

    # ------------------------------------------------------------------
    # fetch_records
    # ------------------------------------------------------------------

    def fetch_records(self, entity: str) -> List:
        """Pull records for an entity from ServiceNow.

        Args:
            entity (str): One of Users, Devices, Applications.

        Returns:
            List: Normalized records keyed by CE field names.

        Raises:
            ServiceNowZTREPluginException: On invalid entity or API error.
        """
        if entity not in SUPPORTED_ENTITIES:
            err_msg = (
                f"Invalid entity '{entity}' provided. Supported entities "
                f"are: {', '.join(SUPPORTED_ENTITIES)}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure the entity is one of "
                    f"{', '.join(SUPPORTED_ENTITIES)}."
                ),
            )
            raise ServiceNowZTREPluginException(err_msg)

        try:
            instance_url, username, password = (
                self.servicenow_helper.get_config_params(self.configuration)
            )
            headers = self.servicenow_helper.basic_auth(username, password)
            if entity == USERS_ENTITY:
                return self._fetch_users(headers, instance_url)
            elif entity == DEVICES_ENTITY:
                return self._fetch_devices(headers, instance_url)
            return self._fetch_applications(headers, instance_url)
        except ServiceNowZTREPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while fetching "
                f"{ENTITY_RECORD_LABELS[entity]} from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise ServiceNowZTREPluginException(err_msg)

    def _build_fields(self, mapping: Dict) -> str:
        """Build a sysparm_fields string (no spaces) from a mapping."""
        keys = []
        for spec in mapping.values():
            keys.append(spec["key"])
            if spec.get("fallback"):
                keys.append(spec["fallback"])
        # Preserve order, drop duplicates.
        return ",".join(list(dict.fromkeys(keys)))

    def _records_from_rows(
        self,
        rows: List[Dict],
        mapping: Dict,
        id_field: str,
        echo_field: Optional[str] = None,
    ) -> Tuple[List[Dict], int, int]:
        """Normalize raw rows into CE records, skipping keyless ones.

        Args:
            rows (List[Dict]): Raw API rows (one page's worth).
            mapping (Dict): Field mapping for the entity.
            id_field (str): CE field name of the unique id.
            echo_field (Optional[str]): Raw field holding the row's
                discovery source. When given, rows discovered by this
                plugin itself are dropped so records shared to
                ServiceNow are not pulled straight back in.

        Returns:
            Tuple[List[Dict], int, int]: Normalized records, how many
            rows were skipped for missing an id, and how many were
            dropped as this plugin's own echo.
        """
        records = []
        skip_count = 0
        echo_count = 0
        for row in rows:
            if echo_field and self._is_echoed_row(row, echo_field):
                echo_count += 1
                continue
            record = self._extract_record(row, mapping)
            if not record.get(id_field):
                skip_count += 1
                continue
            records.append(record)
        return records, skip_count, echo_count

    def _is_echoed_row(self, row: Dict, echo_field: str) -> bool:
        """Whether a raw row was created by this plugin's share action.

        Filtered here rather than through a sysparm_query, because the
        server-side "discovery_source!=NetskopeCloudExchange" filter
        does not reliably exclude these rows. Under
        sysparm_display_value=all the field arrives as
        {"value", "display_value"}; either may carry the source
        depending on how the choice is configured on the instance, so
        both are compared.

        Args:
            row (Dict): Raw API row.
            echo_field (str): Raw field holding the discovery source.

        Returns:
            bool: True when the row is this plugin's own echo.
        """
        raw = row.get(echo_field)
        if isinstance(raw, dict):
            candidates = (raw.get("value"), raw.get("display_value"))
        else:
            candidates = (raw,)
        return any(
            str(candidate).strip() == NETSKOPE_DISCOVERY_SOURCE
            for candidate in candidates
            if candidate
        )

    def _fetch_users(self, headers: Dict, instance_url: str) -> List[Dict]:
        """Fetch Users from sys_user."""
        selected = self.configuration.get(
            "pull_options", PULL_OPTIONS_VALUES
        )
        query = ""
        mapping = USER_FIELD_MAPPING
        if PULL_INACTIVE_USERS not in selected:
            query = "active=true"
            # Every row this query returns is active, so 'Is Active'
            # would be a constant True. get_entities does not declare
            # the field in this case, so it must not be extracted either
            # - dropping it here also keeps 'active' out of
            # sysparm_fields.
            mapping = {
                field: spec
                for field, spec in USER_FIELD_MAPPING.items()
                if field != "Is Active"
            }
            self.logger.info(
                f"{self.log_prefix}: Fetching only active User records as "
                f"'{PULL_OPTION_LABELS[PULL_INACTIVE_USERS]}' is not "
                "selected in the Pull Additional Details configuration "
                "parameter."
            )
        return self._fetch_paginated_records(
            url_path=URLS["USERS"],
            headers=headers,
            instance_url=instance_url,
            mapping=mapping,
            id_field="User ID",
            entity=USERS_ENTITY,
            query=query,
        )

    def _fetch_devices(self, headers: Dict, instance_url: str) -> List[Dict]:
        """Fetch Devices from cmdb_ci_computer."""
        return self._fetch_paginated_records(
            url_path=URLS["DEVICES"],
            headers=headers,
            instance_url=instance_url,
            mapping=DEVICE_FIELD_MAPPING,
            id_field="Device ID",
            entity=DEVICES_ENTITY,
            query="",
        )

    def _fetch_applications(
        self, headers: Dict, instance_url: str
    ) -> List[Dict]:
        """Fetch Applications from cmdb_ci_business_app (echo-filtered).

        Applications this plugin's Share Application Data action created
        are stamped with discovery_source=NetskopeCloudExchange and must
        not be pulled back in. The server-side
        "discovery_source!=NetskopeCloudExchange" sysparm_query does not
        reliably exclude them, so every row is fetched and the echo is
        dropped on our side while each page is processed - see
        `_is_echoed_row`.
        """
        return self._fetch_paginated_records(
            url_path=URLS["APPLICATIONS"],
            headers=headers,
            instance_url=instance_url,
            mapping=APPLICATION_FIELD_MAPPING,
            id_field="Application ID",
            entity=APPLICATIONS_ENTITY,
            query="",
            echo_field=DISCOVERY_SOURCE_FIELD,
        )

    # ------------------------------------------------------------------
    # update_records (enrichment via bulk fetch-and-join)
    # ------------------------------------------------------------------

    def update_records(self, entity: str, records: List[Dict]) -> List:
        """Enrich records with fetch-and-join data from ServiceNow.

        Runs only the enrichments selected in Pull Additional
        Details. Each
        enrichment fetches a relationship table once, builds an
        in-memory map, and joins it onto the records by sys_id.

        Args:
            entity (str): One of Users, Devices, Applications.
            records (List[Dict]): Existing records from the CE store.
                Only the required id field is guaranteed to be
                populated; every other field is a null placeholder.

        Returns:
            List: Records containing only the id field plus the
                enrichment fields actually updated this run (never
                None). Untouched fields are omitted rather than sent
                as null, so already-stored values are not overwritten.

        Raises:
            ServiceNowZTREPluginException: On invalid entity.
        """
        if entity not in SUPPORTED_ENTITIES:
            err_msg = (
                f"Invalid entity '{entity}' provided. Supported entities "
                f"are: {', '.join(SUPPORTED_ENTITIES)}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure the entity is one of "
                    f"{', '.join(SUPPORTED_ENTITIES)}."
                ),
            )
            raise ServiceNowZTREPluginException(err_msg)

        selected = self.configuration.get(
            "pull_options", PULL_OPTIONS_VALUES
        )
        if not records:
            self.logger.info(
                f"{self.log_prefix}: No "
                f"{ENTITY_RECORD_LABELS[entity]} to update. "
                "Hence skipping update records workflow."
            )
            return records

        try:
            instance_url, username, password = (
                self.servicenow_helper.get_config_params(self.configuration)
            )
            headers = self.servicenow_helper.basic_auth(username, password)

            if entity == USERS_ENTITY:
                return self._enrich_users(
                    records, headers, instance_url, selected
                )
            if entity == DEVICES_ENTITY:
                return self._enrich_tags(
                    records,
                    headers,
                    instance_url,
                    selected,
                    PULL_DEVICE_TAGS,
                    "Device ID",
                    ["Serial Number"],
                )
            return self._enrich_tags(
                records,
                headers,
                instance_url,
                selected,
                PULL_APPLICATION_TAGS,
                "Application ID",
                ["Application Name"],
            )
        except ServiceNowZTREPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while enriching "
                f"{ENTITY_RECORD_LABELS[entity]} from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise ServiceNowZTREPluginException(err_msg)

    def _log_skipped_pull(self, option: str) -> None:
        """Log that a gated fetch/enrichment was skipped.

        Args:
            option (str): The Pull Additional Details value that was not
                selected.
        """
        label = PULL_OPTION_LABELS[option]
        self.logger.info(
            f"{self.log_prefix}: Skipped fetching {label.lower()} as "
            f"'{label}' is not selected in the Pull Additional Details "
            "configuration parameter."
        )

    def _enrich_users(
        self,
        records: List[Dict],
        headers: Dict,
        instance_url: str,
        selected: List[str],
    ) -> List[Dict]:
        """Enrich Users with roles, groups and delegation.

        Related rows are fetched with a "userIN<sys_id,...>" filter over
        the Batch API (see _fetch_relationships), so only the incoming
        users' data is pulled rather than whole relationship tables.
        The framework populates only the required 'User ID' and 'Email'
        fields on each incoming record; every other field is a null
        placeholder. Returned records therefore carry only those two
        plus the enrichment fields actually selected - echoing back the
        null placeholders would overwrite already-stored values with
        None. Users whose fetch failed are left untouched (the field is
        omitted) and reported as a skip count.
        """
        specs = []
        if PULL_USER_ROLES in selected:
            specs.append({
                "url": URLS["USER_HAS_ROLE"],
                "key_field": "user",
                "fields": "user,role.name",
                "value_of": lambda row: self._get_raw_value(
                    row, "role.name", "value"
                ),
                "ce_field": "User Roles",
                "logger_msg": f"user roles from {PLATFORM_NAME}",
                "batch_tag": "user-roles",
            })
        else:
            self._log_skipped_pull(PULL_USER_ROLES)
        if PULL_USER_GROUPS in selected:
            specs.append({
                "url": URLS["USER_GRMEMBER"],
                "key_field": "user",
                "fields": "user,group.name",
                "value_of": lambda row: self._get_raw_value(
                    row, "group.name", "value"
                ),
                "ce_field": "User Groups",
                "logger_msg": f"user groups from {PLATFORM_NAME}",
                "batch_tag": "user-groups",
            })
        else:
            self._log_skipped_pull(PULL_USER_GROUPS)
        if PULL_USER_DELEGATION in selected:
            specs.append({
                "url": URLS["USER_DELEGATE"],
                "key_field": "user",
                "fields": "user,delegate.email",
                "value_of": lambda row: self._get_raw_value(
                    row, "delegate.email", "value"
                ),
                "ce_field": "User Delegation",
                "logger_msg": (
                    f"user delegation details from {PLATFORM_NAME}"
                ),
                "batch_tag": "user-delegation",
            })
        else:
            self._log_skipped_pull(PULL_USER_DELEGATION)

        if not specs:
            return []

        target_ids = [
            record.get("User ID")
            for record in records
            if record.get("User ID")
        ]
        values, skipped_ids = self._fetch_relationships(
            target_ids=target_ids,
            headers=headers,
            instance_url=instance_url,
            specs=specs,
        )

        updated_records = []
        for record in records:
            user_id = record.get("User ID")
            if not user_id:
                continue
            updated = {
                "User ID": user_id,
                "Email": record.get("Email"),
            }
            for spec in specs:
                ce_field = spec["ce_field"]
                if user_id in values[ce_field]:
                    self._add_field(
                        updated, ce_field, values[ce_field][user_id]
                    )
            updated_records.append(updated)

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched additional data "
            f"for {len(target_ids) - len(skipped_ids)} "
            f"{ENTITY_RECORD_LABELS[USERS_ENTITY]}."
        )
        if skipped_ids:
            self.logger.info(
                f"{self.log_prefix}: Skipped {len(skipped_ids)} "
                f"{ENTITY_RECORD_LABELS[USERS_ENTITY]} whose "
                "additional data could not be fetched "
                f"from {PLATFORM_NAME}."
            )
        return updated_records

    def _enrich_tags(
        self,
        records: List[Dict],
        headers: Dict,
        instance_url: str,
        selected: List[str],
        option: str,
        id_field: str,
        extra_fields: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Enrich Devices/Applications with cmdb_key_value tags.

        Tags are fetched with a "configuration_itemIN<sys_id,...>"
        filter over the Batch API (see _fetch_relationships), so only
        the incoming records' tags are pulled rather than the whole
        cmdb_key_value table. The framework populates only the required
        fields on each incoming record; every other field is a null
        placeholder. Returned records therefore carry only the id field,
        any extra_fields merge keys, and 'Tags' - echoing back the null
        placeholders would overwrite already-stored values with None.
        Records whose fetch failed are left untouched (Tags omitted) and
        reported as a skip count.

        Args:
            extra_fields (Optional[List[str]]): Additional
                already-populated fields (the entity's other required
                fields) to carry through onto each returned record -
                Serial Number for Devices, Application Name for
                Applications.
        """
        if option not in selected:
            self._log_skipped_pull(option)
            return []

        # entity_label is the lowercase noun for the fetch context and
        # the batch tag ("device tags", "device-tags"); anything that
        # logs a count uses record_label, so a tag count reads the same
        # way as the fetch count for the same records.
        entity_label = (
            "device" if option == PULL_DEVICE_TAGS else "application"
        )
        record_label = ENTITY_RECORD_LABELS[
            DEVICES_ENTITY if option == PULL_DEVICE_TAGS
            else APPLICATIONS_ENTITY
        ]

        def _tag_value(row):
            key = self._get_raw_value(row, "key", "value")
            value = self._get_raw_value(row, "value", "value")
            if not key:
                return None
            return f"{key}={value}" if value else key

        target_ids = [
            record.get(id_field)
            for record in records
            if record.get(id_field)
        ]
        values, skipped_ids = self._fetch_relationships(
            target_ids=target_ids,
            headers=headers,
            instance_url=instance_url,
            specs=[{
                "url": URLS["KEY_VALUE"],
                "key_field": "configuration_item",
                "fields": "configuration_item,key,value",
                "value_of": _tag_value,
                "ce_field": "Tags",
                "logger_msg": f"{entity_label} tags from {PLATFORM_NAME}",
                "batch_tag": f"{entity_label}-tags",
            }],
        )

        tag_map = values["Tags"]
        updated_records = []
        for record in records:
            ci_id = record.get(id_field)
            if not ci_id:
                continue
            updated = {id_field: ci_id}
            for field in extra_fields or []:
                updated[field] = record.get(field)
            if ci_id in tag_map:
                self._add_field(updated, "Tags", tag_map[ci_id])
            updated_records.append(updated)

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched tags for "
            f"{len(target_ids) - len(skipped_ids)} {record_label}."
        )
        if skipped_ids:
            self.logger.info(
                f"{self.log_prefix}: Skipped {len(skipped_ids)} "
                f"{record_label} whose tags could not be fetched "
                f"from {PLATFORM_NAME}."
            )
        return updated_records

    def _fetch_relationships(
        self,
        target_ids: List[str],
        headers: Dict,
        instance_url: str,
        specs: List[Dict],
    ) -> Tuple[Dict[str, Dict[str, List[str]]], Set[str]]:
        """Fetch related rows for target_ids via IN-filtered batch GETs.

        Rather than sweeping a whole relationship table into memory,
        each table in `specs` is filtered by "<key_field>IN<chunk of
        target sys_ids>". Those GET sub-requests are bundled
        ENRICHMENT_BATCH_SIZE at a time into Batch API calls, and each
        batch response is processed and discarded as it arrives (via the
        _send_batch on_batch callback), so the working set scales with
        target_ids - the records under update - not with the tenant.

        A sub-request whose result hits ENRICHMENT_SUBREQUEST_LIMIT keeps
        the rows it returned and resumes offset-paging from that cap (a
        batch sub-request cannot paginate itself). A sub-request (or a
        whole batch) that fails leaves its sys_ids out of the results and
        adds them to the skipped set. A successfully-fetched sys_id always
        gets an entry (empty when it has no rows), so a field that has
        dropped to zero is written through as empty rather than left
        stale.

        Args:
            target_ids (List[str]): sys_ids of the records under update.
            headers (Dict): Basic Auth headers.
            instance_url (str): Instance URL.
            specs (List[Dict]): One dict per relationship table, with
                keys url, key_field, fields, value_of (row -> str value
                or None), ce_field, logger_msg and batch_tag. Each spec
                is fetched in its own set of Batch API calls so both the
                log line and the correlation id name that specific
                relationship (e.g. "user roles") rather than a generic
                "additional data".

        Returns:
            Tuple[Dict[str, Dict[str, List[str]]], Set[str]]:
                values[ce_field][sys_id] -> collected values (present,
                even if empty, only for successfully-fetched sys_ids),
                and the set of sys_ids whose fetch failed for at least
                one spec.
        """
        values: Dict[str, Dict[str, List[str]]] = {
            spec["ce_field"]: {} for spec in specs
        }
        skipped_ids: Set[str] = set()
        if not target_ids or not specs:
            return values, skipped_ids

        for spec in specs:
            rest_requests = []
            sub_meta: Dict[str, Dict] = {}
            counter = 0
            for chunk in chunk_list(
                target_ids, ENRICHMENT_IN_CHUNK_SIZE
            ):
                counter += 1
                sub_id = str(counter)
                url = build_lookup_url(
                    spec["url"],
                    f"{spec['key_field']}IN{','.join(chunk)}",
                    spec["fields"],
                    limit=ENRICHMENT_SUBREQUEST_LIMIT,
                ) + "&sysparm_exclude_reference_link=true"
                rest_requests.append(
                    {"id": sub_id, "method": "GET", "url": url}
                )
                sub_meta[sub_id] = {"ids": chunk}

            def process(
                chunk_index, chunk_results, spec=spec, sub_meta=sub_meta
            ):
                bucket = values[spec["ce_field"]]
                for sub_id, (status, decoded) in chunk_results.items():
                    meta = sub_meta.get(sub_id)
                    if not meta:
                        continue
                    ids = meta["ids"]
                    if status is None or not (200 <= status < 300):
                        skipped_ids.update(ids)
                        continue
                    rows = decoded.get("result", []) or []
                    if len(rows) >= ENRICHMENT_SUBREQUEST_LIMIT:
                        # The sub-request filled its page cap, so more
                        # rows may exist. Keep the ones we already have
                        # and resume offset-paging from where it stopped
                        # rather than re-fetching from the start.
                        self.logger.info(
                            message=(
                                f"{self.log_prefix}: Found more than "
                                f"{ENRICHMENT_SUBREQUEST_LIMIT} records "
                                f"in subrequest {sub_id} in batch "
                                f"{chunk_index} while fetching "
                                f"{spec['logger_msg']}, hence paginating "
                                "over the remaining records."
                            )
                        )
                        try:
                            for page_rows in self._paginate_table(
                                url_path=spec["url"],
                                headers=headers,
                                instance_url=instance_url,
                                fields=spec["fields"],
                                query=(
                                    f"{spec['key_field']}IN"
                                    f"{','.join(ids)}"
                                ),
                                logger_msg=spec["logger_msg"],
                                display_value_all=False,
                                start_offset=ENRICHMENT_SUBREQUEST_LIMIT,
                                limit=ENRICHMENT_SUBREQUEST_LIMIT,
                                sub_id=sub_id,
                                batch_index=chunk_index,
                            ):
                                rows.extend(page_rows)
                        except Exception:
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: Error occurred "
                                    "while fetching the remaining pages "
                                    f"of {spec['logger_msg']}; treating "
                                    "those record(s) as skipped."
                                ),
                                details=traceback.format_exc(),
                            )
                            skipped_ids.update(ids)
                            continue
                    for sid in ids:
                        bucket.setdefault(sid, [])
                    for row in rows:
                        key = self._get_raw_value(
                            row, spec["key_field"], "value"
                        )
                        if not key:
                            continue
                        value = spec["value_of"](row)
                        if not value:
                            continue
                        bucket.setdefault(key, []).append(value)

            self._send_batch(
                rest_requests=rest_requests,
                headers=headers,
                instance_url=instance_url,
                logger_msg=f"fetching {spec['logger_msg']}",
                batch_tag=spec["batch_tag"],
                batch_size=ENRICHMENT_BATCH_SIZE,
                on_batch=process,
            )
        return values, skipped_ids

    # ------------------------------------------------------------------
    # Batch API transport
    # ------------------------------------------------------------------

    def _send_batch(
        self,
        rest_requests: List[Dict],
        headers: Dict,
        instance_url: str,
        logger_msg: str,
        batch_tag: str,
        report_chunk=None,
        batch_size: Optional[int] = None,
        on_batch=None,
        is_validation: bool = False,
    ) -> Dict[str, Tuple[Optional[int], Dict]]:
        """Send sub-requests via the Batch API and return per-id outcomes.

        Sub-request bodies are base64-encoded; serviced response bodies
        are base64-decoded. The batch call returns HTTP 200 even when
        individual sub-requests fail, so outcomes are parsed per
        sub-request. Unserviced sub-requests are recorded with a None
        status so callers can fail them. Each sub-request sets
        exclude_response_headers=true, since only status_code and
        body are ever read below - this shrinks the response with no
        functional effect. A chunk whose outer batch call itself fails
        (e.g. a non-2xx on POST /api/now/v1/batch) is caught here and
        every sub-request in that chunk is recorded as unserviced, so
        one bad chunk doesn't abort the remaining chunks.

        Args:
            rest_requests (List[Dict]): Each dict has keys id (str),
                method, url (path-only) and optional body (dict).
            headers (Dict): Basic Auth headers for the outer call.
            instance_url (str): Instance URL.
            logger_msg (str): Log context.
            batch_tag (str): Short "<entity>-<operation>" label (e.g.
                "group-add-check") folded into batch_request_id so
                ServiceNow-side logs show what each batch call did.
            report_chunk (Optional[Callable[[int, Set[str], List[str]],
                None]]): When given, called once per chunk as
                (chunk_index, success_ids, fail_ids) - the sub_ids of
                this chunk's requests, split by outcome - so the
                caller can log a natural per-batch summary in its own
                vocabulary.
            batch_size (Optional[int]): Sub-requests per Batch API
                call. Defaults to SERVICENOW_BATCH_SIZE; the enrichment
                sweep passes ENRICHMENT_BATCH_SIZE.
            on_batch (Optional[Callable[[int, Dict], None]]): When
                given, called once per chunk as (chunk_index, that
                chunk's sub_id -> (status, decoded_body) results), and
                those results are NOT accumulated into the return
                value - so a streaming caller can process and discard
                each batch response and keep memory flat. When omitted,
                all results are accumulated and returned as before.
            is_validation (bool): Set by the configuration-time table
                access check. Marks the outer call as a validation call
                (for the helper's error wording) and re-raises a failed
                chunk instead of marking it unserviced, so a bad URL or
                bad credentials is reported as such rather than as
                every table being inaccessible.

        Returns:
            Dict[str, Tuple[Optional[int], Dict]]: sub_id ->
                (status_code, decoded_body). status_code is None when the
                sub-request was unserviced.
        """
        results: Dict[str, Tuple[Optional[int], Dict]] = {}
        endpoint = f"{instance_url}{URLS['BATCH']}"
        for chunk_index, chunk in enumerate(
            chunk_list(
                rest_requests, batch_size or SERVICENOW_BATCH_SIZE
            ),
            start=1,
        ):
            chunk_results: Dict[str, Tuple[Optional[int], Dict]] = {}
            payload_requests = []
            for req in chunk:
                entry = {
                    "id": str(req["id"]),
                    "method": req["method"],
                    "url": req["url"],
                    "exclude_response_headers": True,
                    "headers": [
                        {
                            "name": "Content-Type",
                            "value": "application/json",
                        },
                        {"name": "Accept", "value": "application/json"},
                    ],
                }
                if req.get("body") is not None:
                    entry["body"] = b64encode(
                        json.dumps(req["body"]).encode("utf-8")
                    ).decode("ascii")
                payload_requests.append(entry)
            batch_body = {
                "batch_request_id": (
                    f"{BATCH_REQUEST_ID}-{batch_tag}-{chunk_index}"
                ),
                "rest_requests": payload_requests,
            }
            try:
                response = self.servicenow_helper.api_helper(
                    url=endpoint,
                    method="POST",
                    headers=headers,
                    json=batch_body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=(
                        f"{logger_msg} in batch {chunk_index}"
                    ),
                    is_validation=is_validation,
                )
                for serviced in (
                    response.get("serviced_requests", []) or []
                ):
                    sub_id = str(serviced.get("id"))
                    try:
                        status = int(serviced.get("status_code"))
                    except (TypeError, ValueError):
                        status = None
                    decoded = {}
                    body_b64 = serviced.get("body")
                    if body_b64:
                        try:
                            decoded = json.loads(
                                b64decode(body_b64).decode("utf-8")
                            )
                        except Exception:
                            decoded = {}
                    chunk_results[sub_id] = (status, decoded)
                for unserviced in (
                    response.get("unserviced_requests", []) or []
                ):
                    if isinstance(unserviced, dict):
                        sub_id = str(unserviced.get("id"))
                    else:
                        sub_id = str(unserviced)
                    chunk_results[sub_id] = (None, {})
            except Exception:
                if is_validation:
                    raise
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"{logger_msg} in batch {chunk_index}. Skipping "
                        "this batch and moving onto the next batch."
                    ),
                    details=traceback.format_exc(),
                )
                for req in chunk:
                    chunk_results[str(req["id"])] = (None, {})

            if report_chunk is not None:
                success_ids = {
                    str(req["id"]) for req in chunk
                    if chunk_results.get(str(req["id"]), (None, {}))[0]
                    in (200, 201, 204)
                }
                fail_ids = [
                    str(req["id"]) for req in chunk
                    if str(req["id"]) not in success_ids
                ]
                report_chunk(chunk_index, success_ids, fail_ids)
            if on_batch is not None:
                on_batch(chunk_index, chunk_results)
            else:
                results.update(chunk_results)
        return results

    def _resolve_sys_ids(
        self,
        url_path: str,
        query_fields: List[str],
        values: List[str],
        headers: Dict,
        instance_url: str,
    ) -> Dict[str, Optional[str]]:
        """Resolve many names/emails to sys_ids in one call per chunk.

        Instead of one GET per value, the values are packed into a
        single "<field>IN<v1,v2,...>" filter (OR-combined across
        query_fields) and matched back to their rows locally, so a bulk
        action call resolving N distinct users costs
        ceil(N / RESOLVE_IN_CHUNK_SIZE) requests rather than N. The
        chunk size bounds the query string, since a plain GET carries
        the filter in the URL and the value list is repeated once per
        query field.

        Matching is case-insensitive, as ServiceNow's own string
        comparisons are, and query_fields order decides precedence when
        a value matches on more than one column (e.g. one user's email
        is another's user name).

        Args:
            url_path (str): Path-only endpoint from URLS.
            query_fields (List[str]): Columns to match values against
                (OR-combined).
            values (List[str]): The values to resolve.
            headers (Dict): Request headers.
            instance_url (str): Instance URL.

        Returns:
            Dict[str, Optional[str]]: Every input value mapped to its
                sys_id, or to None when nothing matched.
        """
        resolved: Dict[str, Optional[str]] = {
            value: None for value in values
        }
        if not values:
            return resolved
        self.logger.debug(
            f"{self.log_prefix}: Resolving sys_id for {len(values)} "
            "user(s)."
        )
        endpoint = f"{instance_url}{url_path}"
        fields = ",".join(["sys_id"] + query_fields)
        for chunk in chunk_list(values, RESOLVE_IN_CHUNK_SIZE):
            joined = ",".join(chunk)
            query = "^OR".join(
                f"{field}IN{joined}" for field in query_fields
            )
            response = self.servicenow_helper.api_helper(
                url=endpoint,
                method="GET",
                params={
                    "sysparm_query": query,
                    "sysparm_fields": fields,
                    "sysparm_limit": LIMIT,
                },
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"resolving {len(chunk)} value(s) to sys_id(s)"
                ),
            )
            rows = response.get("result", []) or []
            by_value: Dict[str, str] = {}
            ambiguous: Set[str] = set()
            for field in query_fields:
                for row in rows:
                    key = str(row.get(field) or "").strip().lower()
                    sys_id = row.get("sys_id")
                    if not key or not sys_id:
                        continue
                    if key in by_value:
                        if by_value[key] != sys_id:
                            ambiguous.add(key)
                        continue
                    by_value[key] = sys_id
            for value in chunk:
                key = value.strip().lower()
                resolved[value] = by_value.get(key)
                if key in ambiguous:
                    self.logger.debug(
                        f"{self.log_prefix}: Multiple matches found "
                        f"for '{value}'. Using the first match."
                    )
        resolved_count = sum(1 for sys_id in resolved.values() if sys_id)
        self.logger.debug(
            f"{self.log_prefix}: Successfully resolved "
            f"{resolved_count} username(s)/email(s) to sys_id(s)."
        )
        return resolved

    def _prefetch_user_sys_ids(
        self,
        raw_values: List,
        headers: Dict,
        instance_url: str,
        cache: Dict[str, Optional[str]],
    ) -> None:
        """Warm the resolution cache for a whole bulk action call.

        Each action names its own user(s), so resolving them action by
        action would be one request per action. Collecting every value
        the call mentions and resolving them together up front turns
        that into one request per RESOLVE_IN_CHUNK_SIZE distinct users;
        the per-action lookups afterwards are pure cache hits. Values
        that are already sys_ids, already cached, or that resolve to
        nothing are all recorded, so nothing is looked up twice.

        Args:
            raw_values (List): Raw User/Delegate parameter values (each
                a str or a list) across every action in the call.
            headers (Dict): Basic Auth headers.
            instance_url (str): Instance URL.
            cache (Dict): Per-call value -> sys_id resolution cache,
                updated in place.
        """
        pending = []
        for raw_value in raw_values:
            for value in normalize_csv_values(raw_value):
                if not is_sys_id(value) and value not in cache:
                    pending.append(value)
        pending = list(dict.fromkeys(pending))
        if not pending:
            return
        cache.update(
            self._resolve_sys_ids(
                URLS["SYS_USER"],
                ["email", "user_name"],
                pending,
                headers,
                instance_url,
            )
        )

    def _resolve_user_sys_id(
        self,
        value: str,
        headers: Dict,
        instance_url: str,
        cache: Dict[str, Optional[str]],
    ) -> Optional[str]:
        """Resolve a user value (sys_id, email or user name) to a sys_id."""
        resolved, _ = self._resolve_user_sys_ids(
            value, headers, instance_url, cache
        )
        return resolved[0][1] if resolved else None

    def _resolve_user_sys_ids(
        self,
        raw_value,
        headers: Dict,
        instance_url: str,
        cache: Dict[str, Optional[str]],
    ) -> Tuple[List[Tuple[str, str]], List[str]]:
        """Resolve one or many user values to sys_ids.

        The User / Delegate action parameters accept a Static
        comma-separated string or a List-type Source field, so one
        action can target several users. Values are normalized the same
        way as Tag Value and de-duplicated by sys_id - so two spellings
        of the same user (an email and its sys_id, say) produce one
        sub-request rather than two.

        Anything not already a sys_id or in the cache is resolved in a
        single bulk lookup, so this costs one request (or none at all,
        when _prefetch_user_sys_ids has already warmed the cache for
        the whole call) rather than one per value.

        Args:
            raw_value: Raw action parameter value (str or list).
            headers (Dict): Basic Auth headers.
            instance_url (str): Instance URL.
            cache (Dict): Per-call value -> sys_id resolution cache.

        Returns:
            Tuple[List[Tuple[str, str]], List[str]]: One (value,
                sys_id) pair per resolved user - order preserved,
                de-duplicated by sys_id, the value kept so logs can
                name the user the way the action did - and the values
                that could not be resolved.
        """
        values = normalize_csv_values(raw_value)
        self._prefetch_user_sys_ids(
            values, headers, instance_url, cache
        )
        resolved: List[Tuple[str, str]] = []
        unresolved: List[str] = []
        seen: Set[str] = set()
        for value in values:
            sys_id = value if is_sys_id(value) else cache.get(value)
            if not sys_id:
                unresolved.append(value)
                continue
            if sys_id not in seen:
                seen.add(sys_id)
                resolved.append((value, sys_id))
        return resolved, unresolved

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Returns:
            List[ActionWithoutParams]: Supported action descriptors.
        """
        return [
            ActionWithoutParams(
                label="Add/Remove User from Group", value=ACTION_USER_GROUP
            ),
            ActionWithoutParams(
                label="Add/Remove User from Role", value=ACTION_USER_ROLE
            ),
            ActionWithoutParams(
                label="Update User Delegation",
                value=ACTION_USER_DELEGATION,
            ),
            ActionWithoutParams(
                label="Manage Device Tags", value=ACTION_TAG_DEVICE
            ),
            ActionWithoutParams(
                label="Manage Application Tags",
                value=ACTION_TAG_APPLICATION,
            ),
            ActionWithoutParams(
                label="Share Application Data",
                value=ACTION_SHARE_APPLICATION_DATA,
            ),
            ActionWithoutParams(label="No Action", value=ACTION_NO_ACTION),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action.

        Returns:
            List: Parameter field descriptors for the CE UI.
        """
        if action.value == ACTION_NO_ACTION:
            return []

        if action.value == ACTION_USER_GROUP:
            return self._user_group_params()

        if action.value == ACTION_USER_ROLE:
            return self._user_role_params()

        if action.value == ACTION_USER_DELEGATION:
            return self._user_delegation_params()

        if action.value in (ACTION_TAG_DEVICE, ACTION_TAG_APPLICATION):
            return self._tag_params(action.value)

        if action.value == ACTION_SHARE_APPLICATION_DATA:
            return self._share_application_data_params()

        return []

    def _user_group_params(self) -> List[Dict]:
        """Build params for the Add/Remove User from Group action."""
        instance_url, username, password = (
            self.servicenow_helper.get_config_params(self.configuration)
        )
        headers = self.servicenow_helper.basic_auth(username, password)
        groups = self._fetch_all_rows(
            url_path=URLS["USER_GROUP"],
            headers=headers,
            instance_url=instance_url,
            fields="sys_id,name",
            query="",
            logger_msg=f"user groups from {PLATFORM_NAME}",
            display_value_all=False,
        )
        choices = sorted(
            [
                {
                    "key": g.get("name"),
                    "value": f"{g.get('name')}{CUSTOM_SEPARATOR}"
                    f"{g.get('sys_id')}",
                }
                for g in groups
                if g.get("name") and g.get("sys_id")
            ],
            key=lambda c: c["key"].lower(),
        )
        choices.append({"key": "Create New Group", "value": CREATE_NEW_GROUP})
        default_group = choices[0]["value"]
        return [
            {
                "label": "Action Type",
                "key": "action_type",
                "type": "choice",
                "choices": USER_GROUP_ACTION_TYPE_OPTIONS,
                "default": ACTION_TYPE_ADD,
                "mandatory": True,
                "description": (
                    "Whether to add the user to the group or remove the "
                    "user from it. Select from the Static field dropdown."
                ),
            },
            {
                "label": "Group",
                "key": "group",
                "type": "choice",
                "choices": choices,
                "default": default_group,
                "mandatory": True,
                "description": (
                    "Select the ServiceNow group to add the user to or "
                    "remove the user from, or 'Create New Group' to "
                    "create one. Creating a new group is only supported "
                    "when Action Type is 'Add to Group'."
                ),
            },
            {
                "label": "New Group Name",
                "key": "new_group_name",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    "Name for the new group. Required when 'Create New "
                    "Group' is selected in the Group field; ignored "
                    "otherwise. Provide the name in the Static field "
                    "only - Source fields are not supported."
                ),
            },
            {
                "label": "User",
                "key": "user",
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "Select the User ID or Email source field or "
                    "provide comma separated user sys_id, email or "
                    "user name in the Static field."
                ),
            },
        ]

    def _user_role_params(self) -> List[Dict]:
        """Build params for the Add/Remove User from Role action."""
        instance_url, username, password = (
            self.servicenow_helper.get_config_params(self.configuration)
        )
        headers = self.servicenow_helper.basic_auth(username, password)
        roles = self._fetch_all_rows(
            url_path=URLS["USER_ROLE"],
            headers=headers,
            instance_url=instance_url,
            fields="sys_id,name",
            query="",
            logger_msg=f"user roles from {PLATFORM_NAME}",
            display_value_all=False,
        )
        choices = sorted(
            [
                {
                    "key": r.get("name"),
                    "value": f"{r.get('name')}{CUSTOM_SEPARATOR}"
                    f"{r.get('sys_id')}",
                }
                for r in roles
                if r.get("name") and r.get("sys_id")
            ],
            key=lambda c: c["key"].lower(),
        )
        if not choices:
            err_msg = (
                "No user roles found on ServiceNow. Create at least "
                "one role before configuring this action."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Create a user role on ServiceNow and retry "
                    "configuring this action."
                ),
            )
            raise ServiceNowZTREPluginException(err_msg)
        return [
            {
                "label": "Action Type",
                "key": "action_type",
                "type": "choice",
                "choices": USER_ROLE_ACTION_TYPE_OPTIONS,
                "default": ACTION_TYPE_ADD,
                "mandatory": True,
                "description": (
                    "Whether to add the user to the role or remove "
                    "the user from it. Select from the Static field "
                    "dropdown."
                ),
            },
            {
                "label": "Role",
                "key": "role",
                "type": "multichoice",
                "choices": choices,
                "default": [choices[0]["value"]],
                "mandatory": True,
                "description": (
                    "Select one or more ServiceNow roles to add the "
                    "user to or remove the user from. Every selected "
                    "role is applied to every user named by the User "
                    "field. Creating a new role is not supported from "
                    "this action."
                ),
            },
            {
                "label": "User",
                "key": "user",
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "Select the User ID or Email source field or "
                    "provide comma separated user sys_id, email or "
                    "user name in the Static field."
                ),
            },
        ]

    def _user_delegation_params(self) -> List[Dict]:
        """Build params for the Update User Delegation action."""
        return [
            {
                "label": "User",
                "key": "user",
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "Delegating user. Select the User ID or Email "
                    "source field or provide comma separated user "
                    "sys_id, email or user name in the Static field."
                ),
            },
            {
                "label": "Delegate",
                "key": "delegate",
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "User who acts on the delegator's behalf. Select a "
                    "source field or provide comma separated user "
                    "sys_id, email or user name in the Static field. "
                    "Each user is delegated to every delegate."
                ),
            },
            # Delegation Settings is declared before Delegation
            # Duration because it decides whether Duration is needed at
            # all: with no setting selected the action only deletes, and
            # Duration is never read. Duration is therefore not marked
            # mandatory - validate_action requires it only once at least
            # one setting is selected.
            {
                "label": "Delegation Settings",
                "key": "delegation_settings",
                "type": "multichoice",
                "choices": DELEGATION_SETTINGS_OPTIONS,
                "default": DELEGATION_SETTINGS_VALUES,
                "mandatory": False,
                "description": (
                    "Select which settings to delegate. The delegation "
                    "on ServiceNow is replaced with exactly this "
                    "selection - selected settings are delegated "
                    "(true) and unselected settings are not (false). "
                    "Note: Leaving all settings unselected deletes the "
                    "delegation."
                ),
            },
            {
                "label": "Delegation Duration (In Days)",
                "key": "delegation_duration",
                "type": "number",
                "default": "",
                "mandatory": False,
                "description": (
                    "Number of days the delegation should last, "
                    "starting now, up to a maximum of "
                    f"{DELEGATION_MAX_DURATION_DAYS} (200 years). "
                    "Required when at least one Delegation Setting is "
                    "selected. Always used when a new delegation is "
                    "created; also used to extend an existing "
                    "delegation's end time when Update Delegation "
                    "Duration is set to 'Yes'."
                ),
            },
            {
                "label": "Update Delegation Duration",
                "key": "update_delegation_duration",
                "type": "choice",
                "choices": DELEGATION_EXTEND_DURATION_OPTIONS,
                "default": DELEGATION_EXTEND_DURATION_NO,
                "mandatory": False,
                "description": (
                    "Only applies when a delegation already exists for "
                    "the user and delegate (i.e. its settings are being "
                    "replaced, not created or deleted). Select 'Yes' to "
                    "also move the delegation's end time to now plus "
                    "Delegation Duration - its start time is left as is. "
                    "Select 'No' (default) to leave the existing "
                    "delegation's start and end time untouched."
                ),
            },
        ]

    def _tag_params(self, action_value: str) -> List[Dict]:
        """Build params for the Tag/Untag Device or Application action."""
        if action_value == ACTION_TAG_DEVICE:
            source_hint = "Device ID"
        else:
            source_hint = "Application ID"
        return [
            {
                "label": "Action Type",
                "key": "action_type",
                "type": "choice",
                "choices": TAG_ACTION_TYPE_OPTIONS,
                "default": ACTION_TYPE_ADD,
                "mandatory": True,
                "description": (
                    "Whether to add (tag) or remove (untag). Select from "
                    "the Static field dropdown."
                ),
            },
            {
                "label": source_hint,
                "key": "configuration_item",
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    f"Select the {source_hint} source field or provide "
                    f"comma separated {source_hint} (sys_id) in the "
                    "Static field."
                ),
            },
            {
                "label": "Tag Key",
                "key": "key",
                "type": "text",
                "default": DEFAULT_TAG_KEY,
                "mandatory": True,
                "description": (
                    "Single tag key to add or remove, shared by every "
                    "Tag Value. Provide in the Static field only, with "
                    f"a maximum of {TAG_KEY_MAX_LENGTH} characters."
                ),
            },
            {
                "label": "Tag Value",
                "key": "value",
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "Tag value(s) for Tag Key. Provide a single value "
                    "or comma-separated values in the Static field, or "
                    "select a source field (a List field resolves to "
                    "multiple values) - each value becomes its own tag "
                    "sharing the same key. When removing, only tags "
                    "whose key/value pair exists are deleted."
                ),
            },
        ]

    def _share_application_data_params(self) -> List[Dict]:
        """Build params for the combined Share Application Data action.

        "Select Table" gates which of the two workflows runs: Core
        Company (the former legacy share_app_data behavior) or CMDB CI
        Business App (the former share_application_data behavior).
        Company Name / Parent Company Name / Operator are only used on
        the Core Company path; Application Name is only mandatory on the
        CMDB CI Business App path (enforced in validation, not here,
        since the requirement depends on Select Table).
        """
        tooltip = (
            f"Value of this field will be shared to {PLATFORM_NAME} "
            "platform."
        )
        return [
            {
                "label": "Select Table",
                "key": "select_table",
                "type": "choice",
                "choices": SHARE_TABLE_OPTIONS,
                "default": SHARE_TABLE_CORE_COMPANY,
                "mandatory": True,
                "description": (
                    "Select the ServiceNow table to share the "
                    "application data to. 'Core Company' matches "
                    "Company / Parent Company records. 'CMDB CI "
                    "Business App' matches or creates a Business "
                    "Application record by Application Name."
                ),
            },
            {
                "label": "Company Name",
                "key": "company_name",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    "Select field for Company Name from Source or "
                    "provide Company Name in Static field. Used only "
                    "when Select Table is 'Core Company', for fetching "
                    f"Vendor details from {PLATFORM_NAME} platform."
                ),
            },
            {
                "label": "Parent Company Name",
                "key": "parent_company_name",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    "Select field for Parent Company Name from Source "
                    "or provide Parent Company Name in Static field. "
                    "Used only when Select Table is 'Core Company', "
                    f"for fetching Vendor details from {PLATFORM_NAME} "
                    "platform."
                ),
            },
            {
                "label": "Operator",
                "key": "operator",
                "type": "choice",
                "choices": OPERATOR_OPTIONS,
                "default": "and",
                "mandatory": False,
                "description": (
                    "Select operator from Static field drop down to "
                    "perform operation between Company Name and Parent "
                    "Company Name. Used only when Select Table is "
                    "'Core Company', and required when both Company "
                    "Name and Parent Company Name are provided. e.g. "
                    "name=ABC^ORparent.name=XYZ"
                ),
            },
            {
                "label": "Application Name",
                "key": "application_name",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    "Select the Application Name source field or "
                    "provide the application name in the Static field. "
                    "Required when Select Table is 'CMDB CI Business "
                    f"App'. {tooltip}"
                ),
            },
            {
                "label": "CCI",
                "key": "cci",
                "type": "number",
                "default": "",
                "mandatory": False,
                "description": (
                    "Cloud Confidence Index. Value should be between 0 "
                    f"and 100. {tooltip}"
                ),
            },
            {
                "label": "CCL",
                "key": "ccl",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    f"Cloud Confidence Level. {tooltip}"
                ),
            },
            {
                "label": "Category Name",
                "key": "category_name",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    f"Application category. {tooltip}"
                ),
            },
            {
                "label": "Deep Link",
                "key": "deep_link",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    f"Application deep link. {tooltip}"
                ),
            },
        ]

    # ------------------------------------------------------------------
    # validate_action
    # ------------------------------------------------------------------

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate an action configuration.

        Args:
            action (Action): The action to validate.

        Returns:
            ValidationResult: Validation result with a message.
        """
        action_value = action.value
        if action_value not in SUPPORTED_ACTIONS:
            err_msg = (
                f"Unsupported action '{action_value}' provided in the "
                "action configuration."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if action_value == ACTION_NO_ACTION:
            return ValidationResult(
                success=True, message="Validation successful."
            )

        if action_value == ACTION_USER_GROUP:
            return self._validate_user_group_action(action)
        if action_value == ACTION_USER_ROLE:
            return self._validate_user_role_action(action)
        if action_value == ACTION_USER_DELEGATION:
            return self._validate_user_delegation_action(action)
        if action_value in (ACTION_TAG_DEVICE, ACTION_TAG_APPLICATION):
            return self._validate_tag_action(action)
        if action_value == ACTION_SHARE_APPLICATION_DATA:
            return self._validate_share_application_data_action(action)

        return ValidationResult(success=True, message="Validation successful.")

    def _validate_core_company_fields(
        self, action_params: Dict
    ) -> ValidationResult:
        """Validate the Core Company path of Share Application Data."""
        company_name = action_params.get("company_name", "")
        parent_company_name = action_params.get("parent_company_name", "")
        operator = action_params.get("operator", "")
        cci = action_params.get("cci", None)

        if not (company_name or parent_company_name):
            err_msg = (
                "Either Company Name or Parent Company Name is a required "
                "in the action parameters. Both can not be empty."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if company_name and not isinstance(company_name, str):
            err_msg = "Invalid Company Name provided in the action parameters."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        if parent_company_name and not isinstance(parent_company_name, str):
            err_msg = (
                "Invalid Parent Company Name provided in the action "
                "parameters."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if company_name and parent_company_name:
            if not operator:
                err_msg = (
                    "Operator is a required action parameter when Company "
                    "Name and Parent Company Name are provided."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif "$" in operator:
                err_msg = STATIC_FIELD_ERROR_MESSAGE.format(
                    field_name="Operator"
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif operator not in ["or", "and"]:
                err_msg = (
                    "Invalid Operator provided in the action parameters. "
                    "Supported operators are: 'AND', 'OR'."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
        if cci:
            if isinstance(cci, str) and "$" in cci:
                log_msg = (
                    "CCI contains the Source Field hence validation for "
                    "this field will be performed while executing the "
                    "Sharing app data action."
                )
                self.logger.info(f"{self.log_prefix}: {log_msg}")
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            try:
                cci = int(cci)
                if not isinstance(cci, int) or (cci < 0 or cci > 100):
                    err_msg = (
                        "Invalid CCI provided in the action parameters. "
                        "Valid range should be between 0 to 100."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
            except Exception:
                err_msg = (
                    "Invalid CCI provided in the action parameters. "
                    "Valid should be an integer in range 0 to 100."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation successful.")

    def _validate_user_group_action(
        self, action: Action
    ) -> ValidationResult:
        """Validate the Add/Remove User from Group action."""
        params = action.parameters
        action_type = params.get("action_type", "")
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Action Type",
            field_value=action_type,
            field_type=str,
            allowed_values=[ACTION_TYPE_ADD, ACTION_TYPE_REMOVE],
            static_only=True,
        ):
            return failure
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Group",
            field_value=params.get("group", ""),
            field_type=str,
        ):
            return failure
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="User",
            field_value=params.get("user", ""),
            field_type=str,
            check_dollar=True,
            custom_validation_func=is_valid_csv_value,
            custom_error_message=EMPTY_CSV_ERROR_MESSAGE,
        ):
            return failure
        if (params.get("group") or "").strip() == CREATE_NEW_GROUP:
            if action_type != ACTION_TYPE_ADD:
                err_msg = (
                    "Creating a new group is only supported when Action "
                    "Type is 'Add to Group'."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            new_group_name = (params.get("new_group_name") or "").strip()
            if failure := self._validate_parameters(
                parameter_type=ACTION,
                field_name="New Group Name",
                field_value=new_group_name,
                field_type=str,
                static_only=True,
            ):
                return failure
            if len(new_group_name) > GROUP_NAME_MAX_LENGTH:
                err_msg = (
                    "New Group Name exceeds the maximum length of "
                    f"{GROUP_NAME_MAX_LENGTH} characters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Shorten the group name to "
                        f"{GROUP_NAME_MAX_LENGTH} characters or fewer."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
        return ValidationResult(success=True, message="Validation successful.")

    def _validate_user_role_action(
        self, action: Action
    ) -> ValidationResult:
        """Validate the Add/Remove User from Role action."""
        params = action.parameters
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Action Type",
            field_value=params.get("action_type", ""),
            field_type=str,
            allowed_values=[ACTION_TYPE_ADD, ACTION_TYPE_REMOVE],
            static_only=True,
        ):
            return failure
        # Role is a multichoice, so its value is a list of packed
        # "<name><CUSTOM_SEPARATOR><sys_id>" entries. This is the second
        # field _validate_parameters cannot express (Delegation Settings
        # is the other): it collapses a list to its first entry, so only
        # one of the selected roles would ever be checked - and silently
        # so. Left as a bespoke check rather than widening the shared
        # helper, since the rules differ from Delegation Settings' -
        # Role is mandatory and is validated on its packing rather than
        # against a fixed set of allowed values.
        roles = normalize_choice_values(params.get("role"))
        if not roles or not all(
            unpack_choice_value(role)[1] for role in roles
        ):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name="Role", parameter_type=ACTION
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    "Select one or more Role(s) from the Static field "
                    "dropdown."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="User",
            field_value=params.get("user", ""),
            field_type=str,
            check_dollar=True,
            custom_validation_func=is_valid_csv_value,
            custom_error_message=EMPTY_CSV_ERROR_MESSAGE,
        ):
            return failure
        return ValidationResult(success=True, message="Validation successful.")

    def _validate_user_delegation_action(
        self, action: Action
    ) -> ValidationResult:
        """Validate the Update User Delegation action."""
        params = action.parameters
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="User",
            field_value=params.get("user", ""),
            field_type=str,
            check_dollar=True,
            custom_validation_func=is_valid_csv_value,
            custom_error_message=EMPTY_CSV_ERROR_MESSAGE,
        ):
            return failure
        # Delegate accepts the same shapes as User - a Static comma
        # separated list, a single-string Source field or a List-type
        # Source field - so one action can name several delegates.
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Delegate",
            field_value=params.get("delegate", ""),
            field_type=str,
            check_dollar=True,
            custom_validation_func=is_valid_csv_value,
            custom_error_message=EMPTY_CSV_ERROR_MESSAGE,
        ):
            return failure
        # Delegation Settings is the one field _validate_parameters
        # cannot express: it collapses a list value to its first entry
        # before checking allowed_values, so only one of the selected
        # settings would ever be checked, and it rejects an empty value
        # outright - whereas selecting nothing here is legal and means
        # "delete the delegation". Left as a bespoke check rather than
        # widening the shared helper for one caller.
        delegation_settings = params.get("delegation_settings") or []
        if not isinstance(delegation_settings, list) or not all(
            setting in DELEGATION_SETTINGS_VALUES
            for setting in delegation_settings
        ):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name="Delegation Settings", parameter_type=ACTION
            )
            err_msg += INVALID_VALUE_ERROR_MESSAGE.format(
                allowed_values=DELEGATION_SETTINGS_VALUES
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        # ServiceNow requires both starts and ends on sys_user_delegate,
        # so duration (used to compute both) is required whenever the
        # action could create a delegation. With no setting selected the
        # action can only ever delete, and duration is then unused - so
        # it is not validated at all, otherwise a delete would fail on a
        # field it never reads.
        if delegation_settings and (
            failure := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Delegation Duration",
                field_value=params.get("delegation_duration", None),
                # A CE number field hands over either an int or the
                # typed string, so both shapes are accepted here and
                # is_positive_int does the real check.
                field_type=(int, str),
                check_dollar=True,
                custom_validation_func=lambda value: (
                    is_positive_int(value)
                    and int(value) <= DELEGATION_MAX_DURATION_DAYS
                ),
                custom_error_message=(
                    DELEGATION_DURATION_ERROR_MESSAGE.format(
                        max_days=DELEGATION_MAX_DURATION_DAYS
                    )
                ),
            )
        ):
            return failure
        # Defaults to "no" so an omitted value validates the same as an
        # explicit "no", matching the field's declared default.
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Update Delegation Duration",
            field_value=(
                params.get("update_delegation_duration")
                or DELEGATION_EXTEND_DURATION_NO
            ),
            field_type=str,
            allowed_values=[
                DELEGATION_EXTEND_DURATION_YES, DELEGATION_EXTEND_DURATION_NO,
            ],
            static_only=True,
        ):
            return failure
        return ValidationResult(success=True, message="Validation successful.")

    def _validate_tag_action(self, action: Action) -> ValidationResult:
        """Validate the Tag/Untag Device or Application action."""
        params = action.parameters
        # Same key on both actions, but the label the user sees (and so
        # the one the error names) is per entity.
        ci_field_name = (
            "Device ID"
            if action.value == ACTION_TAG_DEVICE
            else "Application ID"
        )
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Action Type",
            field_value=params.get("action_type", ""),
            field_type=str,
            allowed_values=[ACTION_TYPE_ADD, ACTION_TYPE_REMOVE],
            static_only=True,
        ):
            return failure
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name=ci_field_name,
            field_value=params.get("configuration_item", ""),
            field_type=str,
            check_dollar=True,
            custom_validation_func=is_valid_csv_value,
            custom_error_message=EMPTY_CSV_ERROR_MESSAGE,
        ):
            return failure
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Tag Key",
            field_value=params.get("key", ""),
            field_type=str,
            static_only=True,
        ):
            return failure
        # Tag Key is Static-only, so the value validated here is the
        # exact value the action writes - no source field to resolve.
        tag_key = (params.get("key") or "").strip()
        if len(tag_key) > TAG_KEY_MAX_LENGTH:
            err_msg = (
                "Tag Key exceeds the maximum length of "
                f"{TAG_KEY_MAX_LENGTH} characters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Shorten the Tag Key to {TAG_KEY_MAX_LENGTH} "
                    "characters or fewer."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Tag Value",
            field_value=params.get("value", ""),
            field_type=str,
            check_dollar=True,
            custom_validation_func=is_valid_csv_value,
            custom_error_message=EMPTY_CSV_ERROR_MESSAGE,
        ):
            return failure
        return ValidationResult(success=True, message="Validation successful.")

    def _validate_share_application_data_action(
        self, action: Action
    ) -> ValidationResult:
        """Validate the combined Share Application Data action.

        Dispatches to the Core Company or CMDB CI Business App field
        rules based on the Select Table parameter.
        """
        action_params = action.parameters
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Select Table",
            field_value=action_params.get("select_table", ""),
            field_type=str,
            allowed_values=[
                SHARE_TABLE_CORE_COMPANY, SHARE_TABLE_BUSINESS_APP
            ],
            static_only=True,
        ):
            return failure
        if action_params.get("select_table") == SHARE_TABLE_CORE_COMPANY:
            return self._validate_core_company_fields(action_params)
        return self._validate_business_app_fields(action_params)

    def _validate_business_app_fields(
        self, action_params: Dict
    ) -> ValidationResult:
        """Validate the CMDB CI Business App path of Share Application
        Data.
        """
        if failure := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Application Name",
            field_value=action_params.get("application_name", ""),
            field_type=str,
            check_dollar=True,
        ):
            return failure
        cci = action_params.get("cci", None)
        if cci not in (None, ""):
            if isinstance(cci, str) and "$" in cci:
                self.logger.info(
                    f"{self.log_prefix}: CCI contains the Source Field "
                    "hence validation for this field will be performed "
                    "while executing the action."
                )
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            try:
                cci_int = int(cci)
                if cci_int < 0 or cci_int > 100:
                    raise ValueError()
            except Exception:
                err_msg = (
                    "Invalid CCI provided in the action parameters. Valid "
                    "range should be between 0 to 100."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
        return ValidationResult(success=True, message="Validation successful.")

    def _validate_parameters(
        self,
        parameter_type: str,
        field_name: str,
        field_value,
        field_type: Type,
        check_dollar: bool = False,
        allowed_values: Optional[List] = None,
        static_only: bool = False,
        custom_validation_func: Optional[Callable] = None,
        custom_error_message: str = "",
    ) -> Optional[ValidationResult]:
        """Validate a single action/config parameter value.

        Args:
            parameter_type (str): CONFIGURATION or ACTION.
            field_name (str): Human-readable field name.
            field_value: Value to validate.
            field_type (Type): Expected Python type.
            check_dollar (bool): When True, a "$" value is a Source field
                and validation is deferred to execution (returns None).
            allowed_values (Optional[List]): Permitted values.
            static_only (bool): When True, the field is a Static-only
                dropdown, so a "$" value is a configuration error and is
                rejected instead of deferred.
            custom_validation_func (Optional[Callable]): Field-specific
                rule run after the empty/type checks. Takes the value
                and returns True when it is acceptable.
            custom_error_message (str): Appended to the generic invalid
                value message when custom_validation_func rejects the
                value, so the user is told which rule was broken.

        Returns:
            ValidationResult on failure, else None.
        """
        if isinstance(field_value, list):
            field_value = field_value[0] if field_value else ""
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()
        if (
            static_only
            and isinstance(field_value, str)
            and "$" in field_value
        ):
            err_msg = STATIC_FIELD_ERROR_MESSAGE.format(
                field_name=field_name
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    f"Select {field_name} from the Static Field dropdown "
                    "only."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if (
            check_dollar
            and isinstance(field_value, str)
            and "$" in field_value
        ):
            self.logger.info(
                f"{self.log_prefix}: '{field_name}' contains the Source "
                "Field hence validation for this field will be performed "
                "while executing the action."
            )
            return None
        if not field_value:
            err_msg = EMPTY_ERROR_MESSAGE.format(
                field_name=field_name, parameter_type=parameter_type
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=f"Provide a value for the '{field_name}' field.",
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(field_value, field_type):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name, parameter_type=parameter_type
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=f"Provide a valid value for '{field_name}'.",
            )
            return ValidationResult(success=False, message=err_msg)
        if custom_validation_func and not custom_validation_func(field_value):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name, parameter_type=parameter_type
            ) + custom_error_message
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=f"Provide a valid value for '{field_name}'.",
            )
            return ValidationResult(success=False, message=err_msg)
        if allowed_values and field_value not in allowed_values:
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name, parameter_type=parameter_type
            )
            err_msg += INVALID_VALUE_ERROR_MESSAGE.format(
                allowed_values=allowed_values
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution="Provide a value from the allowed values.",
            )
            return ValidationResult(success=False, message=err_msg)
        return None

    # ------------------------------------------------------------------
    # execute_actions (bulk)
    # ------------------------------------------------------------------

    def execute_actions(self, actions: List):
        """Execute a batch of actions against ServiceNow.

        All actions in a batch share the same action value. Dispatches to
        the matching per-action executor which uses the Batch API and
        returns the failed action ids.

        Args:
            actions (List): CE-supplied list of {"id", "params"} dicts.

        Returns:
            ActionResult: Reports per-action failures to the framework.
        """
        if not actions:
            return ActionResult(
                success=True,
                message="Action execution completed.",
                failed_action_ids=[],
            )

        action_value = actions[0].get("params").value

        if action_value == ACTION_NO_ACTION:
            self.logger.info(
                f"{self.log_prefix}: Successfully performed 'No Action' "
                f"on {len(actions)} record(s). Note: No processing will "
                "be done from plugin for the 'No Action' action."
            )
            return ActionResult(
                success=True,
                message="Action execution completed.",
                failed_action_ids=[],
            )

        try:
            instance_url, username, password = (
                self.servicenow_helper.get_config_params(self.configuration)
            )
            headers = self.servicenow_helper.basic_auth(username, password)

            if action_value == ACTION_USER_GROUP:
                failed = self._execute_user_group_actions(
                    actions, headers, instance_url
                )
            elif action_value == ACTION_USER_ROLE:
                failed = self._execute_user_role_actions(
                    actions, headers, instance_url
                )
            elif action_value == ACTION_USER_DELEGATION:
                failed = self._execute_user_delegation_actions(
                    actions, headers, instance_url
                )
            elif action_value in (
                ACTION_TAG_DEVICE, ACTION_TAG_APPLICATION
            ):
                failed = self._execute_tag_actions(
                    actions, headers, instance_url
                )
            elif action_value == ACTION_SHARE_APPLICATION_DATA:
                failed = self._execute_share_application_data_actions(
                    actions, headers, instance_url
                )
            else:
                failed = [a.get("id") for a in actions]
        except ServiceNowZTREPluginException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while executing "
                    f"'{action_value}' action. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            failed = [a.get("id") for a in actions]
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred while "
                    f"executing '{action_value}' action. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            failed = [a.get("id") for a in actions]

        failed = [fid for fid in failed if fid is not None]
        return ActionResult(
            success=True,
            message="Action execution completed.",
            failed_action_ids=list(dict.fromkeys(failed)),
        )

    # ---- Per-action bulk executors -----------------------------------

    def _resolve_or_create_group(
        self, group_name: str, headers: Dict, instance_url: str
    ) -> Optional[str]:
        """Resolve an existing group by name, creating it if missing.

        'Create New Group' is a static (non-source-field) action
        parameter, so every action in a bulk call that requests it
        carries the identical group_name - the caller resolves it
        exactly once for the whole call rather than once per action.
        This is always exactly one lookup and, at most, one create,
        so it goes straight to the Table API rather than through the
        Batch API - the batch request/response envelope (base64
        body encoding, serviced/unserviced parsing) only pays off
        when bundling several sub-requests together.

        Args:
            group_name (str): The requested new group's name.
            headers (Dict): Basic Auth headers.
            instance_url (str): Instance URL.

        Returns:
            Optional[str]: The existing or newly-created group's
                sys_id, or None if the lookup/create failed.
        """
        endpoint = f"{instance_url}{URLS['USER_GROUP']}"
        lookup_msg = f"checking if group '{group_name}' exists"
        response = self.servicenow_helper.api_helper(
            url=endpoint,
            method="GET",
            params={
                "sysparm_query": f"name={group_name}",
                "sysparm_fields": "sys_id,name",
            },
            headers=headers,
            verify=self.ssl_validation,
            proxies=self.proxy,
            logger_msg=lookup_msg,
            is_handle_error_required=False,
        )
        if response.status_code not in (200, 201):
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Failed to check whether user "
                    f"group '{group_name}' already exists."
                ),
                details=f"API response: {response.text}",
                resolution=(
                    "Verify the configured user can read records on "
                    "the sys_user_group table."
                ),
            )
            return None

        try:
            body = response.json()
        except ValueError:
            body = {}
        result = body.get("result", []) or []
        if result:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Skipped creating group "
                    f"'{group_name}' as it already exists on "
                    "ServiceNow."
                )
            )
            return result[0].get("sys_id")

        response = self.servicenow_helper.api_helper(
            url=endpoint,
            method="POST",
            json={"name": group_name},
            headers=headers,
            verify=self.ssl_validation,
            proxies=self.proxy,
            logger_msg=f"creating new group '{group_name}'",
            is_handle_error_required=False,
        )
        group_id = None
        if response.status_code in (200, 201):
            try:
                body = response.json()
            except ValueError:
                body = {}
            group_id = (body.get("result") or {}).get("sys_id")
        if not group_id:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Failed to create a new user "
                    f"group '{group_name}'."
                ),
                details=f"API response: {response.text}",
                resolution=(
                    "Verify the configured user can create records "
                    "on the sys_user_group table."
                ),
            )
            return None

        self.logger.info(
            f"{self.log_prefix}: Successfully created new user group "
            f"'{group_name}' on ServiceNow."
        )
        return group_id

    def _execute_user_group_actions(
        self, actions: List, headers: Dict, instance_url: str
    ) -> List:
        """Execute Add/Remove User from Group via the Batch API."""
        user_cache: Dict[str, Optional[str]] = {}
        # sub_id -> request metadata, carrying every action id merged
        # onto that sub-request.
        sub_meta: Dict[str, Dict] = {}
        # (action type, user, group) -> that membership's metadata. Keyed
        # so two actions naming the same membership share one
        # sub-request; see the emit loop below for why that matters.
        targets: Dict[Tuple, Dict] = {}
        membership_lookup_requests = []
        add_requests = []
        remove_lookup = []
        failed = []

        # New Group Name is validated as a static value (see
        # _validate_user_group_action), so every action in this batch
        # that requests 'Create New Group' shares the identical name -
        # resolve/create it once, up front, instead of once per action
        # (which would otherwise send N duplicate create POSTs and hit
        # ServiceNow's uniqueness constraint on sys_user_group.name for
        # N-1 of them).
        shared_new_group_name = ""
        for action in actions:
            packed = (
                (action.get("params").parameters.get("group") or "")
                .strip()
            )
            if packed == CREATE_NEW_GROUP:
                shared_new_group_name = (
                    action.get("params").parameters.get(
                        "new_group_name"
                    ) or ""
                ).strip()
                if shared_new_group_name:
                    break

        shared_group_id: Optional[str] = None
        if shared_new_group_name:
            shared_group_id = self._resolve_or_create_group(
                shared_new_group_name, headers, instance_url,
            )

        # Resolve every user named anywhere in this call in one go, so
        # the per-action lookups below cost no requests at all.
        self._prefetch_user_sys_ids(
            [
                action.get("params").parameters.get("user")
                for action in actions
            ],
            headers, instance_url, user_cache,
        )

        for action in actions:
            action_id = action.get("id")
            params = action.get("params").parameters
            action_type = (params.get("action_type") or "").strip()
            packed = (params.get("group") or "").strip()
            user_values = normalize_csv_values(params.get("user"))
            if action_type not in (ACTION_TYPE_ADD, ACTION_TYPE_REMOVE) \
                    or not packed or not user_values:
                group_suffix = (
                    f" Group value: '{packed}'." if packed else ""
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping User from Group "
                        "action with missing or invalid "
                        f"parameters.{group_suffix}"
                    )
                )
                failed.append(action_id)
                continue
            resolved_users, unresolved_users = self._resolve_user_sys_ids(
                user_values, headers, instance_url, user_cache
            )
            if unresolved_users:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unable to resolve "
                        f"{len(unresolved_users)} user(s) to a sys_id. "
                        "Skipping action execution for those user(s)."
                    ),
                    details=f"User(s): {', '.join(unresolved_users)}.",
                    resolution=(
                        "Provide a valid user sys_id, email or user "
                        "name that exists on ServiceNow."
                    ),
                )
                failed.append(action_id)
            if not resolved_users:
                continue

            if packed == CREATE_NEW_GROUP:
                new_group_name = (
                    params.get("new_group_name") or ""
                ).strip()
                if action_type != ACTION_TYPE_ADD or not new_group_name:
                    name_suffix = (
                        f" '{new_group_name}'" if new_group_name else ""
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Skipping User from "
                            f"Group action for new group{name_suffix} "
                            "- creating a new group requires Action "
                            "Type 'Add to Group' and a New Group Name."
                        )
                    )
                    failed.append(action_id)
                    continue
                if not shared_group_id:
                    # Already logged once, up front, by
                    # _resolve_or_create_group.
                    failed.append(action_id)
                    continue
                group_id, group_name = shared_group_id, new_group_name
            else:
                group_name, sep, group_id = packed.rpartition(
                    CUSTOM_SEPARATOR
                )
                if not sep or not group_id:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Skipping User from "
                            "Group action with an invalid Group value: "
                            f"'{packed}'."
                        )
                    )
                    failed.append(action_id)
                    continue

            # One entry per user, so a single action carrying several
            # users is checked, added and reported per user - and one
            # entry per *distinct* membership, so several actions naming
            # the same one collapse onto a single sub-request.
            for _, user_id in resolved_users:
                target = targets.setdefault(
                    (action_type, user_id, group_id),
                    {
                        "action_ids": [],
                        "action_type": action_type,
                        "user": user_id,
                        "group": group_id,
                        "group_name": group_name,
                    },
                )
                target["action_ids"].append(action_id)

        # The check round below reads every membership before the first
        # write of that round is built, so two sub-requests for the same
        # membership would both read "not a member" and then both POST,
        # creating the duplicate row the check exists to prevent. Merging
        # them above is what keeps the check meaningful, and it also
        # keeps every count reported below a count of distinct
        # memberships rather than of sub-requests.
        for counter, target in enumerate(targets.values(), start=1):
            sub_id = str(counter)
            sub_meta[sub_id] = target
            query = f"user={target['user']}^group={target['group']}"
            if target["action_type"] == ACTION_TYPE_ADD:
                membership_lookup_requests.append(
                    {
                        "id": sub_id,
                        "method": "GET",
                        "url": build_lookup_url(
                            URLS["USER_GRMEMBER"], query, "sys_id",
                            limit=1,
                        ),
                    }
                )
            else:
                remove_lookup.append(
                    {
                        "id": sub_id,
                        "method": "GET",
                        "url": build_lookup_url(
                            URLS["USER_GRMEMBER"], query, "sys_id"
                        ),
                    }
                )

        # Membership check round: skip a user who is already a member
        # of the target group, so a re-synced action doesn't create a
        # duplicate sys_user_grmember row. Enforced here rather than by
        # asking customers to add a uniqueness constraint on their own
        # instance.
        if membership_lookup_requests:
            membership_results = self._send_batch(
                membership_lookup_requests, headers, instance_url,
                "check existing user group membership",
                "group-add-check",
            )
            already_member_requests = []
            for sub_id, (status, body) in membership_results.items():
                meta = sub_meta.get(sub_id)
                if meta is None or "group" not in meta:
                    continue
                if status is None or status not in (200, 201):
                    failed.extend(meta["action_ids"])
                    group_label = (
                        meta.get("group_name")
                        or meta.get("new_group_name")
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Failed to check "
                            "whether the user is already a member of "
                            f"group '{group_label}'."
                        ),
                        details=f"Batch sub-request response: {body}",
                        resolution=(
                            "Verify the configured user can read "
                            "records on the sys_user_grmember table."
                        ),
                    )
                    continue
                result = body.get("result", []) or []
                if result:
                    # The user is already in the group, so the state the
                    # action asks for already holds - a successful
                    # no-op, not a failure. Only the add is skipped.
                    already_member_requests.append({"id": sub_id})
                    continue
                add_requests.append(
                    {
                        "id": sub_id,
                        "method": "POST",
                        "url": URLS["USER_GRMEMBER"],
                        "body": {
                            "user": meta["user"], "group": meta["group"]
                        },
                    }
                )
            if already_member_requests:
                already_member_target = describe_targets(
                    sub_meta, already_member_requests,
                    ("group_name", "new_group_name"), "group", "groups",
                )
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"{len(already_member_requests)} user(s) are "
                    f"already present in {already_member_target} "
                    "hence skipping action execution for them."
                )

        # Add round (single batch).
        if add_requests:
            add_target = describe_targets(
                sub_meta, add_requests, ("group_name", "new_group_name"),
                "group", "groups",
            )

            def _report_add_batch(chunk_index, success_ids, fail_ids):
                message = (
                    f"{self.log_prefix}: Successfully added "
                    f"{len(success_ids)} user(s) in batch "
                    f"{chunk_index} to {add_target}."
                )
                if fail_ids:
                    message += (
                        f" Failed to add {len(fail_ids)} user(s)."
                    )
                self.logger.info(message)

            results = self._send_batch(
                add_requests, headers, instance_url,
                f"add users to {add_target}",
                "group-add",
                report_chunk=_report_add_batch,
            )
            round_failed, failed_sub_ids = self._collect_failed_mutations(
                results, sub_meta
            )
            failed.extend(round_failed)
            # Counted from the sub-request ids, not from round_failed:
            # one sub-request is one user, however many actions asked to
            # add them.
            added_count = len(add_requests) - len(failed_sub_ids)
            if added_count:
                self.logger.info(
                    f"{self.log_prefix}: Successfully added "
                    f"{added_count} user(s) to {add_target}."
                )
            if failed_sub_ids:
                self.logger.error(
                    f"{self.log_prefix}: Failed to add "
                    f"{len(failed_sub_ids)} user(s) to {add_target}."
                )

        # Remove round 1: find membership sys_ids.
        if remove_lookup:
            remove_target = describe_targets(
                sub_meta, remove_lookup, "group_name", "group", "groups",
            )

            def _report_remove_batch(chunk_index, success_ids, fail_ids):
                message = (
                    f"{self.log_prefix}: Successfully removed "
                    f"{len(success_ids)} user(s) in batch "
                    f"{chunk_index} from {remove_target}."
                )
                if fail_ids:
                    message += (
                        f" Failed to remove {len(fail_ids)} user(s)."
                    )
                self.logger.info(message)

            round_failed, removed_sub_ids, noop_sub_ids, failed_sub_ids = (
                self._execute_remove_round(
                    remove_lookup,
                    sub_meta,
                    headers,
                    instance_url,
                    URLS["USER_GRMEMBER"],
                    f"users from {remove_target}",
                    "group",
                    report_chunk=_report_remove_batch,
                )
            )
            failed.extend(round_failed)
            if removed_sub_ids:
                self.logger.info(
                    f"{self.log_prefix}: Successfully removed "
                    f"{len(removed_sub_ids)} user(s) from "
                    f"{remove_target}."
                )
            if noop_sub_ids:
                self.logger.info(
                    f"{self.log_prefix}: {len(noop_sub_ids)} user(s) "
                    f"were already not in {remove_target}."
                )
            # The sub-request set, not round_failed, so the count stays a
            # count of users rather than of actions.
            if failed_sub_ids:
                self.logger.error(
                    f"{self.log_prefix}: Failed to remove "
                    f"{len(failed_sub_ids)} user(s) from {remove_target}."
                )
        return failed

    def _execute_user_role_actions(
        self, actions: List, headers: Dict, instance_url: str
    ) -> List:
        """Execute Add/Remove User from Role via the Batch API."""
        user_cache: Dict[str, Optional[str]] = {}
        # sub_id -> request metadata, carrying every action id merged
        # onto that sub-request.
        sub_meta: Dict[str, Dict] = {}
        # (action type, user, role) -> that assignment's metadata. Keyed
        # so two actions naming the same assignment share one
        # sub-request; see the emit loop below for why that matters.
        targets: Dict[Tuple, Dict] = {}
        role_lookup_requests = []
        add_requests = []
        remove_lookup = []
        failed = []

        # Resolve every user named anywhere in this call in one go, so
        # the per-action lookups below cost no requests at all.
        self._prefetch_user_sys_ids(
            [
                action.get("params").parameters.get("user")
                for action in actions
            ],
            headers, instance_url, user_cache,
        )

        for action in actions:
            action_id = action.get("id")
            params = action.get("params").parameters
            action_type = (params.get("action_type") or "").strip()
            packed_roles = normalize_choice_values(params.get("role"))
            user_values = normalize_csv_values(params.get("user"))
            if action_type not in (ACTION_TYPE_ADD, ACTION_TYPE_REMOVE) \
                    or not packed_roles or not user_values:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping User from Role "
                        "action with missing or invalid parameters."
                    )
                )
                failed.append(action_id)
                continue
            resolved_users, unresolved_users = self._resolve_user_sys_ids(
                user_values, headers, instance_url, user_cache
            )
            if unresolved_users:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unable to resolve "
                        f"{len(unresolved_users)} user(s) to a sys_id. "
                        "Skipping those user(s)."
                    ),
                    details=f"User(s): {', '.join(unresolved_users)}.",
                    resolution=(
                        "Provide a valid user sys_id, email or user "
                        "name that exists on ServiceNow."
                    ),
                )
                failed.append(action_id)
            if not resolved_users:
                continue

            # Role is a multichoice, so one action can name several
            # roles. A malformed entry is dropped on its own rather than
            # taking the whole action down with it - the same treatment
            # the unresolved users above get.
            roles = []
            invalid_roles = []
            for packed in packed_roles:
                role_name, role_id = unpack_choice_value(packed)
                if not role_id:
                    invalid_roles.append(packed)
                    continue
                roles.append((role_name, role_id))
            if invalid_roles:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping "
                        f"{len(invalid_roles)} invalid Role value(s) on "
                        "a User from Role action."
                    ),
                    details=f"Role value(s): {', '.join(invalid_roles)}.",
                    resolution=(
                        "Select the Role(s) from the Static field "
                        "dropdown."
                    ),
                )
                failed.append(action_id)
            if not roles:
                continue
            # One entry per (user, role), since both fields accept
            # several values - and one entry per *distinct* assignment,
            # so several actions naming the same one collapse onto a
            # single sub-request.
            for role_name, role_id in roles:
                for _, user_id in resolved_users:
                    target = targets.setdefault(
                        (action_type, user_id, role_id),
                        {
                            "action_ids": [],
                            "action_type": action_type,
                            "user": user_id,
                            "role": role_id,
                            "role_name": role_name,
                        },
                    )
                    target["action_ids"].append(action_id)

        # The check round below reads every assignment before the first
        # write of that round is built, so two sub-requests for the same
        # assignment would both read "does not have the role" and then
        # both POST, creating the duplicate row the check exists to
        # prevent. Merging them above is what keeps the check meaningful,
        # and it also keeps every count reported below a count of
        # distinct assignments rather than of sub-requests.
        for counter, target in enumerate(targets.values(), start=1):
            sub_id = str(counter)
            sub_meta[sub_id] = target
            query = f"user={target['user']}^role={target['role']}"
            if target["action_type"] == ACTION_TYPE_ADD:
                role_lookup_requests.append(
                    {
                        "id": sub_id,
                        "method": "GET",
                        "url": build_lookup_url(
                            URLS["USER_HAS_ROLE"], query, "sys_id",
                            limit=1,
                        ),
                    }
                )
            else:
                remove_lookup.append(
                    {
                        "id": sub_id,
                        "method": "GET",
                        "url": build_lookup_url(
                            URLS["USER_HAS_ROLE"], query, "sys_id"
                        ),
                    }
                )

        # Role check round: skip a user who already has the target
        # role, so a re-synced action doesn't create a duplicate
        # sys_user_has_role row. Enforced here rather than by asking
        # customers to add a uniqueness constraint on their own
        # instance. Outcomes are folded into add_stats - one bucket of
        # distinct users per role - instead of being counted across
        # roles, since Role is a multichoice and "N user(s)" would
        # otherwise be a count of assignments.
        add_stats: Dict[str, Dict[str, Set[str]]] = {}
        if role_lookup_requests:
            role_lookup_results = self._send_batch(
                role_lookup_requests, headers, instance_url,
                "check existing user role assignment",
                "role-add-check",
            )
            for sub_id, (status, body) in role_lookup_results.items():
                meta = sub_meta.get(sub_id)
                if meta is None or "role" not in meta:
                    continue
                bucket = outcome_bucket(add_stats, meta["role_name"])
                if status is None or status not in (200, 201):
                    failed.extend(meta["action_ids"])
                    bucket["failed"].add(meta["user"])
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Failed to check "
                            "whether the user already has role "
                            f"'{meta['role_name']}'."
                        ),
                        details=f"Batch sub-request response: {body}",
                        resolution=(
                            "Verify the configured user can read "
                            "records on the sys_user_has_role table."
                        ),
                    )
                    continue
                result = body.get("result", []) or []
                if result:
                    # The user already has the role, so the state the
                    # action asks for already holds - a successful
                    # no-op, not a failure. Only the add is skipped.
                    bucket["already_exists"].add(meta["user"])
                    continue
                add_requests.append(
                    {
                        "id": sub_id,
                        "method": "POST",
                        "url": URLS["USER_HAS_ROLE"],
                        "body": {
                            "user": meta["user"], "role": meta["role"]
                        },
                    }
                )

        # Add round (single batch).
        if add_requests:
            add_target = describe_targets(
                sub_meta, add_requests, "role_name", "role", "roles",
            )

            def _report_add_batch(chunk_index, success_ids, fail_ids):
                success_users = {
                    sub_meta[sid]["user"] for sid in success_ids
                }
                added_roles = sorted({
                    sub_meta[sid]["role_name"] for sid in success_ids
                })
                message = (
                    f"{self.log_prefix}: Successfully added "
                    f"{add_target} to {len(success_users)} user(s) "
                    f"in batch {chunk_index}."
                )
                if fail_ids:
                    fail_users = {
                        sub_meta[sid]["user"] for sid in fail_ids
                    }
                    message += (
                        f" Failed to add {add_target} to "
                        f"{len(fail_users)} user(s)."
                    )
                self.logger.info(
                    message=message,
                    details=f"Role(s) added: {', '.join(added_roles)}",
                )

            results = self._send_batch(
                add_requests, headers, instance_url,
                f"add {add_target} to users",
                "role-add",
                report_chunk=_report_add_batch,
            )
            round_failed, _ = self._collect_failed_mutations(
                results, sub_meta
            )
            failed.extend(round_failed)
            for req in add_requests:
                meta = sub_meta[req["id"]]
                status = results.get(req["id"], (None, {}))[0]
                bucket = outcome_bucket(add_stats, meta["role_name"])
                outcome = (
                    "success"
                    if status in (200, 201, 204)
                    else "failed"
                )
                bucket[outcome].add(meta["user"])

        if add_stats:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Successfully executed add "
                    "role to user(s). Expand log to view action stats."
                ),
                details=json.dumps(
                    outcome_counts(add_stats, TAG_STATS_ALREADY_EXISTS),
                    indent=2,
                ),
            )

        # Remove round 1: find role-assignment sys_ids.
        if remove_lookup:
            remove_target = describe_targets(
                sub_meta, remove_lookup, "role_name", "role", "roles",
            )

            def _report_remove_batch(chunk_index, success_ids, fail_ids):
                success_users = {
                    sub_meta[sid]["user"] for sid in success_ids
                }
                removed_roles = sorted({
                    sub_meta[sid]["role_name"] for sid in success_ids
                })
                message = (
                    f"{self.log_prefix}: Successfully revoked "
                    f"{remove_target} from {len(success_users)} "
                    f"user(s) in batch {chunk_index}."
                )
                if fail_ids:
                    fail_users = {
                        sub_meta[sid]["user"] for sid in fail_ids
                    }
                    message += (
                        f" Failed to revoke {remove_target} from "
                        f"{len(fail_users)} user(s)."
                    )
                self.logger.info(
                    message=message,
                    details=f"Role(s) revoked: {', '.join(removed_roles)}",
                )

            round_failed, removed_sub_ids, noop_sub_ids, failed_sub_ids = (
                self._execute_remove_round(
                    remove_lookup,
                    sub_meta,
                    headers,
                    instance_url,
                    URLS["USER_HAS_ROLE"],
                    f"{remove_target} from users",
                    "role",
                    report_chunk=_report_remove_batch,
                )
            )
            failed.extend(round_failed)
            # Per role, as for the add round: with several roles in play
            # a single count across all of them would be a count of
            # assignments, not of users.
            remove_stats: Dict[str, Dict[str, Set[str]]] = {}
            for sub_ids, outcome in (
                (removed_sub_ids, "success"),
                (noop_sub_ids, "already_exists"),
                (failed_sub_ids, "failed"),
            ):
                for sub_id in sub_ids:
                    meta = sub_meta[sub_id]
                    bucket = outcome_bucket(
                        remove_stats, meta["role_name"]
                    )
                    bucket[outcome].add(meta["user"])
            if remove_stats:
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Successfully executed "
                        "remove role from user(s). Expand log to view "
                        "action stats."
                    ),
                    details=json.dumps(
                        outcome_counts(
                            remove_stats, TAG_STATS_DOES_NOT_EXIST
                        ),
                        indent=2,
                    ),
                )
        return failed

    def _execute_user_delegation_actions(
        self, actions: List, headers: Dict, instance_url: str
    ) -> List:
        """Execute Update User Delegation via the Batch API.

        The action is declarative: it names the delegation settings
        ServiceNow should end up with, and this executor makes
        ServiceNow match. Every (user, delegate) pair an action names is
        read once, classified into exactly one of create / replace
        settings / delete / fail (ambiguous) / nothing-to-do, and every
        resulting mutation rides in a single batch round.

        Delegation Duration always feeds a newly created delegation. An
        existing delegation keeps the start and end time it already has
        unless Update Delegation Duration is "Yes", in which case only
        its end time is moved to now plus Delegation Duration - the
        start time is never touched once a delegation exists. Selecting
        no setting at all means nothing is delegated, which is carried
        out by deleting the delegation.

        sys_user_delegate does not enforce one row per (user, delegate)
        pair. A pair that resolves to exactly one row is reconciled
        towards the desired state; a pair that resolves to more than one
        row is ambiguous, so it is failed outright and none of its rows
        are touched - this action cannot guess which row(s) are stale on
        a customer's behalf.

        Counts reported below are always distinct (user, delegate)
        pairs, never sub-requests: a single pair can fan out into
        several mutations.
        """
        user_cache: Dict[str, Optional[str]] = {}
        # sub_id -> request metadata, carrying every action id merged
        # onto that sub-request.
        sub_meta: Dict[str, Dict] = {}
        # (user, delegate, settings, window end) -> that delegation's
        # metadata. The settings and the window are part of the key
        # because, unlike the group/role/tag actions, they decide what is
        # written: two actions naming the same pair with *different*
        # settings are asking for different end states, so they stay
        # separate sub-requests rather than silently merging and having
        # one action's intent dropped.
        targets: Dict[Tuple, Dict] = {}
        lookup_requests = []
        failed = []
        self_pairs: Set[str] = set()
        now = datetime.datetime.now(datetime.timezone.utc)
        starts = now.strftime(DELEGATION_DATETIME_FORMAT)

        # Resolve every user and delegate named anywhere in this call in
        # one go, so the per-action lookups below cost no requests.
        self._prefetch_user_sys_ids(
            [
                action.get("params").parameters.get(field)
                for action in actions
                for field in ("user", "delegate")
            ],
            headers, instance_url, user_cache,
        )

        for action in actions:
            action_id = action.get("id")
            params = action.get("params").parameters
            user_values = normalize_csv_values(params.get("user"))
            delegate_values = normalize_csv_values(params.get("delegate"))
            if not user_values or not delegate_values:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping Update User "
                        "Delegation action with missing or invalid "
                        "parameters."
                    ),
                    resolution=(
                        "Provide a value for both the User and the "
                        "Delegate action parameter."
                    ),
                )
                failed.append(action_id)
                continue
            settings = params.get("delegation_settings") or []
            # Duration and settings are per action, so they are read
            # once here rather than once per (user, delegate) pair
            # below - otherwise a bad duration would be reported once
            # for every delegate. An action with no setting selected
            # can only delete, and a delete never needs a duration.
            ends = None
            if settings:
                try:
                    duration_days = int(
                        params.get("delegation_duration")
                    )
                    # A Source field skips the save-time check, so the
                    # same bounds are enforced here - the upper one also
                    # keeps the timedelta below from overflowing.
                    if not 0 < duration_days <= (
                        DELEGATION_MAX_DURATION_DAYS
                    ):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Skipping Update User "
                            "Delegation action with an invalid "
                            "Delegation Duration."
                        ),
                        resolution=(
                            "Provide a positive whole number of days "
                            "for Delegation Duration, up to "
                            f"{DELEGATION_MAX_DURATION_DAYS}."
                        ),
                    )
                    failed.append(action_id)
                    continue
                ends = (
                    now + datetime.timedelta(days=duration_days)
                ).strftime(DELEGATION_DATETIME_FORMAT)
            # Only meaningful on the update path (exactly one existing
            # row, settings selected) - harmless to read unconditionally
            # since it is simply never consulted on the create/delete
            # paths below.
            update_duration = (
                params.get("update_delegation_duration")
                or DELEGATION_EXTEND_DURATION_NO
            ).strip() == DELEGATION_EXTEND_DURATION_YES

            resolved_users, unresolved_users = self._resolve_user_sys_ids(
                user_values, headers, instance_url, user_cache
            )
            resolved_delegates, unresolved_delegates = (
                self._resolve_user_sys_ids(
                    delegate_values, headers, instance_url, user_cache
                )
            )
            if unresolved_users or unresolved_delegates:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unable to resolve "
                        f"{len(unresolved_users)} user(s) and "
                        f"{len(unresolved_delegates)} delegate(s) to a "
                        "sys_id. Skipping those delegation(s)."
                    ),
                    details=(
                        f"User(s): {', '.join(unresolved_users) or 'NA'}."
                        " Delegate(s): "
                        f"{', '.join(unresolved_delegates) or 'NA'}."
                    ),
                    resolution=(
                        "Provide a valid user and delegate (sys_id, "
                        "email or user name) that exist on ServiceNow."
                    ),
                )
                failed.append(action_id)
            if not resolved_users or not resolved_delegates:
                continue
            # Both User and Delegate accept several values, so an action
            # delegates every user it names to every delegate it names.
            # One lookup per pair.
            for user_value, user_id in resolved_users:
                for delegate_value, delegate_id in resolved_delegates:
                    if user_id == delegate_id:
                        # Delegating to oneself delegates nothing. Only
                        # reachable now that both sides accept a List
                        # source field, which can name one person on
                        # both sides of the same pair.
                        self_pairs.add(f"{user_id}|{delegate_id}")
                        continue
                    # Sorted because only membership of `settings` is
                    # ever read, so two orderings of the same selection
                    # ask for the same end state and must share one
                    # sub-request. update_duration is part of the key
                    # for the same reason settings and ends are: "Yes"
                    # and "No" ask for different end states (move the
                    # window or leave it), so they must not be merged
                    # into one sub-request either.
                    target = targets.setdefault(
                        (
                            user_id, delegate_id,
                            tuple(sorted(settings)), ends, update_duration,
                        ),
                        {
                            "action_ids": [],
                            "user_id": user_id,
                            "delegate_id": delegate_id,
                            "user_display": user_value,
                            "delegate_display": delegate_value,
                            "settings": settings,
                            "ends": ends,
                            "update_duration": update_duration,
                            "pair": f"{user_id}|{delegate_id}",
                        },
                    )
                    target["action_ids"].append(action_id)

        # Round 1 below reads every pair before the first mutation is
        # built, so two sub-requests for the same pair would both read
        # "no delegation yet" and then both POST, creating a duplicate
        # sys_user_delegate row. Merging them above prevents that.
        for counter, target in enumerate(targets.values(), start=1):
            sub_id = str(counter)
            sub_meta[sub_id] = target
            query = (
                f"user={target['user_id']}"
                f"^delegate={target['delegate_id']}"
            )
            lookup_requests.append(
                {
                    "id": sub_id,
                    "method": "GET",
                    "url": build_lookup_url(
                        URLS["USER_DELEGATE"], query,
                        DELEGATION_LOOKUP_FIELDS,
                    ),
                }
            )

        if self_pairs:
            self.logger.info(
                f"{self.log_prefix}: Skipped {len(self_pairs)} user "
                "delegation(s) where the user and the delegate are the "
                "same user."
            )
        if not lookup_requests:
            return failed

        # Round 1: read what each pair currently has, so the mutation
        # queued below is the smallest one that reaches the state the
        # action asks for - and so a pair already in that state costs no
        # write at all.
        lookup_results = self._send_batch(
            lookup_requests, headers, instance_url,
            "checking existing user delegation",
            "delegation-update-check",
        )
        mutate_requests = []
        mutate_meta: Dict[str, Dict] = {}
        unchanged_pairs: Set[str] = set()
        mutated_pairs: Set[str] = set()
        failed_pairs: Set[str] = set()
        # pair -> "<user>-><delegate>" display, for the aggregated >1
        # row failure log below. A dict, not a list, so a pair hit by
        # more than one sub-request (e.g. two actions naming it with
        # different settings) is only reported once.
        multi_row_pairs: Dict[str, str] = {}
        mutate_counter = 0
        for req in lookup_requests:
            sub_id = req["id"]
            meta = sub_meta[sub_id]
            status, body = lookup_results.get(sub_id, (None, {}))
            # Checked before the rows are read, so a failed or
            # unserviced lookup can never be mistaken for "this pair
            # has no delegation yet" and turned into a create.
            if status is None or status not in (200, 201):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to check the "
                        "existing user delegation."
                    ),
                    details=f"Batch sub-request response: {body}",
                    resolution=(
                        "Verify the configured user can read records "
                        "on the sys_user_delegate table."
                    ),
                )
                failed.extend(meta["action_ids"])
                failed_pairs.add(meta["pair"])
                continue
            settings = meta["settings"]
            desired = {
                setting: setting in settings
                for setting in DELEGATION_SETTINGS_VALUES
            }
            # The same four booleans whether the delegation is created
            # or its settings replaced, so the two paths cannot drift.
            settings_body = {
                setting: str(value).lower()
                for setting, value in desired.items()
            }
            rows = body.get("result", []) or []
            if not rows:
                if not settings:
                    # Nothing delegated, and nothing asked for - the
                    # state the action wants already holds.
                    unchanged_pairs.add(meta["pair"])
                    continue
                mutate_counter += 1
                mutate_id = f"m{mutate_counter}"
                mutate_meta[mutate_id] = {
                    "action_ids": meta["action_ids"],
                    "pair": meta["pair"],
                    "op": DELEGATION_OP_CREATED,
                }
                mutate_requests.append(
                    {
                        "id": mutate_id,
                        "method": "POST",
                        "url": URLS["USER_DELEGATE"],
                        "body": {
                            "user": meta["user_id"],
                            "delegate": meta["delegate_id"],
                            "starts": starts,
                            "ends": meta["ends"],
                            **settings_body,
                        },
                    }
                )
                mutated_pairs.add(meta["pair"])
                continue
            if len(rows) > 1:
                # sys_user_delegate does not enforce one row per (user,
                # delegate) pair. More than one row for a pair is
                # ambiguous - there is no way to tell which row(s)
                # reflect the real intent - so the pair fails outright,
                # uniformly across the create/update/delete paths,
                # rather than guessing by reconciling every row found.
                failed.extend(meta["action_ids"])
                failed_pairs.add(meta["pair"])
                multi_row_pairs[meta["pair"]] = (
                    f"{meta['user_display']}->{meta['delegate_display']}"
                )
                continue
            row = rows[0]
            row_sys_id = row.get("sys_id")
            if not row_sys_id:
                continue
            # With display values not requested, ServiceNow returns a
            # boolean field as the string "true"/"false" (some
            # instances as "1"/"0"); an absent field reads as false,
            # which is also the correct desired-state default.
            current = {
                setting: str(row.get(setting, "")).strip().lower()
                in ("true", "1")
                for setting in DELEGATION_SETTINGS_VALUES
            }
            if not settings:
                op = DELEGATION_OP_REMOVED
                request = {
                    "method": "DELETE",
                    "url": f"{URLS['USER_DELEGATE']}/{row_sys_id}",
                }
            elif current != desired or meta["update_duration"]:
                # Update Delegation Duration = "Yes" forces this PATCH
                # even when the settings already match current, so the
                # requested window move is never silently dropped - it
                # folds into the same "updated" op, with no separate
                # label or log line.
                op = DELEGATION_OP_UPDATED
                patch_body = dict(settings_body)
                if meta["update_duration"]:
                    # Only the end moves - the start of an existing
                    # delegation is never touched.
                    patch_body["ends"] = meta["ends"]
                request = {
                    "method": "PATCH",
                    "url": f"{URLS['USER_DELEGATE']}/{row_sys_id}",
                    "body": patch_body,
                }
            else:
                unchanged_pairs.add(meta["pair"])
                continue
            mutate_counter += 1
            mutate_id = f"m{mutate_counter}"
            mutate_meta[mutate_id] = {
                "action_ids": meta["action_ids"],
                "pair": meta["pair"],
                "op": op,
            }
            request["id"] = mutate_id
            mutate_requests.append(request)
            mutated_pairs.add(meta["pair"])

        if multi_row_pairs:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: More than 1 record found on "
                    f"{PLATFORM_NAME} for "
                    f"{len(multi_row_pairs)} user-delegate pair(s), "
                    "hence failing the delegation action for those "
                    "pair(s)."
                ),
                details=(
                    "User-Delegate pair(s): "
                    + ", ".join(multi_row_pairs.values())
                ),
                resolution=(
                    "Ensure the user and delegate pair maps to exactly "
                    f"one delegation record on {PLATFORM_NAME}; delete or "
                    "merge the duplicate sys_user_delegate record(s) "
                    "for the affected pair(s) before re-running the "
                    "action."
                ),
            )

        # A pair whose rows were partly already correct and partly not
        # is an updated pair, not an unchanged one; a pair already
        # counted as failed (lookup failure or >1 rows found) is never
        # also reported as unchanged.
        unchanged_pairs -= mutated_pairs | failed_pairs
        stats: Dict[str, Set[str]] = {op: set() for op in DELEGATION_OPS}
        if mutate_requests:
            def _report_mutate_batch(chunk_index, success_ids, fail_ids):
                buckets = {op: set() for op in DELEGATION_OPS}
                for mutate_id in success_ids:
                    entry = mutate_meta.get(mutate_id)
                    if entry:
                        buckets[entry["op"]].add(entry["pair"])
                done = ", ".join(
                    f"{op} {len(buckets[op])}"
                    for op in DELEGATION_OPS if buckets[op]
                )
                if done:
                    message = (
                        f"{self.log_prefix}: Successfully {done} user "
                        f"delegation(s) in batch {chunk_index}."
                    )
                else:
                    message = (
                        f"{self.log_prefix}: No user delegation was "
                        f"updated in batch {chunk_index}."
                    )
                if fail_ids:
                    fail_pairs = {
                        mutate_meta[mutate_id]["pair"]
                        for mutate_id in fail_ids
                        if mutate_id in mutate_meta
                    }
                    message += (
                        f" Failed to update {len(fail_pairs)} user "
                        "delegation(s)."
                    )
                self.logger.info(message)

            results = self._send_batch(
                mutate_requests, headers, instance_url,
                "updating user delegation",
                "delegation-update",
                report_chunk=_report_mutate_batch,
            )
            # Only the action ids are needed here: the per-pair counts
            # below are what the stats payload reports, and a pair can
            # fan out into several mutations.
            round_failed, _ = self._collect_failed_mutations(
                results, mutate_meta
            )
            failed.extend(round_failed)
            # A pair is counted where it succeeded and, separately,
            # where it failed - so a pair with one mutated row and one
            # failed row is not reported as a clean success.
            for mutate_id, entry in mutate_meta.items():
                status = results.get(mutate_id, (None, {}))[0]
                if status in (200, 201, 204):
                    stats[entry["op"]].add(entry["pair"])
                else:
                    failed_pairs.add(entry["pair"])

        self.logger.info(
            message=(
                f"{self.log_prefix}: Successfully executed update user "
                "delegation. Expand log to view action stats."
            ),
            details=json.dumps(
                {
                    **{op: len(stats[op]) for op in DELEGATION_OPS},
                    "unchanged": len(unchanged_pairs),
                    "skipped": len(self_pairs),
                    "failed": len(failed_pairs),
                },
                indent=2,
            ),
        )
        return failed

    def _execute_tag_actions(
        self, actions: List, headers: Dict, instance_url: str
    ) -> List:
        """Execute Tag/Untag Device or Application via the Batch API."""
        # sub_id -> request metadata, carrying every action id merged
        # onto that sub-request.
        sub_meta: Dict[str, Dict] = {}
        # (action type, configuration item, key, value) -> that tag's
        # metadata. Keyed so two actions naming the same tag share one
        # sub-request; see the emit loop below for why that matters.
        targets: Dict[Tuple, Dict] = {}
        tag_lookup_requests = []
        add_requests = []
        remove_lookup = []
        failed = []
        entity_label = (
            "device"
            if actions[0].get("params").value == ACTION_TAG_DEVICE
            else "application"
        )

        for action in actions:
            action_id = action.get("id")
            params = action.get("params").parameters
            action_type = (params.get("action_type") or "").strip()
            cis = normalize_csv_values(params.get("configuration_item"))
            key = (params.get("key") or "").strip()
            values = normalize_csv_values(params.get("value"))
            if action_type not in (ACTION_TYPE_ADD, ACTION_TYPE_REMOVE) \
                    or not cis or not key or not values:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping Tag action with "
                        "missing or invalid parameters."
                    )
                )
                failed.append(action_id)
                continue
            # One entry per (configuration item, tag value) pair, since
            # both fields accept several values - a comma separated
            # Static value or a List-type Source field - and one entry
            # per *distinct* tag, so several actions naming the same one
            # collapse onto a single sub-request.
            for ci in cis:
                for value in values:
                    target = targets.setdefault(
                        (action_type, ci, key, value),
                        {
                            "action_ids": [],
                            "action_type": action_type,
                            "key": key,
                            "ci": ci,
                            "value": value,
                        },
                    )
                    target["action_ids"].append(action_id)

        # The check round below reads every tag before the first write of
        # that round is built, so two sub-requests for the same tag would
        # both read "not tagged" and then both POST, creating the
        # duplicate row the check exists to prevent. Merging them above is
        # what keeps the check meaningful.
        for counter, target in enumerate(targets.values(), start=1):
            sub_id = str(counter)
            sub_meta[sub_id] = target
            query = (
                f"configuration_item={target['ci']}^key={target['key']}"
                f"^value={target['value']}"
            )
            if target["action_type"] == ACTION_TYPE_ADD:
                tag_lookup_requests.append(
                    {
                        "id": sub_id,
                        "method": "GET",
                        "url": build_lookup_url(
                            URLS["KEY_VALUE"], query, "sys_id",
                            limit=1,
                        ),
                    }
                )
            else:
                remove_lookup.append(
                    {
                        "id": sub_id,
                        "method": "GET",
                        "url": build_lookup_url(
                            URLS["KEY_VALUE"], query, "sys_id"
                        ),
                    }
                )

        # Tag check round: skip a configuration item that already has
        # this exact key/value tag, so a re-synced action doesn't
        # create a duplicate cmdb_key_value row. Enforced here rather
        # than by asking customers to add a uniqueness constraint on
        # their own instance. Outcomes are folded into add_stats
        # instead of logged individually, and reported once below.
        add_stats: Dict[str, Dict[str, Set[str]]] = {}
        if tag_lookup_requests:
            tag_lookup_results = self._send_batch(
                tag_lookup_requests, headers, instance_url,
                "check existing configuration item tags",
                "tag-add-check",
            )
            for sub_id, (status, body) in tag_lookup_results.items():
                meta = sub_meta.get(sub_id)
                if meta is None or "ci" not in meta:
                    continue
                bucket = outcome_bucket(
                    add_stats, f"{meta['key']}={meta['value']}"
                )
                if status is None or status not in (200, 201):
                    failed.extend(meta["action_ids"])
                    bucket["failed"].add(meta["ci"])
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Failed to check "
                            "whether the configuration item already "
                            f"has tag '{meta['key']}={meta['value']}'."
                        ),
                        details=f"Batch sub-request response: {body}",
                        resolution=(
                            "Verify the configured user can read "
                            "records on the cmdb_key_value table."
                        ),
                    )
                    continue
                result = body.get("result", []) or []
                if result:
                    # The configuration item already carries this tag,
                    # so the state the action asks for already holds - a
                    # successful no-op, not a failure. Only the add is
                    # skipped.
                    bucket["already_exists"].add(meta["ci"])
                    continue
                add_requests.append(
                    {
                        "id": sub_id,
                        "method": "POST",
                        "url": URLS["KEY_VALUE"],
                        "body": {
                            "configuration_item": meta["ci"],
                            "key": meta["key"],
                            "value": meta["value"],
                        },
                    }
                )

        if add_requests:
            add_target = describe_targets(
                sub_meta, add_requests, "key", "tag", "tags",
            )

            def _report_add_batch(chunk_index, success_ids, fail_ids):
                success_cis = {
                    sub_meta[sid]["ci"] for sid in success_ids
                }
                added_values = sorted({
                    sub_meta[sid]["value"] for sid in success_ids
                })
                message = (
                    f"{self.log_prefix}: Successfully added "
                    f"{add_target} to {len(success_cis)} "
                    f"configuration item(s) in batch {chunk_index}."
                )
                if fail_ids:
                    fail_cis = {
                        sub_meta[sid]["ci"] for sid in fail_ids
                    }
                    message += (
                        f" Failed to add {add_target} to "
                        f"{len(fail_cis)} configuration item(s)."
                    )
                self.logger.info(
                    message=message,
                    details=(
                        "Tag values added: "
                        f"{', '.join(added_values)}"
                    ),
                )

            results = self._send_batch(
                add_requests, headers, instance_url,
                f"add {add_target} to configuration items",
                "tag-add",
                report_chunk=_report_add_batch,
            )
            # Only the action ids are needed here: the add_stats buckets
            # below count distinct configuration items per tag.
            round_failed, _ = self._collect_failed_mutations(
                results, sub_meta
            )
            failed.extend(round_failed)
            for req in add_requests:
                meta = sub_meta[req["id"]]
                status = results.get(req["id"], (None, {}))[0]
                bucket = outcome_bucket(
                    add_stats, f"{meta['key']}={meta['value']}"
                )
                outcome = (
                    "success"
                    if status in (200, 201, 204)
                    else "failed"
                )
                bucket[outcome].add(meta["ci"])

        if add_stats:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Successfully executed add "
                    "tag to configuration item(s) "
                    f"({entity_label}). Expand log to view action "
                    "stats."
                ),
                details=json.dumps(
                    outcome_counts(
                        add_stats, TAG_STATS_ALREADY_EXISTS
                    ),
                    indent=2,
                ),
            )

        remove_stats: Dict[str, Dict[str, Set[str]]] = {}
        if remove_lookup:
            remove_target = describe_targets(
                sub_meta, remove_lookup, "key", "tag", "tags",
            )

            def _report_remove_batch(chunk_index, success_ids, fail_ids):
                success_cis = {
                    sub_meta[sid]["ci"] for sid in success_ids
                }
                removed_values = sorted({
                    sub_meta[sid]["value"] for sid in success_ids
                })
                message = (
                    f"{self.log_prefix}: Successfully removed "
                    f"{remove_target} from {len(success_cis)} "
                    f"configuration item(s) in batch {chunk_index}."
                )
                if fail_ids:
                    fail_cis = {
                        sub_meta[sid]["ci"] for sid in fail_ids
                    }
                    message += (
                        f" Failed to remove {remove_target} from "
                        f"{len(fail_cis)} configuration item(s)."
                    )
                self.logger.info(
                    message=message,
                    details=(
                        "Tag values removed: "
                        f"{', '.join(removed_values)}"
                    ),
                )

            round_failed, removed_sub_ids, noop_sub_ids, failed_sub_ids = (
                self._execute_remove_round(
                    remove_lookup,
                    sub_meta,
                    headers,
                    instance_url,
                    URLS["KEY_VALUE"],
                    f"{remove_target} from configuration items",
                    "tag",
                    report_chunk=_report_remove_batch,
                )
            )
            failed.extend(round_failed)
            for sid in removed_sub_ids:
                meta = sub_meta[sid]
                bucket = outcome_bucket(
                    remove_stats, f"{meta['key']}={meta['value']}"
                )
                bucket["success"].add(meta["ci"])
            for sid in noop_sub_ids:
                meta = sub_meta[sid]
                bucket = outcome_bucket(
                    remove_stats, f"{meta['key']}={meta['value']}"
                )
                bucket["already_exists"].add(meta["ci"])
            for sid in failed_sub_ids:
                meta = sub_meta[sid]
                bucket = outcome_bucket(
                    remove_stats, f"{meta['key']}={meta['value']}"
                )
                bucket["failed"].add(meta["ci"])

        if remove_stats:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Successfully executed "
                    "remove tag from configuration item(s) "
                    f"({entity_label}). Expand log to view action "
                    "stats."
                ),
                details=json.dumps(
                    outcome_counts(
                        remove_stats, TAG_STATS_DOES_NOT_EXIST
                    ),
                    indent=2,
                ),
            )
        return failed

    def _execute_share_application_data_actions(
        self, actions: List, headers: Dict, instance_url: str
    ) -> List:
        """Execute the combined Share Application Data action.

        Splits the batch by each action instance's Select Table value.
        Both paths are 2-round Batch API executors: Core Company finds
        the companies each action's query matches and prepends the
        summary block to their Notes; CMDB CI Business App finds each
        application by name and creates it or replaces its Comments.
        The block text itself is unchanged from the two actions these
        paths were merged from.
        """
        core_company_actions = []
        business_app_actions = []
        failed = []

        for action in actions:
            action_id = action.get("id")
            params = action.get("params").parameters
            select_table = (params.get("select_table") or "").strip()
            if select_table == SHARE_TABLE_CORE_COMPANY:
                core_company_actions.append(action)
            elif select_table == SHARE_TABLE_BUSINESS_APP:
                business_app_actions.append(action)
            else:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping Share Application "
                        "Data action with an invalid or missing Select "
                        "Table value."
                    )
                )
                failed.append(action_id)

        if core_company_actions:
            failed.extend(
                self._execute_core_company_share_data(
                    core_company_actions, headers, instance_url
                )
            )

        if business_app_actions:
            failed.extend(
                self._execute_business_app_share_data(
                    business_app_actions, headers, instance_url
                )
            )

        return [fid for fid in failed if fid is not None]

    def _execute_core_company_share_data(
        self, actions: List, headers: Dict, instance_url: str
    ) -> List:
        """Execute the Core Company path (2 rounds, batched).

        Round 1 runs each action's Company Name / Parent Company Name
        query against core_company; round 2 writes the [Netskope CE]
        summary block(s) onto every company those queries matched,
        prepending them to whatever Notes already held so previously
        shared details are kept - the pre-2.0.0 behaviour.

        Two groupings keep the request count flat however many records
        CE hands over:

        - actions sharing the same query issue ONE lookup between them,
          since the answer cannot differ;
        - every block destined for the same company is concatenated and
          written by ONE PATCH, instead of one PATCH per application
          record. Appending per record would need each write to see the
          previous one's result, which sub-requests in a single batch
          cannot do - so records sharing to the same company would
          overwrite each other's block. Building the whole Notes value
          up front avoids that entirely.

        Companies are never created here - only existing ones are
        updated. An action whose query matches no company therefore has
        nothing to write to: it is skipped and reported in
        failed_action_ids.
        """
        # query -> the actions that resolved to it, in action order.
        query_entries: Dict[str, List[Dict]] = {}
        failed = []

        for action in actions:
            action_id = action.get("id")
            action_params = action.get("params").parameters
            action_label = action.get("params").label
            application_name = action_params.get("application_name", "NA")
            try:
                _ = ServiceNowQuery(
                    company_name=action_params.get("company_name", "NA"),
                    parent_company_name=action_params.get(
                        "parent_company_name", "NA"
                    ),
                    operator=action_params.get("operator", "and"),
                    cci=action_params.get("cci") or None,
                )
            except ValidationError as exp:
                err_msg = (
                    f"{exp.errors()[0]['msg']} "
                    f"Hence, skipping execution of '{action_label}' "
                    f"action for application '{application_name}'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(exp),
                )
                failed.append(action_id)
                continue
            query = make_query_list(action_parameters=action_params)
            if not query:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping Share Application "
                        "Data action for application "
                        f"'{application_name}' as neither Company Name "
                        "nor Parent Company Name was provided."
                    ),
                    resolution=(
                        "Provide a Company Name or a Parent Company "
                        "Name in the action parameters."
                    ),
                )
                failed.append(action_id)
                continue
            cci = action_params.get("cci", None)
            ccl = action_params.get("ccl", "NA")
            category_name = action_params.get("category_name", "NA")
            deep_link = action_params.get("deep_link", "NA")
            # UTC, matching the Business App path so both Share
            # Application Data paths stamp the same way - and making the
            # trailing "Z" accurate, which it was not when the pre-2.0.0
            # action stamped naive local time under it.
            current_time = datetime.datetime.now(
                datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%SZ")
            # Block text preserved verbatim from the pre-2.0.0
            # share_app_data action, so what lands in Notes does not
            # change now that the write goes through the Batch API.
            block = (
                f"[Netskope CE] Last shared at: {current_time}\n"
                f"Application Name: "
                f"{application_name if application_name else 'NA'}, "
                f"Cloud Confidence Index: {cci if cci else 'NA'}, "
                f"CCL: {ccl if ccl else 'NA'}, "
                f"Category Name: "
                f"{category_name if category_name else 'NA'}, "
                f"Deep Link: {deep_link if deep_link else 'NA'}\n"
            )
            query_entries.setdefault(query, []).append(
                {
                    "action_id": action_id,
                    "application_name": application_name,
                    "block": block,
                }
            )

        if not query_entries:
            return failed

        sub_meta: Dict[str, Dict] = {}
        lookup_requests = []
        for counter, (query, entries) in enumerate(
            query_entries.items(), start=1
        ):
            sub_id = str(counter)
            sub_meta[sub_id] = {"query": query, "entries": entries}
            lookup_requests.append(
                {
                    "id": sub_id,
                    "method": "GET",
                    "url": build_lookup_url(
                        # Notes is read back because the block is
                        # prepended to it, not written over it.
                        URLS["COMPANY"], query, "sys_id,name,notes",
                        limit=COMPANY_LOOKUP_SUBREQUEST_LIMIT,
                    ),
                }
            )

        # Round 1: find the companies each distinct query matches.
        self.logger.info(
            f"{self.log_prefix}: Checking existence of company(ies) on "
            f"{PLATFORM_NAME}."
        )
        lookup_results = self._send_batch(
            lookup_requests, headers, instance_url,
            "checking the companies to share the application data with",
            "share-company-lookup",
        )
        # company sys_id -> everything needed to build its one PATCH.
        companies: Dict[str, Dict] = {}
        lookup_failed_count = 0
        not_found_apps = []
        for sub_id, meta in sub_meta.items():
            entries = meta["entries"]
            apps = ", ".join(
                dict.fromkeys(
                    entry["application_name"] for entry in entries
                )
            )
            status, body = lookup_results.get(sub_id, (None, {}))
            if status is None or status not in (200, 201):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to check the "
                        "companies to share the data of "
                        f"{len(entries)} record(s) with."
                    ),
                    details=(
                        f"Application(s): {apps}. Batch sub-request "
                        f"response: {body}"
                    ),
                    resolution=(
                        "Verify the ServiceNow instance is reachable "
                        "and the configured user can read the "
                        "core_company table."
                    ),
                )
                failed.extend(entry["action_id"] for entry in entries)
                lookup_failed_count += len(entries)
                continue
            rows = body.get("result", []) or []
            if len(rows) >= COMPANY_LOOKUP_SUBREQUEST_LIMIT:
                # The sub-request filled its page cap, so more matching
                # companies may exist. Keep the ones already returned
                # and resume offset-paging from where it stopped rather
                # than re-fetching from the start.
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Found more than "
                        f"{COMPANY_LOOKUP_SUBREQUEST_LIMIT} companies "
                        f"matching the query for {len(entries)} "
                        "record(s), hence paginating over the "
                        "remaining companies."
                    ),
                    details=f"Application(s): {apps}.",
                )
                try:
                    for page_rows in self._paginate_table(
                        url_path=URLS["COMPANY"],
                        headers=headers,
                        instance_url=instance_url,
                        fields="sys_id,name,notes",
                        query=meta["query"],
                        logger_msg=(
                            "the companies to share the application "
                            "data with"
                        ),
                        display_value_all=False,
                        start_offset=COMPANY_LOOKUP_SUBREQUEST_LIMIT,
                        limit=COMPANY_LOOKUP_SUBREQUEST_LIMIT,
                    ):
                        rows.extend(page_rows)
                except Exception:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error occurred while "
                            "fetching the remaining companies to share "
                            f"the data of {len(entries)} record(s) "
                            "with, hence sharing will be skipped for "
                            "them."
                        ),
                        details=(
                            f"{traceback.format_exc()}"
                        ),
                    )
                    failed.extend(
                        entry["action_id"] for entry in entries
                    )
                    continue
            # Logged for a zero count too, since an empty result is the
            # thing worth seeing the query for.
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Found {len(rows)} company(ies) "
                    "satisfying the query."
                ),
                details=(
                    f"Query: {meta['query']}."
                ),
            )
            if not rows:
                # Nothing to write the summary block to, so the action
                # could not be carried out at all.
                not_found_apps.extend(
                    entry["application_name"] for entry in entries
                )
                failed.extend(entry["action_id"] for entry in entries)
                continue
            for row in rows:
                company_id = row.get("sys_id")
                if not company_id:
                    continue
                bucket = companies.setdefault(
                    company_id,
                    {
                        "name": row.get("name") or company_id,
                        # A company matched by more than one query is
                        # read more than once, but it is the same row
                        # each time, so the first read's Notes value is
                        # as good as any.
                        "existing": row.get("notes") or "",
                        "blocks": [],
                        "action_ids": [],
                        "applications": [],
                    },
                )
                bucket["blocks"].extend(
                    entry["block"] for entry in entries
                )
                bucket["action_ids"].extend(
                    entry["action_id"] for entry in entries
                )
                bucket["applications"].extend(
                    entry["application_name"] for entry in entries
                )

        if lookup_failed_count:
            self.logger.error(
                f"{self.log_prefix}: Failed to check the companies for "
                f"{lookup_failed_count} record(s); sharing of the "
                "application data was skipped for those."
            )
        if not_found_apps:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: No matching company was found "
                    f"on {PLATFORM_NAME} for {len(not_found_apps)} "
                    "record(s), hence sharing of the application data "
                    "was skipped for them."
                ),
                details=(
                    "Application(s): "
                    f"{', '.join(dict.fromkeys(not_found_apps))}."
                ),
                resolution=(
                    "Verify the Company Name and Parent Company Name "
                    "provided in the action parameters exist on the "
                    "'User Administration > Companies' page of the "
                    "ServiceNow instance."
                ),
            )

        # Round 2: one PATCH per company, carrying every block bound for
        # it plus the Notes it already had.
        mutate_requests = []
        mutate_meta: Dict[str, Dict] = {}
        for counter, (company_id, bucket) in enumerate(
            companies.items(), start=1
        ):
            mutate_id = f"c{counter}"
            # Newest block(s) first and the previous Notes below, the
            # order the pre-2.0.0 action wrote in, so a company's share
            # history still reads newest to oldest.
            parts = list(bucket["blocks"])
            if bucket["existing"]:
                parts.append(bucket["existing"])
            mutate_meta[mutate_id] = {
                "action_ids": bucket["action_ids"],
                "company_name": bucket["name"],
                "applications": bucket["applications"],
            }
            mutate_requests.append(
                {
                    "id": mutate_id,
                    "method": "PATCH",
                    "url": f"{URLS['COMPANY']}/{company_id}",
                    "body": {"notes": "\n\n".join(parts)},
                }
            )

        if mutate_requests:
            sharing_apps = {
                app
                for meta in mutate_meta.values()
                for app in meta["applications"]
            }
            self.logger.info(
                f"{self.log_prefix}: Sharing {len(sharing_apps)} "
                f"application(s) data to {len(mutate_requests)} "
                "company(ies)."
            )

            def _report_share_batch(chunk_index, success_ids, fail_ids):
                message = (
                    f"{self.log_prefix}: Successfully shared the "
                    f"application data with {len(success_ids)} "
                    f"company(ies) in batch {chunk_index}."
                )
                if fail_ids:
                    message += (
                        " Failed to share the application data with "
                        f"{len(fail_ids)} company(ies)."
                    )
                self.logger.info(message)

            mutate_results = self._send_batch(
                mutate_requests, headers, instance_url,
                "sharing the application data with the companies",
                "share-company-update",
                report_chunk=_report_share_batch,
            )
            # One PATCH can carry blocks from several records, so a
            # failed write fails every record that contributed to it -
            # which is why this is not _collect_failed_mutations.
            shared_count = 0
            failed_companies = []
            # company name -> how many application shares landed on it
            # and how many did not. One PATCH carries every application
            # bound for a company, so a company is all-or-nothing; the
            # two keys still differ per company across the batch.
            stats: Dict[str, Dict[str, int]] = {}
            for mutate_id, (status, body) in mutate_results.items():
                meta = mutate_meta.get(mutate_id)
                if meta is None:
                    continue
                bucket = stats.setdefault(
                    meta["company_name"], {"app shared": 0, "failed": 0}
                )
                outcome = (
                    "app shared"
                    if status in (200, 201, 204)
                    else "failed"
                )
                bucket[outcome] += len(set(meta["applications"]))
                if status in (200, 201, 204):
                    shared_count += 1
                    continue
                failed_companies.append(meta["company_name"])
                failed.extend(meta["action_ids"])
                reason = (
                    "the sub-request was not executed (unserviced)"
                    if status is None
                    else f"status code {status} was returned"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to share the "
                        "application data with company "
                        f"'{meta['company_name']}' because {reason}."
                    ),
                    details=f"Batch sub-request response: {body}",
                    resolution=(
                        "Verify the company exists on ServiceNow and "
                        "the configured user has permission to update "
                        "its Notes field."
                    ),
                )
            if shared_count:
                self.logger.info(
                    f"{self.log_prefix}: Successfully shared the "
                    f"application data with {shared_count} "
                    "company(ies)."
                )
            if failed_companies:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to share the "
                        f"application data with "
                        f"{len(failed_companies)} company(ies)."
                    ),
                    details=(
                        "Company(ies): "
                        f"{', '.join(dict.fromkeys(failed_companies))}."
                    ),
                )
            if stats:
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Successfully executed "
                        "share application data to core company(ies). "
                        "Expand log to view action stats."
                    ),
                    details=json.dumps(stats, indent=2),
                )
        return failed

    def _execute_business_app_share_data(
        self, actions: List, headers: Dict, instance_url: str
    ) -> List:
        """Execute the CMDB CI Business App path (2 rounds, batched).

        Round 1 finds each application by name; round 2 creates it with
        the [Netskope CE] summary block, or PATCHes an existing one so
        the block replaces the previous contents of Comments.
        """
        # sub_id -> request metadata, carrying every action id merged
        # onto that sub-request.
        sub_meta: Dict[str, Dict] = {}
        # Application name -> that application's share. Keyed on the name
        # alone because Comments holds exactly one block - the write
        # replaces it rather than appending - so however many records
        # name an application, only one block can survive. Keying any
        # wider (on the payload, or on the rendered block) would leave
        # two sub-requests for one application, and since round 1 reads
        # them both before either write is built, both would read "does
        # not exist" and then both POST, creating a duplicate
        # cmdb_ci_business_app row. Deliberately NOT keyed on the block:
        # the "Last shared at" stamp would split records that are
        # otherwise identical.
        targets: Dict[str, Dict] = {}
        lookup_requests = []
        failed = []
        current_time = datetime.datetime.now(datetime.timezone.utc)
        current_time = current_time.strftime("%Y-%m-%d %H:%M:%SZ")

        for action in actions:
            action_id = action.get("id")
            params = action.get("params").parameters
            app_name = (params.get("application_name") or "").strip()
            if not app_name:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping Share Application "
                        "Data action with an empty Application Name."
                    )
                )
                failed.append(action_id)
                continue
            cci = params.get("cci") or "NA"
            ccl = params.get("ccl") or "NA"
            category_name = params.get("category_name") or "NA"
            deep_link = params.get("deep_link") or "NA"
            target = targets.setdefault(
                app_name,
                {
                    "action_ids": [],
                    "application_name": app_name,
                    # First record to name the application wins, since
                    # only one block can be written. Kept alongside the
                    # data it was rendered from so a later record naming
                    # the same application can be compared against it.
                    "data": (cci, ccl, category_name, deep_link),
                    "block": (
                        f"[Netskope CE] Last shared at: {current_time}\n"
                        f"Application Name: {app_name}, "
                        f"Cloud Confidence Index: {cci}, "
                        f"CCL: {ccl}, "
                        f"Category Name: {category_name}, "
                        f"Deep Link: {deep_link}\n"
                    ),
                },
            )
            target["action_ids"].append(action_id)
            if target["data"] != (cci, ccl, category_name, deep_link):
                target["conflicting"] = True

        # Only one block per application reaches ServiceNow, so say so
        # rather than letting the discarded data vanish silently.
        conflicting = [
            target["application_name"]
            for target in targets.values()
            if target.get("conflicting")
        ]
        if conflicting:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: {len(conflicting)} "
                    "application(s) were named by several records "
                    "carrying different data. The data of the first "
                    "record is shared for each, since the Comments "
                    "field holds one summary per application."
                ),
                details=f"Application(s): {', '.join(conflicting)}.",
            )

        for counter, target in enumerate(targets.values(), start=1):
            sub_id = str(counter)
            sub_meta[sub_id] = target
            query = f"name={target['application_name']}"
            lookup_requests.append(
                {
                    "id": sub_id,
                    "method": "GET",
                    "url": build_lookup_url(
                        URLS["APPLICATIONS"],
                        query,
                        "sys_id,discovery_source",
                    ),
                }
            )

        if not lookup_requests:
            return failed

        # Round 1: find existing apps by name.
        app_target = describe_targets(
            sub_meta, lookup_requests, "application_name",
            "application", "applications",
        )
        lookup_results = self._send_batch(
            lookup_requests, headers, instance_url,
            f"find {app_target} by name",
            "share-app-lookup",
        )

        mutate_requests = []
        lookup_failed_count = 0
        for sub_id, meta in sub_meta.items():
            status, body = lookup_results.get(sub_id, (None, {}))
            if status is None or status not in (200, 201):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to look up "
                        f"application '{meta['application_name']}'."
                    ),
                    details=f"Batch sub-request response: {body}",
                    resolution=(
                        "Verify the ServiceNow instance is reachable and "
                        "the configured user can read the "
                        "cmdb_ci_business_app table."
                    ),
                )
                failed.extend(meta["action_ids"])
                lookup_failed_count += 1
                continue
            result = body.get("result", []) or []
            if result:
                existing = result[0]
                sys_id = existing.get("sys_id")
                # The summary block replaces whatever the field holds
                # instead of being prepended to it, so Comments cannot
                # grow without bound as the action is re-run. Only the
                # latest share is kept.
                mutate_requests.append(
                    {
                        "id": sub_id,
                        "method": "PATCH",
                        "url": f"{URLS['APPLICATIONS']}/{sys_id}",
                        "body": {"comments": meta["block"]},
                    }
                )
            else:
                mutate_requests.append(
                    {
                        "id": sub_id,
                        "method": "POST",
                        "url": URLS["APPLICATIONS"],
                        "body": {
                            "name": meta["application_name"],
                            "comments": meta["block"],
                            "discovery_source": NETSKOPE_DISCOVERY_SOURCE,
                        },
                    }
                )

        if lookup_failed_count:
            self.logger.error(
                f"{self.log_prefix}: Failed to look up "
                f"{lookup_failed_count} application(s); share skipped "
                "for those."
            )

        # Round 2: create / update.
        if mutate_requests:
            def _report_share_batch(chunk_index, success_ids, fail_ids):
                message = (
                    f"{self.log_prefix}: Successfully shared data "
                    f"for {len(success_ids)} application(s) in "
                    f"batch {chunk_index}."
                )
                if fail_ids:
                    message += (
                        " Failed to share data for "
                        f"{len(fail_ids)} application(s)."
                    )
                self.logger.info(message)

            mutate_results = self._send_batch(
                mutate_requests, headers, instance_url,
                f"share data for {app_target}",
                "share-app-share",
                report_chunk=_report_share_batch,
            )
            round_failed, failed_sub_ids = self._collect_failed_mutations(
                mutate_results, sub_meta
            )
            failed.extend(round_failed)
            # Counted from the sub-request ids, not from round_failed:
            # one sub-request is one application, however many records
            # named it.
            shared_count = len(mutate_requests) - len(failed_sub_ids)
            if shared_count:
                self.logger.info(
                    f"{self.log_prefix}: Successfully shared data for "
                    f"{shared_count} application(s)."
                )
            if failed_sub_ids:
                self.logger.error(
                    f"{self.log_prefix}: Failed to share data for "
                    f"{len(failed_sub_ids)} application(s)."
                )
        return failed

    # ---- Shared batch outcome helpers --------------------------------

    def _collect_failed_mutations(
        self, results: Dict, sub_meta: Dict
    ) -> Tuple[List, Set[str]]:
        """Report the failures of a mutation round two ways.

        A sub-request is failed when it is unserviced (status None) or
        returns a non-2xx status.

        Returns:
            Tuple[List, Set[str]]: (failed_action_ids, failed_sub_ids).
                The list holds every action id merged onto a failed
                sub-request, since a sub-request shared by several
                actions fails all of them - that is what CE needs.
                The set holds the failed sub-request ids, which is what
                a log line counting real-world targets (users,
                applications) needs: one sub-request is one target,
                however many actions asked for it.
        """
        failed = []
        failed_sub_ids = set()
        for sub_id, (status, body) in results.items():
            if sub_id not in sub_meta:
                continue
            if status is None or status not in (200, 201, 204):
                failed.extend(sub_meta[sub_id]["action_ids"])
                failed_sub_ids.add(sub_id)
                reason = (
                    "the sub-request was not executed (unserviced)"
                    if status is None
                    else f"status code {status} was returned"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: A record action failed "
                        f"because {reason}."
                    ),
                    details=f"Batch sub-request response: {body}",
                    resolution=(
                        "Verify the record, tag, group or delegate "
                        "exists on ServiceNow and the configured user "
                        "has permission to modify it."
                    ),
                )
        return failed, failed_sub_ids

    def _execute_remove_round(
        self,
        lookup_requests: List,
        sub_meta: Dict,
        headers: Dict,
        instance_url: str,
        table_url: str,
        logger_msg: str,
        entity: str,
        report_chunk=None,
    ) -> Tuple[List, Set[str], Set[str], Set[str]]:
        """Run the find→delete rounds for a remove/untag action.

        A lookup that finds no row is a successful no-op (nothing to
        delete). Lookup failures and delete failures fail the action.

        Args:
            entity (str): Short label ("group", "role", "delegation"
                or "tag") folded into each batch call's
                batch_request_id.
            report_chunk: Passed through to the delete-phase batch
                call only - the lookup/check phase doesn't mutate
                anything, so there's nothing to report there.

        Returns:
            Tuple[List, Set[str], Set[str], Set[str]]:
                (failed_action_ids, removed_sub_ids, noop_sub_ids,
                failed_sub_ids). The three sets hold the original
                lookup_requests ids (not the internal delete ids),
                so a caller whose action fans out into several
                sub-requests per real-world target (e.g. Tag's
                comma-separated values) can map ids back to
                sub_meta and count distinct targets, not
                sub-requests.
        """
        failed = []
        noop_sub_ids = set()
        failed_sub_ids = set()
        lookup_results = self._send_batch(
            lookup_requests, headers, instance_url,
            f"checking {logger_msg} for removal",
            f"{entity}-remove-check",
        )
        delete_requests = []
        delete_meta: Dict[str, Dict] = {}
        counter = 0
        for req in lookup_requests:
            sub_id = req["id"]
            status, body = lookup_results.get(sub_id, (None, {}))
            action_ids = sub_meta[sub_id]["action_ids"]
            if status is None or status not in (200, 201):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to check "
                        f"{logger_msg} for removal."
                    ),
                    details=f"Batch sub-request response: {body}",
                    resolution=(
                        "Verify the ServiceNow instance is reachable and "
                        "the configured user can read the target table."
                    ),
                )
                failed.extend(action_ids)
                failed_sub_ids.add(sub_id)
                continue
            rows = body.get("result", []) or []
            if not rows:
                noop_sub_ids.add(sub_id)
                continue
            for row in rows:
                row_sys_id = row.get("sys_id")
                if not row_sys_id:
                    continue
                counter += 1
                del_id = f"d{counter}"
                delete_meta[del_id] = {
                    "action_ids": action_ids,
                    "sub_id": sub_id,
                }
                delete_requests.append(
                    {
                        "id": del_id,
                        "method": "DELETE",
                        "url": f"{table_url}/{row_sys_id}",
                    }
                )
        removed_sub_ids = set()
        if delete_requests:
            def _translate_chunk(chunk_index, del_success, del_fail):
                if report_chunk is None:
                    return
                success_ids = {
                    delete_meta[did]["sub_id"] for did in del_success
                    if did in delete_meta
                }
                # A set, like success_ids: a target with several matching
                # rows fans out into several deletes, and the caller
                # counts targets, not rows.
                fail_ids = {
                    delete_meta[did]["sub_id"] for did in del_fail
                    if did in delete_meta
                }
                report_chunk(chunk_index, success_ids, fail_ids)

            delete_results = self._send_batch(
                delete_requests, headers, instance_url,
                f"removing {logger_msg}",
                f"{entity}-remove",
                report_chunk=_translate_chunk,
            )
            # The second element is discarded: it holds *delete* ids,
            # while failed_sub_ids below is built from the lookup
            # sub-request ids the caller counts targets by.
            round_failed, _ = self._collect_failed_mutations(
                delete_results, delete_meta
            )
            failed.extend(round_failed)
            for del_id, (status, _body) in delete_results.items():
                del_meta = delete_meta.get(del_id)
                if del_meta is None:
                    continue
                if status in (200, 201, 204):
                    removed_sub_ids.add(del_meta["sub_id"])
                else:
                    failed_sub_ids.add(del_meta["sub_id"])
        return failed, removed_sub_ids, noop_sub_ids, failed_sub_ids

    def revert_action(self, action: Action):
        """Profile-style actions are not revertible.

        Args:
            action (Action): Action to revert.

        Raises:
            NotImplementedError: Always.
        """
        raise NotImplementedError(
            "Revert is not supported for ServiceNow actions."
        )

    # ------------------------------------------------------------------
    # validate
    # ------------------------------------------------------------------

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidationResult: Validation result with success flag and
                message.
        """
        # Validate Instance URL
        instance_url = configuration.get("instance_url", "")
        if isinstance(instance_url, str):
            instance_url = instance_url.strip().strip("/")
        if failure := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Instance URL",
            field_value=instance_url,
            field_type=str,
            custom_validation_func=self._validate_url,
            custom_error_message=INVALID_URL_ERROR_MESSAGE,
        ):
            return failure

        # Validate Username
        username = configuration.get("username", "")
        if isinstance(username, str):
            username = username.strip()
        if failure := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Username",
            field_value=username,
            field_type=str,
        ):
            return failure

        # Validate Password
        password = configuration.get("password", "")
        if failure := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Password",
            field_value=password,
            field_type=str,
        ):
            return failure

        # Validate Pull Additional Details. This one is not routed
        # through
        # _validate_parameters: it is an optional multichoice, so an
        # empty selection is valid (it just pulls no additional data)
        # and every selected value has to be checked, not just one.
        pull_options = configuration.get("pull_options", PULL_OPTIONS_VALUES)
        if not isinstance(pull_options, list):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name="Pull Additional Details",
                parameter_type=CONFIGURATION,
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    "Select the additional data to pull from the "
                    "'Pull Additional Details' dropdown."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        invalid_options = [
            str(option)
            for option in pull_options
            if option not in PULL_OPTIONS_VALUES
        ]
        if invalid_options:
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name="Pull Additional Details",
                parameter_type=CONFIGURATION,
            ) + INVALID_VALUE_ERROR_MESSAGE.format(
                allowed_values=PULL_OPTIONS_VALUES
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                details=(
                    "Unsupported Pull Additional Details value(s): "
                    f"{', '.join(invalid_options)}."
                ),
                resolution="Provide a value from the allowed values.",
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate connectivity to the ServiceNow server.
        return self._validate_connectivity(
            instance_url=instance_url,
            username=username,
            password=password,
        )

    def _validate_connectivity(
        self,
        instance_url: str,
        username: str,
        password: str,
    ) -> ValidationResult:
        """Validate connectivity and per-table access with ServiceNow.

        Sends a single Batch API call carrying one "first row" GET per
        table the plugin reads or writes, so a table the configured user
        cannot read is named during validation instead of surfacing
        later as a failed pull or action. The outer batch call still
        covers plain connectivity and credentials: an unreachable
        instance, a bad Instance URL or bad credentials fails the POST
        itself and is reported by the helper's validation wording.

        Args:
            instance_url (str): Instance URL.
            username (str): Instance username.
            password (str): Instance password.

        Returns:
            ValidationResult: Validation Result.
        """
        try:
            logger_msg = f"connectivity with {PLATFORM_NAME} server"
            self.logger.debug(f"{self.log_prefix}: Validating {logger_msg}.")
            headers = self.servicenow_helper.basic_auth(
                username=username, password=password
            )

            sub_tables = {}
            rest_requests = []
            for index, url_key in enumerate(VALIDATION_TABLE_KEYS, start=1):
                url_path = URLS[url_key]
                sub_id = f"table-{index}"
                sub_tables[sub_id] = url_path.rsplit("/", 1)[-1]
                rest_requests.append(
                    {
                        "id": sub_id,
                        "method": "GET",
                        "url": build_lookup_url(
                            url_path, "", "sys_id", 1
                        ),
                    }
                )
            results = self._send_batch(
                rest_requests=rest_requests,
                headers=headers,
                instance_url=instance_url,
                logger_msg=(
                    f"validating access to {len(rest_requests)} "
                    f"{PLATFORM_NAME} table(s)"
                ),
                batch_tag="validate-table-access",
                is_validation=True,
            )

            inaccessible = []
            unverified = []
            details = {}
            for sub_id, table in sub_tables.items():
                status, body = results.get(sub_id, (None, {}))
                if status is None:
                    unverified.append(table)
                    details[table] = "No response received for this table."
                elif status not in (200, 201):
                    inaccessible.append(table)
                    details[table] = f"Status code {status}, response: {body}"
            if inaccessible:
                err_msg = (
                    "Unable to read the following "
                    f"{PLATFORM_NAME} table(s): "
                    f"{', '.join(inaccessible)}. Verify permission for "
                    "the Username provided in the configuration "
                    "parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=json.dumps(details),
                    resolution=(
                        "Grant the configured user read access to the "
                        "listed table(s) on the ServiceNow instance, or "
                        "use a user that already has it."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
            if unverified:
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Access to "
                        f"{len(unverified)} {PLATFORM_NAME} table(s) "
                        "could not be verified as the batch request "
                        "returned no response for them. Expand log to "
                        "view the table names."
                    ),
                    details=json.dumps(details),
                )

            self.logger.debug(
                f"{self.log_prefix}: Successfully validated {logger_msg} "
                f"and access to {len(sub_tables) - len(unverified)} of "
                f"{len(sub_tables)} table(s)."
            )
            return ValidationResult(
                success=True,
                message=(
                    f"Validation successful for {MODULE_NAME} "
                    f"{self.plugin_name} plugin configuration."
                ),
            )
        except ServiceNowZTREPluginException as exp:
            return ValidationResult(success=False, message=f"{str(exp)}")
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

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True if URL is valid else False.
        """
        parsed_url = urlparse(url.strip())
        return bool(parsed_url.scheme and parsed_url.netloc)
