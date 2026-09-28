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

CRE Cisco ISE plugin.
"""

import hashlib
import os
import re
import ssl
import tempfile
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    HOST_ENTITY_NAME,
    CERTIFICATE_KEY,
    ERS_HEADERS,
    ERS_PAGE_SIZE,
    ERS_PASSWORD_KEY,
    ERS_PORT,
    ERS_SGMAPPING_ENDPOINT,
    ERS_SGT_ENDPOINT,
    ERS_SGT_NAME_FILTER_TEMPLATE,
    ERS_USERNAME_KEY,
    ISE_HOST_KEY,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    PXGRID_GET_SESSIONS_ENDPOINT,
    PXGRID_NODE_NAME_KEY,
    PXGRID_PASSWORD_KEY,
    PXGRID_PORT,
    PXGRID_REST_BASE_URL_KEY,
    PXGRID_SECRET_KEY,
    PXGRID_SGT_FILTER_TEMPLATE,
    PXGRID_STATE_ENABLED,
    SESSION_FIELD_MAPPING,
    SGT_IP_MAPPING_SOURCE,
    SGT_NAME_FILTER,
    SOURCE_ERS,
    SOURCE_LABEL_ERS,
    SOURCE_LABEL_PXGRID,
    SOURCE_PXGRID,
    SSL_CERT_FILE_KEY,
    SSL_CERT_HASH_KEY,
    SSL_VALIDATION_CUSTOM_CERT,
    SSL_VALIDATION_DISABLE,
    SSL_VALIDATION_MODE,
    SSL_VALIDATION_SYSTEM_DEFAULT,
    SUPPORTED_SOURCES,
    SUPPORTED_SSL_VALIDATION_MODES,
)
from .utils.helper import CiscoISEPluginException, CiscoISEPluginHelper


class CiscoISEPlugin(PluginBase):
    """Cisco ISE plugin implementation for Netskope CRE."""

    def __init__(self, name, *args, **kwargs):
        """Cisco ISE plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.cisco_ise_helper = CiscoISEPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )
        # Resolved by _resolve_ssl_verify() at the start of validate()/
        # fetch_records() and used in place of self.ssl_validation for
        # every ERS/pxGrid request - see _resolve_ssl_verify()'s
        # docstring for why this plugin has its own SSL validation
        # control independent of Cloud Exchange's own.
        self._plugin_ssl_verify: Union[bool, str] = True

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of (plugin_name, plugin_version).
        """
        try:
            manifest_json = CiscoISEPlugin.metadata
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

    def get_entities(self) -> List[Entity]:
        """Get available entities for Cisco ISE plugin.

        A single 'Hosts' entity: one record per IP address, merging
        the ERS static SGT-IP mapping list and the pxGrid live session
        directory (live session wins on a shared IP), with each tag
        resolved to both its name and its numeric value via the SGT
        dictionary.

        Returns:
            List[Entity]: List containing the 'Hosts' Entity.
        """
        return [
            Entity(
                name=HOST_ENTITY_NAME,
                fields=[
                    EntityField(
                        name="IP Address",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="MAC Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Security Group Tag",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Security Group Tag Value",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Secondary Security Groups",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Session State",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="User Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="AD User",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="NAS IP Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Authorization Profiles",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="MDM Compliant",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="MDM Disk Encrypted",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="MDM Jail Broken",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="MDM Pin Locked",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Last Seen",
                        type=EntityFieldType.DATETIME,
                    ),
                    EntityField(
                        name="Source",
                        type=EntityFieldType.STRING,
                    ),
                ],
            ),
        ]

    # Every Hosts field from get_entities() above except 'IP Address'
    # and 'Source', which every record-building method always sets
    # itself. Keep in sync with get_entities() by hand -
    # see _fill_missing_host_fields()'s docstring for why every one of
    # these must be explicitly present (real value or None) in every
    # record, rather than omitted when a source has nothing for it.
    OPTIONAL_HOST_FIELDS = [
        "MAC Address",
        "Security Group Tag",
        "Security Group Tag Value",
        "Secondary Security Groups",
        "Session State",
        "User Name",
        "AD User",
        "NAS IP Address",
        "Authorization Profiles",
        "MDM Compliant",
        "MDM Disk Encrypted",
        "MDM Jail Broken",
        "MDM Pin Locked",
        "Last Seen",
    ]

    def _fill_missing_host_fields(self, record: dict) -> dict:
        """Explicitly null every optional Hosts field this record's
        source didn't provide.

        Cloud Exchange's record store only overwrites fields present
        in the dict a plugin returns for a given IP - an omitted key
        leaves whatever value is already stored from a previous pull
        untouched, it does not clear it. Without this, a field
        populated while an IP was reported via one source (e.g.
        pxGrid's 'MAC Address', 'MDM Compliant') stays stuck at its
        last value forever once that IP starts being reported only by
        a source with no data for that field (e.g. IP SGT Static
        Mapping), even though the field genuinely has no current
        value anymore.

        Args:
            record (dict): Partially-built Hosts record.

        Returns:
            dict: The same dict, with every field in
                OPTIONAL_HOST_FIELDS present - either its real value
                or None.
        """
        for field_name in self.OPTIONAL_HOST_FIELDS:
            record.setdefault(field_name, None)
        return record

    def _get_pxgrid_node_name(self) -> str:
        """Derive the pxGrid client node name from this plugin
        configuration's own name.

        pxGrid registration requires an alphanumeric name (dashes,
        underscores, and periods also allowed), so any other
        character in the configuration name is replaced with a dash,
        then truncated to pxGrid's 100-character limit.

        This is deliberately derived rather than a separate editable
        configuration field: the plugin configuration's name can't be
        changed once set, which keeps the pxGrid node name - and the
        ISE-side account bootstrap_pxgrid()/create_account() register
        for it - stable for the configuration's lifetime, with no
        rename/mismatch case and no way for a user to edit it out from
        under an already-registered account.

        Returns:
            str: Sanitized pxGrid client node name.
        """
        return re.sub(r"[^A-Za-z0-9_.-]", "-", self.name)[:100]

    def get_dynamic_fields(self) -> List:
        """Return the 'Certificate' field only when 'SSL Validation' is
        set to 'Use Custom SSL Certificate'.

        A single field, not one per service: Cloud Exchange does not
        support dynamic field rendering driven by more than one
        configuration field, so visibility can only be gated on 'SSL
        Validation' here - not also on 'SGT-IP Mapping Source' the way
        an earlier revision (separate 'ERS Certificate'/'pxGrid
        Certificate' fields) attempted. Both the ERS certificate and
        the pxGrid certificate are unconditionally required whenever
        this field is shown, regardless of 'SGT-IP Mapping Source' -
        the user pastes both, concatenated one after another, in this
        same field - see
        _resolve_ssl_verify()/_split_pem_certificates().

        Returns:
            List: List containing the single 'Certificate' field
                dictionary, or an empty list when a custom certificate
                isn't in use.
        """
        if (
            self.configuration.get(SSL_VALIDATION_MODE)
            != SSL_VALIDATION_CUSTOM_CERT
        ):
            return []

        return [
            {
                "label": "Certificate",
                "key": CERTIFICATE_KEY,
                "type": "textarea",
                "default": "",
                "mandatory": True,
                "description": (
                    "Navigate to Administration > System > "
                    "Certificates > Certificate Management > System "
                    "Certificates in the ISE Admin Console, find the "
                    "certificate in the table whose 'Used By' column "
                    "shows 'Admin', and export it. Navigate to "
                    "Administration > System > Certificates > "
                    "Certificate Authority > Certificate Authority "
                    "Certificates, find the certificate in the table "
                    "whose name is like 'Certificate Services Root "
                    "CA - <ISE hostname>', and export it. Both "
                    "certificates are required - paste them one after "
                    "another in this same field. Paste only the "
                    "'-----BEGIN CERTIFICATE-----'/'-----END "
                    "CERTIFICATE-----' block(s) - remove any "
                    "additional text ISE or your browser may add "
                    "before or after them."
                ),
            },
        ]

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Returns:
            List[ActionWithoutParams]: List with the "No action" entry.
        """
        return [ActionWithoutParams(label="No action", value="generate")]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The action type.

        Returns:
            List: Empty list for all actions (Cisco ISE has no configurable
                action parameters).
        """
        return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Cisco ISE action configuration.

        Args:
            action (Action): The action type.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        action_value = action.value
        if action_value not in ["generate"]:
            resolution = (
                "Ensure that the action is selected from the supported "
                "action(s). Supported action(s): 'No action'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unsupported action "
                    f"'{action_value}' provided in the action configuration."
                ),
                resolution=resolution,
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        self.logger.debug(
            f"{self.log_prefix}: Successfully validated action "
            f"configuration for '{action.label}'."
        )
        return ValidationResult(
            success=True, message="Validation successful."
        )

    def execute_actions(self, actions: List[Action]):
        """Execute a batch of actions on the application.

        Cisco ISE only supports the 'No action' action, which performs
        no processing. Since a business rule can match thousands of
        records in a single run, this batch entry point logs one summary
        line for the whole batch instead of once per record.

        Args:
            actions (List[Action]): Actions to perform.

        Returns:
            None
        """
        if not actions:
            return
        first_action = actions[0]
        action_label = first_action.label
        if first_action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed "
                f"'{action_label}' action on {len(actions)} record(s). "
                f"Note: No processing will be done from plugin for the "
                f"'{action_label}' action."
            )
            return
        self.logger.error(
            message=(
                f"{self.log_prefix}: Unsupported action '{action_label}' "
                "provided in the action configuration."
            ),
        )

    def _extract_field_from_event(
        self,
        key: str,
        event: dict,
        default,
        transformation=None,
    ):
        """Extract a field from an event dict using dot-notation key.

        Args:
            key (str): Dot-separated key path (e.g., "a.b.c").
            event (dict): Source event dictionary.
            default: Default value if key not found.
            transformation (str, optional): Transformation to apply.
                "string" converts the value to str.

        Returns:
            Any: Extracted (and optionally transformed) value, or
                'default' - including when 'default' is None - if any
                segment of 'key' is missing or the path runs into a
                non-dict value before reaching the end.
        """
        value = event
        for k in key.split("."):
            if not isinstance(value, dict) or k not in value:
                return default
            value = value[k]
        if transformation == "string":
            return str(value)
        return value

    def _get_storage(self) -> dict:
        """Return this plugin's storage dict, or an empty dict if it
        hasn't been initialized yet (e.g. during validate()).

        Returns:
            dict: self.storage, or {} if it is None.
        """
        return self.storage if self.storage is not None else {}

    def add_field(self, fields_dict: dict, field_name: str, value):
        """Add a field to the extracted_fields dictionary safely.

        Empty dicts and lists are treated as falsy and not stored
        (MongoDB safety). Integers and floats (including 0) are always
        stored.

        Args:
            fields_dict (dict): Dictionary to update.
            field_name (str): Field name key.
            value: Value to store.
        """
        if isinstance(value, (int, float)):
            fields_dict[field_name] = value
            return
        if value:
            fields_dict[field_name] = value

    def _parse_datetime(self, value: str) -> Optional[datetime]:
        """Parse a Cisco ISE ISO-8601 timestamp into a datetime object.

        Args:
            value (str): Timestamp string, e.g.
                '2026-09-14T08:48:02.248Z'.

        Returns:
            Optional[datetime]: Parsed datetime, or None if the value
                could not be parsed.
        """
        if not value or not isinstance(value, str):
            return None
        for date_format in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(value, date_format)
            except ValueError:
                continue
        return None

    def _parse_sgt_filter(self, configuration: dict) -> List[str]:
        """Parse the comma-separated 'SGT Name Filter' configuration
        parameter into a list of trimmed, non-empty tag names.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            List[str]: Configured SGT names, or an empty list when the
                filter is not set (meaning: pull data for every tag).
        """
        raw = configuration.get(SGT_NAME_FILTER, "") or ""
        return [name.strip() for name in raw.split(",") if name.strip()]

    # -- SGT dictionary (always runs) -------------------------------------

    def _extract_sgt_dict_entry(self, resource: dict) -> dict:
        """Pull the raw id/name/value out of a merged SGT ERS resource.

        Args:
            resource (dict): Merged list+detail resource dict (see
                _fetch_ers_paginated's fetch_detail handling).

        Returns:
            dict: {'id', 'name', 'value'}, or empty dict if the
                resource has no id.
        """
        sgt_id = resource.get("id", "")
        if not sgt_id:
            return {}
        return {
            "id": sgt_id,
            "name": resource.get("name"),
            "value": resource.get("value"),
        }

    def _fetch_sgt_dictionary(
        self,
        ise_host: str,
        ers_username: str,
        ers_password: str,
    ) -> Tuple[Dict[str, Dict], Dict[str, float]]:
        """Fetch the SGT dictionary and index it two ways.

        This always runs on every pull: other ISE responses refer to
        a tag either by its internal id (ERS SGMapping's 'sgt' field)
        or by its bare name (pxGrid's 'ctsSecurityGroup'), and the
        'Security Group Tag Value' output field needs the tag's
        number resolved either way.

        Args:
            ise_host (str): ISE PAN base URL, including scheme (e.g.
                https://10.50.1.14).
            ers_username (str): ERS API username.
            ers_password (str): ERS API password.

        Returns:
            Tuple[Dict[str, Dict], Dict[str, float]]: (id_index,
                name_index) - id_index maps a tag's id to its
                {'name', 'value'}; name_index maps a tag's name to its
                numeric value.
        """
        entries = self._fetch_ers_paginated(
            ise_host=ise_host,
            ers_username=ers_username,
            ers_password=ers_password,
            endpoint_url_template=ERS_SGT_ENDPOINT,
            entity_name="SGT dictionary",
            record_extractor=self._extract_sgt_dict_entry,
            fetch_detail=True,
            detail_key="Sgt",
        )
        id_index: Dict[str, Dict] = {}
        name_index: Dict[str, float] = {}
        for entry in entries:
            sgt_id = entry.get("id")
            name = entry.get("name")
            value = entry.get("value")
            if sgt_id:
                id_index[sgt_id] = {"name": name, "value": value}
            if name and isinstance(value, (int, float)):
                name_index[name] = value
        return id_index, name_index

    # -- ERS static SGT-IP mapping ----------------------------------------

    def _extract_sgmapping_entry(self, resource: dict) -> dict:
        """Pull the raw id/hostIp/sgt out of a merged SGMapping resource.

        Args:
            resource (dict): Merged list+detail resource dict.

        Returns:
            dict: {'id', 'hostIp', 'sgt'}, or empty dict if the
                resource has no id.
        """
        mapping_id = resource.get("id", "")
        if not mapping_id:
            return {}
        return {
            "id": mapping_id,
            "hostIp": resource.get("hostIp"),
            "sgt": resource.get("sgt"),
        }

    def _fetch_ers_records(
        self,
        ise_host: str,
        ers_username: str,
        ers_password: str,
        tag_id_index: Dict[str, Dict],
        sgt_names: List[str],
    ) -> Dict[str, Dict]:
        """Fetch static SGT-to-IP mappings and build Hosts records.

        When 'SGT Name Filter' is configured, the ERS 'filter' query
        parameter only accepts a single tag at a time, so this makes
        one paginated pass per configured name and combines the
        results. With no filter configured, a single unfiltered pass
        fetches every mapping.

        Args:
            ise_host (str): ISE PAN base URL, including scheme (e.g.
                https://10.50.1.14).
            ers_username (str): ERS API username.
            ers_password (str): ERS API password.
            tag_id_index (Dict[str, Dict]): Tag id -> {'name', 'value'}
                from _fetch_sgt_dictionary().
            sgt_names (List[str]): Configured 'SGT Name Filter' values,
                or an empty list to fetch every mapping.

        Returns:
            Dict[str, Dict]: Hosts records keyed by bare IP address.
        """
        if sgt_names:
            mappings: List[dict] = []
            for sgt_name in sgt_names:
                mappings.extend(
                    self._fetch_ers_paginated(
                        ise_host=ise_host,
                        ers_username=ers_username,
                        ers_password=ers_password,
                        endpoint_url_template=ERS_SGMAPPING_ENDPOINT,
                        entity_name=f"SGMapping (SGT '{sgt_name}')",
                        record_extractor=self._extract_sgmapping_entry,
                        fetch_detail=True,
                        detail_key="SGMapping",
                        filter_param=ERS_SGT_NAME_FILTER_TEMPLATE.format(
                            sgt_name=sgt_name
                        ),
                    )
                )
        else:
            mappings = self._fetch_ers_paginated(
                ise_host=ise_host,
                ers_username=ers_username,
                ers_password=ers_password,
                endpoint_url_template=ERS_SGMAPPING_ENDPOINT,
                entity_name="SGMapping",
                record_extractor=self._extract_sgmapping_entry,
                fetch_detail=True,
                detail_key="SGMapping",
            )

        records: Dict[str, Dict] = {}
        skip_count = 0
        for mapping in mappings:
            ip_address = self.cisco_ise_helper.strip_cidr_suffix(
                mapping.get("hostIp")
            )
            if not ip_address:
                skip_count += 1
                continue
            tag_info = tag_id_index.get(mapping.get("sgt"), {})
            record = {
                "IP Address": ip_address,
                "Source": SOURCE_LABEL_ERS,
            }
            tag_name = tag_info.get("name")
            if tag_name:
                record["Security Group Tag"] = tag_name
            tag_value = tag_info.get("value")
            if isinstance(tag_value, (int, float)):
                record["Security Group Tag Value"] = tag_value
            records[ip_address] = self._fill_missing_host_fields(record)

        if skip_count:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} SGMapping "
                "record(s) with no host IP address."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(records)} "
            f"IP SGT Static Mapping record(s) from {PLATFORM_NAME}."
        )
        return records

    def _fetch_ers_resource(
        self,
        resource_url: str,
        resource_id: str,
        headers: dict,
        entity_name: str,
    ) -> Optional[dict]:
        """Fetch a single ERS resource by its detail URL.

        Args:
            resource_url (str): Full URL for the individual resource.
            resource_id (str): Resource ID (used for logging only).
            headers (dict): ERS authentication and content headers.
            entity_name (str): Entity name for log messages.

        Returns:
            Optional[dict]: The detail object (e.g., "SGMapping" or
                "Sgt" inner dict), or None if the fetch failed. None
                is distinct from an empty dict: it tells the caller
                this resource's detail fetch genuinely failed (API/
                network error), as opposed to ISE returning a detail
                object with no useful fields - the caller must not
                treat the two the same way, or a transient failure
                silently looks like "this resource has no data" (see
                _fetch_ers_paginated).
        """
        try:
            resp_json = self.cisco_ise_helper.api_helper(
                logger_msg=(
                    f"fetching {entity_name} detail for ID '{resource_id}'"
                ),
                url=resource_url,
                method="GET",
                headers=headers,
                verify=self._plugin_ssl_verify,
                proxies=self.proxy,
                is_handle_error_required=True,
                is_validation=False,
            )
            return resp_json
        except CiscoISEPluginException as exc:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Failed to fetch {entity_name} "
                    f"detail for ID '{resource_id}'. Error: {exc}"
                ),
                details=traceback.format_exc(),
            )
            return None
        except Exception as exc:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error fetching "
                    f"{entity_name} detail for ID '{resource_id}'. "
                    f"Error: {exc}"
                ),
                details=traceback.format_exc(),
            )
            return None

    def _fetch_ers_paginated(
        self,
        ise_host: str,
        ers_username: str,
        ers_password: str,
        endpoint_url_template: str,
        entity_name: str,
        record_extractor,
        fetch_detail: bool = False,
        detail_key: str = "",
        filter_param: Optional[str] = None,
    ) -> List[dict]:
        """Generic paginated ERS API fetch method.

        Iterates over pages of ERS results until all records are fetched.
        When fetch_detail is True, each list item's detail URL is fetched
        individually to retrieve fields not available in the list response.
        Logs page progress at each iteration.

        Args:
            ise_host (str): ISE PAN base URL, including scheme (e.g.
                https://10.50.1.14).
            ers_username (str): ERS API username.
            ers_password (str): ERS API password.
            endpoint_url_template (str): URL format string with
                {ise_host} and {port} placeholders.
            entity_name (str): Entity name for log messages.
            record_extractor (callable): Function that takes a raw resource
                dict and returns an extracted dict (or empty/None to skip).
            fetch_detail (bool): If True, fetch individual resource detail
                URL to get full field data. Defaults to False.
            detail_key (str): Top-level JSON key containing the detail
                object (e.g., "SGMapping", "Sgt"). Used when fetch_detail
                is True.
            filter_param (Optional[str]): ERS 'filter' query parameter
                value, e.g. 'sgtName.EQ.BU-Servers', to restrict results
                to a single Security Group Tag. Defaults to None (no
                filter - all results are fetched).

        Returns:
            List[dict]: All extracted records across all pages. When
                fetch_detail is True, a resource whose detail fetch
                failed is excluded here (not extracted from the bare
                list item) and logged as a distinct failure - see
                _fetch_ers_resource - so it's never miscounted as a
                successful fetch of incomplete data.

        Raises:
            CiscoISEPluginException: On API or parsing errors.
        """
        all_records = []
        page = 1
        total_skip_count = 0
        total_detail_fail_count = 0

        base_url = endpoint_url_template.format(
            ise_host=ise_host, port=ERS_PORT
        )
        auth_header = self.cisco_ise_helper.get_ers_auth_header(
            username=ers_username, password=ers_password
        )
        headers = dict(ERS_HEADERS)
        headers.update(auth_header)

        params_base = {"size": ERS_PAGE_SIZE}
        if filter_param:
            params_base["filter"] = filter_param

        while True:
            logger_msg = (
                f"{entity_name} records for page {page} "
                f"from {PLATFORM_NAME}"
            )
            self.logger.debug(
                f"{self.log_prefix}: Fetching {logger_msg}."
            )
            try:
                resp_json = self.cisco_ise_helper.api_helper(
                    logger_msg=f"fetching {logger_msg}",
                    url=base_url,
                    method="GET",
                    params={**params_base, "page": page},
                    headers=headers,
                    verify=self._plugin_ssl_verify,
                    proxies=self.proxy,
                    is_handle_error_required=True,
                    is_validation=False,
                )
            except CiscoISEPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    f"Unexpected error occurred while fetching {logger_msg}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                raise CiscoISEPluginException(err_msg)

            search_result = resp_json.get("SearchResult", {})
            if not search_result or not isinstance(search_result, dict):
                self.logger.debug(
                    f"{self.log_prefix}: Empty or invalid SearchResult "
                    f"in response for page {page}. Stopping pagination."
                )
                break

            resources = search_result.get("resources", [])

            if not resources or not isinstance(resources, list):
                self.logger.debug(
                    f"{self.log_prefix}: No resources in page {page} "
                    f"for {entity_name}. Stopping pagination."
                )
                break

            page_count = 0
            page_skip_count = 0
            page_detail_fail_count = 0
            for resource in resources:
                resource_id = resource.get("id", "")
                try:
                    if fetch_detail and detail_key:
                        # The list response contains a 'link.href' with
                        # the detail URL. Fall back to constructing it.
                        link_href = (
                            resource.get("link", {}).get("href", "")
                            or f"{base_url}/{resource_id}"
                        )
                        detail_resp = self._fetch_ers_resource(
                            resource_url=link_href,
                            resource_id=resource_id,
                            headers=headers,
                            entity_name=entity_name,
                        )
                        if detail_resp is None:
                            # The detail fetch itself failed (API/
                            # network error) - _fetch_ers_resource
                            # already logged the cause. Exclude this
                            # resource rather than extracting from the
                            # bare list item, which is missing the
                            # fields only the detail response carries
                            # and would otherwise be miscounted as a
                            # successful, if incomplete, fetch.
                            page_detail_fail_count += 1
                            continue
                        detail_obj = detail_resp.get(detail_key, {})
                        if detail_obj and isinstance(detail_obj, dict):
                            merged = dict(resource)
                            merged.update(detail_obj)
                            resource_data = merged
                        else:
                            resource_data = resource
                    else:
                        resource_data = resource

                    extracted = record_extractor(resource_data)
                    if extracted:
                        all_records.append(extracted)
                        page_count += 1
                    else:
                        page_skip_count += 1
                except Exception as err:
                    page_skip_count += 1
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Unable to extract fields "
                            f"from {entity_name} resource with ID "
                            f"'{resource_id}' in page {page}. Error: {err}"
                        ),
                        details=traceback.format_exc(),
                    )

            if page_skip_count > 0:
                self.logger.debug(
                    f"{self.log_prefix}: Skipped {page_skip_count} "
                    f"{entity_name} record(s) in page {page}."
                )
            if page_detail_fail_count > 0:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Data pull failed for "
                        f"{page_detail_fail_count} {entity_name} "
                        f"resource(s) in page {page}."
                    ),
                )

            total_skip_count += page_skip_count
            total_detail_fail_count += page_detail_fail_count
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{page_count} {entity_name} record(s) in page {page}. "
                f"Total records fetched: {len(all_records)}."
            )

            if len(resources) < ERS_PAGE_SIZE:
                break
            page += 1

        if total_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {total_skip_count} "
                f"{entity_name} record(s) because fields could not be "
                "extracted."
            )
        if total_detail_fail_count > 0:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Data pull failed for "
                    f"{total_detail_fail_count} {entity_name} "
                    "resource(s)."
                ),
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(all_records)} "
            f"{entity_name} record(s) from {PLATFORM_NAME}."
        )
        return all_records

    # -- pxGrid live sessions ---------------------------------------------

    def _build_pxgrid_host_records(
        self, session: dict, tag_name_index: Dict[str, float]
    ) -> List[dict]:
        """Build one Hosts record per IP address in a pxGrid session.

        A session can report more than one IP address (e.g. IPv4 and
        IPv6 on the same endpoint); each one becomes its own Hosts
        record - sharing every other field from the session - so it
        can be merged and matched independently by IP address. A
        session with no IP address carries nothing this plugin can
        key a host record on, so it is skipped (returns an empty
        list). A session with no Security Group Tag is still
        included, with the tag fields left empty.

        Args:
            session (dict): A single session dict from getSessions.
            tag_name_index (Dict[str, float]): Tag name -> numeric
                value, from _fetch_sgt_dictionary(). pxGrid sessions
                only carry the tag's name, not its number.

        Returns:
            List[dict]: One Hosts record per IP address in the
                session, or an empty list when the session has no IP
                address.
        """
        ip_addresses = session.get("ipAddresses")
        if not ip_addresses or not isinstance(ip_addresses, list):
            return []

        base_record = {}
        for field_name, field_conf in SESSION_FIELD_MAPPING.items():
            key = field_conf.get("key", "")
            default = field_conf.get("default")
            self.add_field(
                base_record,
                field_name,
                self._extract_field_from_event(key, session, default),
            )

        security_group_tag = session.get("ctsSecurityGroup")
        if security_group_tag:
            base_record["Security Group Tag"] = security_group_tag
            tag_value = tag_name_index.get(security_group_tag)
            if isinstance(tag_value, (int, float)):
                base_record["Security Group Tag Value"] = tag_value

        self.add_field(
            base_record,
            "Secondary Security Groups",
            session.get("ctsSecondarySecurityGroups") or [],
        )
        self.add_field(
            base_record,
            "Authorization Profiles",
            session.get("selectedAuthzProfiles") or [],
        )

        user_name = session.get("userName") or session.get(
            "adNormalizedUser"
        )
        self.add_field(base_record, "User Name", user_name)
        self.add_field(
            base_record, "AD User", session.get("adNormalizedUser")
        )

        # MDM posture fields are only meaningful once the endpoint has
        # actually enrolled with an MDM - when mdmRegistered is falsy,
        # leave them out of base_record here; _fill_missing_host_fields()
        # explicitly nulls them below, clearing any stale values from
        # a previous pull rather than just not adding new ones.
        # Declared as STRING fields, so the raw booleans are stringified.
        if session.get("mdmRegistered"):
            for field_name, key in (
                ("MDM Compliant", "mdmCompliant"),
                ("MDM Disk Encrypted", "mdmDiskEncrypted"),
                ("MDM Jail Broken", "mdmJailBroken"),
                ("MDM Pin Locked", "mdmPinLocked"),
            ):
                value = session.get(key)
                if value is not None:
                    self.add_field(base_record, field_name, str(value))

        last_seen = self._parse_datetime(session.get("timestamp"))
        if last_seen:
            base_record["Last Seen"] = last_seen

        base_record["Source"] = SOURCE_LABEL_PXGRID
        self._fill_missing_host_fields(base_record)

        records = []
        for ip_address in ip_addresses:
            record = dict(base_record)
            record["IP Address"] = ip_address
            records.append(record)
        return records

    def _fetch_sessions_data(
        self,
        ise_host: str,
        node_name: str,
        storage: dict,
        sgt_name: Optional[str] = None,
    ) -> List[dict]:
        """Call getSessions, retrying once with a refreshed secret on a
        401.

        Args:
            ise_host (str): ISE PAN base URL, including scheme (e.g.
                https://10.50.1.14).
            node_name (str): pxGrid client node name.
            storage (dict): Plugin storage holding 'pxgrid_secret'.
            sgt_name (Optional[str]): Security Group Tag name to
                restrict results to. Defaults to None (no filter -
                every active session is returned).

        Returns:
            List[dict]: List of raw session dictionaries.
        """
        # Called directly against ise_host:PXGRID_PORT, not the
        # 'restBaseUrl' discovered via ServiceLookup - see the comment
        # on PXGRID_GET_SESSIONS_ENDPOINT in utils/constants.py.
        get_sessions_url = PXGRID_GET_SESSIONS_ENDPOINT.format(
            ise_host=ise_host, port=PXGRID_PORT
        )
        # Always sent as the request's json= body, even when still {}
        # at request time (see below) - getSessions rejects a request
        # with no JSON body at all ("Required request body is
        # missing"), so this must never collapse to None.
        # No 'startTimestamp' - this plugin always fetches every
        # currently active session matching 'sgt_name' (a full
        # current-state snapshot), never a delta. An incremental
        # fetch can't distinguish "session ended" from "session still
        # active, no new activity" when it's absent from the
        # response, which silently let ERS's static-mapping data mask
        # real pxGrid data for a still-active session on the next
        # pull (see the 'Critical' merge-erasure finding in
        # mr-174-cisco-ise-cre-review.md).
        request_body = {}
        if sgt_name:
            request_body["filter"] = PXGRID_SGT_FILTER_TEMPLATE.format(
                sgt_name=sgt_name
            )
            logger_msg = (
                f"fetching live sessions for Security Group '{sgt_name}' "
                "from the pxGrid session directory"
            )
        else:
            logger_msg = (
                "fetching live sessions from the pxGrid session directory"
            )

        session_auth_header = self.cisco_ise_helper.get_pxgrid_auth_header(
            node_name=node_name, secret=storage.get(PXGRID_SECRET_KEY, "")
        )
        data_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        data_headers.update(session_auth_header)

        self.logger.debug(
            f"{self.log_prefix}: {logger_msg[0].upper()}{logger_msg[1:]}."
        )

        response = self.cisco_ise_helper.api_helper(
            logger_msg=logger_msg,
            url=get_sessions_url,
            method="POST",
            headers=data_headers,
            json=request_body,
            verify=self._plugin_ssl_verify,
            proxies=self.proxy,
            is_handle_error_required=False,
            is_validation=False,
        )

        if response.status_code == 401:
            self.logger.info(
                f"{self.log_prefix}: Received 401 from pxGrid session "
                "directory. Refreshing access secret and retrying."
            )
            new_secret = self.cisco_ise_helper.refresh_pxgrid_secret(
                ise_host=ise_host,
                storage=storage,
                verify=self._plugin_ssl_verify,
                proxies=self.proxy,
            )
            session_auth_header = (
                self.cisco_ise_helper.get_pxgrid_auth_header(
                    node_name=node_name, secret=new_secret
                )
            )
            data_headers.update(session_auth_header)
            response = self.cisco_ise_helper.api_helper(
                logger_msg=f"{logger_msg} (after secret refresh)",
                url=get_sessions_url,
                method="POST",
                headers=data_headers,
                json=request_body,
                verify=self._plugin_ssl_verify,
                proxies=self.proxy,
                is_handle_error_required=True,
                is_validation=False,
            )
        else:
            response = self.cisco_ise_helper.handle_error(
                resp=response,
                logger_msg=logger_msg,
                is_validation=False,
            )

        sessions = (
            response.get("sessions", [])
            if isinstance(response, dict)
            else []
        )
        return sessions

    def _fetch_pxgrid_records(
        self,
        ise_host: str,
        tag_name_index: Dict[str, float],
        sgt_names: List[str],
    ) -> Dict[str, Dict]:
        """Fetch live sessions via the pxGrid session directory.

        Returns an empty dict (not an error) when the pxGrid account
        for this configuration hasn't been set up via validate() yet,
        or isn't ENABLED yet - a scheduled pull skips pxGrid data for
        that run rather than blocking on ISE admin approval.

        pxGrid's 'filter' body field only accepts a single tag
        expression at a time, and getSessions has no pagination at
        all (confirmed against Cisco's own pxgrid-rest-ws API
        reference - no page/size/limit/offset field exists for this
        operation), so a single unfiltered call risks an enormous,
        unbounded response on a busy ISE instance (timeouts, a peer
        closing the connection early). This always calls getSessions
        once per Security Group Tag name instead - the configured
        'SGT Name Filter' names if set, otherwise every name already
        known from the SGT dictionary (tag_name_index, reused as-is
        from the ERS SGT dictionary walk rather than fetched again) -
        keeping each individual response bounded to one tag's worth
        of sessions. A session with no SGT assigned at all isn't
        matched by any per-tag filter and is therefore not included -
        a known, currently-accepted gap versus the old unfiltered
        call, which did include untagged sessions.

        Args:
            ise_host (str): ISE PAN base URL, including scheme (e.g.
                https://10.50.1.14).
            tag_name_index (Dict[str, float]): Tag name -> numeric
                value, from _fetch_sgt_dictionary().
            sgt_names (List[str]): Configured 'SGT Name Filter' values,
                or an empty list to fetch every known tag.

        Returns:
            Dict[str, Dict]: Hosts records keyed by IP address.
        """
        storage = self._get_storage()
        node_name = storage.get(PXGRID_NODE_NAME_KEY)
        password = storage.get(PXGRID_PASSWORD_KEY)
        if not node_name or not password:
            self.logger.info(
                f"{self.log_prefix}: the pxGrid account for this "
                "configuration has not been set up yet, so pxGrid data "
                "will be skipped for this run. Please save the "
                "configuration again to set it up."
            )
            return {}

        account_state = self.cisco_ise_helper.activate_account(
            ise_host=ise_host,
            node_name=node_name,
            password=password,
            verify=self._plugin_ssl_verify,
            proxies=self.proxy,
            is_validation=False,
        )
        if account_state != PXGRID_STATE_ENABLED:
            self.logger.info(
                f"{self.log_prefix}: the pxGrid account for node "
                f"'{node_name}' is not approved yet (status: "
                f"'{account_state}'), so pxGrid data will be skipped "
                "for this run. Please ask your Cisco ISE admin to "
                "approve this plugin's pxGrid account."
            )
            return {}

        # restBaseUrl itself isn't used to build the getSessions call
        # (see PXGRID_GET_SESSIONS_ENDPOINT); its presence just signals
        # that ServiceLookup + AccessSecret have already run once.
        if not storage.get(PXGRID_REST_BASE_URL_KEY) or not storage.get(
            PXGRID_SECRET_KEY
        ):
            self.cisco_ise_helper.discover_session_service(
                ise_host=ise_host,
                node_name=node_name,
                password=password,
                storage=storage,
                verify=self._plugin_ssl_verify,
                proxies=self.proxy,
                is_validation=False,
            )

        # Always fetched one tag at a time - see this method's
        # docstring for why. Fall back to every name already known
        # from the SGT dictionary when 'SGT Name Filter' isn't set;
        # if that dictionary is somehow empty too (no SGTs defined in
        # ISE at all), fall back further to a single unfiltered call
        # rather than silently fetching nothing.
        names_to_fetch = sgt_names or list(tag_name_index.keys())

        sessions: List[dict] = []
        if names_to_fetch:
            for sgt_name in names_to_fetch:
                sessions.extend(
                    self._fetch_sessions_data(
                        ise_host=ise_host,
                        node_name=node_name,
                        storage=storage,
                        sgt_name=sgt_name,
                    )
                )
        else:
            self.logger.info(
                f"{self.log_prefix}: No SGT names could be fetched "
                f"from the {PLATFORM_NAME} platform. Pulling all "
                "sessions data."
            )
            sessions = self._fetch_sessions_data(
                ise_host=ise_host, node_name=node_name, storage=storage
            )

        records: Dict[str, Dict] = {}
        skip_count = 0
        for session in sessions:
            session_records = self._build_pxgrid_host_records(
                session, tag_name_index
            )
            if not session_records:
                skip_count += 1
                continue
            for record in session_records:
                records[record["IP Address"]] = record

        if skip_count:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} session "
                "record(s) from the pxGrid session directory because "
                "they had no IP address."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(records)} "
            f"live session record(s) from the {PLATFORM_NAME} pxGrid "
            "session directory."
        )
        return records

    # -- merge --------------------------------------------------------------

    def merge_host_records(
        self, ers_records: Dict[str, Dict], pxgrid_records: Dict[str, Dict]
    ) -> List[Dict]:
        """Merge ERS and pxGrid records keyed by IP address.

        When both sources produced a record for the same IP address,
        the pxGrid record wins outright (full replacement, not a
        field-by-field merge), since it reflects a live session.

        Args:
            ers_records (Dict[str, Dict]): ERS records keyed by IP
                address.
            pxgrid_records (Dict[str, Dict]): pxGrid records keyed by
                IP address.

        Returns:
            List[Dict]: Merged list of Hosts records.
        """
        merged: Dict[str, Dict] = dict(ers_records)
        merged.update(pxgrid_records)
        return list(merged.values())

    # -- fetch_records --------------------------------------------------

    def fetch_records(self, entity: str) -> List:
        """Fetch 'Hosts' records from Cisco ISE.

        Always fetches the SGT dictionary, then fetches the ERS
        static SGT-IP mapping list and/or the pxGrid live session
        directory according to the configured 'SGT-IP Mapping
        Source', and merges both into one record per IP address.

        Args:
            entity (str): Entity name - must be 'Hosts'.

        Returns:
            List: List of Hosts record dicts.

        Raises:
            CiscoISEPluginException: On API errors or an unsupported
                entity.
        """
        if entity != HOST_ENTITY_NAME:
            err_msg = (
                f"Invalid entity '{entity}' provided. {PLATFORM_NAME} "
                f"plugin only supports the '{HOST_ENTITY_NAME}' entity."
            )
            resolution = f"Ensure that the entity is '{HOST_ENTITY_NAME}'."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            raise CiscoISEPluginException(err_msg)

        self.logger.debug(
            f"{self.log_prefix}: Fetching '{entity}' records from "
            f"{PLATFORM_NAME}."
        )

        ise_host, ers_username, ers_password = (
            self.cisco_ise_helper.get_config_params(self.configuration)
        )
        sources = self.configuration.get(SGT_IP_MAPPING_SOURCE, [])
        sgt_names = self._parse_sgt_filter(self.configuration)
        self._plugin_ssl_verify = self._resolve_ssl_verify(
            self.configuration
        )

        try:
            tag_id_index, tag_name_index = self._fetch_sgt_dictionary(
                ise_host=ise_host,
                ers_username=ers_username,
                ers_password=ers_password,
            )

            ers_records: Dict[str, Dict] = {}
            pxgrid_records: Dict[str, Dict] = {}
            if SOURCE_ERS in sources:
                ers_records = self._fetch_ers_records(
                    ise_host=ise_host,
                    ers_username=ers_username,
                    ers_password=ers_password,
                    tag_id_index=tag_id_index,
                    sgt_names=sgt_names,
                )
            if SOURCE_PXGRID in sources:
                pxgrid_records = self._fetch_pxgrid_records(
                    ise_host=ise_host,
                    tag_name_index=tag_name_index,
                    sgt_names=sgt_names,
                )

            records = self.merge_host_records(
                ers_records=ers_records, pxgrid_records=pxgrid_records
            )
        except CiscoISEPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while fetching '{entity}' "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise CiscoISEPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(records)} "
            f"{entity} record(s) from {PLATFORM_NAME}."
        )
        return records

    def update_records(
        self, entity: str, records: list
    ) -> list:
        """Update records (no-op for Cisco ISE plugin).

        Cisco ISE data is always fetched fresh from the API. No separate
        enrichment step is required.

        Args:
            entity (str): Entity name.
            records (list): Records to update.

        Returns:
            list: Empty list — no enrichment performed.
        """
        return []

    def _validate_url(self, url: str) -> bool:
        """Validate a URL using urlparse.

        Args:
            url (str): URL string to validate.

        Returns:
            bool: True if the URL has a valid scheme and netloc.
        """
        parsed_url = urlparse(url)
        return bool(parsed_url.scheme and parsed_url.netloc)

    def _split_pem_certificates(self, cert_value: str) -> List[str]:
        """Split a PEM string holding one or more concatenated
        certificates into individual single-certificate PEM blocks.

        `ssl.PEM_cert_to_DER_cert()` only accepts exactly one
        certificate per call, but a certificate chain (leaf +
        intermediate + root) concatenated into one field - the normal
        export format for a private-CA-issued certificate - is
        multiple blocks. This lets callers validate each block
        independently instead of rejecting the whole chain.

        Args:
            cert_value (str): One or more concatenated PEM
                certificates.

        Returns:
            List[str]: Each individual certificate block, with its
                own '-----BEGIN CERTIFICATE-----'/'-----END
                CERTIFICATE-----' markers restored.
        """
        delimiter = "-----END CERTIFICATE-----"
        return [
            f"{block.strip()}\n{delimiter}"
            for block in cert_value.split(delimiter)
            if block.strip()
        ]

    def _resolve_ssl_verify(self, configuration: dict) -> Union[bool, str]:
        """Resolve the effective 'verify' value for this plugin's ERS/
        pxGrid requests from the 'SSL Validation'/'Certificate'
        configuration fields.

        This is independent of Cloud Exchange's own per-configuration
        SSL validation checkbox: it lets a customer who cannot (or
        should not) turn that checkbox off keep SSL validation on
        while still trusting Cisco ISE's own certificates - typically
        self-signed - without needing infrastructure-level access to
        add them to the Cloud Exchange host's CA trust store.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            Union[bool, str]: False to skip validation ('Disable SSL
                Validation'), True to validate against the system's
                default trusted CA store ('Use System Defaults', or a
                fallback if 'Use Custom SSL Certificate' was selected
                with an empty certificate saved), or a filesystem path
                to a file holding the pasted certificate(s) to
                validate against instead ('Use Custom SSL
                Certificate') - see _get_or_create_ssl_cert_file() for
                how that file's lifecycle is managed.
        """
        mode = configuration.get(
            SSL_VALIDATION_MODE, SSL_VALIDATION_SYSTEM_DEFAULT
        )
        if mode == SSL_VALIDATION_DISABLE:
            return False

        if mode == SSL_VALIDATION_CUSTOM_CERT:
            certificate = configuration.get(CERTIFICATE_KEY, "")
            if isinstance(certificate, str):
                certificate = certificate.strip()
            if certificate:
                return self._get_or_create_ssl_cert_file(certificate)

        return True

    def _get_or_create_ssl_cert_file(self, certificate: str) -> str:
        """Return a filesystem path to a file holding 'certificate',
        writing it only once per distinct certificate value instead of
        on every validate()/fetch_records() call.

        The path (and a hash of the certificate content it holds) are
        cached in self.storage, which Cloud Exchange persists across
        pulls. A cached file is reused as-is as long as it still
        exists on disk and its hash matches the current 'Certificate'
        field value; otherwise (first use, the certificate was edited,
        or the file was lost - e.g. a host restart clearing /tmp) a
        new file is written and storage is updated. For an already
        saved, working configuration this file survives until
        cleanup() removes it on delete - but see validate()'s own
        cleanup of a freshly-written file when overall validation
        fails, which does remove a file this method just wrote.

        Sets self._cert_file_freshly_written to True when a new file
        was written this call, False when an existing cached file was
        reused - validate() uses this to know whether it's safe to
        remove the file on a failed validation attempt (only ever
        true for a file it just wrote itself, never a reused one that
        may still be in use by an already-working configuration).

        Args:
            certificate (str): PEM-encoded certificate content.

        Returns:
            str: Filesystem path to a file holding 'certificate'.
        """
        storage = self._get_storage()
        cert_hash = hashlib.sha256(certificate.encode()).hexdigest()

        cached_path = storage.get(SSL_CERT_FILE_KEY)
        if (
            cached_path
            and storage.get(SSL_CERT_HASH_KEY) == cert_hash
            and os.path.isfile(cached_path)
        ):
            self._cert_file_freshly_written = False
            return cached_path

        if cached_path and os.path.isfile(cached_path):
            # The certificate value changed since this file was
            # written - replace it rather than leaking the old one.
            try:
                os.remove(cached_path)
            except OSError as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unable to remove stale "
                        f"SSL certificate file '{cached_path}'. "
                        f"Error: {exp}"
                    ),
                )

        cert_file = tempfile.NamedTemporaryFile(
            mode="w", prefix="cre_cisco_ise_", suffix=".pem", delete=False
        )
        try:
            cert_file.write(certificate)
        finally:
            cert_file.close()

        storage[SSL_CERT_FILE_KEY] = cert_file.name
        storage[SSL_CERT_HASH_KEY] = cert_hash
        self._cert_file_freshly_written = True
        return cert_file.name

    def _remove_ssl_cert_file(self, context: str) -> None:
        """Remove the cached custom SSL certificate file (see
        _get_or_create_ssl_cert_file()) from disk and clear its
        storage keys.

        Args:
            context (str): Short description of why this is being
                removed, used only in the log message if removal
                fails (e.g. 'cleanup' or 'a failed validation
                attempt').
        """
        storage = self._get_storage()
        cert_path = storage.pop(SSL_CERT_FILE_KEY, None)
        storage.pop(SSL_CERT_HASH_KEY, None)
        if not cert_path:
            return
        if os.path.exists(cert_path):
            try:
                os.remove(cert_path)
            except OSError as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unable to remove SSL "
                        f"certificate file '{cert_path}' during "
                        f"{context}. Error: {exp}"
                    ),
                )

    def cleanup(self, action_type: str = "delete") -> None:
        """Remove the cached SSL certificate file (see
        _get_or_create_ssl_cert_file()) when this configuration is
        deleted.

        Called by Cloud Exchange on both configuration delete and
        disable; the file is only removed on delete, since a disabled
        configuration may be re-enabled and would otherwise just pay
        the (cheap, one-time) cost of writing it again.

        Args:
            action_type (str): 'delete' or 'disable'.
        """
        if action_type != "delete":
            raise NotImplementedError()
        self._remove_ssl_cert_file(context="cleanup")

    def _validate_connectivity(
        self,
        ise_host: str,
        ers_username: str,
        ers_password: str,
        pxgrid_node_name: str,
        sources: List[str],
        sgt_names: List[str],
    ) -> ValidationResult:
        """Validate connectivity with Cisco ISE ERS API and, when
        selected, pxGrid.

        ERS connectivity is always validated - the SGT dictionary
        lookup behind the ERS API always runs regardless of the
        selected source(s). When 'SGT Name Filter' is configured, each
        provided name is checked against that dictionary. The pxGrid
        AccountCreate/AccountActivate bootstrap (returning a clear
        failure if PENDING) only runs when 'Live Sessions' is selected.

        Args:
            ise_host (str): ISE PAN base URL, including scheme (e.g.
                https://10.50.1.14).
            ers_username (str): ERS API username.
            ers_password (str): ERS API password.
            pxgrid_node_name (str): pxGrid client node name.
            sources (List[str]): Selected SGT-IP Mapping Source values.
            sgt_names (List[str]): Configured 'SGT Name Filter' values,
                or an empty list when no filter is configured.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating ERS API connectivity with "
                f"{PLATFORM_NAME} at '{ise_host}'."
            )
            sgt_url = ERS_SGT_ENDPOINT.format(
                ise_host=ise_host, port=ERS_PORT
            )
            auth_header = self.cisco_ise_helper.get_ers_auth_header(
                username=ers_username, password=ers_password
            )
            headers = dict(ERS_HEADERS)
            headers.update(auth_header)

            self.cisco_ise_helper.api_helper(
                logger_msg=(
                    f"validating ERS connectivity with {PLATFORM_NAME}"
                ),
                url=sgt_url,
                method="GET",
                params={"page": 1, "size": 1},
                headers=headers,
                verify=self._plugin_ssl_verify,
                proxies=self.proxy,
                is_handle_error_required=True,
                is_validation=True,
            )
            self.logger.info(
                f"{self.log_prefix}: ERS API connectivity validated "
                f"successfully."
            )

            if sgt_names:
                self.logger.debug(
                    f"{self.log_prefix}: Validating {len(sgt_names)} "
                    "'SGT Name Filter' value(s) against the ERS SGT "
                    "dictionary."
                )
                tag_id_index, _ = self._fetch_sgt_dictionary(
                    ise_host=ise_host,
                    ers_username=ers_username,
                    ers_password=ers_password,
                )
                known_names = {
                    info.get("name")
                    for info in tag_id_index.values()
                    if info.get("name")
                }
                unknown_names = [
                    name for name in sgt_names if name not in known_names
                ]
                if unknown_names:
                    err_msg = (
                        "'SGT Name Filter' contains unknown Security "
                        f"Group Tag name(s): {', '.join(unknown_names)}."
                    )
                    resolution = (
                        "Please check the SGT names against "
                        "Administration > Policy Elements > Results > "
                        "TrustSec > Security Groups in the Cisco ISE "
                        "Admin Console, and correct the comma-separated "
                        "list."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=resolution,
                    )
                    return ValidationResult(success=False, message=err_msg)
                self.logger.info(
                    f"{self.log_prefix}: Successfully validated the "
                    "'SGT Name Filter' configuration."
                )

            if SOURCE_PXGRID in sources:
                self.logger.debug(
                    f"{self.log_prefix}: Validating pxGrid bootstrap for "
                    f"node '{pxgrid_node_name}'."
                )
                storage = self._get_storage()
                bootstrap_result = self.cisco_ise_helper.bootstrap_pxgrid(
                    ise_host=ise_host,
                    configured_node_name=pxgrid_node_name,
                    storage=storage,
                    verify=self._plugin_ssl_verify,
                    proxies=self.proxy,
                    is_validation=True,
                )
                if bootstrap_result is None:
                    # Already logged by bootstrap_pxgrid() at info level -
                    # nothing further to log here for the
                    # pending-approval case.
                    pass
                else:
                    self.logger.debug(
                        f"{self.log_prefix}: Successfully validated "
                        f"pxGrid client '{pxgrid_node_name}'."
                    )

            success_msg = (
                "Successfully validated connectivity with "
                f"{PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {success_msg}")
            return ValidationResult(success=True, message=success_msg)

        except CiscoISEPluginException as exp:
            return ValidationResult(
                success=False, message=str(exp)
            )
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

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the Cisco ISE plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        validation_msg = "Validation error occurred."

        # --- Validate ISE Host ---
        # Expected to already include its 'https://' scheme (see
        # manifest.json) - nothing in this plugin adds one.
        ise_host = configuration.get(ISE_HOST_KEY, "").strip().strip("/")
        if not ise_host:
            err_msg = (
                "'ISE Primary Admin Node Base URL' is a required "
                "configuration parameter."
            )
            resolution = (
                "Provide the base URL of the Cisco ISE Primary "
                "Administration Node, including the 'https://' scheme "
                "(e.g. https://10.50.1.14), in the configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_msg} {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        if not self._validate_url(ise_host):
            err_msg = (
                "Invalid value provided for 'ISE Primary Admin Node "
                "Base URL'. Please provide a valid base URL including "
                "the 'https://' scheme (e.g., https://10.50.1.14 or "
                "https://ise.example.com)."
            )
            resolution = (
                "Ensure the ISE Primary Admin Node Base URL includes "
                "the 'https://' scheme and has no trailing slash."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_msg} {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        # --- Validate SGT-IP Mapping Source ---
        sources = configuration.get(SGT_IP_MAPPING_SOURCE, [])
        if not sources or not isinstance(sources, list):
            err_msg = (
                "'SGT-IP Mapping Source' is a required configuration "
                "parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_msg} {err_msg}",
                resolution=(
                    "Please select at least one SGT-IP Mapping Source."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        invalid_sources = [
            source for source in sources if source not in SUPPORTED_SOURCES
        ]
        if invalid_sources:
            err_msg = (
                "Invalid value(s) provided for 'SGT-IP Mapping Source'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_msg} {err_msg}",
                resolution=(
                    "Please select values only from 'Live Sessions' and "
                    "'IP SGT Static Mapping'."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # --- Validate ERS Username/Password (always required - the SGT
        # dictionary lookup always runs, regardless of which source is
        # selected) ---
        ers_username = configuration.get(ERS_USERNAME_KEY, "").strip()
        if not ers_username:
            err_msg = (
                "'ERS Username' is a required configuration parameter."
            )
            resolution = (
                "Provide the ERS API username. The account must be in "
                "the ERS-Admin or ERS-Operator group."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_msg} {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        ers_password = configuration.get(ERS_PASSWORD_KEY)
        if not ers_password:
            err_msg = (
                "'ERS Password' is a required configuration parameter."
            )
            resolution = (
                "Provide the ERS API password for the configured "
                "ERS Username."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_msg} {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        # --- pxGrid Node Name is derived from this plugin
        # configuration's own name, not a user-provided parameter ---
        pxgrid_node_name = self._get_pxgrid_node_name()

        # --- Validate SSL Validation mode / Certificate ---
        ssl_validation_mode = configuration.get(
            SSL_VALIDATION_MODE, SSL_VALIDATION_SYSTEM_DEFAULT
        )
        if ssl_validation_mode not in SUPPORTED_SSL_VALIDATION_MODES:
            err_msg = "Invalid value provided for 'SSL Validation'."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_msg} {err_msg}",
                resolution=(
                    "Please select one of 'Disable SSL Validation', "
                    "'Use System Defaults', or 'Use Custom SSL "
                    "Certificate'."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if ssl_validation_mode == SSL_VALIDATION_CUSTOM_CERT:
            # A single 'Certificate' field, not one per service - see
            # get_dynamic_fields()'s docstring for why. Always
            # required in this mode: the ERS SGT dictionary lookup
            # always runs, and if 'Live Sessions' is also selected the
            # user is expected to have appended the pxGrid certificate
            # into this same field.
            cert_value = configuration.get(CERTIFICATE_KEY, "")
            if isinstance(cert_value, str):
                cert_value = cert_value.strip()

            if not cert_value:
                err_msg = (
                    "'Certificate' is a required configuration "
                    "parameter when 'SSL Validation' is set to "
                    "'Use Custom SSL Certificate'."
                )
                resolution = (
                    "Paste ISE's PEM-encoded certificate(s) into the "
                    "'Certificate' field, or choose a different "
                    "'SSL Validation' option."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_msg} "
                        f"{err_msg}"
                    ),
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)

            for pem_block in self._split_pem_certificates(cert_value):
                try:
                    ssl.PEM_cert_to_DER_cert(pem_block)
                except (ValueError, ssl.SSLError) as exp:
                    err_msg = (
                        "Invalid value provided for 'Certificate'. "
                        "Every certificate in the field must be a "
                        "valid PEM-encoded X.509 certificate."
                    )
                    resolution = (
                        "Paste only the '-----BEGIN CERTIFICATE-----' "
                        "through '-----END CERTIFICATE-----' block(s) "
                        "for one or more full PEM-encoded "
                        "certificates. Remove any other text before "
                        "the first '-----BEGIN CERTIFICATE-----' or "
                        "after the last '-----END CERTIFICATE-----' "
                        "line - e.g. a certificate details dump some "
                        "export tools append is not part of the "
                        "certificate and is not accepted here."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {validation_msg} "
                            f"{err_msg} Error: {exp}"
                        ),
                        resolution=resolution,
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )

        # --- Validate SGT Name Filter format ---
        # A comma-separated list must not contain empty entries (e.g.
        # a double comma, or a leading/trailing comma) - each segment
        # is expected to be a real Security Group Tag name.
        # Leading/trailing whitespace around a name is fine and is
        # trimmed by _parse_sgt_filter(); an empty segment is not.
        raw_sgt_name_filter = configuration.get(SGT_NAME_FILTER, "") or ""
        if raw_sgt_name_filter and not raw_sgt_name_filter.strip():
            # Non-empty but entirely whitespace (e.g. a single typed
            # space) - distinct from a genuinely empty field, which
            # is the valid "pull every tag" case handled below.
            err_msg = (
                "Invalid value provided for 'SGT Name Filter'. The "
                "field must not contain only whitespace."
            )
            resolution = (
                "Provide a comma-separated list of Security Group "
                "Tag names, or leave the field completely empty to "
                "pull data for every Security Group Tag."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_msg} {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        if raw_sgt_name_filter.strip():
            sgt_name_segments = raw_sgt_name_filter.split(",")
            if any(not segment.strip() for segment in sgt_name_segments):
                err_msg = (
                    "Invalid value provided for 'SGT Name Filter'. "
                    "The comma-separated list must not contain empty "
                    "Security Group Tag name(s)."
                )
                resolution = (
                    "Remove any empty entries between, before, or "
                    "after the commas (e.g. use 'BU-Servers, "
                    "BU-Printers', not 'BU-Servers,,BU-Printers' or a "
                    "trailing comma), or leave the field empty to "
                    "pull every tag."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_msg} {err_msg}"
                    ),
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)

        # --- Validate connectivity (ERS always, pxGrid when selected,
        # SGT Name Filter names checked against the ERS SGT dictionary) ---
        sgt_names = self._parse_sgt_filter(configuration)
        self._cert_file_freshly_written = False
        self._plugin_ssl_verify = self._resolve_ssl_verify(configuration)
        result = self._validate_connectivity(
            ise_host=ise_host,
            ers_username=ers_username,
            ers_password=ers_password,
            pxgrid_node_name=pxgrid_node_name,
            sources=sources,
            sgt_names=sgt_names,
        )
        if not result.success and self._cert_file_freshly_written:
            # A file _get_or_create_ssl_cert_file() wrote during this
            # exact validate() call - not one reused from a prior,
            # still-working configuration - has nothing to ever clean
            # it up if this attempt fails and is abandoned: cleanup()
            # only runs on a saved configuration's disable/delete,
            # which never happens for a configuration that never
            # successfully saves. Left alone, such files accumulate in
            # /tmp until the Cloud Exchange host is restarted.
            self._remove_ssl_cert_file(context="a failed validation attempt")
        return result
