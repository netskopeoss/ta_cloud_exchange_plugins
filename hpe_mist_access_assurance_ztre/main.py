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

CRE HPE Mist Plugin main module.
"""

import json
import traceback
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    ACTION,
    ACTION_ADD_DEVICES_TO_NAC,
    ACTION_ADD_REMOVE_LABEL,
    ACTION_DELETE_DEVICE_FROM_NAC,
    ACTION_GENERATE,
    BASE_URL_DYNAMIC_FIELDS,
    CONFIGURATION,
    DEFAULT_LABEL_ACTION,
    DEFAULT_LABEL_OPERATION,
    DEVICES_ENTITY,
    EMPTY_CSV_ERROR_MESSAGE,
    EMPTY_ERROR_MESSAGE,
    ENTITY_FIELD_DESCRIPTIONS,
    ENTITY_FIELD_TYPE_OVERRIDES,
    FETCH_ACCESS_POINTS_CHOICES,
    FETCH_ACCESS_POINTS_NO,
    FETCH_LABELS_CHOICES,
    FETCH_LABELS_DYNAMIC_FIELDS,
    FIELD_MAPPING,
    INVALID_LABEL_NAME_LENGTH_ERROR_MESSAGE,
    INVALID_URL_ERROR_MESSAGE,
    INVALID_VALUE_ERROR_MESSAGE,
    LABEL_ACTION_ADD,
    LABEL_ACTION_CHOICES,
    LABEL_ACTION_REMOVE,
    LABEL_DEVICE_BATCH_SIZE,
    LABEL_NAME_CHARACTER_LIMIT,
    LABEL_OPERATION_CHOICES,
    LABEL_OPERATION_IN,
    LABEL_OPERATION_NOT_IN,
    LABELS_FIELD,
    MODULE_NAME,
    NAC_ACTIONS,
    NAC_BASE_URL_KEY,
    NAC_CLIENT_SECRET_KEY,
    NAC_CONFIG_FIELDS,
    NAC_CONFIG_INCOMPLETE_ERROR_MESSAGE,
    NAC_DEVICE_BATCH_SIZE,
    NAC_DEVICE_UUID_FIELD,
    NAC_ETHER_TYPE_CHOICES,
    NAC_ETHER_TYPE_FIELD,
    NAC_ETHER_TYPE_WIRED,
    NAC_ETHER_TYPE_WIRELESS,
    NAC_LABELS_FIELD,
    NAC_MAC_ADDRESSES_FIELD,
    ORG_ID_DYNAMIC_FIELDS,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    SELF_ENDPOINT,
    SITE_ID_FIELD,
    SITE_NAME_DYNAMIC_FIELDS,
    SOURCE_FIELD_ERROR_MESSAGE,
    STATIC_FIELD_ERROR_MESSAGE,
    STATUS_FIELD,
    SUPPORTED_ACTIONS,
    SUPPORTED_ENTITIES,
    TOKEN_AUTH_DYNAMIC_FIELDS,
    TYPE_ERROR_MESSAGE,
    UNIQUE_ID_FIELD,
    VALIDATION_ERROR_MESSAGE,
    WHITESPACE_ONLY_ERROR_MESSAGE,
)
from .utils.exceptions import HPEMistAccessAssurancePluginException
from .utils.helper import HPEMistAccessAssurancePluginHelper


class HPEMistAccessAssurancePlugin(PluginBase):
    """CRE HPE Mist plugin implementation."""

    def __init__(self, name, *args, **kwargs):
        """Initialize the HPE Mist plugin.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.hpe_mist_helper = HPEMistAccessAssurancePluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
            configuration=self.configuration,
        )
        # minimum_version (6.0.0, required for get_dynamic_fields()) is
        # always > 5.1.2, so execute_actions()/ActionResult with
        # failed_action_ids is always available, and self.logger.error()
        # natively accepts a 'resolution' kwarg with no compatibility
        # shim needed.
        self.provide_action_id = True

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from the manifest.

        Returns:
            Tuple[str, str]: Plugin's name and version fetched from the
            manifest, falling back to the constants on failure.
        """
        try:
            manifest_json = HPEMistAccessAssurancePlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _get_storage(self) -> Dict:
        """Return the plugin storage dict, used for the NAC token cache.

        Creates the real dict first when self.storage is unset, so a
        token written into the returned dict actually persists (a
        throwaway {} would silently lose it).

        Returns:
            Dict: The plugin storage dictionary.
        """
        if self.storage is None:
            self.storage = {}
        return self.storage

    # ------------------------------------------------------------------ #
    # Dynamic configuration
    # ------------------------------------------------------------------ #
    def get_dynamic_fields(self) -> List[Dict]:
        """Return configuration fields revealed by trigger parameters.

        manifest.json declares exactly ONE has_api_call trigger —
        'Fetch Access Points' (manifest/config key 'fetch_access_points')
        — so CE renders this method's entire return as one block
        directly after it, fully replacing the previous render (not
        appending) every time the trigger changes. When 'Fetch Access
        Points' is FETCH_ACCESS_POINTS_NO ("No", the default), this
        returns an empty list — none of the Mist connection fields are
        relevant since the Device (Access Point) pull is skipped
        entirely. Otherwise (FETCH_ACCESS_POINTS_YES), the Token
        Authentication credential field (API Token) is included, along
        with Base URL (rendered first), Organization ID, Site Names,
        and Fetch Labels — all plain, ALWAYS-included entries, never
        conditionally hidden. Site Names has no separate visibility
        toggle at all: it is optional, and an empty value simply means
        "fetch Devices from every Site" (enforced in fetch_records(),
        not via visibility) — there is no "Fetch From Particular Site"
        field to gate it on. The five NAC fields are NOT part of this
        dynamic block: they are declared as plain static fields in
        manifest.json (before Base URL), so they render by default
        independently of the trigger; their real requirement is
        enforced in validate() (all five when Fetch Access Points is
        'No', otherwise all-or-nothing once any one is filled in)
        and in validate_action() (all five before either NAC action
        may be saved). As with the trigger itself,
        nothing returned here may carry 'has_api_call' of its own — see
        the long comment in constants.py above "Dynamic configuration
        fields" for the two failure modes (recursion crash, duplicate
        fields) that ruled out every attempt at a second reactive
        trigger.

        Returns:
            List[Dict]: Dynamic field definitions for the current
            configuration, in display order.
        """
        configuration = self.configuration or {}
        fetch_access_points = (
            configuration.get("fetch_access_points") or ""
        ).strip()
        if fetch_access_points == FETCH_ACCESS_POINTS_NO:
            return []
        return (
            BASE_URL_DYNAMIC_FIELDS
            + TOKEN_AUTH_DYNAMIC_FIELDS
            + ORG_ID_DYNAMIC_FIELDS
            + SITE_NAME_DYNAMIC_FIELDS
            + FETCH_LABELS_DYNAMIC_FIELDS
        )

    # ------------------------------------------------------------------ #
    # Entities
    # ------------------------------------------------------------------ #
    def get_entities(self) -> List[Entity]:
        """Get available entities.

        Returns:
            List[Entity]: Single 'Devices' entity, with one field per
            FIELD_MAPPING key plus the derived 'Labels' and 'Status'
            fields. 'Unique ID' and 'Site ID' are required - 'Site ID'
            is what several actions (e.g. Update Device Notes and
            Tags) resolve from the acted-on record itself. No
            'Netskope Normalized Score' field is added since Score
            Mapping is Not Applicable for this plugin.
        """
        fields = []
        for field_name in FIELD_MAPPING:
            fields.append(
                EntityField(
                    name=field_name,
                    type=ENTITY_FIELD_TYPE_OVERRIDES.get(
                        field_name, EntityFieldType.STRING
                    ),
                    required=(
                        field_name in (UNIQUE_ID_FIELD, SITE_ID_FIELD)
                    ),
                    description=ENTITY_FIELD_DESCRIPTIONS.get(
                        field_name, ""
                    ),
                )
            )
        fields.append(
            EntityField(
                name=LABELS_FIELD,
                type=EntityFieldType.LIST,
                description=ENTITY_FIELD_DESCRIPTIONS.get(
                    LABELS_FIELD, ""
                ),
            )
        )
        fields.append(
            EntityField(
                name=STATUS_FIELD,
                type=EntityFieldType.STRING,
                description=ENTITY_FIELD_DESCRIPTIONS.get(
                    STATUS_FIELD, ""
                ),
            )
        )
        return [Entity(name=DEVICES_ENTITY, fields=fields)]

    # ------------------------------------------------------------------ #
    # fetch_records
    # ------------------------------------------------------------------ #
    def _validate_entity(self, entity: str) -> None:
        """Raise when the requested entity is not supported.

        Args:
            entity (str): Entity name requested by the platform.

        Raises:
            HPEMistAccessAssurancePluginException: When entity is unsupported.
        """
        if entity.lower() != DEVICES_ENTITY.lower():
            err_msg = (
                f"Error occurred, invalid entity '{entity}' "
                f"provided. Supported entities are: "
                f"{', '.join(SUPPORTED_ENTITIES)}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the entity is one of "
                    f"{', '.join(SUPPORTED_ENTITIES)}."
                ),
            )
            raise HPEMistAccessAssurancePluginException(err_msg)

    def _resolve_site_ids(
        self, config_params: Dict, headers: Dict
    ) -> Tuple[List[str], Dict[str, str]]:
        """Resolve the site_id list to pull devices from.

        Uses every Site under the org when no Site Names are
        configured; otherwise resolves the configured comma-separated
        Site Names to site_id via GET orgs/{org_id}/sites (see
        fetch_org_sites()/build_site_name_map()), dropping (not a hard
        failure, per the TDD) any INDIVIDUAL configured name not found
        under the organization. Invalid names are reported once, in
        aggregate (count + the actual list), in a single info log
        after resolution completes — not one log line per invalid
        name, since a per-name log would be noisy for a large
        configured list.
        If NONE of the configured Site Names match (every one was
        dropped), that is treated as a hard failure rather than a
        silent zero-record pull — a total mismatch is a clear
        misconfiguration (wrong Organization ID, stale/incorrect Site
        Names), not a partial typo the per-name tolerance is meant
        for. A name shared by more than one Site (Mist does not
        guarantee Site names are unique) resolves to ALL of them.

        Also returns the org-wide mac -> status map (a separate
        inventory/search pass — see fetch_device_status_map()), so the
        caller doesn't have to fetch it separately.

        Args:
            config_params (Dict): Extracted configuration parameters.
            headers (Dict): Request headers (including auth).

        Returns:
            Tuple[List[str], Dict[str, str]]: (resolved site_id
            values to pull devices from, mac -> status map).

        Raises:
            HPEMistAccessAssurancePluginException: When Site Names are
                configured and none of them were found.
        """
        base_url = config_params["base_url"]
        org_id = config_params["org_id"]
        org_sites = self.hpe_mist_helper.fetch_org_sites(
            base_url=base_url, org_id=org_id, headers=headers
        )
        device_status_map = (
            self.hpe_mist_helper.fetch_device_status_map(
                base_url=base_url, org_id=org_id, headers=headers
            )
        )
        all_site_ids = [
            site.get("id") for site in org_sites if site.get("id")
        ]
        if not (config_params.get("site_name") or "").strip():
            return all_site_ids, device_status_map

        name_to_ids = self.hpe_mist_helper.build_site_name_map(
            org_sites
        )
        configured_names = [
            name.strip()
            for name in (config_params.get("site_name") or "").split(",")
            if name.strip()
        ]
        resolved_ids: List[str] = []
        invalid_names = []
        for name in configured_names:
            site_ids_for_name = name_to_ids.get(name)
            if site_ids_for_name:
                resolved_ids.extend(site_ids_for_name)
            else:
                invalid_names.append(name)
        resolved_ids = list(dict.fromkeys(resolved_ids))
        # One aggregated summary instead of one log line per invalid
        # Site Name, since a per-name log would be excessive noise
        # for a large configured list.
        if invalid_names:
            self.logger.info(
                f"{self.log_prefix}: Resolved {len(resolved_ids)} "
                f"Site(s) from {len(configured_names)} configured "
                f"Site Name(s) to pull devices from. "
                f"{len(invalid_names)} configured Site Name(s) were "
                "not found under the configured Organization ID and "
                f"were skipped: {', '.join(invalid_names)}."
            )
        if configured_names and not resolved_ids:
            err_msg = (
                "Error occurred, none of the configured Site Names "
                f"({', '.join(configured_names)}) were found among "
                "the Sites under the configured Organization ID."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the Site Names provided in the "
                    "configuration parameters are correct and belong "
                    "to the configured Organization ID."
                ),
            )
            raise HPEMistAccessAssurancePluginException(err_msg)
        return resolved_ids, device_status_map

    def _transform_field_value(self, value, transformation: str):
        """Apply a FIELD_MAPPING transformation to a raw device value.

        Null values are always passed through as None (matching the
        TDD's nullable-passthrough fields such as map_id,
        evpn_scope, evpntopo_id, bundled_mac and deviceprofile_id);
        non-null empty strings (e.g. st_ip_base) are preserved as-is.

        Args:
            value: Raw value read from the device payload.
            transformation (str): One of "string", "integer",
                "boolean", "json_string", "list", "epoch_datetime".

        Returns:
            The transformed value.
        """
        if value is None:
            return None
        if transformation == "string":
            return str(value)
        if transformation == "integer":
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
        if transformation == "boolean":
            return self.hpe_mist_helper._to_boolean(value)
        if transformation == "json_string":
            return json.dumps(value)
        if transformation == "list":
            return value if isinstance(value, list) else []
        if transformation == "epoch_datetime":
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
            except (TypeError, ValueError, OSError, OverflowError):
                return None
        return value

    def _extract_device_fields(self, raw_device: Dict) -> Dict:
        """Map a raw Mist device payload to CE field names.

        Args:
            raw_device (Dict): Raw device record from the devices
                endpoint.

        Returns:
            Dict: Record keyed by CE field names (FIELD_MAPPING keys
            only; 'Labels' and 'Status' are both derived fields
            merged in separately by the caller, from different
            endpoints than this one).
        """
        record = {}
        for field_name, spec in FIELD_MAPPING.items():
            record[field_name] = self._transform_field_value(
                raw_device.get(spec["key"]), spec["transformation"]
            )
        return record

    def _fetch_devices_for_sites(
        self,
        site_ids: List[str],
        config_params: Dict,
        headers: Dict,
        device_status_map: Dict[str, str],
    ) -> List[Dict]:
        """Pull and merge Device records for every resolved site.

        Args:
            site_ids (List[str]): Resolved site_id values to pull.
            config_params (Dict): Extracted configuration parameters.
            headers (Dict): Request headers (including auth).
            device_status_map (Dict[str, str]): mac -> status, from
                the same inventory/search pass _resolve_site_ids()
                already made. The devices endpoint itself never
                returns a status field, so this is the only source.

        Returns:
            List[Dict]: Mapped Device records with 'Labels' and
            'Status' merged in.
        """
        records: List[Dict] = []
        fetch_labels = self.hpe_mist_helper.is_label_fetch_enabled(
            self.configuration
        )
        base_url = config_params["base_url"]
        for site_id in site_ids:
            raw_devices = self.hpe_mist_helper.fetch_devices_for_site(
                site_id=site_id, base_url=base_url, headers=headers
            )
            label_map: Dict[str, List[str]] = {}
            if fetch_labels:
                wxtags = self.hpe_mist_helper.fetch_wxtags_for_site(
                    site_id=site_id, base_url=base_url, headers=headers
                )
                label_map = self.hpe_mist_helper.build_label_map(
                    wxtags
                )
            for raw_device in raw_devices:
                record = self._extract_device_fields(raw_device)
                record[LABELS_FIELD] = label_map.get(
                    raw_device.get("id"), []
                )
                record[STATUS_FIELD] = device_status_map.get(
                    raw_device.get("mac")
                )
                records.append(record)
        return records

    def fetch_records(self, entity: str) -> List:
        """Pull Device records from HPE Mist.

        Full pull on every run - there is no incremental fetch mode
        for this plugin (the devices endpoint has no "modified
        since" filter per the TDD), so self.last_run_at/initial_range
        are intentionally not used here.

        Args:
            entity (str): Entity name requested by the platform.

        Returns:
            List: Mapped Device records.

        Raises:
            HPEMistAccessAssurancePluginException: On invalid entity or API
                error.
        """
        self._validate_entity(entity)
        entity_name = entity.lower()
        if not self.hpe_mist_helper.is_fetch_access_points_enabled(
            self.configuration
        ):
            self.logger.info(
                f"{self.log_prefix}: 'Fetch Access Points' is set to "
                f"'{FETCH_ACCESS_POINTS_NO}' in the configuration; "
                f"skipping the {entity_name} records pull from "
                f"{PLATFORM_NAME} platform."
            )
            return []
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )
        try:
            config_params = self.hpe_mist_helper.get_config_params(
                self.configuration
            )
            headers = self.hpe_mist_helper.get_auth_header(
                self.configuration
            )
            site_ids, device_status_map = self._resolve_site_ids(
                config_params, headers
            )
            records = self._fetch_devices_for_sites(
                site_ids, config_params, headers, device_status_map
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{len(records)} device record(s) from {len(site_ids)} "
                f"sites from HPE Mist."
            )
            return records
        except HPEMistAccessAssurancePluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Error occurred while fetching {entity_name} "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the configuration parameters "
                    "provided are correct."
                ),
            )
            raise HPEMistAccessAssurancePluginException(err_msg)

    # ------------------------------------------------------------------ #
    # update_records
    # ------------------------------------------------------------------ #
    def update_records(self, entity: str, records: List[Dict]) -> List:
        """No-op update: this plugin has no periodically-refreshed
        fields.

        All data, including 'Labels', is produced during
        fetch_records(); nothing here needs re-enrichment.

        Args:
            entity (str): Entity name requested by the platform.
            records (List[Dict]): Existing records from the CE store.

        Returns:
            List: Always an empty list.
        """
        return []

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #
    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Returns:
            List[ActionWithoutParams]: Supported action descriptors.
        """
        return [
            ActionWithoutParams(
                label="Add/Remove Label", value=ACTION_ADD_REMOVE_LABEL
            ),
            ActionWithoutParams(
                label="Add/Update NAC Devices",
                value=ACTION_ADD_DEVICES_TO_NAC,
            ),
            ActionWithoutParams(
                label="Delete NAC Devices",
                value=ACTION_DELETE_DEVICE_FROM_NAC,
            ),
            ActionWithoutParams(label="No Action", value=ACTION_GENERATE),
        ]

    def _add_remove_label_params(self) -> List[Dict]:
        """Build params for the consolidated Add/Remove Label action.

        Every parameter is a plain, Static-or-Source text/choice field
        with no live-fetched dropdowns, and the action operates on ONE
        device at a time - grouped into batches of
        LABEL_DEVICE_BATCH_SIZE by (Site ID, Label Name, Label Action,
        Operation) in execute_actions() - rather than aggregating the
        whole selection into a single "Devices" list the way this
        action used to.

        "Label Action" and "Operation" are Static Field only: they
        decide WHICH API behavior runs and WHICH existing label (if
        any) is targeted, and are assumed constant for the whole
        action run (see _collect_label_targets()). "Site ID" is
        Source Field only - a device only ever belongs to one Site,
        so its Site ID must come from the acted-on record itself
        (e.g. bound to "$Site ID") rather than a fixed Static value
        that could name a Site the device isn't even in. "Label Name"
        supports Source Field binding too, so a single action run can
        target a different Label per acted-on device.
        "Label Name" additionally supports MultiSource - it can be
        bound to one or more Source fields at once (in place of a
        single Static comma-separated value), resolved and flattened
        in _collect_label_targets() the same way the NAC "Labels"
        field already is.

        Returns:
            List[Dict]: Parameter field descriptors.
        """
        return [
            {
                "label": "Label Action",
                "key": "label_action",
                "type": "choice",
                "choices": [
                    {"key": "Add", "value": LABEL_ACTION_ADD},
                    {"key": "Remove", "value": LABEL_ACTION_REMOVE},
                ],
                "default": DEFAULT_LABEL_ACTION,
                "mandatory": True,
                "description": (
                    "Whether to add the device to a label or remove "
                    "it from one. Select Label Action from the "
                    "Static Field dropdown only."
                ),
            },
            {
                "label": "Site ID",
                "key": "site_id",
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "Mist Site ID the label belongs to. Select Site "
                    "ID from the Source Field dropdown only."
                ),
            },
            {
                "label": "Label Name",
                "key": "name",
                "type": "text",
                "default": "",
                "mandatory": True,
                "allowMultipleSource": True,
                "description": (
                    "Name of the label to add the device to (created "
                    "automatically if it doesn't already exist under "
                    "the given Site ID, Operation) or to remove the "
                    "device from. Select one or more Label Name "
                    "source fields, or provide a comma-separated "
                    "static list to add/remove the device to/from "
                    "more than one label at once. Each label name "
                    "must be 64 characters or less - HPE Mist trims "
                    "anything beyond that."
                ),
            },
            {
                "label": "Operation",
                "key": "operation",
                "type": "choice",
                "choices": [
                    {"key": "In", "value": LABEL_OPERATION_IN},
                    {"key": "Not In", "value": LABEL_OPERATION_NOT_IN},
                ],
                "default": DEFAULT_LABEL_OPERATION,
                "mandatory": True,
                "description": (
                    "Match operation of the label. Must match an "
                    "existing label's own Operation exactly to "
                    "locate it - a same-named label with a different "
                    "Operation is left untouched and the action "
                    "fails instead of modifying it or creating a "
                    "duplicate. Used as-is when a new label is "
                    "created. Select Operation from the Static Field "
                    "dropdown only."
                ),
            },
            {
                "label": "Device Unique ID",
                "key": "device_id",
                "type": "text",
                "default": "$Unique ID",
                "mandatory": True,
                "description": (
                    "Unique id of the device to add to or remove the "
                    "label from. Select from static or source field "
                    "dropdown."
                ),
            },
        ]

    def _add_devices_to_nac_params(self) -> List[Dict]:
        """Build params for the Add/Update NAC Devices action.

        One parameter per device field the NAC API accepts, in the
        same order as the request body. 'Netskope Device UUID' is
        Source Field only - it identifies exactly one device, so its
        value must come from the acted-on record itself rather than a
        fixed Static value that would be identical (and so produce
        duplicate device objects) across every record an action run
        matches. 'MAC Address' is the one field that legitimately
        accepts a comma-separated Static list (or a Source Field bound
        to a list-type value), since the NAC API takes it as a list on
        a single device object; every other field (all but 'Connection
        Type', which is a static choice of 'wired'/'wireless') is
        plain Static-or-Source text (the NAC API has nothing to
        populate a dropdown from for those). 'Netskope Device UUID'
        and 'MAC Address' are mandatory (a record missing either is
        marked as failed). 'Labels' supports MultiSource so several
        label fields can be bound to it at once.

        Returns:
            List[Dict]: Parameter field descriptors.
        """
        return [
            {
                "label": "Netskope Device UUID",
                "key": NAC_DEVICE_UUID_FIELD,
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "Netskope device UUID to send to NAC. Select "
                    "Netskope Device UUID from the Source Field "
                    "dropdown only."
                ),
            },
            {
                "label": "MAC Address",
                "key": NAC_MAC_ADDRESSES_FIELD,
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "MAC Address(es) of the device to add or update in"
                    " NAC. Select MAC Address source field or provide"
                    " comma-separated MAC Addresses. Required: a record"
                    " with no MAC Address is marked as failed."
                ),
            },
            {
                "label": "Hostname",
                "key": "hostname",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    "Hostname of the device. Select Hostname source "
                    "field or provide a static value."
                ),
            },
            {
                "label": "Username/Email",
                "key": "username",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    "Username or email of the device user. Select "
                    "Username/Email source field or provide a static "
                    "value."
                ),
            },
            {
                "label": "OS",
                "key": "os",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    "Operating system of the device. Select OS source "
                    "field or provide a static value."
                ),
            },
            {
                "label": "OS Version",
                "key": "os_version",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    "Operating system version of the device. Select "
                    "OS Version source field or provide a static "
                    "value."
                ),
            },
            {
                "label": "Device Make",
                "key": "device_make",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    "Make of the device. Select Device Make source "
                    "field or provide a static value."
                ),
            },
            {
                "label": "Device Model",
                "key": "device_model",
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    "Model of the device. Select Device Model source "
                    "field or provide a static value."
                ),
            },
            {
                "label": "Labels",
                "key": NAC_LABELS_FIELD,
                "type": "text",
                "default": "",
                "mandatory": False,
                "allowMultipleSource": True,
                "description": (
                    "Labels to send with the device. Select one or "
                    "more Label source fields, or provide a "
                    "comma-separated list of static Labels."
                ),
            },
            {
                "label": "Connection Type",
                "key": NAC_ETHER_TYPE_FIELD,
                "type": "choice",
                "choices": [
                    {"key": "Wired", "value": NAC_ETHER_TYPE_WIRED},
                    {"key": "Wireless", "value": NAC_ETHER_TYPE_WIRELESS},
                ],
                "default": "",
                "mandatory": False,
                "description": (
                    "Connection type of the device, sent to NAC as "
                    "'ether_type'. Select 'Wired' or 'Wireless' from "
                    "the Static or Source Field dropdown, or leave "
                    "blank to let NAC default it to 'wireless'."
                ),
            },
        ]

    def _delete_device_from_nac_params(self) -> List[Dict]:
        """Build params for the Delete NAC Devices action.

        Returns:
            List[Dict]: Parameter field descriptors.
        """
        return [
            {
                "label": "Netskope Device UUID",
                "key": NAC_DEVICE_UUID_FIELD,
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "Netskope device UUID to delete from NAC. Select "
                    "from the Static or Source Field dropdown."
                ),
            },
        ]

    def get_action_params(self, action: Action) -> List[Dict]:
        """Get parameters required for an action.

        Args:
            action (Action): The action to build parameters for.

        Returns:
            List[Dict]: Parameter field descriptors for the CE UI.
        """
        if action.value == ACTION_GENERATE:
            return []
        if action.value == ACTION_ADD_REMOVE_LABEL:
            return self._add_remove_label_params()
        if action.value == ACTION_ADD_DEVICES_TO_NAC:
            return self._add_devices_to_nac_params()
        if action.value == ACTION_DELETE_DEVICE_FROM_NAC:
            return self._delete_device_from_nac_params()
        return []

    # ------------------------------------------------------------------ #
    # execute_actions
    # ------------------------------------------------------------------ #
    def _collect_label_targets(
        self, actions: List
    ) -> Dict[Tuple[str, str, str, str], List[Tuple[str, Optional[str]]]]:
        """Group (device_id, action_id) pairs for the Add/Remove Label
        action by (site_id, name, label_action, operation).

        "Label Name" accepts a comma-separated Static list or one-or-
        more bound Source fields (MultiSource), so one device can
        target more than one label in a single execution - each name
        is exploded into its own group, so a device appears once per
        label it references. The raw value is normalized by
        self.hpe_mist_helper._resolve_label_param_values(), which
        comma-splits a Static string and flattens a MultiSource list
        (nested one level, one sub-list per bound Source field) the
        same way it already does for the NAC "Labels" field.
        "label_action" ("Add"/"Remove") and
        "operation" ("in"/"not_in") are both Static fields and do not
        vary within one execute_actions() call in practice; they are
        folded into the grouping key anyway, defensively. Actions
        with a missing Site ID, Label Name, or Device Unique ID are
        marked failed inline via the returned
        action id being paired with a None device_id under the
        special ("", "", "", "") key.

        A resolved label name over LABEL_NAME_CHARACTER_LIMIT
        characters is only logged (not failed) here: a Static value
        that long would already have been rejected at
        validate_action() time (see _validate_label_name_lengths()),
        so reaching this point means it came from a Source Field,
        whose value isn't known until now - HPE Mist trims it
        rather than rejecting it, so the action still proceeds.

        Args:
            actions (List): CE-supplied {"id", "params"} dicts.

        Returns:
            Dict[Tuple[str, str, str, str], List[Tuple[str, Optional[str]]]]:
            (site_id, name, label_action, operation) -> list of
            (device_id, action_id) pairs.
        """
        targets: Dict[
            Tuple[str, str, str, str], List[Tuple[str, Optional[str]]]
        ] = {}
        for action_dict in actions:
            action_id = action_dict.get("id")
            params = action_dict["params"].parameters
            label_action = (
                params.get("label_action") or DEFAULT_LABEL_ACTION
            ).strip()
            site_id = (params.get("site_id") or "").strip()
            names = self.hpe_mist_helper._resolve_label_param_values(
                params.get("name")
            )
            operation = (
                params.get("operation") or DEFAULT_LABEL_OPERATION
            ).strip()
            device_id = (params.get("device_id") or "").strip()
            if not site_id or not names or not device_id:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred, "
                        "skipping Add/Remove Label operation due to "
                        "a missing Site ID, Label Name, or Device "
                        "Unique ID."
                    ),
                    resolution=(
                        "Ensure that Site ID, Label Name, and Device "
                        "Unique ID are all provided."
                    ),
                )
                targets.setdefault(("", "", "", ""), []).append(
                    (None, action_id)
                )
                continue
            for name in names:
                if len(name) > LABEL_NAME_CHARACTER_LIMIT:
                    self.logger.info(
                        f"{self.log_prefix}: Label name '{name}' is "
                        f"{len(name)} characters, over HPE Mist's "
                        f"{LABEL_NAME_CHARACTER_LIMIT}-character "
                        "limit; the platform will trim it."
                    )
                targets.setdefault(
                    (site_id, name, label_action, operation), []
                ).append((device_id, action_id))
        return targets

    def _apply_label_batch(
        self,
        site_id: str,
        name: str,
        label_action: str,
        operation: str,
        device_ids: List[str],
        base_url: str,
        headers: Dict,
        wxtags: List[Dict],
    ) -> Tuple[List[str], int, int]:
        """Add or remove one batch of devices for one (Site ID, Label)
        pair.

        Locates the target label via match_wxtag() (name + match=
        "ap_id" + Operation) against the caller-supplied `wxtags` -
        this Site's WX Tags, fetched once per execute_actions() run
        rather than re-fetched before every batch/group (see
        _execute_add_remove_label()). An exact match returns the label
        to update; a name+match match with a different Operation is a
        hard failure for every device in this batch (an existing,
        differently-configured label is never silently duplicated or
        modified); no match at all means Add creates a brand-new
        label seeded with this batch's devices, while Remove skips
        (nothing to detach from) without failing. `wxtags` is mutated
        in place after a successful create/update, so a later group or
        batch in the same run that targets this same label sees this
        run's own write without an extra GET - accepted as a deliberate
        trade of a (small, same-run-only) staleness window for far
        fewer API calls; a label changed by another, truly concurrent
        actor mid-run is not reflected until the next run.

        Args:
            site_id (str): Mist site ID.
            name (str): Label name.
            label_action (str): LABEL_ACTION_ADD or
                LABEL_ACTION_REMOVE.
            operation (str): The label's match operation
                ("in"/"not_in").
            device_ids (List[str]): Device ids in this batch (already
                deduplicated by the caller).
            base_url (str): API base URL.
            headers (Dict): Request headers (including auth).
            wxtags (List[Dict]): This Site's WX Tags, fetched once by
                the caller and shared across every group/batch on this
                Site for the duration of one execute_actions() run.

        Returns:
            Tuple[List[str], int, int]: (failed device ids in this
            batch - empty on full success, count of devices actually
            added/removed, count of devices already in the label's
            target state - already a member for Add, already absent
            for Remove - so no API-visible change was needed for
            them).
        """
        tag, op_conflict = self.hpe_mist_helper.match_wxtag(
            wxtags=wxtags, name=name, operation=operation
        )
        if op_conflict:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred, label "
                    f"'{name}' already exists on site '{site_id}' "
                    "with a different Operation than configured."
                ),
                resolution=(
                    "Ensure that the Operation selected matches the "
                    "existing label's own Operation, or use a "
                    "different Label Name."
                ),
            )
            return device_ids, 0, 0

        if tag is None:
            if label_action == LABEL_ACTION_REMOVE:
                self.logger.info(
                    f"{self.log_prefix}: Label '{name}' was not "
                    f"found on site '{site_id}'; skipping label "
                    f"removal for {len(device_ids)} device(s)."
                )
                return [], 0, len(device_ids)
            self.logger.info(
                f"{self.log_prefix}: Creating label '{name}' in site "
                f"'{site_id}' as it does not exist."
            )
            created_tag = self.hpe_mist_helper.create_label(
                site_id=site_id,
                name=name,
                headers=headers,
                base_url=base_url,
                device_ids=device_ids,
                operation=operation,
            )
            if isinstance(created_tag, dict):
                wxtags.append(created_tag)
            return [], len(device_ids), 0

        current_values = [
            value
            for value in (tag.get("values") or [])
            if isinstance(value, str)
        ]
        existing = set(current_values)
        if label_action == LABEL_ACTION_REMOVE:
            remove_set = set(device_ids)
            updated_values = [
                value for value in current_values if value not in remove_set
            ]
            changed_count = len(existing & remove_set)
        else:
            updated_values = list(current_values)
            changed_count = 0
            for device_id in device_ids:
                if device_id not in existing:
                    updated_values.append(device_id)
                    existing.add(device_id)
                    changed_count += 1
        already_count = len(device_ids) - changed_count

        verb = "remove" if label_action == LABEL_ACTION_REMOVE else "add"
        self.logger.info(
            f"{self.log_prefix}: Updating label '{name}' in site "
            f"'{site_id}' to {verb} {changed_count} device(s)."
        )
        self.hpe_mist_helper.update_wxtag_values(
            site_id=site_id,
            wxtag_id=tag.get("id"),
            name=name,
            values=updated_values,
            headers=headers,
            base_url=base_url,
        )
        # tag is the same dict object stored inside `wxtags` (returned
        # by reference from match_wxtag()), so this keeps the shared
        # cache in sync for the next group/batch on this label too.
        tag["values"] = updated_values
        return [], changed_count, already_count

    def _execute_add_remove_label(
        self, actions: List, config_params: Dict, headers: Dict
    ) -> List:
        """Execute the consolidated Add/Remove Label action in
        batches of LABEL_DEVICE_BATCH_SIZE devices per (Site ID, Label
        Name, Label Action, Operation) group.

        Devices are grouped and batched, the target label is resolved
        (or, for Add, auto-created) once per batch, and a batch's
        failure marks only the action ids that contributed a device
        to that specific batch as failed.

        A Site's WX Tags are fetched at most once per Site for the
        whole run (see `site_wxtags_cache`), not once per group/batch -
        every group/batch targeting the same Site reuses that same
        list, which _apply_label_batch() mutates in place after each
        create/update so later groups on that Site see this run's own
        writes. This trades perfect same-instant freshness (a change
        made by a genuinely concurrent actor mid-run would not be
        picked up until the next run) for far fewer WX Tags GET calls.

        A per-(Site ID, Label Name, Label Action) device count
        (`label_stats`) is accumulated across every group/batch and
        logged as one summary at the end - the middle bucket is
        labelled "Already Exists" for Add (device was already a
        member) and "Does Not Exist" for Remove (device, or the whole
        label, was never a member to begin with).

        Args:
            actions (List): CE-supplied {"id", "params"} dicts sharing
                this action value.
            config_params (Dict): Extracted configuration parameters.
            headers (Dict): Request headers (including auth).

        Returns:
            List: Failed action ids.
        """
        failed_action_ids: List = []
        targets = self._collect_label_targets(actions)
        # Action ids collected under the ("", "", "", "") key had a
        # missing required field; they always fail.
        for _, action_id in targets.pop(("", "", "", ""), []):
            failed_action_ids.append(action_id)

        base_url = config_params["base_url"]
        site_wxtags_cache: Dict[str, List[Dict]] = {}
        label_stats: Dict[Tuple[str, str, str], Dict[str, int]] = {}
        for (site_id, name, label_action, operation), pairs in (
            targets.items()
        ):
            stats = label_stats.setdefault(
                (site_id, name, label_action),
                {"success": 0, "already_exists": 0, "failed": 0},
            )
            device_to_actions: Dict[str, List[str]] = {}
            for device_id, action_id in pairs:
                device_to_actions.setdefault(device_id, []).append(
                    action_id
                )
            unique_device_ids = list(device_to_actions.keys())

            if site_id not in site_wxtags_cache:
                self.logger.info(
                    f"{self.log_prefix}: Fetching WX Tags for site "
                    f"'{site_id}'."
                )
                try:
                    site_wxtags_cache[site_id] = (
                        self.hpe_mist_helper.fetch_wxtags_for_site(
                            site_id=site_id,
                            base_url=base_url,
                            headers=headers,
                        )
                    )
                except HPEMistAccessAssurancePluginException:
                    stats["failed"] += len(unique_device_ids)
                    for device_id in unique_device_ids:
                        failed_action_ids.extend(
                            device_to_actions[device_id]
                        )
                    continue
            wxtags = site_wxtags_cache[site_id]

            for start in range(
                0, len(unique_device_ids), LABEL_DEVICE_BATCH_SIZE
            ):
                batch = unique_device_ids[
                    start:start + LABEL_DEVICE_BATCH_SIZE
                ]
                try:
                    failed_in_batch, success_count, already_count = (
                        self._apply_label_batch(
                            site_id=site_id,
                            name=name,
                            label_action=label_action,
                            operation=operation,
                            device_ids=batch,
                            base_url=base_url,
                            headers=headers,
                            wxtags=wxtags,
                        )
                    )
                except HPEMistAccessAssurancePluginException:
                    failed_in_batch = batch
                    success_count = 0
                    already_count = 0
                stats["success"] += success_count
                stats["already_exists"] += already_count
                stats["failed"] += len(failed_in_batch)
                for device_id in failed_in_batch:
                    failed_action_ids.extend(
                        device_to_actions[device_id]
                    )

        if label_stats:
            label_counts: Dict[str, int] = {}
            device_counts: Dict[str, int] = {}
            for (_, _, label_action), stats in label_stats.items():
                label_counts[label_action] = (
                    label_counts.get(label_action, 0) + 1
                )
                device_counts[label_action] = (
                    device_counts.get(label_action, 0)
                    + stats["success"]
                )
            for label_action in (LABEL_ACTION_ADD, LABEL_ACTION_REMOVE):
                if label_action not in label_counts:
                    continue
                verb = (
                    "added"
                    if label_action == LABEL_ACTION_ADD
                    else "removed"
                )
                preposition = (
                    "to" if label_action == LABEL_ACTION_ADD else "from"
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully {verb} "
                    f"{label_counts[label_action]} label(s) "
                    f"{preposition} {device_counts[label_action]} "
                    "device(s)."
                )

            details = "\n".join(
                f"Site ID '{site_id}', Label '{name}' "
                f"({label_action.capitalize()}): "
                f"Success={stats['success']}, "
                + (
                    "Does Not Exist"
                    if label_action == LABEL_ACTION_REMOVE
                    else "Already Exists"
                )
                + f"={stats['already_exists']}, Failed={stats['failed']}."
                for (site_id, name, label_action), stats in (
                    label_stats.items()
                )
            )
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Completed Add/Remove Label "
                    "action execution. Expand the log to view "
                    "per-label stats."
                ),
                details=details,
            )
        return failed_action_ids

    # ------------------------------------------------------------------ #
    # NAC action execution
    # ------------------------------------------------------------------ #
    def _collect_nac_device_objects(
        self, actions: List
    ) -> Tuple[List[Dict], List, List]:
        """Build the device objects for the Add/Update NAC Devices action.

        Netskope Device UUID is Source Field only, so each action row
        (one per matched record) resolves to exactly one device
        object. The device objects and their action ids are kept in
        the same order, so a batch slice of one lines up with the
        same slice of the other. Duplicate UUIDs (e.g. two matched
        records that happen to resolve to the same Netskope Device
        UUID) are NOT removed - the UUID is not guaranteed unique and
        the API takes duplicates as-is.

        Args:
            actions (List): CE-supplied {"id", "params"} dicts.

        Returns:
            Tuple[List[Dict], List, List]: (device objects, their
            action ids in the same order, action ids that had no
            Netskope Device UUID or MAC Address(es) and are already
            failed).
        """
        device_objects: List[Dict] = []
        action_ids: List = []
        failed_action_ids: List = []
        for action_dict in actions:
            action_id = action_dict.get("id")
            params = action_dict["params"].parameters
            device = self.hpe_mist_helper._build_device_object(params)
            if device is None:
                failed_action_ids.append(action_id)
                continue
            device_objects.append(device)
            action_ids.append(action_id)
        # One summary line instead of one per record, matching
        # _resolve_site_ids().
        if failed_action_ids:
            self.logger.info(
                f"{self.log_prefix}: Skipped "
                f"{len(failed_action_ids)} record(s) with no Netskope "
                "Device UUID or MAC Address(es). These records were "
                "marked as failed."
            )
        return device_objects, action_ids, failed_action_ids

    def _get_nac_action_headers(
        self, config_params: Dict, storage: Dict
    ) -> Dict:
        """Get the NAC Authorization header for an action run.

        The token is fetched once per action run and reused for every
        call in that run. A 401 later on is handled inside
        api_helper()'s NAC re-auth branch, which gets a new token and
        sends that one request again.

        Args:
            config_params (Dict): Extracted configuration parameters.
            storage (Dict): Plugin storage dictionary.

        Returns:
            Dict: Request headers holding the NAC Bearer token.
        """
        access_token = self.hpe_mist_helper.get_nac_access_token(
            storage=storage, config_params=config_params
        )
        return self.hpe_mist_helper.get_nac_auth_header(access_token)

    def _mark_nac_batch_errors(
        self,
        response: Dict,
        uuid_to_action_ids: Dict[str, List],
        batch_number: int,
    ) -> List:
        """Read a batch response's 'errors' list and collect failures.

        Every error entry that carries a Netskope Device UUID marks
        every action id sending that UUID in this batch as failed, as
        the UUID is not guaranteed unique. Entries with no UUID cannot
        be matched to a record, so they are counted and reported in
        one line.

        Args:
            response (Dict): Parsed add-devices API response.
            uuid_to_action_ids (Dict[str, List]): UUID -> action ids
                for this batch only.
            batch_number (int): 1-based batch number, for logging.

        Returns:
            List: Failed action ids from this batch's errors list.
        """
        failed_action_ids: List = []
        skipped_error_count = 0
        error_reasons: List[str] = []
        for error in response.get("errors") or []:
            if not isinstance(error, dict):
                skipped_error_count += 1
                continue
            device_uuid = str(
                error.get(NAC_DEVICE_UUID_FIELD) or ""
            ).strip()
            reason = str(error.get("reason") or "").strip()
            if device_uuid and device_uuid in uuid_to_action_ids:
                failed_action_ids.extend(
                    uuid_to_action_ids[device_uuid]
                )
                error_reasons.append(
                    f"{device_uuid}: {reason}" if reason else device_uuid
                )
            else:
                skipped_error_count += 1
        if failed_action_ids:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Failed to add/update "
                    f"{len(error_reasons)} NAC device(s) in batch "
                    f"{batch_number}."
                ),
                details=(
                    "Devices reported as failed: "
                    f"{', '.join(error_reasons)}."
                ),
            )
        if skipped_error_count:
            self.logger.info(
                f"{self.log_prefix}: Batch {batch_number}: Skipped "
                f"{skipped_error_count} error(s) from NAC that could "
                "not be matched to a record."
            )
        return failed_action_ids

    def _execute_add_devices_to_nac(
        self, actions: List, config_params: Dict
    ) -> List:
        """Execute the Add/Update NAC Devices action in batches.

        Device objects are sent NAC_DEVICE_BATCH_SIZE at a time. A
        batch that fails outright marks every action id in that batch
        as failed and the next batch still runs. A batch that
        succeeds can still report per-device errors, which mark only
        those devices as failed.

        Args:
            actions (List): CE-supplied {"id", "params"} dicts sharing
                this action value.
            config_params (Dict): Extracted configuration parameters.

        Returns:
            List: Failed action ids.
        """
        storage = self._get_storage()
        device_objects, action_ids, failed_action_ids = (
            self._collect_nac_device_objects(actions)
        )
        if not device_objects:
            return failed_action_ids

        try:
            headers = self._get_nac_action_headers(
                config_params, storage
            )
        except HPEMistAccessAssurancePluginException:
            # No call can be made without a token, so every device
            # left in this run fails.
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Could not get a NAC API "
                    f"access token, so {len(device_objects)} "
                    "device(s) were not sent to NAC."
                ),
                resolution=(
                    "Ensure that the NAC API Base URL, Client ID, "
                    "Client Secret, Mist Org ID and Netskope Account "
                    "ID provided in the configuration parameters are "
                    "correct."
                ),
            )
            failed_action_ids.extend(action_ids)
            return failed_action_ids

        total_devices = len(device_objects)
        for start in range(0, total_devices, NAC_DEVICE_BATCH_SIZE):
            batch = device_objects[start:start + NAC_DEVICE_BATCH_SIZE]
            batch_action_ids = action_ids[
                start:start + NAC_DEVICE_BATCH_SIZE
            ]
            batch_number = start // NAC_DEVICE_BATCH_SIZE + 1
            uuid_to_action_ids: Dict[str, List] = {}
            for device, action_id in zip(batch, batch_action_ids):
                uuid_to_action_ids.setdefault(
                    device[NAC_DEVICE_UUID_FIELD], []
                ).append(action_id)
            try:
                response = self.hpe_mist_helper.push_nac_devices(
                    devices=batch,
                    config_params=config_params,
                    storage=storage,
                    headers=headers,
                )
            except HPEMistAccessAssurancePluginException:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Batch {batch_number}: "
                        f"failed to add {len(batch)} device(s) to "
                        "NAC. Moving on to the next batch."
                    ),
                    resolution=(
                        "Check the earlier log entries for this "
                        "batch to see why the call failed."
                    ),
                )
                failed_action_ids.extend(batch_action_ids)
                continue
            response = response if isinstance(response, dict) else {}
            failed_count = response.get("failed", 0)
            summary_msg = (
                f"{self.log_prefix}: Successfully added/updated "
                f"{response.get('processed', 0)} NAC device(s)"
            )
            if failed_count:
                summary_msg += (
                    f", failed to add/update {failed_count} NAC "
                    "device(s),"
                )
            summary_msg += f" in batch {batch_number}."
            self.logger.info(summary_msg)
            failed_action_ids.extend(
                self._mark_nac_batch_errors(
                    response, uuid_to_action_ids, batch_number
                )
            )
        return failed_action_ids

    def _collect_nac_delete_targets(
        self, actions: List
    ) -> Tuple[Dict[str, List], List]:
        """Map each Netskope Device UUID to the action ids using it.

        The dict keeps insertion order, so the UUIDs are de-duplicated
        while their original order is kept. More than one action can
        carry the same UUID, and all of those ids share that UUID's
        outcome.

        Args:
            actions (List): CE-supplied {"id", "params"} dicts.

        Returns:
            Tuple[Dict[str, List], List]: (UUID -> action ids, action
            ids that had no UUID and are already failed).
        """
        uuid_to_action_ids: Dict[str, List] = {}
        failed_action_ids: List = []
        for action_dict in actions:
            action_id = action_dict.get("id")
            params = action_dict["params"].parameters
            device_uuid = self.hpe_mist_helper._resolve_string_param(
                params.get(NAC_DEVICE_UUID_FIELD)
            )
            if not device_uuid:
                failed_action_ids.append(action_id)
                continue
            uuid_to_action_ids.setdefault(device_uuid, []).append(
                action_id
            )
        if failed_action_ids:
            self.logger.info(
                f"{self.log_prefix}: Skipped "
                f"{len(failed_action_ids)} record(s) with no Netskope "
                "Device UUID. These records were marked as failed."
            )
        return uuid_to_action_ids, failed_action_ids

    def _execute_delete_device_from_nac(
        self, actions: List, config_params: Dict
    ) -> List:
        """Execute the Delete NAC Devices action, one call each.

        The NAC delete endpoint takes one device at a time, so the
        UUIDs are de-duplicated first and one DELETE call is made per
        UUID. A failed call marks every action id carrying that UUID
        as failed and the next UUID is still tried.

        Args:
            actions (List): CE-supplied {"id", "params"} dicts sharing
                this action value.
            config_params (Dict): Extracted configuration parameters.

        Returns:
            List: Failed action ids.
        """
        storage = self._get_storage()
        uuid_to_action_ids, failed_action_ids = (
            self._collect_nac_delete_targets(actions)
        )
        if not uuid_to_action_ids:
            return failed_action_ids

        try:
            headers = self._get_nac_action_headers(
                config_params, storage
            )
        except HPEMistAccessAssurancePluginException:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Could not get a NAC API "
                    f"access token, so {len(uuid_to_action_ids)} "
                    "device(s) were not deleted from NAC."
                ),
                resolution=(
                    "Ensure that the NAC API Base URL, Client ID, "
                    "Client Secret, Mist Org ID and Netskope Account "
                    "ID provided in the configuration parameters are "
                    "correct."
                ),
            )
            for action_ids in uuid_to_action_ids.values():
                failed_action_ids.extend(action_ids)
            return failed_action_ids

        success_count = 0
        failure_count = 0
        for device_uuid, action_ids in uuid_to_action_ids.items():
            try:
                self.hpe_mist_helper.delete_nac_device(
                    netskope_device_uuid=device_uuid,
                    config_params=config_params,
                    storage=storage,
                    headers=headers,
                )
                success_count += 1
            except HPEMistAccessAssurancePluginException:
                failure_count += 1
                failed_action_ids.extend(action_ids)
        summary_msg = (
            f"{self.log_prefix}: Successfully deleted "
            f"{success_count} device(s) from NAC."
        )
        if failure_count:
            summary_msg += (
                f" Failed to delete {failure_count} device(s)."
            )
        self.logger.info(summary_msg)
        return failed_action_ids

    def _execute_nac_action(
        self, action_value: str, actions: List, config_params: Dict
    ) -> List:
        """Dispatch a NAC action to its execution method.

        Args:
            action_value (str): The action value being executed.
            actions (List): CE-supplied {"id", "params"} dicts sharing
                this action value.
            config_params (Dict): Extracted configuration parameters.

        Returns:
            List: Failed action ids.
        """
        if action_value == ACTION_ADD_DEVICES_TO_NAC:
            return self._execute_add_devices_to_nac(
                actions, config_params
            )
        return self._execute_delete_device_from_nac(
            actions, config_params
        )

    def execute_actions(self, actions: List):
        """Execute a batch of actions against HPE Mist.

        All actions in a batch share the same action value.
        Add/Update NAC Devices and Delete NAC Devices go to the NAC /
        EDR API instead of the Mist API, and are dispatched before the
        Mist auth header is built so they never depend on the Mist
        credentials.

        Args:
            actions (List): CE-supplied list of {"id", "params"}
                dicts.

        Returns:
            ActionResult: Reports per-action failures to the
            framework.
        """
        from netskope.integrations.crev2.plugin_base import ActionResult

        if not actions:
            return ActionResult(
                success=True,
                message="Action execution completed.",
                failed_action_ids=[],
            )

        action_value = actions[0]["params"].value

        if action_value == ACTION_GENERATE:
            self.logger.debug(
                f"{self.log_prefix}: Successfully performed 'No Action' "
                f"on {len(actions)} record(s). No processing is done "
                "for this action."
            )
            return ActionResult(
                success=True,
                message="Action execution completed.",
                failed_action_ids=[],
            )

        try:
            config_params = self.hpe_mist_helper.get_config_params(
                self.configuration
            )
            # The NAC actions talk to a different API with its own
            # credentials, so they are dispatched BEFORE the Mist auth
            # header is built - a NAC action must never fail because
            # of Mist credentials, so get_auth_header() is never even
            # called on that path. get_config_params() makes no API
            # call, so it is safe to keep it first for both paths.
            if action_value in NAC_ACTIONS:
                failed_action_ids = self._execute_nac_action(
                    action_value, actions, config_params
                )
            else:
                headers = self.hpe_mist_helper.get_auth_header(
                    self.configuration
                )
                if action_value == ACTION_ADD_REMOVE_LABEL:
                    failed_action_ids = self._execute_add_remove_label(
                        actions, config_params, headers
                    )
                else:
                    err_msg = (
                        f"Error occurred, unsupported action "
                        f"'{action_value}' provided."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Ensure that a supported action is "
                            "selected."
                        ),
                    )
                    failed_action_ids = [a.get("id") for a in actions]
        except HPEMistAccessAssurancePluginException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while "
                    f"executing '{action_value}' action. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            failed_action_ids = [a.get("id") for a in actions]
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while "
                    f"executing '{action_value}' action. Error: {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the configured action parameters "
                    "are valid."
                ),
            )
            failed_action_ids = [a.get("id") for a in actions]

        failed_action_ids = list(
            {fid for fid in failed_action_ids if fid is not None}
        )
        return ActionResult(
            success=True,
            message="Action execution completed.",
            failed_action_ids=failed_action_ids,
        )

    # ------------------------------------------------------------------ #
    # validate_action
    # ------------------------------------------------------------------ #
    @staticmethod
    def _validate_no_blank_csv_entries(value: str) -> bool:
        """Return False when a comma-separated Static value contains
        any blank entry (e.g. "a,,b", a leading/trailing comma, or a
        whitespace-only entry).

        Shared by every Static field that accepts a comma-separated
        list: "Label Name" (Add/Remove Label) and "MAC Address"
        (Add/Update NAC Devices) - "Netskope Device UUID" is Source
        Field only, so it never reaches this check (see
        _validate_parameters(source_only=True)). Only ever runs for a
        Static value - check_dollar already defers a Source Field
        value (one containing "$") entirely, since its real,
        per-record value isn't known until execution, and a
        MultiSource (list) value is shape-checked separately (see
        _validate_add_remove_label_action()) without reaching this
        function at all. A Source Field's resolved value is instead
        handled leniently at execution time (_collect_label_targets()
        for Label Name, helper._resolve_mac_addresses() for MAC
        Address), which simply skips any blank entry rather than
        failing the whole action.
        """
        return all(item.strip() for item in value.split(","))

    @staticmethod
    def _validate_label_name_lengths(value: str) -> bool:
        """Return False when any comma-separated label name in `value`
        is over LABEL_NAME_CHARACTER_LIMIT characters.

        Only ever runs for a Static "Label Name" value - check_dollar
        already defers a Source Field value (one containing "$")
        entirely, since its real, per-device value isn't known until
        execution, and a MultiSource (list) value is shape-checked
        separately in _validate_add_remove_label_action() without
        reaching this function at all. That later, per-name check
        (after the Source or MultiSource value is resolved) lives in
        _collect_label_targets(), and only logs there rather than
        failing, since HPE Mist trims an over-length label name
        instead of rejecting it.
        """
        names = [name.strip() for name in value.split(",") if name.strip()]
        return all(
            len(name) <= LABEL_NAME_CHARACTER_LIMIT for name in names
        )

    def _validate_add_remove_label_action(
        self, action: Action
    ) -> ValidationResult:
        """Validate the consolidated Add/Remove Label action parameters.

        Every field is required for BOTH Label Action values now -
        Site ID, Label Name, and Operation together identify the target
        label (for Add: what to create if missing; for Remove: what
        to locate), and Device Unique ID identifies which device to
        attach/detach. All fields are mandatory; Label Name and Device
        Unique ID are Static-or-Source via check_dollar, Site ID is
        Source Field only via source_only (a blank or Static value is
        rejected outright - see the source_only branch of
        _validate_parameters()), with no per-action-value branching.

        "Label Name" is additionally MultiSource-eligible: when one or
        more Source fields are bound to it, CE resolves the value to a
        list (already known at this point, unlike a single Source
        Field's "$"-prefixed placeholder) instead of a comma-separated
        string. That list is only shape-checked here (non-empty, every
        item a string) - the comma-count/blank/length custom
        validators below only make sense for a Static string, the same
        split CrowdStrike's Tag(s) action validation makes for its own
        MultiSource field.
        """
        params = action.parameters
        if result := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Label Action",
            field_value=params.get("label_action", ""),
            field_type=str,
            static_only=True,
            allowed_values=LABEL_ACTION_CHOICES,
        ):
            return result
        if result := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Site ID",
            field_value=params.get("site_id", ""),
            field_type=str,
            check_dollar=True,
            source_only=True,
        ):
            return result
        name_value = params.get("name", "")
        if isinstance(name_value, list):
            if not name_value or not all(
                isinstance(item, str) for item in name_value
            ):
                err_msg = TYPE_ERROR_MESSAGE.format(
                    field_name="Label Name", parameter_type=ACTION
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that a valid value is provided for "
                        "'Label Name'."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
        else:
            if result := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Label Name",
                field_value=name_value,
                field_type=str,
                check_dollar=True,
                custom_validation_func=(
                    self._validate_no_blank_csv_entries
                ),
                custom_error_message=EMPTY_CSV_ERROR_MESSAGE,
            ):
                return result
            if result := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Label Name",
                field_value=name_value,
                field_type=str,
                check_dollar=True,
                custom_validation_func=self._validate_label_name_lengths,
                custom_error_message=(
                    INVALID_LABEL_NAME_LENGTH_ERROR_MESSAGE.format(
                        limit=LABEL_NAME_CHARACTER_LIMIT
                    )
                ),
            ):
                return result
        if result := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Operation",
            field_value=params.get("operation", ""),
            field_type=str,
            static_only=True,
            allowed_values=LABEL_OPERATION_CHOICES,
        ):
            return result
        if result := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Device Unique ID",
            field_value=params.get("device_id", ""),
            field_type=str,
            check_dollar=True,
        ):
            return result
        return ValidationResult(success=True, message="Validation successful.")

    def _validate_nac_configuration(
        self, action_label: str
    ) -> Optional[ValidationResult]:
        """Check the five NAC configuration fields are all filled in.

        The NAC fields are rendered as non-mandatory configuration
        fields, because they cannot be revealed by a toggle of their
        own (see get_dynamic_fields()). This is where the real
        requirement is enforced: neither NAC action can be saved until
        all five values are present. self.configuration is read
        directly here, which is correct for validate_action() - it has
        no configuration argument of its own.

        Args:
            action_label (str): Label of the action being saved.

        Returns:
            Optional[ValidationResult]: A failed ValidationResult
            naming the first missing field, else None.
        """
        configuration = self.configuration or {}
        for key, label in NAC_CONFIG_FIELDS:
            value = configuration.get(key)
            # Secrets are never stripped, matching the rest of the
            # plugin.
            if isinstance(value, str) and key != NAC_CLIENT_SECRET_KEY:
                value = value.strip()
            if not value:
                err_msg = NAC_CONFIG_INCOMPLETE_ERROR_MESSAGE.format(
                    field_name=label, action_label=action_label
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that all five NAC fields are filled "
                        "in on the plugin configuration before saving "
                        "this action."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
        return None

    def _validate_nac_device_field_types(
        self, params: Dict
    ) -> Optional[ValidationResult]:
        """Type-check the optional device fields of the Add action.

        Args:
            params (Dict): This action's parameters.

        Returns:
            Optional[ValidationResult]: A failed ValidationResult on
            the first bad value, else None.
        """
        string_fields = [
            ("Hostname", "hostname"),
            ("Username/Email", "username"),
            ("OS", "os"),
            ("OS Version", "os_version"),
            ("Device Make", "device_make"),
            ("Device Model", "device_model"),
        ]
        list_fields = [
            ("MAC Address", NAC_MAC_ADDRESSES_FIELD),
            ("Labels", NAC_LABELS_FIELD),
        ]
        for field_name, key in string_fields:
            value = params.get(key)
            if value and not isinstance(value, str):
                return self._nac_type_error(field_name)
        for field_name, key in list_fields:
            value = params.get(key)
            if value and not isinstance(value, (str, list)):
                return self._nac_type_error(field_name)
        return None

    def _nac_type_error(self, field_name: str) -> ValidationResult:
        """Build and log a type error for a NAC action parameter.

        Args:
            field_name (str): Human-readable field name.

        Returns:
            ValidationResult: The failed result to return.
        """
        err_msg = TYPE_ERROR_MESSAGE.format(
            field_name=field_name, parameter_type=ACTION
        )
        self.logger.error(
            message=(
                f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                f"{err_msg}"
            ),
            resolution=(
                f"Ensure that a valid value is provided for "
                f"'{field_name}'."
            ),
        )
        return ValidationResult(success=False, message=err_msg)

    def _validate_add_devices_to_nac_action(
        self, action: Action
    ) -> ValidationResult:
        """Validate the Add/Update NAC Devices action parameters.

        The Netskope Device UUID and MAC Address(es) are the two
        mandatory fields. Netskope Device UUID is Source Field only -
        any value that is not a "$..." Source Field reference
        (including blank) is rejected outright by
        _validate_parameters(source_only=True); its real,
        per-record value isn't checked until execution, where a
        record resolving to an empty UUID is marked as failed. MAC
        Address is Static-or-Source and accepts a comma-separated
        Static list (see helper._build_device_object()), so a Static
        value for it is additionally rejected when it has a blank
        entry (e.g. "a,,b", a leading/trailing comma) - the same check
        "Label Name" already gets in the Add/Remove Label action (see
        _validate_no_blank_csv_entries()).
        """
        if result := self._validate_nac_configuration(
            "Add/Update NAC Devices"
        ):
            return result
        params = action.parameters
        if result := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Netskope Device UUID",
            field_value=params.get(NAC_DEVICE_UUID_FIELD, ""),
            field_type=str,
            check_dollar=True,
            source_only=True,
        ):
            return result
        if result := self._validate_parameters(
            parameter_type=ACTION,
            field_name="MAC Address",
            field_value=params.get(NAC_MAC_ADDRESSES_FIELD, ""),
            field_type=str,
            check_dollar=True,
            custom_validation_func=self._validate_no_blank_csv_entries,
            custom_error_message=EMPTY_CSV_ERROR_MESSAGE,
        ):
            return result
        # 'Connection Type' (ether_type) is optional; only when a value
        # is provided must it be one of NAC_ETHER_TYPE_CHOICES. A blank
        # value is allowed and a Source Field value is deferred to
        # execution time.
        ether_type = params.get(NAC_ETHER_TYPE_FIELD)
        if isinstance(ether_type, str):
            ether_type = ether_type.strip()
        if ether_type:
            if result := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Connection Type",
                field_value=ether_type,
                field_type=str,
                check_dollar=True,
                allowed_values=NAC_ETHER_TYPE_CHOICES,
            ):
                return result
        if result := self._validate_nac_device_field_types(params):
            return result
        return ValidationResult(success=True, message="Validation successful.")

    def _validate_delete_device_from_nac_action(
        self, action: Action
    ) -> ValidationResult:
        """Validate the Delete NAC Devices action parameters.

        The Netskope Device UUID is only checked for being present -
        its format is never checked.
        """
        if result := self._validate_nac_configuration(
            "Delete NAC Devices"
        ):
            return result
        if result := self._validate_parameters(
            parameter_type=ACTION,
            field_name="Netskope Device UUID",
            field_value=action.parameters.get(
                NAC_DEVICE_UUID_FIELD, ""
            ),
            field_type=str,
            check_dollar=True,
        ):
            return result
        return ValidationResult(success=True, message="Validation successful.")

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate an action and its parameters.

        Args:
            action (Action): Action configuration to validate.

        Returns:
            ValidationResult: Success/failure with a message.
        """
        if action.value not in SUPPORTED_ACTIONS:
            err_msg = (
                "Unsupported action provided. Supported actions are: "
                "'Add/Remove Label', 'Add/Update NAC Devices', "
                "'Delete NAC Devices', 'No Action'."
            )
            self.logger.error(message=f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if action.value == ACTION_GENERATE:
            return ValidationResult(
                success=True, message="Validation successful."
            )
        if action.value == ACTION_ADD_REMOVE_LABEL:
            return self._validate_add_remove_label_action(action)
        if action.value == ACTION_ADD_DEVICES_TO_NAC:
            return self._validate_add_devices_to_nac_action(action)
        return self._validate_delete_device_from_nac_action(action)

    # ------------------------------------------------------------------ #
    # Reusable configuration/action parameter validator
    # ------------------------------------------------------------------ #
    def _validate_parameters(
        self,
        parameter_type: str,
        field_name: str,
        field_value,
        field_type,
        check_dollar: bool = False,
        static_only: bool = False,
        source_only: bool = False,
        allowed_values: Optional[List] = None,
        custom_validation_func=None,
        custom_error_message: str = "",
    ) -> Optional[ValidationResult]:
        """Validate a single action/configuration parameter value.

        Args:
            parameter_type (str): CONFIGURATION or ACTION.
            field_name (str): Human-readable field name.
            field_value: Value to validate.
            field_type: Expected Python type (or tuple of types).
            check_dollar (bool): When True, a "$" value is a Source
                Field and validation is deferred to execution time.
            static_only (bool): When True, a "$" value is rejected
                instead of deferred (the field only supports the
                Static Field dropdown).
            source_only (bool): When True, any value that is NOT a "$"
                Source Field reference is rejected outright - including
                a blank Static value, so this also serves as the
                field's mandatory/empty check (the field only supports
                the Source Field dropdown).
            allowed_values (Optional[List]): Permitted values.
            custom_validation_func: Field-specific rule run after the
                empty/type checks. Takes the value, returns True when
                acceptable.
            custom_error_message (str): Appended to the invalid-value
                message when custom_validation_func rejects the
                value.

        Returns:
            Optional[ValidationResult]: ValidationResult on failure,
            else None.
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
                    f"Ensure that {field_name} is selected from the "
                    "Static Field dropdown only."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if source_only and not (
            isinstance(field_value, str) and "$" in field_value
        ):
            err_msg = SOURCE_FIELD_ERROR_MESSAGE.format(
                field_name=field_name
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    f"Ensure that {field_name} is selected from the "
                    "Source Field dropdown only."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if (
            check_dollar
            and isinstance(field_value, str)
            and "$" in field_value
        ):
            self.logger.info(
                f"{self.log_prefix}: '{field_name}' contains the "
                "Source Field hence validation for this field will "
                "be performed while executing the action."
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
                resolution=(
                    f"Ensure that a value is provided for the "
                    f"'{field_name}' field."
                ),
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
                resolution=(
                    f"Ensure that a valid value is provided for "
                    f"'{field_name}'."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if custom_validation_func and not custom_validation_func(
            field_value
        ):
            err_msg = (
                TYPE_ERROR_MESSAGE.format(
                    field_name=field_name, parameter_type=parameter_type
                )
                + custom_error_message
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    f"Ensure that a valid value is provided for "
                    f"'{field_name}'."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if allowed_values and field_value not in allowed_values:
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name, parameter_type=parameter_type
            ) + INVALID_VALUE_ERROR_MESSAGE.format(
                allowed_values=allowed_values
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    "Ensure that the value provided is one of the "
                    "allowed values."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        return None

    def _validate_url(self, url: str) -> bool:
        """Validate a URL string using urlparse.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True when the URL has both a scheme and a netloc.
        """
        parsed = urlparse(url.strip())
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    # ------------------------------------------------------------------ #
    # validate
    # ------------------------------------------------------------------ #
    def _validate_api_token_field(
        self, configuration: Dict
    ) -> Optional[ValidationResult]:
        """Validate the Token Authentication credential field."""
        if result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="API Token",
            field_value=configuration.get("api_key"),
            field_type=str,
        ):
            return result
        return None

    def _validate_site_name_field(
        self, configuration: Dict
    ) -> Optional[ValidationResult]:
        """Validate 'Site Names'.

        Optional and self-gating: a blank value means "fetch Devices
        from every Site" and needs no further checking here (the
        actual names, when provided, are confirmed live against
        GET orgs/{org_id}/sites inside _validate_auth_params(), not
        here — this only checks the comma-separated shape).
        """
        site_name_raw = configuration.get("site_name", "") or ""
        if site_name_raw and not site_name_raw.strip():
            # Non-empty but entirely whitespace (e.g. a single typed
            # space) - distinct from a genuinely empty field, which
            # is the valid "pull every Site" case handled below.
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name="Site Names", parameter_type=CONFIGURATION
            ) + WHITESPACE_ONLY_ERROR_MESSAGE
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    "Provide a comma-separated list of Site Names, or "
                    "leave the field completely empty to pull "
                    "Devices from every Site."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if not site_name_raw.strip():
            return None

        site_names_list = [
            site_name.strip() for site_name in site_name_raw.split(",")
        ]
        if any(not site_name for site_name in site_names_list):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name="Site Names", parameter_type=CONFIGURATION
            ) + EMPTY_CSV_ERROR_MESSAGE
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} "
                    f"{err_msg}"
                ),
                resolution=(
                    "Ensure that the comma-separated Site Names list "
                    "does not contain empty entries."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        return None

    def _validate_nac_config_fields(
        self, configuration: Dict, require: bool = False
    ) -> Optional[ValidationResult]:
        """Validate the five NAC configuration fields.

        Two modes, selected by 'require':

        * require=False (default) - all-or-nothing. A Mist-only
          configuration that leaves all five blank is perfectly valid;
          as soon as one of them is filled in, all five are required, so
          a half-filled NAC block cannot be saved and then fail later at
          action time. Used when 'Fetch Access Points' is 'Yes' (NAC
          is the optional, secondary workflow).
        * require=True - all five are mandatory. Used when 'Fetch Access
          Points' is disabled, where NAC is the only active workflow, so
          a completely blank NAC block must be rejected.

        Only the presence/format of the values is checked here; the
        live NAC token-endpoint check (which verifies the credentials
        are actually valid) is done separately by
        _validate_nac_auth_params().

        Args:
            configuration (Dict): Plugin configuration dictionary.
            require (bool): When True, treat all five NAC fields as
                mandatory instead of all-or-nothing.

        Returns:
            Optional[ValidationResult]: A failed ValidationResult on
            the first problem found, else None.
        """
        values = {}
        for key, _ in NAC_CONFIG_FIELDS:
            value = configuration.get(key)
            # Secrets are never stripped.
            if isinstance(value, str) and key != NAC_CLIENT_SECRET_KEY:
                value = value.strip()
            if key == NAC_BASE_URL_KEY and isinstance(value, str):
                value = value.rstrip("/")
            values[key] = value
        if not require and not any(values.values()):
            return None

        for key, label in NAC_CONFIG_FIELDS:
            if key == NAC_BASE_URL_KEY:
                if result := self._validate_parameters(
                    parameter_type=CONFIGURATION,
                    field_name=label,
                    field_value=values[key],
                    field_type=str,
                    custom_validation_func=self._validate_url,
                    custom_error_message=INVALID_URL_ERROR_MESSAGE,
                ):
                    return result
            elif result := self._validate_parameters(
                parameter_type=CONFIGURATION,
                field_name=label,
                field_value=values[key],
                field_type=str,
            ):
                return result
        return None

    def _is_nac_block_configured(self, configuration: Dict) -> bool:
        """Return True when at least one NAC configuration field is set.

        Used to decide whether the live NAC connectivity check should
        run when the NAC block is optional ('Fetch Access Points' is 'Yes').
        When any one field is filled in, _validate_nac_config_fields()
        has already required all five, so a True here means a complete,
        ready-to-validate NAC block.

        Args:
            configuration (Dict): Plugin configuration dictionary.

        Returns:
            bool: Whether the NAC block has any value filled in.
        """
        for key, _ in NAC_CONFIG_FIELDS:
            value = configuration.get(key)
            if isinstance(value, str):
                value = value.strip()
            if value:
                return True
        return False

    def _validate_nac_auth_params(
        self, configuration: Dict
    ) -> Optional[ValidationResult]:
        """Validate the NAC credentials against the NAC token endpoint.

        On every validation this calls the NAC access-token generation
        endpoint (force_regenerate=True, so the cache is bypassed) and,
        on success, stores the returned access token in plugin storage
        next to its config hash - so a just-saved configuration already
        has a warm NAC token cache. A failure (bad credentials, wrong
        Base URL / IDs, connectivity) surfaces as a failed
        ValidationResult.

        Args:
            configuration (Dict): Plugin configuration dictionary.

        Returns:
            Optional[ValidationResult]: A failed ValidationResult when
            a NAC token could not be obtained, else None.
        """
        try:
            config_params = self.hpe_mist_helper.get_config_params(
                configuration
            )
            storage = self._get_storage()
            self.hpe_mist_helper.get_nac_access_token(
                storage=storage,
                config_params=config_params,
                force_regenerate=True,
            )
        except HPEMistAccessAssurancePluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = (
                "Error occurred while validating the NAC configuration "
                "parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the NAC configuration parameters "
                    "provided are correct, then retry."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        return None

    def _extract_accessible_org_ids(self, response: Dict) -> List[str]:
        """Extract accessible Organization IDs from a GET /self response.

        [TDD ASSUMPTION] The exact /self response schema is not
        confirmed by the source specification; this reads Mist's
        documented 'privileges' array of {"org_id": ..., ...} entries.
        When 'privileges' is absent/empty (schema mismatch), no org
        ids are returned and the org-id check is skipped rather than
        hard-failing validation on an unconfirmed assumption.

        Args:
            response (Dict): Parsed GET /self response.

        Returns:
            List[str]: Accessible Organization IDs found, if any.
        """
        org_ids = []
        privileges = response.get("privileges") if response else None
        if isinstance(privileges, list):
            for privilege in privileges:
                if isinstance(privilege, dict) and privilege.get("org_id"):
                    org_ids.append(privilege.get("org_id"))
        return org_ids

    def _validate_site_names_exist(
        self, config_params: Dict, headers: Dict
    ) -> Optional[ValidationResult]:
        """Confirm configured Site Names exist under the Organization.

        Skipped entirely when Site Names is blank (nothing to check).
        Mirrors _resolve_site_ids()'s runtime tolerance: an individual
        configured name not found is reported in aggregate (not a
        hard failure) via an info log; only a total mismatch (none of
        the configured names resolve to a Site) fails validation.

        Args:
            config_params (Dict): Extracted configuration parameters.
            headers (Dict): Request headers (including auth).

        Returns:
            Optional[ValidationResult]: ValidationResult on failure,
            else None.
        """
        if not (config_params.get("site_name") or "").strip():
            return None

        org_sites = self.hpe_mist_helper.fetch_org_sites(
            base_url=config_params["base_url"],
            org_id=config_params["org_id"],
            headers=headers,
            is_validation=True,
        )
        name_to_ids = self.hpe_mist_helper.build_site_name_map(
            org_sites
        )
        configured_names = [
            name.strip()
            for name in (config_params.get("site_name") or "").split(",")
            if name.strip()
        ]
        invalid_names = [
            name for name in configured_names if name not in name_to_ids
        ]
        if invalid_names:
            self.logger.info(
                f"{self.log_prefix}: {len(invalid_names)} of "
                f"{len(configured_names)} configured Site Name(s) "
                "were not found under the configured Organization ID: "
                f"{', '.join(invalid_names)}."
            )
        if configured_names and len(invalid_names) == len(
            configured_names
        ):
            err_msg = (
                "Error occurred, none of the configured Site Names "
                f"({', '.join(configured_names)}) were found under "
                "the configured Organization ID."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the Site Names provided in the "
                    "configuration parameters are correct and belong "
                    "to the configured Organization ID."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        return None

    def _validate_auth_params(self, configuration: Dict) -> ValidationResult:
        """Validate credentials and Organization ID with GET /self.

        This is the same connectivity call fetch_records() depends on.

        Args:
            configuration (Dict): Plugin configuration dictionary.

        Returns:
            ValidationResult: Success/failure with a message.
        """
        try:
            config_params = self.hpe_mist_helper.get_config_params(
                configuration
            )
            headers = self.hpe_mist_helper.get_auth_header(
                configuration, is_validation=True
            )
            url = SELF_ENDPOINT.format(base_url=config_params["base_url"])
            response = self.hpe_mist_helper.api_helper(
                logger_msg=(
                    "validating connectivity with HPE Mist platform"
                ),
                url=url,
                method="GET",
                headers=headers,
                is_validation=True,
            )
            accessible_org_ids = self._extract_accessible_org_ids(response)
            org_id = config_params["org_id"]
            if accessible_org_ids and org_id not in accessible_org_ids:
                err_msg = (
                    f"Error occurred, Organization ID '{org_id}' was "
                    "not found among the organizations accessible to "
                    "the configured credentials."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that the Organization ID provided in "
                        "the configuration parameters is correct."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

            if result := self._validate_site_names_exist(
                config_params, headers
            ):
                return result
        except HPEMistAccessAssurancePluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = (
                "Error occurred while validating configuration "
                "parameters."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the configuration parameters "
                    "provided are correct, then retry."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        self.logger.debug(
            f"{self.log_prefix}: Validation completed successfully."
        )
        return ValidationResult(
            success=True, message="Validation successful."
        )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the plugin configuration parameters.

        The 'Fetch Access Points' choice selects which of the plugin's
        two workflows a configuration uses, and therefore which fields
        are mandatory:

        * 'Yes' - Device (Access Point) records are pulled from the
          HPE Mist API using Token Authentication, so the Mist
          connection is required: Base URL, API Token,
          Organization ID, and Fetch Labels. Site Names is optional
          (blank means every Site). A live GET /self connectivity
          check is run, and any configured Site Names are confirmed
          against GET orgs/{org_id}/sites. The NAC block is optional
          (all-or-nothing); when it is configured, its credentials are
          also verified live against the NAC token endpoint.
        * 'No' (the default) - no devices are fetched, so none of the
          Mist connection fields are required; instead all five NAC
          configuration fields become mandatory and are verified live
          against the NAC token endpoint.

        Every NAC token-endpoint validation generates a fresh token and
        stores it in plugin storage, warming the NAC token cache.

        Args:
            configuration (Dict): Plugin configuration dictionary.

        Returns:
            ValidationResult: Success/failure with a message.
        """
        if not self.hpe_mist_helper.is_fetch_access_points_enabled(
            configuration
        ):
            # NAC-only workflow: the five NAC fields are mandatory and
            # the Mist connection fields are not validated at all. The
            # NAC credentials are then verified live against the token
            # endpoint.
            if result := self._validate_nac_config_fields(
                configuration, require=True
            ):
                return result
            if result := self._validate_nac_auth_params(configuration):
                return result
            self.logger.debug(
                f"{self.log_prefix}: Validation completed successfully."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )

        # Device (Access Point) pull workflow: the full Mist connection
        # is required; the NAC block is optional (all-or-nothing).
        if result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Base URL",
            field_value=(
                (configuration.get("base_url") or "").strip().rstrip("/")
            ),
            field_type=str,
            custom_validation_func=self._validate_url,
            custom_error_message=INVALID_URL_ERROR_MESSAGE,
        ):
            return result

        if result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Fetch Access Points",
            field_value=(
                configuration.get("fetch_access_points") or ""
            ).strip(),
            field_type=str,
            allowed_values=FETCH_ACCESS_POINTS_CHOICES,
        ):
            return result

        if result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Organization ID",
            field_value=(configuration.get("org_id") or "").strip(),
            field_type=str,
        ):
            return result

        if result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Fetch Labels",
            field_value=(configuration.get("fetch_labels") or "").strip(),
            field_type=str,
            allowed_values=FETCH_LABELS_CHOICES,
        ):
            return result

        if result := self._validate_api_token_field(configuration):
            return result

        if result := self._validate_site_name_field(configuration):
            return result

        if result := self._validate_nac_config_fields(configuration):
            return result

        # The NAC block is optional here; when it is configured, verify
        # its credentials live against the token endpoint as well.
        if self._is_nac_block_configured(configuration):
            if result := self._validate_nac_auth_params(configuration):
                return result

        return self._validate_auth_params(configuration)
