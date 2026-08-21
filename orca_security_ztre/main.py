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

CRE Orca Security Plugin.
"""

import traceback
from typing import Dict, List, Optional, Tuple

from netskope.integrations.crev2.models import Action, ActionWithoutParams
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
    ACTION_ADD_REMOVE_TAG,
    ACTION_LABELS,
    ACTION_NO_ACTION,
    ACTION_PARAM_LABELS,
    ACTION_SCAN_DATA_NOW,
    BASE_URL_CHOICE_VALUES,
    BASE_URL_CUSTOM_VALUE,
    BASE_URL_ENDPOINT,
    CONFIG_API_TOKEN,
    CONFIG_BASE_URL,
    CONFIG_CUSTOM_BASE_URL,
    CONFIG_DEVICE_MODELS,
    CONFIG_FETCH_ADDITIONAL_DEVICE_DETAILS,
    CONFIG_FETCH_CUSTOM_TAGS,
    CONFIG_FIELD_LABELS,
    CONFIG_USER_MODELS,
    CONFIGURATION,
    DEVICE_DETAIL_COUNTS,
    DEVICE_DETAIL_PORTS,
    DEVICE_DETAIL_VALUES,
    DEVICE_FIELD_MAPPING,
    DEVICE_HOSTNAME_FALLBACK_KEYS,
    DEVICE_MODELS,
    DEVICES,
    DYNAMIC_FIELDS_CUSTOM_BASE_URL,
    DYNAMIC_FIELDS_DEFAULT,
    ENTITY_LABEL_SINGULAR,
    FIELD_CUSTOM_TAGS,
    FIELD_DISPLAY_NAME,
    FIELD_EMAIL,
    FIELD_ENTITY_ID,
    FIELD_ENTITY_UNIQUE_ID,
    FIELD_EXPOSURE,
    FIELD_HOSTNAME,
    FIELD_MODEL_TAGS,
    FIELD_NORMALIZED_SCORE,
    FIELD_PORT_PROTOCOLS,
    FIELD_PORT_SERVICES,
    FIELD_PORTS,
    FIELD_TAGS,
    FIELD_TYPE,
    MAX_ORCA_SCORE,
    MIN_ORCA_SCORE,
    MODULE_NAME,
    PARAM_ASSET_ID,
    PARAM_ASSET_UNIQUE_ID,
    PARAM_TAG_ACTION,
    PARAM_TAG_KEY,
    PARAM_TAG_VALUE,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PROGRESS_LOG_INTERVAL,
    REQUIRED_ENTITY_FIELDS,
    SUPPORTED_ACTIONS,
    SUPPORTED_ENTITIES,
    TAG_ACTION_ADD,
    TAG_ACTION_REMOVE,
    TAG_ACTIONS,
    TOGGLE_CONFIG_KEYS,
    TOGGLE_NO,
    TOGGLE_VALUES,
    TOGGLE_YES,
    USER_DISPLAY_NAME_FALLBACK_KEYS,
    USER_FIELD_MAPPING,
    USER_MODELS,
    USERS,
    VALIDATION_ERROR_MESSAGE,
)
from .utils.exceptions import OrcaSecurityPluginException
from .utils.helper import OrcaSecurityPluginHelper


class OrcaSecurityPlugin(PluginBase):
    """Orca Security CRE ZTRE plugin class."""

    def __init__(self, name, *args, **kwargs):
        """Initialize the Orca Security plugin.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        # Ask the framework to hand execute_actions() the action IDs so
        # a failure on one record can be reported back for that record
        # alone instead of failing the whole batch.
        self.provide_action_id = True
        self.helper = OrcaSecurityPluginHelper(
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
            metadata = OrcaSecurityPlugin.metadata
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

    def _is_enabled(self, config_key: str) -> bool:
        """Return whether a yes/no configuration toggle is enabled.

        Args:
            config_key (str): Toggle key, e.g. ``fetch_custom_tags``.

        Returns:
            bool: True only when the toggle is set to ``"yes"``.
        """
        value = (self.configuration or {}).get(config_key, TOGGLE_NO)
        return str(value).strip().lower() == TOGGLE_YES

    def _has_device_detail(self, detail_key: str) -> bool:
        """Return whether a Workload detail is selected in the 'Fetch
        Additional Workload Details' multichoice.

        Args:
            detail_key (str): One of ``DEVICE_DETAIL_COUNTS`` /
                ``DEVICE_DETAIL_PORTS``.

        Returns:
            bool: True when *detail_key* is present in the configured
                selection.
        """
        selected = (
            (self.configuration or {}).get(
                CONFIG_FETCH_ADDITIONAL_DEVICE_DETAILS
            )
            or []
        )
        if isinstance(selected, str):
            selected = [selected]
        return detail_key in selected

    def get_dynamic_fields(self) -> List[Dict]:
        """Get dynamic fields based on current configuration.

        'Base URL' is the only field declared statically in
        manifest.json; every other configuration field is returned here
        instead, since the CE UI renders get_dynamic_fields() output as
        a block placed after all static manifest fields. With 'Base
        URL' as the sole static field, that block lands right below it.
        When 'Custom' is selected for 'Base URL', 'Custom Base URL' is
        prepended so it renders directly under 'Base URL'; for every
        other Base URL selection it is omitted.

        Returns:
            List[Dict]: The full list of remaining configuration field
                descriptors, in display order.
        """
        if (self.configuration or {}).get(CONFIG_BASE_URL) == (
            BASE_URL_CUSTOM_VALUE
        ):
            return DYNAMIC_FIELDS_CUSTOM_BASE_URL
        return DYNAMIC_FIELDS_DEFAULT

    def _action_label(self, action_value: str) -> str:
        """Return the UI label of an action, for use in log messages.

        Args:
            action_value (str): Action value, e.g. ``scan_data_now``.

        Returns:
            str: The action's label, or the raw value when unknown.
        """
        return ACTION_LABELS.get(action_value, action_value)

    def _param_label(self, param_key: str) -> str:
        """Return the UI label of an action parameter.

        Args:
            param_key (str): Parameter key, e.g. ``tag_key``.

        Returns:
            str: The parameter's label, or the raw key when unknown.
        """
        return ACTION_PARAM_LABELS.get(param_key, param_key)

    # ------------------------------------------------------------------
    # Entity definitions
    # ------------------------------------------------------------------

    def get_entities(self) -> List[Entity]:
        """Return the list of entities exposed by this plugin.

        Enrichment fields are appended to ``Workloads``/``Users`` only when
        the matching configuration option is enabled - the 'Fetch
        Additional Workload Details' selections for Workloads, and the
        'Fetch Custom Tags' toggle for both entities; when disabled they
        are absent from the schema entirely (not merely empty).

        Returns:
            List[Entity]: Workloads and Users entities.
        """
        fetch_linked_counts = self._has_device_detail(DEVICE_DETAIL_COUNTS)
        fetch_ports = self._has_device_detail(DEVICE_DETAIL_PORTS)
        fetch_custom_tags = self._is_enabled(CONFIG_FETCH_CUSTOM_TAGS)

        device_fields = [
            EntityField(
                name=FIELD_ENTITY_UNIQUE_ID,
                type=EntityFieldType.STRING,
                description="Unique Orca identifier of the workload asset.",
                required=True,
            ),
            EntityField(
                name=FIELD_ENTITY_ID,
                type=EntityFieldType.STRING,
                description="Orca's internal object ID for the asset.",
                required=True,
            ),
            EntityField(
                name=FIELD_HOSTNAME,
                type=EntityFieldType.STRING,
                description="Hostname of the workload.",
                required=True,
            ),
            EntityField(
                name="Asset Name",
                type=EntityFieldType.STRING,
                description="Name of the asset as reported by Orca.",
            ),
            EntityField(
                name=FIELD_TYPE,
                type=EntityFieldType.STRING,
                description="Orca model type of the workload.",
                required=True,
            ),
            EntityField(
                name="Cloud Provider",
                type=EntityFieldType.STRING,
                description=(
                    "Cloud provider derived from the workload's model"
                    " type (AWS, Azure, GCP, OCI, Kubernetes)."
                ),
            ),
            EntityField(
                name="Category",
                type=EntityFieldType.STRING,
                description="Orca asset category.",
            ),
            EntityField(
                name="Risk Level",
                type=EntityFieldType.STRING,
                description="Orca risk level.",
            ),
            EntityField(
                name="Risk Score",
                type=EntityFieldType.NUMBER,
                description=(
                    "Orca's continuous risk "
                    "score between 0.0 and 10.0."
                ),
            ),
            EntityField(
                name=FIELD_NORMALIZED_SCORE,
                type=EntityFieldType.NUMBER,
                description="Netskope Normalized Score.",
            ),
            EntityField(
                name="State",
                type=EntityFieldType.STRING,
                description="Current lifecycle state of the workload.",
            ),
            EntityField(
                name=FIELD_EXPOSURE,
                type=EntityFieldType.STRING,
                description="Orca-assessed network exposure of the workload.",
            ),
            EntityField(
                name="Is Internet Facing",
                type=EntityFieldType.BOOLEAN,
                description="Whether the workload is internet-facing.",
            ),
            EntityField(
                name="Is Crown Jewel",
                type=EntityFieldType.BOOLEAN,
                description="Whether Orca flagged the asset as a crown jewel.",
            ),
            EntityField(
                name="Crown Jewel Score",
                type=EntityFieldType.NUMBER,
                description="Orca's detected crown-jewel score.",
            ),
            EntityField(
                name="Crown Jewel Reason",
                type=EntityFieldType.STRING,
                description="Reason Orca flagged the asset as a crown jewel.",
            ),
            EntityField(
                name="Public IP",
                type=EntityFieldType.STRING,
                description="Public IP address of the workload.",
            ),
            EntityField(
                name="Private IP",
                type=EntityFieldType.STRING,
                description="Private IP address of the workload.",
            ),
            EntityField(
                name="Public DNS",
                type=EntityFieldType.LIST,
                description="Public DNS name of the workload.",
            ),
            EntityField(
                name="Private DNS",
                type=EntityFieldType.LIST,
                description="Private DNS name of the workload.",
            ),
            EntityField(
                name="MAC Addresses",
                type=EntityFieldType.LIST,
                description="MAC address of the workload.",
            ),
            EntityField(
                name="Region",
                type=EntityFieldType.STRING,
                description="Cloud region of the workload.",
            ),
            EntityField(
                name="Availability Zones",
                type=EntityFieldType.LIST,
                description="Availability zone(s) of the workload.",
            ),
            EntityField(
                name="Matched CVEs",
                type=EntityFieldType.NUMBER,
                description="Number of matched CVEs on the workload.",
            ),
            EntityField(
                name="Max CVSS Score",
                type=EntityFieldType.NUMBER,
                description="Maximum CVSS score among matched CVEs.",
            ),
            EntityField(
                name=FIELD_TAGS,
                type=EntityFieldType.LIST,
                description="Cloud-provider tags, as 'key: value' strings.",
            ),
            EntityField(
                name=FIELD_MODEL_TAGS,
                type=EntityFieldType.LIST,
                description="Orca model tags, as 'key: value' strings.",
            ),
        ]
        if fetch_linked_counts:
            device_fields.extend(
                [
                    EntityField(
                        name="Alerts Count",
                        type=EntityFieldType.NUMBER,
                        description="Number of linked alerts on the workload.",
                    ),
                    EntityField(
                        name="Login Attempts Count",
                        type=EntityFieldType.NUMBER,
                        description="Number of linked login attempts.",
                    ),
                    EntityField(
                        name="Vulnerability Count",
                        type=EntityFieldType.NUMBER,
                        description="Number of linked vulnerabilities.",
                    ),
                ]
            )
        if fetch_ports:
            device_fields.extend(
                [
                    EntityField(
                        name=FIELD_PORTS,
                        type=EntityFieldType.LIST,
                        description="Open listening ports on the workload.",
                    ),
                    EntityField(
                        name=FIELD_PORT_SERVICES,
                        type=EntityFieldType.LIST,
                        description="Service names for the open ports.",
                    ),
                    EntityField(
                        name=FIELD_PORT_PROTOCOLS,
                        type=EntityFieldType.LIST,
                        description=(
                            "Protocols of the open ports."
                        ),
                    ),
                ]
            )
        if fetch_custom_tags:
            device_fields.append(
                EntityField(
                    name=FIELD_CUSTOM_TAGS,
                    type=EntityFieldType.LIST,
                    description="Custom/Manual tags.",
                )
            )

        user_fields = [
            EntityField(
                name=FIELD_ENTITY_UNIQUE_ID,
                type=EntityFieldType.STRING,
                description="Unique Orca identifier of the user asset.",
                required=True,
            ),
            EntityField(
                name=FIELD_ENTITY_ID,
                type=EntityFieldType.STRING,
                description="Orca's internal object ID for the asset.",
                required=True,
            ),
            EntityField(
                name=FIELD_EMAIL,
                type=EntityFieldType.STRING,
                description="Email address of the user.",
                required=True,
            ),
            EntityField(
                name=FIELD_DISPLAY_NAME,
                type=EntityFieldType.STRING,
                description="Display name of the user.",
            ),
            EntityField(
                name=FIELD_TYPE,
                type=EntityFieldType.STRING,
                description="Orca model type of the identity.",
            ),
            EntityField(
                name="Cloud Provider",
                type=EntityFieldType.STRING,
                description=(
                    "Cloud provider derived from the identity's model"
                    " type (AWS, Azure, GCP, OCI, Kubernetes)."
                ),
            ),
            EntityField(
                name="Category",
                type=EntityFieldType.STRING,
                description="Orca asset category.",
            ),
            EntityField(
                name="Risk Level",
                type=EntityFieldType.STRING,
                description="Orca risk level.",
            ),
            EntityField(
                name="Risk Score",
                type=EntityFieldType.NUMBER,
                description=(
                    "Orca's continuous risk "
                    "score between 0.0 and 10.0."
                ),
            ),
            EntityField(
                name=FIELD_NORMALIZED_SCORE,
                type=EntityFieldType.NUMBER,
                description="Netskope Normalized Score.",
            ),
            EntityField(
                name="State",
                type=EntityFieldType.STRING,
                description="Current lifecycle state of the identity.",
            ),
            EntityField(
                name=FIELD_TAGS,
                type=EntityFieldType.LIST,
                description="Cloud-provider tags, as 'key: value' strings.",
            ),
            EntityField(
                name=FIELD_MODEL_TAGS,
                type=EntityFieldType.LIST,
                description="Orca model tags, as 'key: value' strings.",
            ),
        ]
        if fetch_custom_tags:
            user_fields.append(
                EntityField(
                    name=FIELD_CUSTOM_TAGS,
                    type=EntityFieldType.LIST,
                    description="Custom/Manual tags.",
                )
            )

        return [
            Entity(name=DEVICES, fields=device_fields),
            Entity(name=USERS, fields=user_fields),
        ]

    # ------------------------------------------------------------------
    # fetch_records
    # ------------------------------------------------------------------

    def fetch_records(self, entity: str) -> List[Dict]:
        """Fetch all records for the given entity type from Orca Security.

        Args:
            entity (str): One of ``Workloads``, ``Users``.

        Returns:
            List[Dict]: List of normalised record dictionaries, deduped
                by ``asset_unique_id`` (last write wins across
                types/pages).

        Raises:
            OrcaSecurityPluginException: On any API or unexpected error.
        """
        try:
            self.helper.validate_entity(entity, SUPPORTED_ENTITIES)
            return self._fetch_entity_records(entity)
        except OrcaSecurityPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while fetching {entity} records."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise OrcaSecurityPluginException(err_msg)

    def _fetch_entity_records(self, entity: str) -> List[Dict]:
        """Core pull implementation shared by both entities.

        Args:
            entity (str): One of ``Workloads``, ``Users``.

        Returns:
            List[Dict]: Normalised, deduped record dictionaries.
        """
        (
            base_url,
            api_token,
            device_models,
            user_models,
            *_,
        ) = self.helper.get_configuration_parameters(self.configuration)
        headers = self.helper.get_auth_headers(api_token)

        if entity == DEVICES:
            models = device_models or DEVICE_MODELS
            mapping = DEVICE_FIELD_MAPPING
        else:
            models = user_models or USER_MODELS
            mapping = USER_FIELD_MAPPING

        entity_label = ENTITY_LABEL_SINGULAR.get(entity, entity)
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity.lower()} records from"
            f" {PLATFORM_NAME} platform."
        )

        collected: Dict[str, Dict] = {}
        skip_count = 0
        duplicate_count = 0
        invalid_score_count = 0

        raw_items = self.helper.paginate_object_set(
            headers=headers,
            base_url=base_url,
            models=models,
            entity_label=entity_label,
        )
        for raw in raw_items:
            asset_unique_id = raw.get("asset_unique_id")
            orca_id = raw.get("id")
            if not asset_unique_id or not orca_id:
                skip_count += 1
                continue

            record = self.helper.extract_entity_fields(raw, mapping)

            if entity == DEVICES:
                hostname = self.helper._first_non_empty(
                    *[
                        self.helper._extract_field_from_event(key, raw, None)
                        for key in DEVICE_HOSTNAME_FALLBACK_KEYS
                    ]
                )
                if not hostname:
                    skip_count += 1
                    continue
                self.helper.add_field(record, FIELD_HOSTNAME, hostname)
            else:
                self.helper.add_field(
                    record,
                    FIELD_DISPLAY_NAME,
                    self.helper._first_non_empty(
                        *[
                            self.helper._extract_field_from_event(
                                key, raw, None
                            )
                            for key in USER_DISPLAY_NAME_FALLBACK_KEYS
                        ]
                    ),
                )

            self.helper.add_field(
                record, FIELD_ENTITY_UNIQUE_ID, asset_unique_id
            )
            self.helper.add_field(
                record, FIELD_TAGS, self.helper._extract_tag_dict(raw, "Tags")
            )
            self.helper.add_field(
                record,
                FIELD_MODEL_TAGS,
                self.helper._extract_tag_dict(raw, "ModelTags"),
            )

            score, invalid = self.helper.normalize_score(
                raw.get("OrcaScore")
            )
            if invalid:
                invalid_score_count += 1
            if score is not None:
                self.helper.add_field(record, FIELD_NORMALIZED_SCORE, score)

            if asset_unique_id in collected:
                duplicate_count += 1
            collected[asset_unique_id] = record

        skip_reason = (
            f"{FIELD_ENTITY_UNIQUE_ID}, {FIELD_ENTITY_ID}, or"
            f" {FIELD_HOSTNAME}"
            if entity == DEVICES
            else f"{FIELD_ENTITY_UNIQUE_ID} or {FIELD_ENTITY_ID}"
        )
        skip_msg = (
            f" Skipped {skip_count} {entity_label} record(s) as they do"
            f" not have {skip_reason}."
            if skip_count
            else ""
        )
        duplicate_msg = (
            f" Deduplicated {duplicate_count} {entity_label} record(s)"
            f" sharing an {FIELD_ENTITY_UNIQUE_ID} with another record"
            " across types/pages; the last one fetched was kept."
            if duplicate_count
            else ""
        )
        if invalid_score_count:
            self.logger.info(
                f"{self.log_prefix}: Skipped calculating Netskope"
                f" Normalized Score for {invalid_score_count}"
                f" {entity_label} record(s) due to invalid Risk Score."
                f" Valid Risk Score range is [{MIN_ORCA_SCORE},"
                f" {MAX_ORCA_SCORE}]."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(collected)}"
            f" {entity} record(s) from {PLATFORM_NAME}."
            f"{skip_msg}{duplicate_msg}"
        )
        return list(collected.values())

    # ------------------------------------------------------------------
    # update_records
    # ------------------------------------------------------------------

    def update_records(self, entity: str, records: List[Dict]) -> List[Dict]:
        """Enrich existing records with live data from Orca Security.

        Driven by the incoming ``records`` argument (filtered to those
        with ``Entity ID`` present) rather than a re-pull. Users are only
        enriched when ``fetch_custom_tags`` is enabled (no other
        enrichment is defined for Users).

        Args:
            entity (str): One of ``Workloads``, ``Users``.
            records (List[Dict]): Existing records from the CE store.

        Returns:
            List[Dict]: Only the records actually enriched, with new
                fields merged in. Always a list, never ``None``.

        Raises:
            OrcaSecurityPluginException: On entity validation failure or
                unexpected error.
        """
        try:
            self.helper.validate_entity(entity, SUPPORTED_ENTITIES)

            if not records:
                self.logger.info(
                    f"{self.log_prefix}: Skipping {entity} records to update."
                )
                return []

            self.logger.info(
                f"{self.log_prefix}: Updating {len(records)} {entity}"
                f" record(s) from {PLATFORM_NAME}."
            )
            if entity == DEVICES:
                return self._update_device_records(records)
            return self._update_user_records(records)
        except OrcaSecurityPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while updating {entity} records."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise OrcaSecurityPluginException(err_msg)

    def _get_enrichable_records(
        self, records: List[Dict], entity_label: str
    ) -> Tuple[List[Dict], Dict, str]:
        """Filter records down to those the plugin can enrich.

        Args:
            records (List[Dict]): Existing records from the CE store.
            entity_label (str): Singular entity label used in log lines.

        Returns:
            Tuple: ``(enrichable_records, auth_headers, base_url)``.
                ``auth_headers`` and ``base_url`` are empty when there
                is nothing to enrich.
        """
        enrichable = [
            record
            for record in records
            if self.helper.get_scalar_field(record, FIELD_ENTITY_ID)
        ]
        skipped = len(records) - len(enrichable)
        skip_msg = (
            f" Skipped {skipped} record(s) as they do not have"
            f" {FIELD_ENTITY_ID}."
            if skipped
            else ""
        )
        self.logger.info(
            f"{self.log_prefix}: {len(enrichable)} of {len(records)}"
            f" {entity_label.lower()} record(s) will be enriched."
            f"{skip_msg}"
        )
        if not enrichable:
            return [], {}, ""

        base_url, api_token, *_ = self.helper.get_configuration_parameters(
            self.configuration
        )
        return enrichable, self.helper.get_auth_headers(api_token), base_url

    def _fetch_custom_tags_for_records(
        self,
        records: List[Dict],
        headers: Dict,
        base_url: str,
        entity_label: str,
    ) -> Dict[str, List[str]]:
        """Fetch custom tags for each record, one API call per asset.

        Failures are counted and reported once at the end rather than
        logged per asset, so a tenant-wide outage cannot flood the log
        with one error line per record.

        Args:
            records (List[Dict]): Records to fetch custom tags for.
            headers (Dict): Authentication headers.
            base_url (str): Configured Orca Security base URL.
            entity_label (str): Singular entity label used in log lines.

        Returns:
            Dict[str, List[str]]: ``Entity Unique ID -> ["key: value"]``
                for every asset whose tags were fetched successfully. The
                list is EMPTY when the asset has no custom tags left, so
                the caller still emits an update that clears the stale
                value. Assets whose fetch failed are absent entirely, so
                a transient API error never wipes tags that are still
                set on the platform — callers must test membership, not
                truthiness.
        """
        tags_by_record: Dict[str, List[str]] = {}
        failure_count = 0
        last_error = ""
        total = len(records)

        for index, record in enumerate(records, start=1):
            if index % PROGRESS_LOG_INTERVAL == 0 or index == total:
                self.logger.info(
                    f"{self.log_prefix}: Processed custom tags for"
                    f" {index} of {total} {entity_label.lower()}"
                    " record(s)."
                )
            merge_key = self.helper.get_scalar_field(
                record, FIELD_ENTITY_UNIQUE_ID
            )
            asset_id = self.helper.get_scalar_field(record, FIELD_ENTITY_ID)
            if not merge_key or not asset_id:
                continue
            try:
                tags_data = self.helper.fetch_custom_tags(
                    headers, base_url, asset_id
                )
            except OrcaSecurityPluginException as exp:
                failure_count += 1
                last_error = str(exp)
                continue
            except Exception as exp:
                failure_count += 1
                last_error = str(exp)
                self.logger.debug(
                    f"{self.log_prefix}: Unexpected error occurred while"
                    f" fetching custom tags for asset '{asset_id}'."
                    f" Error: {exp}"
                )
                continue
            tags_by_record[merge_key] = self.helper.format_tag_pairs(
                tags_data
            )

        if failure_count:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while fetching"
                    f" custom tags for {failure_count} of {total}"
                    f" {entity_label.lower()} record(s). These record(s)"
                    f" will not be enriched. Error: {last_error}"
                ),
                resolution=(
                    "Ensure the API Token has read access to the Orca"
                    " manual tags API and that the assets still exist on"
                    f" the {PLATFORM_NAME} tenant."
                ),
            )
        return tags_by_record

    def _update_device_records(self, records: List[Dict]) -> List[Dict]:
        """Enrich Workload records with linked-entity counts, ports, and/or
        custom tags.

        Args:
            records (List[Dict]): Existing workload records.

        Returns:
            List[Dict]: Partial records (id fields + newly enriched
                fields) for workloads that were actually enriched.
        """
        fetch_linked_counts = self._has_device_detail(DEVICE_DETAIL_COUNTS)
        fetch_ports = self._has_device_detail(DEVICE_DETAIL_PORTS)
        fetch_custom_tags = self._is_enabled(CONFIG_FETCH_CUSTOM_TAGS)
        if not any((fetch_linked_counts, fetch_ports, fetch_custom_tags)):
            self.logger.info(
                f"{self.log_prefix}: All workload enrichments are disabled"
                " in the plugin configuration. Skipping the update cycle"
                f" for {DEVICES}."
            )
            return []

        entity_label = ENTITY_LABEL_SINGULAR.get(DEVICES, DEVICES)
        enrichable, headers, base_url = self._get_enrichable_records(
            records, entity_label
        )
        if not enrichable:
            return []

        merged: Dict[str, Dict] = {}

        def _merge_target(merge_key: str, asset_id: str) -> Dict:
            """Get (or create) the partial record for an asset."""
            return merged.setdefault(
                merge_key,
                {
                    FIELD_ENTITY_UNIQUE_ID: merge_key,
                    FIELD_ENTITY_ID: asset_id,
                },
            )

        # Per-enrichment success counts, reported individually in the
        # summary below. A single blended total cannot be trusted here:
        # each enrichment fails independently, and open ports are fetched
        # in batches that merge every workload in a successful batch, so
        # `len(merged)` reads as a full success even when every
        # per-workload linked-counts or custom-tags call failed.
        updated_counts: List[Tuple[str, int]] = []

        if fetch_ports:
            updated_counts.append(
                (
                    "open ports",
                    self._enrich_open_ports(
                        enrichable, headers, base_url, _merge_target
                    ),
                )
            )

        if fetch_linked_counts:
            updated_counts.append(
                (
                    "linked entity counts",
                    self._enrich_linked_entity_counts(
                        enrichable, headers, base_url, _merge_target
                    ),
                )
            )

        if fetch_custom_tags:
            tags_by_record = self._fetch_custom_tags_for_records(
                enrichable, headers, base_url, entity_label
            )
            tags_updated = 0
            for record in enrichable:
                merge_key = self.helper.get_scalar_field(
                    record, FIELD_ENTITY_UNIQUE_ID
                )
                if merge_key not in tags_by_record:
                    continue
                enriched = _merge_target(
                    merge_key,
                    self.helper.get_scalar_field(record, FIELD_ENTITY_ID),
                )
                # Assigned directly rather than through add_field(): an
                # empty list must reach Cloud Exchange as [] so a tag
                # removed on Orca clears the field instead of leaving
                # the stale value.
                enriched[FIELD_CUSTOM_TAGS] = tags_by_record[merge_key]
                tags_updated += 1
            updated_counts.append(("custom tags", tags_updated))

        self.logger.info(
            f"{self.log_prefix}: Successfully updated"
            f" {self._format_updated_counts(updated_counts)}, of"
            f" {len(records)} {entity_label} record(s) received."
        )
        return list(merged.values())

    def _format_updated_counts(
        self, updated_counts: List[Tuple[str, int]]
    ) -> str:
        """Join per-enrichment counts into one readable clause.

        Args:
            updated_counts (List[Tuple[str, int]]): ``(enrichment name,
                records updated)`` for each ENABLED enrichment, in the
                order they should be reported.

        Returns:
            str: e.g. ``"5 record(s) for open ports, 3 record(s) for
                linked entity counts and 4 record(s) for custom tags"``.
                Empty when no enrichment is enabled.
        """
        parts = [
            f"{count} record(s) for {name}" for name, count in updated_counts
        ]
        if len(parts) <= 1:
            return "".join(parts)
        return f"{', '.join(parts[:-1])} and {parts[-1]}"

    def _enrich_linked_entity_counts(
        self,
        records: List[Dict],
        headers: Dict,
        base_url: str,
        merge_target,
    ) -> int:
        """Add linked-entity counts to the merged Workload records.

        The Orca endpoint takes a single asset per call, so this is one
        API call per workload. Failures are counted and reported once at
        the end instead of one error line per workload.

        Args:
            records (List[Dict]): Enrichable workload records.
            headers (Dict): Authentication headers.
            base_url (str): Configured Orca Security base URL.
            merge_target (Callable): Returns the partial record to write
                the enriched fields into, given a merge key and asset ID.

        Returns:
            int: Number of workload records the counts were merged into.
        """
        failure_count = 0
        enriched_count = 0
        last_error = ""
        total = len(records)

        for index, record in enumerate(records, start=1):
            if index % PROGRESS_LOG_INTERVAL == 0 or index == total:
                self.logger.info(
                    f"{self.log_prefix}: Processed linked entity counts"
                    f" for {index} of {total} workload record(s)."
                )
            merge_key = self.helper.get_scalar_field(
                record, FIELD_ENTITY_UNIQUE_ID
            )
            asset_id = self.helper.get_scalar_field(record, FIELD_ENTITY_ID)
            model = self.helper.get_scalar_field(record, FIELD_TYPE)
            if not merge_key or not asset_id or not model:
                continue
            try:
                counts = self.helper.fetch_linked_entity_counts(
                    headers, base_url, model, asset_id
                )
            except OrcaSecurityPluginException as exp:
                failure_count += 1
                last_error = str(exp)
                continue
            except Exception as exp:
                failure_count += 1
                last_error = str(exp)
                self.logger.debug(
                    f"{self.log_prefix}: Unexpected error occurred while"
                    f" fetching linked entity counts for asset"
                    f" '{asset_id}'. Error: {exp}"
                )
                continue
            # fetch_linked_entity_counts() always returns all three known
            # fields, defaulting an absent relation to 0, so a count that
            # has since gone to zero is written explicitly rather than
            # leaving a prior non-zero value stale.
            enriched = merge_target(merge_key, asset_id)
            for field_name, value in counts.items():
                self.helper.add_field(enriched, field_name, value)
            enriched_count += 1

        if failure_count:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while fetching"
                    f" linked entity counts for {failure_count} of"
                    f" {total} workload record(s). These record(s) will not"
                    f" be enriched. Error: {last_error}"
                ),
                resolution=(
                    "Ensure the API Token has read access to the Orca"
                    " serving layer and that the assets still exist on"
                    f" the {PLATFORM_NAME} tenant."
                ),
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched linked entity counts"
            f" for {enriched_count} of {total} workload record(s)."
        )
        return enriched_count

    def _enrich_open_ports(
        self,
        records: List[Dict],
        headers: Dict,
        base_url: str,
        merge_target,
    ) -> int:
        """Add open listening ports to the merged Workload records.

        Workloads are queried together in batches of up to
        ``LOCAL_PORT_BATCH_SIZE`` via a single combined API call per
        batch (rather than one call per workload); each returned
        ``LocalPort`` record is attributed back to its workload through
        the nested ``Compute.id`` field in the response.

        The ``public_facing`` test is applied to each returned port
        rather than to the workload record, because the workload's own
        ``Exposure`` value is not guaranteed to be present on a stored
        record and the port-level value is what actually determines
        whether that port is reachable from outside.

        Args:
            records (List[Dict]): Enrichable workload records.
            headers (Dict): Authentication headers.
            base_url (str): Configured Orca Security base URL.
            merge_target (Callable): Returns the partial record to write
                the enriched fields into, given a merge key and asset ID.

        Returns:
            int: Number of workload records the ports were merged into.
        """
        total = len(records)
        self.logger.info(
            f"{self.log_prefix}: Fetching open ports for {total} workload"
            " record(s)."
        )

        merge_key_by_device_id: Dict[str, str] = {}
        for record in records:
            merge_key = self.helper.get_scalar_field(
                record, FIELD_ENTITY_UNIQUE_ID
            )
            device_id = self.helper.get_scalar_field(record, FIELD_ENTITY_ID)
            if not merge_key or not device_id:
                continue
            merge_key_by_device_id[device_id] = merge_key

        if not merge_key_by_device_id:
            return 0

        ports_by_device = self.helper.fetch_local_ports_for_devices(
            headers, base_url, list(merge_key_by_device_id.keys())
        )

        updated_count = 0
        with_ports_count = 0
        for device_id, merge_key in merge_key_by_device_id.items():
            ports_data = ports_by_device.get(device_id)
            if ports_data is None:
                # Left out of the merge entirely: this workload's batch
                # failed, so a transient API error must not clear ports
                # that are still open on the workload.
                continue
            # A workload that no longer exposes any public-facing port is
            # still merged, with empty lists, so the stale port data is
            # cleared rather than left behind. Assigned directly rather
            # than through add_field(), which would store [] as None.
            enriched = merge_target(merge_key, device_id)
            for field_name in (
                FIELD_PORTS,
                FIELD_PORT_SERVICES,
                FIELD_PORT_PROTOCOLS,
            ):
                enriched[field_name] = ports_data.get(field_name, [])
            updated_count += 1
            if ports_data.get(FIELD_PORTS):
                with_ports_count += 1

        self.logger.info(
            f"{self.log_prefix}: Successfully updated open ports for"
            f" {updated_count} of {total} workload record(s). Found public"
            f" facing open port(s) on {with_ports_count} record(s)."
        )
        return updated_count

    def _update_user_records(self, records: List[Dict]) -> List[Dict]:
        """Enrich User records with custom tags.

        Args:
            records (List[Dict]): Existing user records.

        Returns:
            List[Dict]: Partial records (id fields + newly enriched
                fields) for users that were actually enriched.
        """
        if not self._is_enabled(CONFIG_FETCH_CUSTOM_TAGS):
            self.logger.info(
                f"{self.log_prefix}: Custom Tags enrichment is disabled"
                " in the plugin configuration. Skipping the update cycle"
                f" for {USERS}."
            )
            return []

        entity_label = ENTITY_LABEL_SINGULAR.get(USERS, USERS)
        enrichable, headers, base_url = self._get_enrichable_records(
            records, entity_label
        )
        if not enrichable:
            return []

        tags_by_record = self._fetch_custom_tags_for_records(
            enrichable, headers, base_url, entity_label
        )

        updated_records = []
        tagged_count = 0
        for record in enrichable:
            merge_key = self.helper.get_scalar_field(
                record, FIELD_ENTITY_UNIQUE_ID
            )
            if merge_key not in tags_by_record:
                continue
            custom_tags = tags_by_record[merge_key]
            # Assigned directly rather than through add_field(): an empty
            # list must reach Cloud Exchange as [] so a tag removed on
            # Orca clears the field instead of leaving the stale value.
            updated_records.append(
                {
                    FIELD_ENTITY_UNIQUE_ID: merge_key,
                    FIELD_ENTITY_ID: self.helper.get_scalar_field(
                        record, FIELD_ENTITY_ID
                    ),
                    FIELD_EMAIL: self.helper.get_scalar_field(
                        record, FIELD_EMAIL
                    ),
                    FIELD_CUSTOM_TAGS: custom_tags,
                }
            )
            if custom_tags:
                tagged_count += 1

        self.logger.info(
            f"{self.log_prefix}: Successfully updated"
            f" {len(updated_records)} of {len(records)} {entity_label}"
            " record(s) received. Fetched custom tag(s) for"
            f" {tagged_count} record(s)."
        )
        return updated_records

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def get_actions(self) -> List[ActionWithoutParams]:
        """Return the list of supported actions for this plugin.

        Returns:
            List[ActionWithoutParams]: Supported action descriptors.
        """
        return [
            ActionWithoutParams(
                label=self._action_label(action_value),
                value=action_value,
            )
            for action_value in SUPPORTED_ACTIONS
        ]

    def get_action_params(self, action: Action) -> List:
        """Return the UI parameter descriptors for a given action.

        Args:
            action (Action): The selected action.

        Returns:
            List[dict]: Parameter field descriptors for the CE UI.
        """
        if action.value == ACTION_NO_ACTION:
            return []

        if action.value == ACTION_SCAN_DATA_NOW:
            return [
                {
                    "label": self._param_label(PARAM_ASSET_UNIQUE_ID),
                    "key": PARAM_ASSET_UNIQUE_ID,
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "The Orca 'asset_unique_id' of the asset to scan."
                        " Select the 'Entity Unique ID' source field to"
                        " resolve it automatically from each Business"
                        " Rule matched record, or enter one fixed value"
                        " to scan a single specific asset regardless of"
                        " which records matched."
                    ),
                }
            ]

        if action.value == ACTION_ADD_REMOVE_TAG:
            return [
                {
                    "label": self._param_label(PARAM_TAG_ACTION),
                    "key": PARAM_TAG_ACTION,
                    "type": "choice",
                    "choices": [
                        {"key": "Add", "value": TAG_ACTION_ADD},
                        {"key": "Remove", "value": TAG_ACTION_REMOVE},
                    ],
                    "default": TAG_ACTION_ADD,
                    "mandatory": True,
                    "description": (
                        "Whether to add or remove the tag on the asset."
                        " Select Tag Action from the static dropdown"
                        " only."
                    ),
                },
                {
                    "label": self._param_label(PARAM_TAG_KEY),
                    "key": PARAM_TAG_KEY,
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Key of the custom tag to add/remove. "
                        "Select static field only."
                    ),
                },
                {
                    "label": self._param_label(PARAM_TAG_VALUE),
                    "key": PARAM_TAG_VALUE,
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Value of the custom tag. Required when Tag"
                        " Action is 'Add' only. Select static field only."
                    ),
                },
                {
                    "label": self._param_label(PARAM_ASSET_ID),
                    "key": PARAM_ASSET_ID,
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "The Orca 'id' of the asset to tag/untag. Select"
                        " the 'Entity ID' source field to resolve it"
                        " automatically from each Business Rule matched"
                        " record, or enter one fixed static value to tag/untag"
                        " a single specific asset regardless of which"
                        " records matched."
                    ),
                },
            ]

        return []

    def execute_actions(self, actions: List) -> ActionResult:
        """Execute a batch of actions against Orca Security.

        Wraps :meth:`_execute_actions` so that an unexpected error raised
        before or between the per-request try/except blocks (e.g. a
        malformed ``actions`` entry) still returns every action ID as
        failed instead of escaping to the framework with no attribution.

        Args:
            actions (List): Actions supplied by the CE framework as
                ``{"id": ..., "params": Action}`` dicts.

        Returns:
            ActionResult: Reports per-action failures to the framework.
        """
        try:
            return self._execute_actions(actions)
        except Exception as exp:
            err_msg = "Unexpected error occurred while executing actions."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ActionResult(
                success=False,
                message=err_msg,
                failed_action_ids=[action.get("id") for action in actions],
            )

    def _execute_actions(self, actions: List) -> ActionResult:
        """Core implementation of :meth:`execute_actions`.

        Neither 'Scan Data Now' nor 'Add/Remove Custom Tag' has a bulk API
        form, so each is issued per asset. Requests are de-duplicated
        first: a Business Rule matching many records that all resolve to
        the same asset (or a fixed asset ID typed into the action form)
        would otherwise repeat the identical call once per record.

        A failure on one asset fails only the actions that targeted it —
        the rest of the batch still executes — and every failed action ID
        is reported back to the framework.

        Args:
            actions (List): Actions supplied by the CE framework as
                ``{"id": ..., "params": Action}`` dicts.

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
        action_label = self._action_label(action_value)

        if action_value == ACTION_NO_ACTION:
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action"
                f" '{action_label}' on {len(actions)} record(s). Note: No"
                " processing will be done from plugin for the"
                f" '{action_label}' action."
            )
            return ActionResult(
                success=True,
                message="Action execution completed.",
                failed_action_ids=[],
            )

        if action_value not in SUPPORTED_ACTIONS:
            err_msg = (
                f"Unsupported action '{action_value}' provided in the"
                " action configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the action is selected from the list of"
                    " supported actions in the action configuration."
                ),
            )
            return ActionResult(
                success=False,
                message=err_msg,
                failed_action_ids=[
                    action.get("id") for action in actions
                ],
            )

        base_url, api_token, *_ = self.helper.get_configuration_parameters(
            self.configuration
        )
        headers = self.helper.get_auth_headers(api_token)

        # Distinct request -> action IDs that asked for it, so one failed
        # call can be attributed back to every action it came from.
        requests_map: Dict[Tuple, List] = {}
        failed_action_ids = []

        for action in actions:
            action_id = action.get("id")
            parameters = action.get("params").parameters or {}
            request_key, err_msg = (
                self._build_scan_request(parameters)
                if action_value == ACTION_SCAN_DATA_NOW
                else self._build_tag_request(parameters)
            )
            if request_key is None:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping action"
                        f" '{action_label}' for a record. {err_msg}"
                    ),
                    resolution=(
                        "Ensure the mapped Source field is populated on"
                        " the matched record, or provide a static value"
                        " in the action configuration."
                    ),
                )
                failed_action_ids.append(action_id)
                continue
            requests_map.setdefault(request_key, []).append(action_id)

        self.logger.info(
            f"{self.log_prefix}: Performing action '{action_label}' on"
            f" {len(requests_map)} unique asset(s) resolved from"
            f" {len(actions)} record(s)."
        )

        success_count = 0
        for request_key, action_ids in requests_map.items():
            try:
                if action_value == ACTION_SCAN_DATA_NOW:
                    self._execute_scan_data_now(
                        headers, base_url, request_key[0]
                    )
                else:
                    self._execute_add_remove_tag(
                        headers, base_url, *request_key
                    )
                success_count += 1
            except OrcaSecurityPluginException:
                failed_action_ids.extend(action_ids)
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred"
                        f" while performing action '{action_label}' on"
                        f" asset '{request_key[0]}'. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
                failed_action_ids.extend(action_ids)

        failed_msg = (
            f" Failed to perform the action on"
            f" {len(requests_map) - success_count} asset(s)."
            if success_count < len(requests_map)
            else ""
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully performed action"
            f" '{action_label}' on {success_count} of"
            f" {len(requests_map)} asset(s).{failed_msg}"
        )
        return ActionResult(
            success=True,
            message="Action execution completed.",
            failed_action_ids=list(dict.fromkeys(failed_action_ids)),
        )

    def _build_scan_request(
        self, parameters: Dict
    ) -> Tuple[Optional[Tuple], str]:
        """Resolve the 'Scan Data Now' parameters for one record.

        Args:
            parameters (Dict): The action's resolved parameters.

        Returns:
            Tuple: ``(request_key, error_message)``. ``request_key`` is
                ``None`` when the record cannot be acted on.
        """
        asset_unique_id = self.helper.get_stripped_param(
            parameters, PARAM_ASSET_UNIQUE_ID
        )
        if not asset_unique_id:
            return None, (
                f"No '{self._param_label(PARAM_ASSET_UNIQUE_ID)}' value"
                " was resolved."
            )
        return (asset_unique_id,), ""

    def _build_tag_request(
        self, parameters: Dict
    ) -> Tuple[Optional[Tuple], str]:
        """Resolve the 'Add/Remove Custom Tag' parameters for one record.

        Tag Action and Tag Key are re-checked here because both can be
        mapped to a Source field, in which case configuration-time
        validation is deferred to execution.

        Args:
            parameters (Dict): The action's resolved parameters.

        Returns:
            Tuple: ``(request_key, error_message)``. ``request_key`` is
                ``None`` when the record cannot be acted on.
        """
        asset_id = self.helper.get_stripped_param(
            parameters, PARAM_ASSET_ID
        )
        tag_action = self.helper.get_stripped_param(
            parameters, PARAM_TAG_ACTION
        ).lower()
        tag_key = self.helper.get_stripped_param(parameters, PARAM_TAG_KEY)
        tag_value = self.helper.get_stripped_param(
            parameters, PARAM_TAG_VALUE
        )

        if not asset_id:
            return None, (
                f"No '{self._param_label(PARAM_ASSET_ID)}' value was"
                " resolved."
            )
        if tag_action not in TAG_ACTIONS:
            return None, (
                f"Invalid '{self._param_label(PARAM_TAG_ACTION)}' value"
                f" '{tag_action}' resolved. Allowed values are"
                f" {TAG_ACTIONS}."
            )
        if not tag_key:
            return None, (
                f"No '{self._param_label(PARAM_TAG_KEY)}' value was"
                " resolved."
            )
        if tag_action == TAG_ACTION_ADD and not tag_value:
            return None, (
                f"No '{self._param_label(PARAM_TAG_VALUE)}' value was"
                f" resolved, which is required when"
                f" '{self._param_label(PARAM_TAG_ACTION)}' is 'Add'."
            )
        return (asset_id, tag_action, tag_key, tag_value), ""

    def _execute_scan_data_now(
        self, headers: Dict, base_url: str, asset_unique_id: str
    ) -> None:
        """Trigger an on-demand Orca scan of a single asset.

        Args:
            headers (Dict): Authentication headers.
            base_url (str): Configured Orca Security base URL.
            asset_unique_id (str): The asset to scan.

        Raises:
            OrcaSecurityPluginException: If the scan trigger call fails.
        """
        try:
            self.helper.trigger_scan(headers, base_url, asset_unique_id)
            self.logger.info(
                f"{self.log_prefix}: Successfully triggered"
                f" '{self._action_label(ACTION_SCAN_DATA_NOW)}' for asset"
                f" '{asset_unique_id}'."
            )
        except OrcaSecurityPluginException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while triggering"
                    f" '{self._action_label(ACTION_SCAN_DATA_NOW)}' for asset"
                    f" '{asset_unique_id}'. Error: {exp}"
                )
            )
            raise

    def _execute_add_remove_tag(
        self,
        headers: Dict,
        base_url: str,
        asset_id: str,
        tag_action: str,
        tag_key: str,
        tag_value: str,
    ) -> None:
        """Add or remove a custom tag on a single asset.

        Calls ``POST /manual_tags/{asset_id}`` to add a tag, or
        ``DELETE /manual_tags/{asset_id}`` to remove one.

        Args:
            headers (Dict): Authentication headers.
            base_url (str): Configured Orca Security base URL.
            asset_id (str): The Orca ``id`` of the asset to tag/untag.
            tag_action (str): ``add`` or ``remove``.
            tag_key (str): Tag key to add/remove.
            tag_value (str): Tag value; used by ``add`` only.

        Raises:
            OrcaSecurityPluginException: If the tag API call fails.
        """
        try:
            if tag_action == TAG_ACTION_REMOVE:
                self.helper.remove_custom_tag(
                    headers, base_url, asset_id, tag_key
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully removed tag"
                    f" '{tag_key}' from asset '{asset_id}'."
                )
            else:
                self.helper.add_custom_tag(
                    headers, base_url, asset_id, tag_key, tag_value
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully added tag"
                    f" '{tag_key}' to asset '{asset_id}'."
                )
        except OrcaSecurityPluginException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while performing"
                    f" '{self._action_label(ACTION_ADD_REMOVE_TAG)}' for asset"
                    f" '{asset_id}'. Error: {exp}"
                )
            )
            raise

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate the parameters of a selected action.

        Args:
            action (Action): Action object including parameters.

        Returns:
            ValidationResult: Success or failure with a message.
        """
        action_value = action.value
        if action_value not in SUPPORTED_ACTIONS:
            supported = ", ".join(
                f"'{self._action_label(value)}'" for value in SUPPORTED_ACTIONS
            )
            err_msg = (
                f"Unsupported action '{action_value}' provided in the"
                f" action configuration. Supported actions are"
                f" {supported}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    "Select the action from the list of supported actions"
                    " in the action configuration."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if action_value == ACTION_NO_ACTION:
            return self._validation_success(action)

        if action_value == ACTION_ADD_REMOVE_TAG:
            return self._validate_add_remove_tag_action(action)

        if validation_failure := self._validate_action_param(
            action, PARAM_ASSET_UNIQUE_ID, check_dollar=True
        ):
            return validation_failure

        return self._validation_success(action)

    def _validation_success(self, action: Action) -> ValidationResult:
        """Log and build the success result for a validated action.

        Args:
            action (Action): The validated action.

        Returns:
            ValidationResult: A successful validation result.
        """
        self.logger.debug(
            f"{self.log_prefix}: Successfully validated action"
            f" '{self._action_label(action.value)}'."
        )
        return ValidationResult(
            success=True, message="Validation successful."
        )

    def _validate_action_param(
        self,
        action: Action,
        param_key: str,
        allowed_values: Optional[List] = None,
        check_dollar: bool = False,
        is_required: bool = True,
    ) -> Optional[ValidationResult]:
        """Validate one action parameter by its key.

        Args:
            action (Action): Action object including parameters.
            param_key (str): Parameter key to validate.
            allowed_values (List | None): Allowed values, when the
                parameter is a static dropdown.
            check_dollar (bool): Defer validation to execution time when
                the value is mapped to a Source field.
            is_required (bool): Whether the parameter is mandatory.

        Returns:
            ValidationResult | None: Failure result, or ``None`` when the
                parameter is valid.
        """
        return self.helper.validate_parameters(
            field_name=self._param_label(param_key),
            field_value=self.helper.get_scalar_value(
                (action.parameters or {}).get(param_key, "")
            ),
            field_type=str,
            parameter_type=ACTION,
            allowed_values=allowed_values,
            check_dollar=check_dollar,
            is_required=is_required,
        )

    def _validate_add_remove_tag_action(
        self, action: Action
    ) -> ValidationResult:
        """Validate the parameters of the 'Add/Remove Custom Tag' action.

        Args:
            action (Action): Action object including parameters.

        Returns:
            ValidationResult: Success or failure with a message.
        """
        if validation_failure := self._validate_action_param(
            action, PARAM_TAG_ACTION, allowed_values=TAG_ACTIONS
        ):
            return validation_failure

        if validation_failure := self._validate_action_param(
            action, PARAM_TAG_KEY, check_dollar=True
        ):
            return validation_failure

        tag_action = self.helper.get_stripped_param(
            action.parameters, PARAM_TAG_ACTION
        )
        if tag_action == TAG_ACTION_ADD:
            if validation_failure := self._validate_action_param(
                action, PARAM_TAG_VALUE, check_dollar=True
            ):
                return validation_failure

        if validation_failure := self._validate_action_param(
            action, PARAM_ASSET_ID, check_dollar=True
        ):
            return validation_failure

        return self._validation_success(action)

    # ------------------------------------------------------------------
    # validate
    # ------------------------------------------------------------------

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the plugin configuration.

        Args:
            configuration (dict): Plugin configuration dictionary.

        Returns:
            ValidationResult: Success or failure with a message.
        """
        # base_url is intentionally NOT taken from
        # get_configuration_parameters() here: that resolves the choice
        # + custom field down to a single URL, which would hide whether
        # the raw dropdown selection itself is a value the UI could ever
        # have produced. The raw 'base_url' choice and the conditional
        # 'custom_base_url' field are validated directly instead.
        _, api_token, device_models, user_models = (
            self.helper.get_configuration_parameters(configuration)
        )

        base_url_choice = configuration.get(CONFIG_BASE_URL, "")
        if isinstance(base_url_choice, str):
            base_url_choice = base_url_choice.strip()
        if validation_failure := self.helper.validate_parameters(
            field_name=CONFIG_FIELD_LABELS.get(CONFIG_BASE_URL),
            field_value=base_url_choice,
            field_type=str,
            parameter_type=CONFIGURATION,
            allowed_values=BASE_URL_CHOICE_VALUES,
        ):
            return validation_failure

        if base_url_choice == BASE_URL_CUSTOM_VALUE:
            custom_base_url = configuration.get(CONFIG_CUSTOM_BASE_URL, "")
            if isinstance(custom_base_url, str):
                custom_base_url = custom_base_url.strip().rstrip("/")
            if validation_failure := self.helper.validate_parameters(
                field_name=CONFIG_FIELD_LABELS.get(CONFIG_CUSTOM_BASE_URL),
                field_value=custom_base_url,
                field_type=str,
                parameter_type=CONFIGURATION,
                custom_validation_func=self.helper._validate_url,
            ):
                return validation_failure

        if validation_failure := self.helper.validate_parameters(
            field_name=CONFIG_FIELD_LABELS.get(CONFIG_API_TOKEN),
            field_value=api_token,
            field_type=str,
            parameter_type=CONFIGURATION,
        ):
            return validation_failure

        for field_value, config_key, allowed_values in (
            (device_models, CONFIG_DEVICE_MODELS, DEVICE_MODELS),
            (user_models, CONFIG_USER_MODELS, USER_MODELS),
            (
                configuration.get(
                    CONFIG_FETCH_ADDITIONAL_DEVICE_DETAILS, []
                ),
                CONFIG_FETCH_ADDITIONAL_DEVICE_DETAILS,
                DEVICE_DETAIL_VALUES,
            ),
        ):
            if validation_failure := self.helper.validate_parameters(
                field_name=CONFIG_FIELD_LABELS.get(config_key),
                field_value=field_value,
                field_type=list,
                parameter_type=CONFIGURATION,
                allowed_values=allowed_values,
                is_required=False,
            ):
                return validation_failure

        for config_key in TOGGLE_CONFIG_KEYS:
            if validation_failure := self.helper.validate_parameters(
                field_name=CONFIG_FIELD_LABELS.get(config_key),
                field_value=configuration.get(config_key, TOGGLE_NO),
                field_type=str,
                parameter_type=CONFIGURATION,
                allowed_values=TOGGLE_VALUES,
            ):
                return validation_failure

        if result := self._validate_required_field_in_entity_mappings():
            return result

        return self._validate_auth_params(configuration)

    def _validate_required_field_in_entity_mappings(
        self,
    ) -> Optional[ValidationResult]:
        """Ensure each entity's identifier fields are mapped.

        Returns:
            ValidationResult | None: Failure result when a required
                field is missing from that entity's mappings, else
                ``None``.
        """
        missing_messages = []
        for mapped_entity in getattr(self, "mappedEntities", None) or []:
            entity_name = mapped_entity.get("entity")
            required_fields = REQUIRED_ENTITY_FIELDS.get(entity_name)
            if not required_fields:
                continue
            mapped_sources = {
                field.get("source", "")
                for field in mapped_entity.get("fields", [])
                if field.get("source")
            }
            missing = [
                field
                for field in required_fields
                if field not in mapped_sources
            ]
            if missing:
                formatted = ", ".join(f"'{field}'" for field in missing)
                missing_messages.append(
                    f"Missing required field(s) {formatted} in entity"
                    f" mappings for {entity_name}."
                )

        if missing_messages:
            err_msg = " ".join(missing_messages)
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    "Add the missing field(s) to the entity mappings in"
                    " the plugin configuration."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        return None

    def _validate_auth_params(
        self, configuration: dict
    ) -> ValidationResult:
        """Verify the Base URL/API Token via a minimal connectivity check.

        Args:
            configuration (dict): Plugin configuration dictionary.

        Returns:
            ValidationResult: Success when the credentials are accepted,
                failure otherwise.
        """
        try:
            (
                base_url,
                api_token,
                *_,
            ) = self.helper.get_configuration_parameters(configuration)
            # Deliberately NOT built via build_object_set_payload(): that
            # helper sets "get_results_and_count", which makes the serving
            # layer compute a full count. Validation only needs to prove
            # the credentials work, so it asks for a single row.
            payload = {
                "query": {"models": [DEVICE_MODELS[0]], "type": "object_set"},
                "limit": 1,
                "start_at_index": 0,
            }
            self.helper.api_helper(
                logger_msg="validating configuration parameters",
                url=f"{base_url}{BASE_URL_ENDPOINT}",
                method="POST",
                headers=self.helper.get_auth_headers(api_token),
                json_data=payload,
                is_validation=True,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated the"
                f" configuration parameters for {PLATFORM_NAME}."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        except OrcaSecurityPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while validating configuration"
                " parameters."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg} Error: {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Verify the configuration parameters provided and"
                    " check the logs for more details."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
