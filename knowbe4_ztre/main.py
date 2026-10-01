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

CRE KnowBe4 Plugin.
"""

import json
import traceback
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

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
    ACTION_ADD_TO_GROUP,
    ACTION_BATCH_SIZE,
    ACTION_ENROLL_TRAINING,
    ACTION_LABELS,
    ACTION_NO_ACTION,
    ACTION_REMOVE_FROM_GROUP,
    ACTION_PARAM_LABELS,
    ACTION_UPDATE_FIELD,
    ADDITIONAL_DETAIL_VALUES,
    ALLOWED_REGION_VALUES,
    AUTH_CHECK_PAGE_SIZE,
    AUTH_CHECK_QUERY,
    CONFIG_ACTION_BATCH_SIZE,
    CONFIG_CUSTOM_REGION_URL,
    CONFIG_FIELD_LABELS,
    CONFIG_KSAT_TOKEN,
    CONFIG_PASSWORDIQ_TOKEN,
    CONFIG_PULL_ADDITIONAL_DETAILS,
    CONFIG_PULL_ARCHIVED_USERS,
    CONFIG_REGION,
    CONFIG_SECURITYCOACH_TOKEN,
    CONFIGURATION,
    CREATE_NEW_GROUP_LABEL,
    CREATE_NEW_GROUP_VALUE,
    CUSTOM_DATE_FIELD_ENTITY_NAMES,
    CUSTOM_FIELD_SLOTS,
    CUSTOM_FIELDS_MAPPING,
    CUSTOM_TEXT_FIELD_ENTITY_NAMES,
    DETAIL_CUSTOM_FIELDS,
    DETAIL_PASSWORDIQ,
    DETAIL_SECURITYCOACH,
    FIELD_ANTI_PHISHING_SCORE,
    FIELD_AWARENESS_SCORE,
    FIELD_EMAIL,
    FIELD_GROUPS,
    FIELD_NORMALIZED_SCORE,
    FIELD_PAST_DUE_COUNT,
    FIELD_PAST_DUE_NAMES,
    FIELD_PHISHING_REPORT_SCORE,
    FIELD_PIQ_DETECTIONS,
    FIELD_RISK_SCORE,
    FIELD_TRAINING_SCORE,
    FIELD_USER_ID,
    FIELD_USER_STATUS,
    MAX_ACTION_BATCH_SIZE,
    MAX_CUSTOM_FIELD_VALUE_LENGTH,
    MAX_GROUP_NAME_LENGTH,
    MIN_ACTION_BATCH_SIZE,
    LENGTH_ERROR_MESSAGE,
    MODULE_NAME,
    PARAM_CUSTOM_FIELD_SLOT,
    PARAM_CUSTOM_FIELD_VALUE,
    PARAM_GROUP_ID,
    PARAM_NEW_GROUP_NAME,
    PARAM_TRAINING_CAMPAIGN_ID,
    PARAM_USER_ID,
    PASSWORDIQ_QUERY,
    PIQ_DETECTIONS,
    PIQ_USER_TYPE,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PRODUCT_KSAT,
    PRODUCT_PASSWORDIQ,
    PRODUCT_SECURITYCOACH,
    RANGE_ERROR_MESSAGE,
    REGION_CUSTOM_VALUE,
    REVERTIBLE_ACTIONS,
    SECURITY_COACH_FIELD_MAPPING,
    SECURITY_COACH_QUERY,
    STATIC_FIELD_ERROR_MESSAGE,
    SUPPORTED_ACTIONS,
    SUPPORTED_ENTITIES,
    TOGGLE_VALUES,
    TOGGLE_YES,
    TOKEN_RESOLUTION_MESSAGE,
    USER_FIELD_MAPPING,
    USERS_ENTITY,
    VALIDATION_ERROR_MESSAGE,
)
from .utils.exceptions import (
    KnowBe4AuthenticationException,
    KnowBe4PluginException,
)
from .utils.helper import KnowBe4PluginHelper


class KnowBe4Plugin(PluginBase):
    """KnowBe4 CRE plugin implementation."""

    def __init__(self, name, *args, **kwargs):
        """Initialize the KnowBe4 plugin.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        # Ask the platform to hand execute_actions() the action IDs so
        # a failure on one user is reported for that user alone.
        self.provide_action_id = True
        self.knowbe4_helper = KnowBe4PluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Read the plugin name and version from the manifest.

        Returns:
            tuple: Plugin name and plugin version.
        """
        try:
            metadata = KnowBe4Plugin.metadata
            return (
                metadata.get("name", PLUGIN_NAME),
                metadata.get("version", PLUGIN_VERSION),
            )
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Unexpected error"
                    " occurred while getting the plugin details."
                    f" Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _action_label(self, action_value: str) -> str:
        """Return the display label of an action.

        Args:
            action_value (str): Action value.

        Returns:
            str: Action label, or the value when it is unknown.
        """
        return ACTION_LABELS.get(action_value, action_value)

    def _param_label(self, param_key: str) -> str:
        """Return the display label of an action parameter.

        Args:
            param_key (str): Action parameter key.

        Returns:
            str: Parameter label, or the key when it is unknown.
        """
        return ACTION_PARAM_LABELS.get(param_key, param_key)

    def _get_ksat_credentials(self) -> tuple:
        """Read the region endpoint and the KSAT token.

        Returns:
            tuple: Region endpoint and KSAT API token.
        """
        region, ksat_token, *_ = self.knowbe4_helper.get_config_params(
            self.configuration
        )
        return region, ksat_token

    def _get_action_batch_size(self) -> int:
        """Read the configured group action batch size.

        Falls back to the default when the value is missing or out
        of range, e.g. a configuration saved before this parameter
        existed.

        Returns:
            int: Number of users to send in one group action batch.
        """
        value = (self.configuration or {}).get(
            CONFIG_ACTION_BATCH_SIZE, ACTION_BATCH_SIZE
        )
        if self._is_valid_action_batch_size(value) is True:
            return value
        return ACTION_BATCH_SIZE

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def get_dynamic_fields(self) -> List[Dict]:
        """Return the token fields for the selected products.

        The platform renders these fields after every field declared
        in manifest.json. 'Pull Additional Details' is the last static
        field, so the token fields appear directly below it.

        Returns:
            List[Dict]: Field definitions for the selected products.
        """
        selected = (self.configuration or {}).get(
            CONFIG_PULL_ADDITIONAL_DETAILS
        ) or []
        if isinstance(selected, str):
            selected = [selected]
        fields = []
        if DETAIL_PASSWORDIQ in selected:
            fields.append(
                {
                    "label": CONFIG_FIELD_LABELS[
                        CONFIG_PASSWORDIQ_TOKEN
                    ],
                    "key": CONFIG_PASSWORDIQ_TOKEN,
                    "type": "password",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "PasswordIQ API token. It can be generated"
                        " from the 'Account Settings > Account"
                        " Integrations > API > Product API > Create"
                        " New API Token ' page of the PasswordIQ"
                        " product."
                    ),
                }
            )
        if DETAIL_SECURITYCOACH in selected:
            fields.append(
                {
                    "label": CONFIG_FIELD_LABELS[
                        CONFIG_SECURITYCOACH_TOKEN
                    ],
                    "key": CONFIG_SECURITYCOACH_TOKEN,
                    "type": "password",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "SecurityCoach API token. It can be generated"
                        " from the 'Account Settings > Account"
                        " Integrations > API > Product API > Create"
                        " New API Token ' page of the SecurityCoach"
                        " product."
                    ),
                }
            )
        return fields

    def get_entities(self) -> List[Entity]:
        """Return the entities this plugin provides.

        User fields are populated dynamically based on the
        'Pull Additional Details' configuration toggle: the PIQ
        Detections field only when 'PasswordIQ' is selected, the
        SecurityCoach sub-score fields only when 'SecurityCoach' is
        selected, and the 6 custom fields only when 'Custom Fields'
        is selected. The 'User Status' field is shown only when 'Pull
        Archived Users' is 'Yes' — otherwise every pulled user is
        active by definition, so the field would always be 'Active'.

        Returns:
            List[Entity]: The Users entity and its fields.
        """
        selected = (self.configuration or {}).get(
            CONFIG_PULL_ADDITIONAL_DETAILS
        ) or []
        if isinstance(selected, str):
            selected = [selected]
        pull_archived_users = (self.configuration or {}).get(
            CONFIG_PULL_ARCHIVED_USERS
        )

        fields = [
            EntityField(
                name=FIELD_EMAIL,
                type=EntityFieldType.STRING,
                required=True,
                label=FIELD_EMAIL,
                description=(
                    "Email address of the KnowBe4 user."
                ),
            ),
            EntityField(
                name=FIELD_USER_ID,
                type=EntityFieldType.STRING,
                required=True,
                label=FIELD_USER_ID,
                description="Unique KnowBe4 user ID.",
            ),
            EntityField(
                name="First Name",
                type=EntityFieldType.STRING,
                label="First Name",
                description=(
                    "First name of the user, from the KnowBe4 user"
                    " profile."
                ),
            ),
            EntityField(
                name="Last Name",
                type=EntityFieldType.STRING,
                label="Last Name",
                description=(
                    "Last name of the user, from the KnowBe4 user"
                    " profile."
                ),
            ),
            EntityField(
                name="Display Name",
                type=EntityFieldType.STRING,
                label="Display Name",
                description=(
                    "Display name of the user shown in the KnowBe4"
                    " console."
                ),
            ),
            EntityField(
                name="Employee Number",
                type=EntityFieldType.STRING,
                label="Employee Number",
                description=(
                    "Employee number of the user, from the KnowBe4"
                    " user profile."
                ),
            ),
            EntityField(
                name="Job Title",
                type=EntityFieldType.STRING,
                label="Job Title",
                description=(
                    "Job title of the user, from the KnowBe4 user"
                    " profile."
                ),
            ),
            EntityField(
                name="Department",
                type=EntityFieldType.STRING,
                label="Department",
                description=(
                    "Department of the user, from the KnowBe4 user"
                    " profile."
                ),
            ),
            EntityField(
                name="Manager Email",
                type=EntityFieldType.STRING,
                label="Manager Email",
                description=(
                    "Email address of the user's manager, from the"
                    " KnowBe4 user profile."
                ),
            ),
            EntityField(
                name=FIELD_GROUPS,
                type=EntityFieldType.LIST,
                label=FIELD_GROUPS,
                description=(
                    "Names of the KnowBe4 groups the user is a"
                    " member of."
                ),
            ),
            EntityField(
                name=FIELD_RISK_SCORE,
                type=EntityFieldType.NUMBER,
                label=FIELD_RISK_SCORE,
                description=(
                    "KnowBe4 SmartRisk score for the user, 0 (least"
                    " risky) to 100 (most risky)."
                ),
            ),
            EntityField(
                name="Phish Prone Percentage",
                type=EntityFieldType.NUMBER,
                label="Phish Prone Percentage",
                description=(
                    "Percentage of phishing security tests the user"
                    " has failed."
                ),
            ),
            EntityField(
                name=FIELD_NORMALIZED_SCORE,
                type=EntityFieldType.NUMBER,
                label=FIELD_NORMALIZED_SCORE,
                description=(
                    f"'{FIELD_RISK_SCORE}' normalized to the Netskope"
                    " 0 (most risky) to 1000 (least risky) range."
                ),
            ),
            EntityField(
                name=FIELD_PAST_DUE_COUNT,
                type=EntityFieldType.NUMBER,
                label=FIELD_PAST_DUE_COUNT,
                description=(
                    "Number of the user's training enrollments that"
                    " are past due."
                ),
            ),
            EntityField(
                name=FIELD_PAST_DUE_NAMES,
                type=EntityFieldType.LIST,
                label=FIELD_PAST_DUE_NAMES,
                description=(
                    "Names of the user's past due training"
                    " campaigns, policies and knowledge refreshers."
                ),
            ),
        ]
        if pull_archived_users == TOGGLE_YES:
            fields.append(
                EntityField(
                    name=FIELD_USER_STATUS,
                    type=EntityFieldType.STRING,
                    label=FIELD_USER_STATUS,
                    description=(
                        "Whether the user is 'Active' or 'Archived'"
                        " in KnowBe4."
                    ),
                )
            )
        if DETAIL_PASSWORDIQ in selected:
            fields.append(
                EntityField(
                    name=FIELD_PIQ_DETECTIONS,
                    type=EntityFieldType.LIST,
                    label=FIELD_PIQ_DETECTIONS,
                    description=(
                        "PasswordIQ Active Directory violation types"
                        " currently detected and unresolved for the"
                        " user."
                    ),
                )
            )
        if DETAIL_SECURITYCOACH in selected:
            fields.extend(
                [
                    EntityField(
                        name=FIELD_AWARENESS_SCORE,
                        type=EntityFieldType.NUMBER,
                        label=FIELD_AWARENESS_SCORE,
                        description=(
                            "SecurityCoach awareness sub-score for"
                            " the user."
                        ),
                    ),
                    EntityField(
                        name=FIELD_ANTI_PHISHING_SCORE,
                        type=EntityFieldType.NUMBER,
                        label=FIELD_ANTI_PHISHING_SCORE,
                        description=(
                            "SecurityCoach anti-phishing sub-score"
                            " for the user."
                        ),
                    ),
                    EntityField(
                        name=FIELD_PHISHING_REPORT_SCORE,
                        type=EntityFieldType.NUMBER,
                        label=FIELD_PHISHING_REPORT_SCORE,
                        description=(
                            "SecurityCoach phishing-report sub-score"
                            " for the user."
                        ),
                    ),
                    EntityField(
                        name=FIELD_TRAINING_SCORE,
                        type=EntityFieldType.NUMBER,
                        label=FIELD_TRAINING_SCORE,
                        description=(
                            "SecurityCoach training sub-score for the"
                            " user."
                        ),
                    ),
                ]
            )
        if DETAIL_CUSTOM_FIELDS in selected:
            fields.extend(
                EntityField(
                    name=name,
                    type=EntityFieldType.STRING,
                    label=name,
                    description=(
                        f"Value of custom text field {index} on the"
                        " KnowBe4 user profile."
                    ),
                )
                for index, name in enumerate(
                    CUSTOM_TEXT_FIELD_ENTITY_NAMES, start=1
                )
            )
            fields.extend(
                EntityField(
                    name=name,
                    type=EntityFieldType.DATETIME,
                    label=name,
                    description=(
                        f"Value of custom date field {index} on the"
                        " KnowBe4 user profile."
                    ),
                )
                for index, name in enumerate(
                    CUSTOM_DATE_FIELD_ENTITY_NAMES, start=1
                )
            )

        return [
            Entity(
                name=USERS_ENTITY,
                fields=fields,
            )
        ]

    # ------------------------------------------------------------------
    # Pull
    # ------------------------------------------------------------------

    def _build_user_record(
        self, node: Dict, include_custom_fields: bool = False
    ) -> Optional[Dict]:
        """Turn one KnowBe4 user node into a plugin record.

        Args:
            node (Dict): User node from the KnowBe4 API.
            include_custom_fields (bool): Whether to also extract the
                6 custom fields.

        Returns:
            Dict: Extracted record, or None when the node has no user
                ID or no email.
        """
        if not isinstance(node, dict):
            return None
        if node.get("id") is None or not node.get("email"):
            return None
        mapping = USER_FIELD_MAPPING
        if include_custom_fields:
            mapping = {**USER_FIELD_MAPPING, **CUSTOM_FIELDS_MAPPING}
        record = self.knowbe4_helper.extract_entity_fields(
            event=node, mapping=mapping
        )
        self.knowbe4_helper.add_field(
            record,
            FIELD_NORMALIZED_SCORE,
            self.knowbe4_helper.normalize_risk_score(
                node.get("riskScore"), identifier=node.get("email")
            ),
        )
        return record

    def fetch_records(self, entity: str) -> List[Dict]:
        """Pull the user roster from KnowBe4.

        KnowBe4 offers no filter or sort key for recently changed
        users, so the full roster is pulled on every sync.

        Args:
            entity (str): Entity to pull.

        Returns:
            List[Dict]: User records.

        Raises:
            KnowBe4PluginException: When the pull fails.
        """
        self.knowbe4_helper.validate_entity(entity, SUPPORTED_ENTITIES)
        region, ksat_token = self._get_ksat_credentials()
        (
            _,
            _,
            additional_details,
            _,
            _,
            pull_archived_users,
        ) = self.knowbe4_helper.get_config_params(self.configuration)
        status = self.knowbe4_helper.get_user_status_filter(
            pull_archived_users
        )
        include_custom_fields = DETAIL_CUSTOM_FIELDS in additional_details
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity} record(s) from"
            f" {PLATFORM_NAME}."
        )
        total_records = []
        skip_count = 0
        logger_msg = f"fetching {entity} record(s) from {PLATFORM_NAME}"
        try:
            for nodes, page in self.knowbe4_helper.fetch_user_pages(
                url=region,
                token=ksat_token,
                status=status,
                ssl_validation=self.ssl_validation,
                proxy=self.proxy,
                include_custom_fields=include_custom_fields,
            ):
                page_record_count = 0
                for node in nodes:
                    record = self._build_user_record(
                        node, include_custom_fields=include_custom_fields
                    )
                    if record:
                        total_records.append(record)
                        page_record_count += 1
                    else:
                        skip_count += 1
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched"
                    f" {page_record_count} user record(s) in page"
                    f" {page}. Total user record(s) fetched:"
                    f" {len(total_records)}."
                )
        except KnowBe4PluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
                f" Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise KnowBe4PluginException(err_msg)

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} record(s)"
                " because they had no user ID or no email address."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched"
            f" {len(total_records)} {entity} record(s) from"
            f" {PLATFORM_NAME}."
        )
        return total_records

    def update_records(
        self, entity: str, records: List[Dict]
    ) -> List[Dict]:
        """Add training and optional product details to the records.

        Args:
            entity (str): Entity being updated.
            records (List[Dict]): Records from the platform. Only the
                fields marked required in get_entities() are present.

        Returns:
            List[Dict]: Records carrying the enrichment fields. Empty
                when there is nothing to update.

        Raises:
            KnowBe4PluginException: When the update fails.
        """
        self.knowbe4_helper.validate_entity(entity, SUPPORTED_ENTITIES)
        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} {entity}"
            f" record(s) from {PLATFORM_NAME}."
        )
        targets = []
        for record in records:
            user_id = self.knowbe4_helper.to_int(
                record.get(FIELD_USER_ID)
            )
            if user_id is None:
                continue
            targets.append((user_id, record))
        skip_count = len(records) - len(targets)
        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} record(s)"
                f" because they had no '{FIELD_USER_ID}' field."
            )
        if not targets:
            self.logger.info(
                f"{self.log_prefix}: No {entity} record(s) to update"
                f" from {PLATFORM_NAME}."
            )
            return []

        logger_msg = (
            f"updating {entity} record(s) from {PLATFORM_NAME}"
        )
        try:
            lookups = self._collect_enrichment_data(
                [user_id for user_id, _ in targets]
            )
            updated_records = self._apply_enrichment(targets, lookups)
        except KnowBe4PluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
                f" Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise KnowBe4PluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Successfully updated"
            f" {len(updated_records)} {entity} record(s) out of"
            f" {len(records)} record(s) from {PLATFORM_NAME}."
        )
        return updated_records

    def _collect_enrichment_data(self, user_ids: List) -> Dict:
        """Read every data set needed to enrich the given users.

        PasswordIQ and SecurityCoach are read once for the whole
        account because neither query accepts a user filter. Each
        source is fetched independently: a failure fetching one (e.g.
        an expired optional PasswordIQ/SecurityCoach token) does not
        prevent the others from updating their fields.

        Args:
            user_ids (List): KnowBe4 user IDs being updated.

        Returns:
            Dict: Lookup maps used by _apply_enrichment().
        """
        (
            region,
            ksat_token,
            additional_details,
            piq_token,
            coach_token,
            _,
        ) = self.knowbe4_helper.get_config_params(self.configuration)

        lookups = {
            "training": {},
            "passwordiq": {},
            "passwordiq_enabled": False,
            "coach_by_email": {},
            "coach_by_id": {},
            "coach_enabled": False,
        }
        lookups["training"] = self._fetch_enrichment_source(
            source_label="training details",
            fetch_func=lambda: self.knowbe4_helper.fetch_training_details(
                url=region,
                token=ksat_token,
                user_ids=user_ids,
                ssl_validation=self.ssl_validation,
                proxy=self.proxy,
            ),
            default={},
        )
        if DETAIL_PASSWORDIQ in additional_details:
            lookups["passwordiq_enabled"] = True
            lookups["passwordiq"] = self._fetch_enrichment_source(
                source_label=f"{PRODUCT_PASSWORDIQ} detections",
                fetch_func=lambda: (
                    self.knowbe4_helper.fetch_passwordiq_states(
                        url=region,
                        token=piq_token,
                        ssl_validation=self.ssl_validation,
                        proxy=self.proxy,
                    )
                ),
                default={},
            )
        if DETAIL_SECURITYCOACH in additional_details:
            lookups["coach_enabled"] = True
            by_email, by_id = self._fetch_enrichment_source(
                source_label=f"{PRODUCT_SECURITYCOACH} scores",
                fetch_func=lambda: (
                    self.knowbe4_helper.fetch_security_coach_scores(
                        url=region,
                        token=coach_token,
                        ssl_validation=self.ssl_validation,
                        proxy=self.proxy,
                    )
                ),
                default=({}, {}),
            )
            lookups["coach_by_email"] = by_email
            lookups["coach_by_id"] = by_id
        return lookups

    def _fetch_enrichment_source(
        self, source_label: str, fetch_func, default: Any
    ) -> Any:
        """Read one enrichment source without blocking the others.

        The rule of thumb is: skip what failed, return what
        succeeded. A failure here still lets every other enrichment
        source, and every other field already extracted for a record,
        update normally on this sync.

        Args:
            source_label (str): What is being fetched, used in logs.
            fetch_func (Callable): Zero-argument function performing
                the fetch.
            default (Any): Value returned when the fetch fails.

        Returns:
            Any: The fetched value, or `default` on failure.
        """
        try:
            return fetch_func()
        except KnowBe4PluginException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Skipping the {source_label}"
                    f" for this sync because they could not be"
                    f" fetched. Error: {exp}"
                ),
                resolution=(
                    "Verify the API token and the Region provided in"
                    " the configuration parameters. The corresponding"
                    " fields will not be updated on this sync."
                ),
            )
            return default
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred"
                    f" while fetching the {source_label} for this"
                    f" sync. Error: {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "The corresponding fields will not be updated on"
                    " this sync."
                ),
            )
            return default

    def _apply_enrichment(
        self, targets: List, lookups: Dict
    ) -> List[Dict]:
        """Build the updated record for every target user.

        Args:
            targets (List): Pairs of user ID and platform record.
            lookups (Dict): Lookup maps from _collect_enrichment_data.

        Returns:
            List[Dict]: Updated records.
        """
        updated_records = []
        failed_count = 0
        for user_id, record in targets:
            try:
                email = record.get(FIELD_EMAIL) or ""
                fields = {
                    FIELD_EMAIL: email,
                    FIELD_USER_ID: str(user_id),
                }
                self._add_training_fields(
                    fields, lookups["training"].get(user_id)
                )
                self._add_password_fields(fields, lookups, user_id)
                self._add_coach_fields(
                    fields, lookups, user_id, email
                )
                updated_records.append(fields)
            except Exception as exp:
                failed_count += 1
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred"
                        f" while updating the record of user ID"
                        f" '{user_id}'. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
        if failed_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {failed_count} record(s)"
                " because their details could not be built."
            )
        return updated_records

    def _add_training_fields(
        self, fields: Dict, training: Optional[Dict]
    ) -> None:
        """Add the training fields of one user.

        Args:
            fields (Dict): Field dictionary updated in place.
            training (Dict): Training details of the user.
        """
        if not training:
            return
        self.knowbe4_helper.add_field(
            fields, FIELD_PAST_DUE_COUNT, training["past_due_count"]
        )
        self.knowbe4_helper.add_field(
            fields, FIELD_PAST_DUE_NAMES, training["past_due_names"]
        )

    def _add_password_fields(
        self, fields: Dict, lookups: Dict, user_id: int
    ) -> None:
        """Add the PasswordIQ Detections field of one user.

        Every AD violation type PasswordIQ reports as currently
        detected and unresolved for the user is added to the list, as
        the raw value returned by the API (e.g.
        'AD_PW_FOUND_IN_BREACH') — not converted to a human readable
        label for now. Written as an empty list when PasswordIQ
        reports no active violation for the user, so a violation
        resolved since the last sync is reflected on this sync too.

        Args:
            fields (Dict): Field dictionary updated in place.
            lookups (Dict): Lookup maps from _collect_enrichment_data.
            user_id (int): KnowBe4 user ID.
        """
        if not lookups["passwordiq_enabled"]:
            return
        detections = lookups["passwordiq"].get(user_id) or []
        self.knowbe4_helper.add_field(
            fields, FIELD_PIQ_DETECTIONS, detections
        )

    def _add_coach_fields(
        self, fields: Dict, lookups: Dict, user_id: int, email: str
    ) -> None:
        """Add the SecurityCoach sub scores of one user.

        Written as None for every sub score when SecurityCoach
        reports no mapped row for the user, the same way PIQ
        Detections is cleared to an empty list — so a user who drops
        out of SecurityCoach since the last sync loses their stale
        scores instead of keeping them indefinitely.

        Args:
            fields (Dict): Field dictionary updated in place.
            lookups (Dict): Lookup maps from _collect_enrichment_data.
            user_id (int): KnowBe4 user ID.
            email (str): Email address of the user.
        """
        if not lookups["coach_enabled"]:
            return
        scores = lookups["coach_by_email"].get(
            str(email).lower()
        ) or lookups["coach_by_id"].get(user_id)
        for field_name in SECURITY_COACH_FIELD_MAPPING:
            fields[field_name] = scores.get(field_name) if scores else None

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def get_actions(self) -> List[ActionWithoutParams]:
        """Return the actions this plugin supports.

        Returns:
            List[ActionWithoutParams]: Supported actions.
        """
        return [
            ActionWithoutParams(
                label=self._action_label(action_value),
                value=action_value,
            )
            for action_value in SUPPORTED_ACTIONS
        ]

    def get_action_params(self, action: Action) -> List:
        """Return the parameter fields of an action.

        Args:
            action (Action): Selected action.

        Returns:
            List: Parameter field definitions for the platform UI.

        Raises:
            KnowBe4PluginException: When the group or training
                campaign dropdown values cannot be read. The platform
                turns this into a clear "Could not get action
                parameters. Check logs." error rather than silently
                showing an empty dropdown.
        """
        action_value = action.value
        if action_value == ACTION_NO_ACTION:
            return []
        params = [self._user_id_param()]
        if action_value == ACTION_ADD_TO_GROUP:
            params.extend(self._group_params(allow_create=True))
        elif action_value == ACTION_REMOVE_FROM_GROUP:
            params.extend(self._group_params(allow_create=False))
        elif action_value == ACTION_ENROLL_TRAINING:
            params.append(self._training_campaign_param())
        elif action_value == ACTION_UPDATE_FIELD:
            params.extend(self._custom_field_params())
        return params

    def _user_id_param(self) -> Dict:
        """Build the target user parameter shared by every action.

        Returns:
            Dict: Parameter field definition.
        """
        return {
            "label": self._param_label(PARAM_USER_ID),
            "key": PARAM_USER_ID,
            "type": "text",
            "mandatory": True,
            "description": (
                "ID of the user on which action is to be taken. Select from"
                " Source Field Dropdown or provide static comma separated"
                " User IDs."
            ),
        }

    def _group_params(self, allow_create: bool) -> List[Dict]:
        """Build the group parameter(s) of a group membership action.

        'Add User to Group' also offers a 'create new group' choice
        and the group-name parameter it needs; a newly created group
        has no members yet, so 'Remove User from Group' only ever
        lists existing groups and has no group-name parameter.

        Args:
            allow_create (bool): True to build the params for 'Add
                User to Group', False for 'Remove User from Group'.

        Returns:
            List[Dict]: Parameter field definitions.
        """
        choices = self._get_group_choices()
        if allow_create:
            choices.append(
                {
                    "key": CREATE_NEW_GROUP_LABEL,
                    "value": CREATE_NEW_GROUP_VALUE,
                }
            )
        default = choices[0]["value"] if choices else ""
        verb = "add the user to" if allow_create else "remove the user from"
        group_param = {
            "label": self._param_label(PARAM_GROUP_ID),
            "key": PARAM_GROUP_ID,
            "type": "choice",
            "choices": choices,
            "default": default,
            "mandatory": True,
            "description": (
                f"KnowBe4 group to {verb}. Only console groups are"
                " listed. Select the group from"
                " the Static Field dropdown only."
            ),
        }
        if not allow_create:
            return [group_param]
        return [
            group_param,
            {
                "label": self._param_label(PARAM_NEW_GROUP_NAME),
                "key": PARAM_NEW_GROUP_NAME,
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    "Name of the group to create. It is used only"
                    f" when '{CREATE_NEW_GROUP_LABEL}' is selected in"
                    f" the '{self._param_label(PARAM_GROUP_ID)}'"
                    f" parameter. Maximum {MAX_GROUP_NAME_LENGTH}"
                    " characters are allowed."
                ),
            },
        ]

    def _get_group_choices(self) -> List[Dict]:
        """Read the group dropdown choices from KnowBe4.

        A failure here is not swallowed into an empty list — an empty
        dropdown looks like a tenant with no groups, when the real
        problem is that the group list could not be read at all (e.g.
        an invalid token). Left to propagate, the platform turns it
        into a clear "Could not get action parameters. Check logs."
        error instead.

        Returns:
            List[Dict]: Group choices sorted by name.

        Raises:
            KnowBe4PluginException: When the groups cannot be read.
        """
        region, ksat_token = self._get_ksat_credentials()
        groups = self.knowbe4_helper.fetch_groups(
            url=region,
            token=ksat_token,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        choices = [
            {
                "key": group.get("name"),
                "value": self.knowbe4_helper.build_group_value(
                    group.get("id"), group.get("name")
                ),
            }
            for group in groups
            if group.get("name") and group.get("id") is not None
        ]
        return sorted(choices, key=lambda item: item["key"].lower())

    def _training_campaign_param(self) -> Dict:
        """Build the training campaign parameter.

        Returns:
            Dict: Parameter field definition.
        """
        choices = self._get_training_campaign_choices()
        return {
            "label": self._param_label(PARAM_TRAINING_CAMPAIGN_ID),
            "key": PARAM_TRAINING_CAMPAIGN_ID,
            "type": "choice",
            "choices": choices,
            "default": choices[0]["value"] if choices else "",
            "mandatory": True,
            "description": (
                "KnowBe4 training campaign to enroll the user into."
                " Only campaigns that accept new users are listed."
                " Select the training campaign from the static"
                " dropdown only."
            ),
        }

    def _get_training_campaign_choices(self) -> List[Dict]:
        """Read the training campaign choices from KnowBe4.

        A failure here is not swallowed into an empty list — see
        _get_group_choices() for why.

        Returns:
            List[Dict]: Campaign choices sorted by name.

        Raises:
            KnowBe4PluginException: When the campaigns cannot be read.
        """
        region, ksat_token = self._get_ksat_credentials()
        campaigns = self.knowbe4_helper.fetch_training_campaigns(
            url=region,
            token=ksat_token,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        choices = [
            {
                "key": campaign.get("name"),
                "value": self.knowbe4_helper.build_campaign_value(
                    campaign.get("id"), campaign.get("name")
                ),
            }
            for campaign in campaigns
            if campaign.get("name") and campaign.get("id") is not None
        ]
        return sorted(choices, key=lambda item: item["key"].lower())

    def _custom_field_params(self) -> List[Dict]:
        """Build the parameters of the custom field action.

        Returns:
            List[Dict]: Parameter field definitions.
        """
        return [
            {
                "label": self._param_label(PARAM_CUSTOM_FIELD_SLOT),
                "key": PARAM_CUSTOM_FIELD_SLOT,
                "type": "choice",
                "choices": [
                    {"key": label, "value": slot}
                    for label, slot in zip(
                        CUSTOM_TEXT_FIELD_ENTITY_NAMES, CUSTOM_FIELD_SLOTS
                    )
                ],
                "default": CUSTOM_FIELD_SLOTS[0],
                "mandatory": True,
                "description": (
                    "KnowBe4 custom field to write the value into."
                    " Select the custom field from the static dropdown"
                    " only."
                ),
            },
            {
                "label": self._param_label(PARAM_CUSTOM_FIELD_VALUE),
                "key": PARAM_CUSTOM_FIELD_VALUE,
                "type": "text",
                "default": "",
                "mandatory": True,
                "description": (
                    "Value to write into the selected custom field."
                    f" It can be up to"
                    f" {MAX_CUSTOM_FIELD_VALUE_LENGTH} characters."
                    " Enter a static value only."
                ),
            },
        ]

    # ------------------------------------------------------------------
    # Action validation
    # ------------------------------------------------------------------

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate the configuration of an action.

        Args:
            action (Action): Action with its parameters.

        Returns:
            ValidationResult: Success or failure with a message.
        """
        action_value = action.value
        if action_value not in SUPPORTED_ACTIONS:
            supported = ", ".join(
                f"'{self._action_label(value)}'"
                for value in SUPPORTED_ACTIONS
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
                    "Select an action from the list of supported"
                    " actions in the action configuration."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if action_value == ACTION_NO_ACTION:
            return self._validation_success(action)

        if result := self._validate_action_param(
            action,
            PARAM_USER_ID,
            check_dollar=True,
            custom_validation_func=self._is_valid_user_id_list,
        ):
            return result

        if action_value == ACTION_ADD_TO_GROUP:
            if result := self._validate_add_group_params(action):
                return result
        elif action_value == ACTION_REMOVE_FROM_GROUP:
            if result := self._validate_remove_group_params(action):
                return result
        elif action_value == ACTION_ENROLL_TRAINING:
            if result := self._validate_static_param(
                action,
                PARAM_TRAINING_CAMPAIGN_ID,
                custom_validation_func=self._is_valid_campaign_value,
            ):
                return result
        elif action_value == ACTION_UPDATE_FIELD:
            if result := self._validate_custom_field_params(action):
                return result

        return self._validation_success(action)

    def _validation_success(self, action: Action) -> ValidationResult:
        """Log and build the success result of a validated action.

        Args:
            action (Action): Validated action.

        Returns:
            ValidationResult: Successful result.
        """
        self.logger.debug(
            f"{self.log_prefix}: Successfully validated the action"
            f" configuration for '{self._action_label(action.value)}'."
        )
        return ValidationResult(
            success=True, message="Validation successful."
        )

    def _validate_action_param(
        self,
        action: Action,
        param_key: str,
        allowed_values: Optional[List] = None,
        custom_validation_func=None,
        check_dollar: bool = False,
        is_required: bool = True,
    ) -> Optional[ValidationResult]:
        """Validate one action parameter.

        Args:
            action (Action): Action with its parameters.
            param_key (str): Parameter key to validate.
            allowed_values (List): Values the parameter may hold.
            custom_validation_func: Extra check for the value.
            check_dollar (bool): Leave a Source field value for
                execution time.
            is_required (bool): Whether the parameter is mandatory.

        Returns:
            ValidationResult: On failure, else None.
        """
        return self.knowbe4_helper.validate_parameters(
            field_name=self._param_label(param_key),
            field_value=(action.parameters or {}).get(param_key, ""),
            field_type=str,
            parameter_type=ACTION,
            allowed_values=allowed_values,
            custom_validation_func=custom_validation_func,
            check_dollar=check_dollar,
            is_required=is_required,
        )

    def _validate_static_param(
        self,
        action: Action,
        param_key: str,
        allowed_values: Optional[List] = None,
        custom_validation_func=None,
        is_required: bool = True,
    ) -> Optional[ValidationResult]:
        """Validate a parameter that must hold a static value.

        Dropdown parameters cannot be mapped to a source field in the
        platform UI, so a source field value is rejected here.

        Args:
            action (Action): Action with its parameters.
            param_key (str): Parameter key to validate.
            allowed_values (List): Values the parameter may hold.
            custom_validation_func: Extra check for the value.
            is_required (bool): Whether the parameter is mandatory.

        Returns:
            ValidationResult: On failure, else None.
        """
        field_name = self._param_label(param_key)
        value = self.knowbe4_helper.get_stripped_param(
            action.parameters, param_key
        )
        if value.startswith("$"):
            err_msg = STATIC_FIELD_ERROR_MESSAGE.format(
                field_name=field_name
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=(
                    f"Select a static value for the '{field_name}'"
                    " action parameter."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        return self._validate_action_param(
            action,
            param_key,
            allowed_values=allowed_values,
            custom_validation_func=custom_validation_func,
            is_required=is_required,
        )

    def _is_valid_user_id_list(self, value: str) -> bool:
        """Check that a User ID value is well formed.

        The value may be a single user ID or a comma-separated list of
        them. Every comma-separated segment must be a non-empty
        numeric user ID — this also rejects an empty segment between
        commas (e.g. '123,,456') or around a leading or trailing comma
        (e.g. ',123' or '123,').

        Args:
            value (str): Value to check.

        Returns:
            bool: True when every comma-separated segment is a valid
                numeric user ID.
        """
        segments = value.split(",")
        return all(
            self.knowbe4_helper.to_int(segment.strip()) is not None
            for segment in segments
        )

    def _is_valid_action_batch_size(self, value: Any) -> Union[bool, str]:
        """Check that a Group Action Batch Size value is in range.

        Args:
            value (Any): Value to check.

        Returns:
            Union[bool, str]: True when value is a non-boolean int
                within [MIN_ACTION_BATCH_SIZE, MAX_ACTION_BATCH_SIZE],
                else an error message naming the valid range.
        """
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and MIN_ACTION_BATCH_SIZE <= value <= MAX_ACTION_BATCH_SIZE
        ):
            return True
        return RANGE_ERROR_MESSAGE.format(
            field_name=CONFIG_FIELD_LABELS[CONFIG_ACTION_BATCH_SIZE],
            parameter_type=CONFIGURATION,
            min_value=MIN_ACTION_BATCH_SIZE,
            max_value=MAX_ACTION_BATCH_SIZE,
        )

    def _is_valid_region_url(self, value: str) -> bool:
        """Check that a Custom Region URL value is a usable URL.

        Args:
            value (str): Value to check.

        Returns:
            bool: True when value has an http(s) scheme and a host.
        """
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)

    def _is_group_value(self, value: str) -> bool:
        """Check that an 'Add User to Group' group value is usable.

        Args:
            value (str): Value to check.

        Returns:
            bool: True for a packed group ID/name value or the create
                new group option.
        """
        if value == CREATE_NEW_GROUP_VALUE:
            return True
        group_id, _ = self.knowbe4_helper.split_group_value(value)
        return group_id is not None

    def _is_existing_group_value(self, value: str) -> bool:
        """Check that a 'Remove User from Group' group value is usable.

        The create-new-group option is never offered for this action,
        so only a packed existing group ID/name value is valid.

        Args:
            value (str): Value to check.

        Returns:
            bool: True for a packed group ID/name value.
        """
        group_id, _ = self.knowbe4_helper.split_group_value(value)
        return group_id is not None

    def _is_valid_campaign_value(self, value: str) -> bool:
        """Check that a 'Training Campaign' dropdown value is usable.

        Args:
            value (str): Value to check.

        Returns:
            bool: True for a packed campaign ID/name value.
        """
        campaign_id, _ = self.knowbe4_helper.split_campaign_value(value)
        return campaign_id is not None

    def _validate_add_group_params(
        self, action: Action
    ) -> Optional[ValidationResult]:
        """Validate the parameters of 'Add User to Group'.

        Args:
            action (Action): Action with its parameters.

        Returns:
            ValidationResult: On failure, else None.
        """
        if result := self._validate_static_param(
            action,
            PARAM_GROUP_ID,
            custom_validation_func=self._is_group_value,
        ):
            return result
        group_value = self.knowbe4_helper.get_stripped_param(
            action.parameters, PARAM_GROUP_ID
        )
        if group_value != CREATE_NEW_GROUP_VALUE:
            return None
        if result := self._validate_static_param(
            action, PARAM_NEW_GROUP_NAME
        ):
            return result
        return self._validate_max_length(
            action, PARAM_NEW_GROUP_NAME, MAX_GROUP_NAME_LENGTH
        )

    def _validate_remove_group_params(
        self, action: Action
    ) -> Optional[ValidationResult]:
        """Validate the parameters of 'Remove User from Group'.

        Args:
            action (Action): Action with its parameters.

        Returns:
            ValidationResult: On failure, else None.
        """
        return self._validate_static_param(
            action,
            PARAM_GROUP_ID,
            custom_validation_func=self._is_existing_group_value,
        )

    def _validate_custom_field_params(
        self, action: Action
    ) -> Optional[ValidationResult]:
        """Validate the parameters of the custom field action.

        Args:
            action (Action): Action with its parameters.

        Returns:
            ValidationResult: On failure, else None.
        """
        if result := self._validate_static_param(
            action,
            PARAM_CUSTOM_FIELD_SLOT,
            allowed_values=CUSTOM_FIELD_SLOTS,
        ):
            return result
        if result := self._validate_static_param(
            action, PARAM_CUSTOM_FIELD_VALUE
        ):
            return result
        return self._validate_max_length(
            action, PARAM_CUSTOM_FIELD_VALUE, MAX_CUSTOM_FIELD_VALUE_LENGTH
        )

    def _validate_max_length(
        self, action: Action, param_key: str, max_length: int
    ) -> Optional[ValidationResult]:
        """Check that a static parameter's value fits a length cap.

        Args:
            action (Action): Action with its parameters.
            param_key (str): Parameter key to check.
            max_length (int): Maximum allowed character count.

        Returns:
            ValidationResult: On failure, else None.
        """
        field_name = self._param_label(param_key)
        value = self.knowbe4_helper.get_stripped_param(
            action.parameters, param_key
        )
        if len(value) <= max_length:
            return None
        err_msg = LENGTH_ERROR_MESSAGE.format(
            field_name=field_name,
            parameter_type=ACTION,
            max_length=max_length,
        )
        self.logger.error(
            message=(
                f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                f" {err_msg}"
            ),
            resolution=(
                f"Provide a shorter value for the '{field_name}'"
                " action parameter."
            ),
        )
        return ValidationResult(success=False, message=err_msg)

    # ------------------------------------------------------------------
    # Action execution
    # ------------------------------------------------------------------

    def execute_actions(
        self, actions: List, revert: bool = False
    ) -> ActionResult:
        """Run a batch of actions against KnowBe4.

        Args:
            actions (List): Actions from the platform, each one a
                dictionary holding the action and its log ID.
            revert (bool): True when the platform is undoing actions
                that ran earlier.

        Returns:
            ActionResult: Result carrying the failed action IDs.
        """
        try:
            return self._execute_actions(actions, revert)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while performing the"
                " action."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ActionResult(
                success=False,
                message=err_msg,
                failed_action_ids=[
                    action.get("id") for action in actions or []
                ],
            )

    def _execute_actions(
        self, actions: List, revert: bool
    ) -> ActionResult:
        """Run the batch after the action type has been checked.

        Args:
            actions (List): Actions from the platform.
            revert (bool): True when undoing earlier actions.

        Returns:
            ActionResult: Result carrying the failed action IDs.
        """
        if not actions:
            return self._action_success([])

        action_value = actions[0].get("params").value
        action_label = self._action_label(action_value)
        all_action_ids = [action.get("id") for action in actions]

        if action_value == ACTION_NO_ACTION:
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action"
                f" '{action_label}' on {len(actions)} record(s). No"
                " processing is done in the plugin for this action."
            )
            return self._action_success([])

        if action_value not in SUPPORTED_ACTIONS:
            err_msg = (
                f"Unsupported action '{action_value}' provided in the"
                " action configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Select an action from the list of supported"
                    " actions in the action configuration."
                ),
            )
            return ActionResult(
                success=False,
                message=err_msg,
                failed_action_ids=all_action_ids,
            )

        if revert and action_value not in REVERTIBLE_ACTIONS:
            err_msg = (
                f"Revert is not supported for the '{action_label}'"
                " action."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Undo this action in the KnowBe4 console. Revert"
                    " is only available for the 'Add User to Group'"
                    " and 'Remove User from Group' actions."
                ),
            )
            return ActionResult(
                success=False,
                message=err_msg,
                failed_action_ids=all_action_ids,
            )

        region, ksat_token = self._get_ksat_credentials()
        self.logger.info(
            f"{self.log_prefix}: "
            + ("Reverting" if revert else "Performing")
            + f" action '{action_label}' on {len(actions)} record(s)."
        )

        if action_value in (ACTION_ADD_TO_GROUP, ACTION_REMOVE_FROM_GROUP):
            return self._execute_group_action(
                region, ksat_token, actions, action_value, revert
            )
        if action_value == ACTION_ENROLL_TRAINING:
            return self._execute_enroll_action(
                region, ksat_token, actions
            )
        return self._execute_custom_field_action(
            region, ksat_token, actions
        )

    def _action_success(
        self,
        failed_action_ids: List,
        message: str = "Action execution completed.",
    ) -> ActionResult:
        """Build the result returned after a batch has run.

        The result is reported as successful even when some actions
        failed, because the platform treats an unsuccessful result as
        a failure of every action in the batch.

        Args:
            failed_action_ids (List): IDs of the actions that failed.
            message (str): Result message shown to the user. Defaults
                to a generic message for the trivial no-op cases; the
                real action executions pass the same message
                `_log_action_summary()` already logged, so the toast
                and the log agree and both say "reverted" on revert
                and include the per-user counts.

        Returns:
            ActionResult: Result carrying the failed action IDs.
        """
        return ActionResult(
            success=True,
            message=message,
            failed_action_ids=list(dict.fromkeys(failed_action_ids)),
        )

    def _parse_target_user_ids(self, value: str) -> List[int]:
        """Parse the User ID parameter into one or more user IDs.

        The value may hold a single ID or a comma-separated list of
        IDs — a Static User ID is the same for every action record
        in the batch, so a comma-separated Static value is how one
        action configuration targets several fixed users at once.

        Args:
            value (str): Raw User ID parameter value.

        Returns:
            List[int]: Valid user IDs found in the value, in the order
                they appear. Empty when none are valid.
        """
        user_ids = []
        for segment in value.split(","):
            user_id = self.knowbe4_helper.to_int(segment.strip())
            if user_id is not None:
                user_ids.append(user_id)
        return user_ids

    def _group_actions(
        self, actions: List, action_label: str, param_keys: List
    ) -> tuple:
        """Group the batch by parameter values and target user.

        A User ID value that resolves to several user IDs (a
        comma-separated Static value) fans one action record out to
        every one of those IDs. Since every record in a batch driven
        by a Static User ID carries the identical value, the same
        user IDs — and the deduplication that follows from keying the
        inner map by user ID — are reached from every record.

        Args:
            actions (List): Actions from the platform.
            action_label (str): Action label used in log messages.
            param_keys (List): Parameter keys that identify a group.

        Returns:
            tuple: Grouped actions and the IDs of actions that could
                not be resolved. Grouped actions map a parameter value
                tuple to a map of user ID to action IDs.
        """
        grouped = {}
        failed_action_ids = []
        for action in actions:
            action_id = action.get("id")
            parameters = action.get("params").parameters or {}
            user_ids = self._parse_target_user_ids(
                self.knowbe4_helper.get_stripped_param(
                    parameters, PARAM_USER_ID
                )
            )
            key = tuple(
                self.knowbe4_helper.get_stripped_param(
                    parameters, param_key
                )
                for param_key in param_keys
            )
            if not user_ids or (param_keys and not key[0]):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping the"
                        f" '{action_label}' action for one record"
                        " because the target user ID(s) or a required"
                        " action parameter was not resolved."
                    ),
                    resolution=(
                        "Ensure that the mapped source field holds a"
                        " value on the matched record, or provide a"
                        " static value in the action configuration."
                    ),
                )
                failed_action_ids.append(action_id)
                continue
            for user_id in user_ids:
                grouped.setdefault(key, {}).setdefault(
                    user_id, []
                ).append(action_id)
        return grouped, failed_action_ids

    def _collect_action_ids(self, user_map: Dict, user_ids) -> List:
        """Collect the action IDs of the given users.

        Args:
            user_map (Dict): User ID to the action IDs targeting it.
            user_ids: User IDs to collect.

        Returns:
            List: Action IDs of those users.
        """
        action_ids = []
        for user_id in user_ids:
            action_ids.extend(user_map.get(user_id, []))
        return action_ids

    def _log_batch_result(
        self,
        message: str,
        failure_clause: str,
        failed_user_ids: List,
    ) -> None:
        """Log the outcome of one mutation batch sent to KnowBe4.

        Args:
            message (str): Success part of the message.
            failure_clause (str): Failure part, empty when none
                failed.
            failed_user_ids (List): Users the action failed for.
        """
        self.logger.info(
            message=f"{self.log_prefix}: {message}{failure_clause}",
            details=json.dumps({"Failed User IDs": failed_user_ids}),
        )

    def _log_action_summary(
        self,
        action_label: str,
        total_count: int,
        failed_count: int,
        revert: bool = False,
    ) -> str:
        """Log the final success/fail tally of one action execution.

        Args:
            action_label (str): Action label, used in the message.
            total_count (int): Users the action was attempted for.
            failed_count (int): Users the action failed for.
            revert (bool): True when this execution was a revert, so
                the message says "reverted" instead of "completed".

        Returns:
            str: The summary message, reused as the ActionResult
                message so the toast and the log agree.
        """
        verb = "revert" if revert else "process"
        message = (
            f"'{action_label}' action"
            f" {'reverted' if revert else 'completed'}. Successfully"
            f" {verb}ed {total_count - failed_count} user(s). Failed"
            f" to {verb} {failed_count} user(s)."
        )
        self.logger.info(f"{self.log_prefix}: {message}")
        return message

    def _execute_group_action(
        self,
        region: str,
        ksat_token: str,
        actions: List,
        action_value: str,
        revert: bool,
    ) -> ActionResult:
        """Add users to a group or remove them from a group.

        Reverting 'Add User to Group' removes the users instead, and
        reverting 'Remove User from Group' adds them instead — the
        direction is simply flipped, since the action's own value
        already says which mutation normally runs.

        Group resolution looks the group up by name the same way
        regardless of direction, so reverting an 'Add User to Group'
        action that created a new group still resolves to that group
        (found by name, not re-created) as long as it still exists.
        `revert` is passed through to `_resolve_group_id()` only for
        the one case where that lookup fails: on revert, a
        'Create new group' whose group was since deleted or renamed
        is skipped with a log instead of creating a fresh, empty
        group just to remove a user who was never a member of it.

        Args:
            region (str): Region GraphQL endpoint.
            ksat_token (str): KSAT API token.
            actions (List): Actions from the platform.
            action_value (str): ACTION_ADD_TO_GROUP or
                ACTION_REMOVE_FROM_GROUP.
            revert (bool): True to perform the inverse action.

        Returns:
            ActionResult: Result carrying the failed action IDs.
        """
        is_add = (action_value == ACTION_ADD_TO_GROUP) != revert
        action_label = self._action_label(action_value)
        batch_size = self._get_action_batch_size()
        verb = "added" if is_add else "removed"
        preposition = "to" if is_add else "from"
        grouped, failed_action_ids = self._group_actions(
            actions,
            action_label,
            [PARAM_GROUP_ID, PARAM_NEW_GROUP_NAME],
        )
        total_user_count = 0
        total_failed_count = 0
        for (group_value, new_group_name), user_map in grouped.items():
            total_user_count += len(user_map)
            try:
                group_id, group_name = self._resolve_group_id(
                    region,
                    ksat_token,
                    group_value,
                    new_group_name,
                    revert,
                )
            except KnowBe4PluginException:
                failed_action_ids.extend(
                    self._collect_action_ids(user_map, user_map.keys())
                )
                total_failed_count += len(user_map)
                continue
            batch_failed_ids, batch_failed_user_ids = (
                self._run_group_batches(
                    region,
                    ksat_token,
                    user_map,
                    group_id,
                    group_name,
                    is_add,
                    batch_size,
                )
            )
            failed_action_ids.extend(batch_failed_ids)
            total_failed_count += len(batch_failed_user_ids)
            success_user_ids = [
                user_id
                for user_id in user_map
                if user_id not in batch_failed_user_ids
            ]
            failure_clause = (
                f" Failed to {'add' if is_add else 'remove'}"
                f" {len(batch_failed_user_ids)} user(s) {preposition}"
                f" group '{group_name}'."
                if batch_failed_user_ids
                else ""
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully {verb}"
                f" {len(success_user_ids)} user(s) {preposition} group"
                f" '{group_name}'.{failure_clause}"
            )
        summary_message = self._log_action_summary(
            action_label, total_user_count, total_failed_count, revert
        )
        return self._action_success(failed_action_ids, summary_message)

    def _resolve_group_id(
        self,
        region: str,
        ksat_token: str,
        group_value: str,
        new_group_name: str,
        revert: bool,
    ) -> Tuple[int, str]:
        """Return the group ID and name an action should act on.

        For an existing group, the name is unpacked from the dropdown
        value the user selected — populated at the same time the
        group's ID was, so it costs no extra API call. For a newly
        created or reused group, the name is the one the user typed.

        Args:
            region (str): Region GraphQL endpoint.
            ksat_token (str): KSAT API token.
            group_value (str): Selected group value.
            new_group_name (str): Name of the group to create.
            revert (bool): True when reverting. When the group named
                by 'Create new group' can no longer be found by name
                (deleted or renamed since it was created), a revert
                is skipped instead of creating a fresh, empty group
                just to remove a user who was never a member of it.

        Returns:
            Tuple: (group_id, group_name).

        Raises:
            KnowBe4PluginException: When the group cannot be resolved.
        """
        if group_value == CREATE_NEW_GROUP_VALUE:
            if not new_group_name:
                err_msg = (
                    "No value was provided for the"
                    f" '{self._param_label(PARAM_NEW_GROUP_NAME)}'"
                    " action parameter."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Provide the name of the group to create in"
                        " the action configuration."
                    ),
                )
                raise KnowBe4PluginException(err_msg)
            existing_group_id = (
                self.knowbe4_helper.find_group_by_name(
                    url=region,
                    token=ksat_token,
                    group_name=new_group_name,
                    ssl_validation=self.ssl_validation,
                    proxy=self.proxy,
                )
            )
            if existing_group_id is not None:
                self.logger.info(
                    f"{self.log_prefix}: Group '{new_group_name}'"
                    f" already exists in {PLATFORM_NAME}. The existing"
                    " group will be used."
                )
                return existing_group_id, new_group_name
            if revert:
                err_msg = (
                    f"Group '{new_group_name}' does not exist in"
                    f" {PLATFORM_NAME}. Skipping the revert action."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "The group created by the original action was"
                        " deleted or renamed in KnowBe4. No action is"
                        " needed; the user was never added to a"
                        " different group."
                    ),
                )
                raise KnowBe4PluginException(err_msg)
            group_id = self.knowbe4_helper.create_group(
                url=region,
                token=ksat_token,
                group_name=new_group_name,
                ssl_validation=self.ssl_validation,
                proxy=self.proxy,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully created group"
                f" '{new_group_name}' in {PLATFORM_NAME}."
            )
            return group_id, new_group_name
        group_id, group_name = self.knowbe4_helper.split_group_value(
            group_value
        )
        if group_id is None:
            err_msg = (
                f"Invalid group '{group_value}' provided in the action"
                " configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Select a group from the dropdown in the action"
                    " configuration."
                ),
            )
            raise KnowBe4PluginException(err_msg)
        return group_id, group_name

    def _run_group_batches(
        self,
        region: str,
        ksat_token: str,
        user_map: Dict,
        group_id: int,
        group_name: str,
        is_add: bool,
        batch_size: int,
    ) -> Tuple[List, List]:
        """Send the group mutation in batches.

        Args:
            region (str): Region GraphQL endpoint.
            ksat_token (str): KSAT API token.
            user_map (Dict): User ID to the action IDs targeting it.
            group_id (int): Target group ID.
            group_name (str): Target group name, used in log messages.
            is_add (bool): True to add users, False to remove them.
            batch_size (int): Users sent in one mutation, from the
                'Group Action Batch Size' configuration parameter.

        Returns:
            Tuple: Action IDs that failed, and the user IDs that
                failed across every batch.
        """
        failed_action_ids = []
        failed_user_ids = []
        verb = "added" if is_add else "removed"
        gerund = "Adding" if is_add else "Removing"
        preposition = "to" if is_add else "from"
        user_ids = list(user_map.keys())
        batches = self.knowbe4_helper.chunk_list(user_ids, batch_size)
        for batch_number, batch in enumerate(batches, start=1):
            self.logger.info(
                f"{self.log_prefix}: {gerund} {len(batch)} user(s)"
                f" {preposition} group '{group_name}' in batch"
                f" {batch_number}."
            )
            stop_after_this_batch = False
            try:
                if is_add:
                    confirmed = (
                        self.knowbe4_helper.add_users_to_group(
                            region, ksat_token, batch, group_id,
                            group_name, batch_number,
                            self.ssl_validation, self.proxy,
                        )
                    )
                else:
                    confirmed = (
                        self.knowbe4_helper.remove_users_from_group(
                            region, ksat_token, batch, group_id,
                            group_name, batch_number,
                            self.ssl_validation, self.proxy,
                        )
                    )
            except KnowBe4AuthenticationException:
                confirmed = set()
                stop_after_this_batch = True
            except KnowBe4PluginException:
                confirmed = set()
            failed_users = [
                user_id
                for user_id in batch
                if user_id not in confirmed
            ]
            success_users = [
                user_id for user_id in batch if user_id not in failed_users
            ]
            failed_action_ids.extend(
                self._collect_action_ids(user_map, failed_users)
            )
            failed_user_ids.extend(failed_users)
            failure_clause = (
                f" Failed to {'add' if is_add else 'remove'}"
                f" {len(failed_users)} user(s) {preposition} group"
                f" '{group_name}' in batch {batch_number}."
                if failed_users
                else ""
            )
            self._log_batch_result(
                message=(
                    f"Successfully {verb} {len(success_users)} user(s)"
                    f" {preposition} group '{group_name}' in batch"
                    f" {batch_number}."
                ),
                failure_clause=failure_clause,
                failed_user_ids=failed_users,
            )
            if stop_after_this_batch:
                remaining_batches = batches[batch_number:]
                remaining_user_ids = [
                    user_id
                    for remaining in remaining_batches
                    for user_id in remaining
                ]
                if remaining_user_ids:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Authentication failed"
                            f" while {gerund.lower()} users"
                            f" {preposition} group '{group_name}'."
                            f" Skipping the remaining"
                            f" {len(remaining_user_ids)} user(s) in"
                            f" {len(remaining_batches)} batch(es)."
                        ),
                        resolution=(
                            "Verify the KSAT API token and the Region"
                            " provided in the configuration"
                            " parameters."
                        ),
                    )
                    failed_action_ids.extend(
                        self._collect_action_ids(
                            user_map, remaining_user_ids
                        )
                    )
                    failed_user_ids.extend(remaining_user_ids)
                break
        return failed_action_ids, failed_user_ids

    def _execute_enroll_action(
        self, region: str, ksat_token: str, actions: List
    ) -> ActionResult:
        """Enroll the users in the batch into a training campaign.

        KnowBe4 enrolls one user per call, so the batch is sent as one
        call per user.

        Args:
            region (str): Region GraphQL endpoint.
            ksat_token (str): KSAT API token.
            actions (List): Actions from the platform.

        Returns:
            ActionResult: Result carrying the failed action IDs.
        """
        action_label = self._action_label(ACTION_ENROLL_TRAINING)
        grouped, failed_action_ids = self._group_actions(
            actions, action_label, [PARAM_TRAINING_CAMPAIGN_ID]
        )
        total_user_count = 0
        total_failed_count = 0
        auth_failed = False
        for (campaign_value,), user_map in grouped.items():
            total_user_count += len(user_map)
            if auth_failed:
                failed_action_ids.extend(
                    self._collect_action_ids(user_map, user_map.keys())
                )
                total_failed_count += len(user_map)
                continue
            campaign_id, campaign_name = (
                self.knowbe4_helper.split_campaign_value(campaign_value)
            )
            if campaign_id is None:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Invalid training campaign"
                        f" '{campaign_value}' provided in the action"
                        " configuration."
                    ),
                    resolution=(
                        "Select a training campaign from the dropdown"
                        " in the action configuration."
                    ),
                )
                failed_action_ids.extend(
                    self._collect_action_ids(user_map, user_map.keys())
                )
                total_failed_count += len(user_map)
                continue
            failed_users = []
            remaining_user_ids = list(user_map)
            for index, user_id in enumerate(remaining_user_ids):
                self.logger.info(
                    f"{self.log_prefix}: Enrolling user ID '{user_id}'"
                    f" into training campaign '{campaign_name}'."
                )
                try:
                    self.knowbe4_helper.enroll_user_in_training(
                        region,
                        ksat_token,
                        campaign_id,
                        campaign_name,
                        user_id,
                        self.ssl_validation,
                        self.proxy,
                    )
                except KnowBe4AuthenticationException:
                    failed_users.append(user_id)
                    auth_failed = True
                    not_yet_attempted = remaining_user_ids[index + 1:]
                    if not_yet_attempted:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Authentication"
                                " failed while enrolling users into"
                                f" training campaign '{campaign_name}'."
                                " Skipping the remaining"
                                f" {len(not_yet_attempted)} user(s)."
                            ),
                            resolution=(
                                "Verify the KSAT API token and the"
                                " Region provided in the configuration"
                                " parameters."
                            ),
                        )
                        failed_users.extend(not_yet_attempted)
                    break
                except KnowBe4PluginException:
                    failed_users.append(user_id)
                    self.logger.info(
                        f"{self.log_prefix}: Failed to enroll user ID"
                        f" '{user_id}' into training campaign"
                        f" '{campaign_name}'."
                    )
                    continue
                except Exception as exp:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Unexpected error"
                            f" occurred while enrolling user ID"
                            f" '{user_id}' into training campaign"
                            f" '{campaign_name}'. Error: {exp}"
                        ),
                        details=traceback.format_exc(),
                    )
                    failed_users.append(user_id)
                    continue
                self.logger.info(
                    f"{self.log_prefix}: Successfully enrolled user ID"
                    f" '{user_id}' into training campaign"
                    f" '{campaign_name}'."
                )
            failed_action_ids.extend(
                self._collect_action_ids(user_map, failed_users)
            )
            total_failed_count += len(failed_users)
        summary_message = self._log_action_summary(
            action_label, total_user_count, total_failed_count
        )
        return self._action_success(failed_action_ids, summary_message)

    def _execute_custom_field_action(
        self, region: str, ksat_token: str, actions: List
    ) -> ActionResult:
        """Write a custom field value on the users in the batch.

        KnowBe4 updates one user per call, so the batch is sent as one
        call per user.

        Args:
            region (str): Region GraphQL endpoint.
            ksat_token (str): KSAT API token.
            actions (List): Actions from the platform.

        Returns:
            ActionResult: Result carrying the failed action IDs.
        """
        action_label = self._action_label(ACTION_UPDATE_FIELD)
        grouped, failed_action_ids = self._group_actions(
            actions,
            action_label,
            [PARAM_CUSTOM_FIELD_SLOT, PARAM_CUSTOM_FIELD_VALUE],
        )
        total_user_count = 0
        total_failed_count = 0
        auth_failed = False
        for (field_slot, field_value), user_map in grouped.items():
            total_user_count += len(user_map)
            if auth_failed:
                failed_action_ids.extend(
                    self._collect_action_ids(user_map, user_map.keys())
                )
                total_failed_count += len(user_map)
                continue
            if field_slot not in CUSTOM_FIELD_SLOTS:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Invalid custom field"
                        f" '{field_slot}' provided in the action"
                        " configuration."
                    ),
                    resolution=(
                        "Select a custom field from the dropdown in"
                        " the action configuration."
                    ),
                )
                failed_action_ids.extend(
                    self._collect_action_ids(user_map, user_map.keys())
                )
                total_failed_count += len(user_map)
                continue
            failed_users = []
            remaining_user_ids = list(user_map)
            for index, user_id in enumerate(remaining_user_ids):
                self.logger.info(
                    f"{self.log_prefix}: Updating custom field"
                    f" '{field_slot}' of user ID '{user_id}'."
                )
                try:
                    self.knowbe4_helper.update_user_custom_field(
                        region,
                        ksat_token,
                        user_id,
                        field_slot,
                        field_value,
                        self.ssl_validation,
                        self.proxy,
                    )
                except KnowBe4AuthenticationException:
                    failed_users.append(user_id)
                    auth_failed = True
                    not_yet_attempted = remaining_user_ids[index + 1:]
                    if not_yet_attempted:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Authentication"
                                " failed while updating custom field"
                                f" '{field_slot}'. Skipping the"
                                f" remaining {len(not_yet_attempted)}"
                                " user(s)."
                            ),
                            resolution=(
                                "Verify the KSAT API token and the"
                                " Region provided in the configuration"
                                " parameters."
                            ),
                        )
                        failed_users.extend(not_yet_attempted)
                    break
                except KnowBe4PluginException:
                    failed_users.append(user_id)
                    self.logger.info(
                        f"{self.log_prefix}: Failed to update custom"
                        f" field '{field_slot}' of user ID"
                        f" '{user_id}'."
                    )
                    continue
                except Exception as exp:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Unexpected error"
                            f" occurred while updating '{field_slot}'"
                            f" of user ID '{user_id}'. Error: {exp}"
                        ),
                        details=traceback.format_exc(),
                    )
                    failed_users.append(user_id)
                    continue
                self.logger.info(
                    f"{self.log_prefix}: Successfully updated custom"
                    f" field '{field_slot}' of user ID '{user_id}' in"
                    f" {PLATFORM_NAME}."
                )
            failed_action_ids.extend(
                self._collect_action_ids(user_map, failed_users)
            )
            total_failed_count += len(failed_users)
        summary_message = self._log_action_summary(
            action_label, total_user_count, total_failed_count
        )
        return self._action_success(failed_action_ids, summary_message)

    # ------------------------------------------------------------------
    # Configuration validation
    # ------------------------------------------------------------------

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the plugin configuration.

        Args:
            configuration (dict): Plugin configuration.

        Returns:
            ValidationResult: Success or failure with a message.
        """
        (
            _,
            ksat_token,
            additional_details,
            passwordiq_token,
            securitycoach_token,
            pull_archived_users,
        ) = self.knowbe4_helper.get_config_params(configuration)

        # Validated against the raw dropdown choice here, not the
        # resolved endpoint get_config_params() returns above - a
        # Custom Region URL value only ever makes sense once the
        # 'Base URL' choice is confirmed to actually be
        # REGION_CUSTOM_VALUE.
        raw_region = (configuration or {}).get(CONFIG_REGION, "")
        if isinstance(raw_region, str):
            raw_region = raw_region.strip()
        if result := self.knowbe4_helper.validate_parameters(
            field_name=CONFIG_FIELD_LABELS[CONFIG_REGION],
            field_value=raw_region,
            field_type=str,
            parameter_type=CONFIGURATION,
            allowed_values=ALLOWED_REGION_VALUES,
        ):
            return result

        if raw_region == REGION_CUSTOM_VALUE:
            custom_region_url = (configuration or {}).get(
                CONFIG_CUSTOM_REGION_URL, ""
            )
            if result := self.knowbe4_helper.validate_parameters(
                field_name=CONFIG_FIELD_LABELS[
                    CONFIG_CUSTOM_REGION_URL
                ],
                field_value=custom_region_url,
                field_type=str,
                parameter_type=CONFIGURATION,
                custom_validation_func=self._is_valid_region_url,
            ):
                return result
        # Else: 'Custom Region URL' can be empty, or hold a leftover
        # value from a previous selection - it is simply ignored when
        # 'Base URL' is not REGION_CUSTOM_VALUE.

        if result := self.knowbe4_helper.validate_parameters(
            field_name=CONFIG_FIELD_LABELS[CONFIG_KSAT_TOKEN],
            field_value=ksat_token,
            field_type=str,
            parameter_type=CONFIGURATION,
        ):
            return result

        if result := self.knowbe4_helper.validate_parameters(
            field_name=CONFIG_FIELD_LABELS[
                CONFIG_PULL_ADDITIONAL_DETAILS
            ],
            field_value=additional_details,
            field_type=list,
            parameter_type=CONFIGURATION,
            allowed_values=ADDITIONAL_DETAIL_VALUES,
            is_required=False,
        ):
            return result

        for detail_value, token_key, token_value in (
            (
                DETAIL_PASSWORDIQ,
                CONFIG_PASSWORDIQ_TOKEN,
                passwordiq_token,
            ),
            (
                DETAIL_SECURITYCOACH,
                CONFIG_SECURITYCOACH_TOKEN,
                securitycoach_token,
            ),
        ):
            if detail_value not in additional_details:
                continue
            if result := self.knowbe4_helper.validate_parameters(
                field_name=CONFIG_FIELD_LABELS[token_key],
                field_value=token_value,
                field_type=str,
                parameter_type=CONFIGURATION,
            ):
                return result

        if result := self.knowbe4_helper.validate_parameters(
            field_name=CONFIG_FIELD_LABELS[CONFIG_PULL_ARCHIVED_USERS],
            field_value=pull_archived_users,
            field_type=str,
            parameter_type=CONFIGURATION,
            allowed_values=TOGGLE_VALUES,
        ):
            return result

        action_batch_size = configuration.get(
            CONFIG_ACTION_BATCH_SIZE, ACTION_BATCH_SIZE
        )
        if result := self.knowbe4_helper.validate_parameters(
            field_name=CONFIG_FIELD_LABELS[CONFIG_ACTION_BATCH_SIZE],
            field_value=action_batch_size,
            field_type=int,
            parameter_type=CONFIGURATION,
            custom_validation_func=self._is_valid_action_batch_size,
            is_required=False,
        ):
            return result

        return self._validate_auth_params(configuration)

    def _validate_auth_params(
        self, configuration: dict
    ) -> ValidationResult:
        """Check every configured API token with a small API call.

        Args:
            configuration (dict): Plugin configuration.

        Returns:
            ValidationResult: Success or failure with a message.
        """
        (
            region,
            ksat_token,
            additional_details,
            passwordiq_token,
            securitycoach_token,
            _,
        ) = self.knowbe4_helper.get_config_params(configuration)
        try:
            self._validate_product_token(
                product=PRODUCT_KSAT,
                region=region,
                token=ksat_token,
                query=AUTH_CHECK_QUERY,
                variables={"per": AUTH_CHECK_PAGE_SIZE, "page": 1},
            )
            if DETAIL_PASSWORDIQ in additional_details:
                self._validate_product_token(
                    product=PRODUCT_PASSWORDIQ,
                    region=region,
                    token=passwordiq_token,
                    query=PASSWORDIQ_QUERY,
                    variables={
                        "detection": PIQ_DETECTIONS,
                        "userType": PIQ_USER_TYPE,
                        "pagination": {
                            "per": AUTH_CHECK_PAGE_SIZE,
                            "page": 1,
                        },
                    },
                )
            if DETAIL_SECURITYCOACH in additional_details:
                self._validate_product_token(
                    product=PRODUCT_SECURITYCOACH,
                    region=region,
                    token=securitycoach_token,
                    query=SECURITY_COACH_QUERY,
                    variables={
                        "search": "",
                        "draw": 1,
                        "start": 0,
                        "length": AUTH_CHECK_PAGE_SIZE,
                    },
                )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated the"
                " configuration parameters."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        except KnowBe4PluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while validating the"
                " configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)

    def _validate_product_token(
        self,
        product: str,
        region: str,
        token: str,
        query: str,
        variables: Dict,
    ) -> None:
        """Validate one product's API token with a small API call.

        Names the product in the error when the token itself is
        invalid, so the validation toast can tell the KSAT,
        PasswordIQ and SecurityCoach tokens apart instead of always
        showing the same generic "Unauthorized" message.

        Args:
            product (str): Product name, used in log/error messages.
            region (str): Region GraphQL endpoint.
            token (str): Product API token.
            query (str): GraphQL document.
            variables (Dict): GraphQL variables.

        Raises:
            KnowBe4PluginException: When the token is invalid, or any
                other validation call failure.
        """
        try:
            self.knowbe4_helper.graphql_request(
                logger_msg=f"validating the {product} API token",
                url=region,
                token=token,
                query=query,
                ssl_validation=self.ssl_validation,
                proxy=self.proxy,
                variables=variables,
                is_validation=True,
            )
        except KnowBe4AuthenticationException:
            err_msg = (
                f"Invalid {product} API Token provided. Verify the"
                " token and the Region."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=TOKEN_RESOLUTION_MESSAGE,
            )
            raise KnowBe4PluginException(err_msg)
