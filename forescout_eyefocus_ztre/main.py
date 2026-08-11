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

CRE Forescout eyeFocus REM Plugin.
"""

import copy
import hashlib
import traceback
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    ACTION_NO_ACTION,
    ADVANCED_FILTER_DYNAMIC_FIELDS,
    ALL_ADVANCED_FILTER_CHOICES,
    ALL_CATEGORY_CHOICES,
    ALL_PULL_STRATEGIES,
    CONFIGURATION,
    DEFAULT_PULL_WINDOW_DAYS,
    EMPTY_ERROR_MESSAGE,
    INTEGER_ERROR_MESSAGE,
    INTEGER_VALUE_KIND,
    INVALID_VALUE_ERROR_MESSAGE,
    MAX_INITIAL_RANGE_DAYS,
    MAX_PULL_WINDOW_DAYS,
    MAX_VALUE_ERROR_MESSAGE,
    MIN_INITIAL_RANGE_DAYS,
    MIN_PULL_WINDOW_DAYS,
    MIN_VALUE_ERROR_MESSAGE,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PULL_STRATEGY_FULL,
    RANGE_ERROR_MESSAGE,
    RISK_SCORE_EXAMPLE,
    RISK_SCORE_FORMAT_ERROR_MESSAGE,
    RISK_SCORE_MAX_PARAM,
    RISK_SCORE_MIN_PARAM,
    RISK_SCORE_SCALE_MAX,
    RISK_SCORE_SCALE_MIN,
    STORAGE_CHECKPOINT_KEY,
    SUPPORTED_ACTIONS,
    SUPPORTED_ENTITY,
    TYPE_ERROR_MESSAGE,
    URL_ERROR_MESSAGE,
    VALIDATION_ERROR_MESSAGE,
)
from .utils.exceptions import ForescoutEyeFocusPluginException
from .utils.helper import ForescoutEyeFocusPluginHelper
from .utils.parser import ForescoutEyeFocusParser


class ForescoutEyeFocusPlugin(PluginBase):
    """Forescout eyeFocus REM CRE plugin implementation."""

    def __init__(self, name, *args, **kwargs):
        """Initialize the plugin.

        Args:
            name (str): Configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.forescout_helper = ForescoutEyeFocusPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )
        self.parser = ForescoutEyeFocusParser()

    # ------------------------------------------------------------------ #
    # Plugin metadata
    # ------------------------------------------------------------------ #
    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from the manifest."""
        try:
            manifest_json = ForescoutEyeFocusPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
                resolution=(
                    "Verify that the plugin package is installed correctly "
                    "and that its manifest.json is valid."
                ),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _get_storage(self) -> Dict:
        """Return the plugin storage dict (mutations persist across runs)."""
        return self.storage if self.storage is not None else {}

    # ------------------------------------------------------------------ #
    # Dynamic configuration fields
    # ------------------------------------------------------------------ #
    def get_dynamic_fields(self) -> List[Dict]:
        """Return the configuration fields that depend on other fields.

        Setting "Apply Risk Score Filter" to Yes reveals the optional
        server-side risk-score bounds ("Minimum Risk Score" / "Maximum Risk
        Score"); selecting No hides them and the pull fetches assets of every
        risk score.
        """
        if self.forescout_helper.is_advanced_filters_enabled(
            self.configuration or {}
        ):
            return copy.deepcopy(ADVANCED_FILTER_DYNAMIC_FIELDS)
        return []

    # ------------------------------------------------------------------ #
    # Entities
    # ------------------------------------------------------------------ #
    def get_entities(self) -> List[Entity]:
        """Get available entities exposed by this plugin."""
        return [
            Entity(
                name=SUPPORTED_ENTITY,
                fields=[
                    EntityField(
                        name="Asset ID",
                        type=EntityFieldType.STRING,
                        description=(
                            "Unique identifier of the Forescout asset."
                        ),
                        required=True,
                    ),
                    EntityField(
                        name="Hostname",
                        type=EntityFieldType.STRING,
                        description="Hostname reported for the asset.",
                    ),
                    EntityField(
                        name="IP Addresses",
                        type=EntityFieldType.LIST,
                        description=(
                            "IP address(es) associated with the asset. The "
                            "key datapoint used to build Netskope Network "
                            "Location objects."
                        ),
                    ),
                    EntityField(
                        name="Category",
                        type=EntityFieldType.STRING,
                        description=(
                            "Forescout asset category (e.g. Network Device, "
                            "Medical Device, OT, IoT, IT, Unknown)."
                        ),
                    ),
                    EntityField(
                        name="Function",
                        type=EntityFieldType.STRING,
                        description=(
                            "Forescout asset function (e.g. CT Scanner, PLC, "
                            "Switch, IP Camera)."
                        ),
                    ),
                    EntityField(
                        name="Vendor",
                        type=EntityFieldType.STRING,
                        description="Asset vendor / manufacturer.",
                    ),
                    EntityField(
                        name="OS",
                        type=EntityFieldType.STRING,
                        description="Operating system of the asset.",
                    ),
                    EntityField(
                        name="Model",
                        type=EntityFieldType.STRING,
                        description="Asset model.",
                    ),
                    EntityField(
                        name="Firmware",
                        type=EntityFieldType.STRING,
                        description="Asset firmware version.",
                    ),
                    EntityField(
                        name="Risk Score",
                        type=EntityFieldType.NUMBER,
                        description=(
                            "Raw Forescout risk score on a 0-10 scale "
                            "(higher = more risk)."
                        ),
                    ),
                    EntityField(
                        name="Risk Severity",
                        type=EntityFieldType.STRING,
                        description=(
                            "Forescout risk severity (e.g. high, medium, low)."
                        ),
                    ),
                    EntityField(
                        name="Asset Criticality",
                        type=EntityFieldType.STRING,
                        description="Forescout asset criticality.",
                    ),
                    EntityField(
                        name="Last Seen",
                        type=EntityFieldType.DATETIME,
                        description=(
                            "Timestamp the asset was last seen by Forescout."
                        ),
                    ),
                    EntityField(
                        name="Last Seen Online",
                        type=EntityFieldType.DATETIME,
                        description=(
                            "Timestamp the asset was last seen online by "
                            "Forescout."
                        ),
                    ),
                    EntityField(
                        name="MAC Addresses",
                        type=EntityFieldType.LIST,
                        description=(
                            "MAC address(es) associated with the asset."
                        ),
                    ),
                ],
            )
        ]

    # ------------------------------------------------------------------ #
    # Actions (data-only plugin: no actions)
    # ------------------------------------------------------------------ #
    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions. This plugin does not support any actions."""
        return [
            ActionWithoutParams(label="No actions", value=ACTION_NO_ACTION),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action."""
        if action.value == ACTION_NO_ACTION:
            return []
        return []

    def execute_actions(self, actions: List[Action]):
        """Execute the (no-op) action in bulk.

        This data-only plugin supports only the 'No actions' action, so there
        is nothing to perform on the assets.

        Args:
            actions (List[Action]): Actions supplied by the CE framework.
        """
        first_action = actions[0]
        action_label = first_action.label
        if first_action.value == ACTION_NO_ACTION:
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action "
                f"'{action_label}' on {len(actions)} record(s). "
                "Note: no processing is done by the plugin for the "
                f"'{action_label}' action."
            )
            return

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate an action configuration."""
        if action.value not in SUPPORTED_ACTIONS:
            err_msg = (
                f"Unsupported action '{action.value}' provided in the action "
                "configuration. Supported action is 'No actions'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} {err_msg}"
                ),
                resolution=(
                    "Select the action from the list of supported actions in "
                    "the action configuration."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        self.logger.debug(
            f"{self.log_prefix}: Successfully validated action "
            f"'{action.label}'."
        )
        return ValidationResult(success=True, message="Validation successful.")

    # ------------------------------------------------------------------ #
    # Fetch (windowed + resumable checkpoint)
    # ------------------------------------------------------------------ #
    def _validate_entity(self, entity: str):
        """Raise when an unsupported entity is requested."""
        if entity != SUPPORTED_ENTITY:
            err_msg = (
                f"Unsupported entity '{entity}' provided. Only "
                f"'{SUPPORTED_ENTITY}' is supported."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Map the '{SUPPORTED_ENTITY}' entity in the plugin "
                    "configuration."
                ),
            )
            raise ForescoutEyeFocusPluginException(err_msg)

    def _config_hash(self) -> str:
        """Hash of the settings that define what a sweep covers.

        A resume checkpoint is only valid while the target instance, the pull
        strategy and the server-side risk bounds are unchanged; editing any of
        them would otherwise let a single sweep mix assets selected under
        different criteria.
        """
        base_url, _ = self.forescout_helper.get_credentials(
            self.configuration
        )
        config_params = self.forescout_helper.get_config_params(
            self.configuration
        )
        signature = "|".join(
            [
                base_url or "",
                str(config_params["pull_strategy"]),
                str(config_params["risk_score_min"]),
                str(config_params["risk_score_max"]),
            ]
        )
        return hashlib.sha256(signature.encode("utf-8")).hexdigest()

    def _save_checkpoint(
        self, storage: Dict, next_window_start: datetime, config_hash: str
    ):
        """Persist the resume point (start of the next un-fetched window)."""
        storage[STORAGE_CHECKPOINT_KEY] = {
            "next_window_start": self.forescout_helper.format_datetime(
                next_window_start
            ),
            "config_hash": config_hash,
        }

    def _clear_checkpoint(self, storage: Dict):
        """Drop the resume checkpoint once a pull completes successfully."""
        storage.pop(STORAGE_CHECKPOINT_KEY, None)

    def _resolve_pull_range(
        self, config_params: Dict, storage: Dict, config_hash: str
    ) -> Tuple[datetime, datetime]:
        """Compute the (from, to) range for this pull.

        An unfinished sweep always wins: a valid resume checkpoint is honoured
        under either strategy so a run interrupted by an API error finishes
        its remaining windows before a fresh range is started.

        Otherwise the range depends on the configured Pull Strategy:

        - ``full``: ``[now - Initial Range, now]`` on *every* pull, so all
          assets in the range are re-fetched each cycle.
        - ``incremental``: ``[last successful run, now]``, falling back to
          ``[now - Initial Range, now]`` when there is no previous run.
        """
        now = datetime.now(timezone.utc)
        checkpoint = storage.get(STORAGE_CHECKPOINT_KEY)
        if (
            isinstance(checkpoint, dict)
            and checkpoint.get("config_hash") == config_hash
            and checkpoint.get("next_window_start")
        ):
            resume_start = self.parser._parse_datetime(
                checkpoint["next_window_start"]
            )
            if resume_start is not None and resume_start < now:
                self.logger.info(
                    f"{self.log_prefix}: Resuming pull from "
                    f"checkpoint {checkpoint['next_window_start']}."
                )
                return resume_start, now

        # No usable checkpoint -> drop any stale one and start a fresh range.
        if checkpoint:
            storage.pop(STORAGE_CHECKPOINT_KEY, None)

        initial_range = config_params["initial_range"]
        if config_params["pull_strategy"] == PULL_STRATEGY_FULL:
            self.logger.info(
                f"{self.log_prefix}: Pull Strategy is 'Full Window'; "
                "fetching all assets last seen in the past "
                f"{initial_range} day(s)."
            )
            return now - timedelta(days=initial_range), now

        if self.last_run_at:
            from_dt = self.last_run_at
            if from_dt.tzinfo is None:
                from_dt = from_dt.replace(tzinfo=timezone.utc)
            self.logger.info(
                f"{self.log_prefix}: Pull Strategy is 'Incremental'; fetching "
                "assets last seen since the previous successful run "
                f"({self.forescout_helper.format_datetime(from_dt)})."
            )
        else:
            from_dt = now - timedelta(days=initial_range)
            self.logger.info(
                f"{self.log_prefix}: Pull Strategy is 'Incremental' and no "
                "previous run was found. This is the initial pull; fetching "
                f"assets last seen in the past {initial_range} day(s)."
            )
        return from_dt, now

    def _merge_record(self, records_by_id: Dict, record: Dict):
        """Insert/update a record keyed by Asset ID, keeping the entry with
        the most recent ``Last Seen`` (de-duplicates assets that appear in
        more than one window)."""
        asset_id = record.get("Asset ID")
        if not asset_id:
            return
        existing = records_by_id.get(asset_id)
        if existing is None:
            records_by_id[asset_id] = record
            return
        new_seen = record.get("Last Seen")
        old_seen = existing.get("Last Seen")
        if new_seen is not None and (
            old_seen is None or new_seen >= old_seen
        ):
            records_by_id[asset_id] = record

    @staticmethod
    def _describe_risk_bounds(
        risk_score_min: Optional[float], risk_score_max: Optional[float]
    ) -> str:
        """Render the active risk-score bounds for a log line."""
        bounds = []
        if risk_score_min is not None:
            bounds.append(f"risk score >= {risk_score_min}")
        if risk_score_max is not None:
            bounds.append(f"risk score <= {risk_score_max}")
        return ", ".join(bounds) if bounds else "disabled"

    def fetch_records(self, entity: str) -> List:
        """Fetch asset records from the Forescout REM Asset Search API.

        The range - determined by the configured Pull Strategy - is swept one
        Data Pull Window at a time. After each window completes, a checkpoint
        is written to storage. If an API error occurs mid-pull, the checkpoint
        stays at the failed window so the next run resumes there; records
        already collected are returned so no data is lost. On full completion
        the checkpoint is cleared.
        """
        try:
            self._validate_entity(entity)
            base_url, api_token = self.forescout_helper.get_credentials(
                self.configuration
            )
            config_params = self.forescout_helper.get_config_params(
                self.configuration
            )
            risk_score_min = config_params["risk_score_min"]
            risk_score_max = config_params["risk_score_max"]
            self.logger.info(
                f"{self.log_prefix}: Fetching {entity.lower()} records from "
                f"{PLATFORM_NAME} eyeFocus platform. Pull Strategy: "
                f"'{config_params['pull_strategy']}'. Apply Risk Score Filter: "
                f"{self._describe_risk_bounds(risk_score_min, risk_score_max)}"
                "."
            )
            storage = self._get_storage()
            config_hash = self._config_hash()
            range_start, range_end = self._resolve_pull_range(
                config_params, storage, config_hash
            )
            window = timedelta(days=config_params["pull_window_days"])
            if window.total_seconds() <= 0:
                window = timedelta(days=DEFAULT_PULL_WINDOW_DAYS)

            records_by_id: Dict = {}
            total_skipped = 0
            window_start = range_start
            window_index = 0
            while window_start < range_end:
                window_index += 1
                window_end = min(window_start + window, range_end)
                try:
                    entities = self.forescout_helper.fetch_asset_window(
                        base_url=base_url,
                        api_token=api_token,
                        from_dt=window_start,
                        to_dt=window_end,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        risk_score_min=risk_score_min,
                        risk_score_max=risk_score_max,
                    )
                except ForescoutEyeFocusPluginException as err:
                    # Persist the failed window as the resume point.
                    self._save_checkpoint(storage, window_start, config_hash)
                    failed_from = self.forescout_helper.format_datetime(
                        window_start
                    )
                    if records_by_id:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Error while fetching "
                                f"window starting {failed_from}. Returning "
                                f"{len(records_by_id)} record(s) collected so "
                                "far; the pull resumes from this window "
                                f"on the next run. Error: {err}"
                            ),
                            details=str(traceback.format_exc()),
                            resolution=(
                                "The remaining assets will be fetched on the "
                                "next pull cycle from the saved checkpoint."
                            ),
                        )
                        return list(records_by_id.values())
                    raise

                records, skipped = self.parser.parse_entities(
                    entities=entities,
                    categories=config_params["asset_categories"],
                )
                total_skipped += skipped

                for record in records:
                    self._merge_record(records_by_id, record)

                window_start = window_end
                self._save_checkpoint(storage, window_start, config_hash)
                self.logger.info(
                    f"{self.log_prefix}: Window {window_index} processed; "
                    f"{len(entities)} asset(s), {len(records)} kept after "
                    f"filtering. Running unique total: {len(records_by_id)}."
                )

            self._clear_checkpoint(storage)
            info_msg = (
                f"Successfully fetched {len(records_by_id)} asset "
                f"record(s) from {PLATFORM_NAME} eyeFocus platform."
            )
            if total_skipped > 0:
                info_msg += (
                    f" Skipped {total_skipped} asset(s) filtered out by the "
                    "configured Asset Categories."
                )
            self.logger.info(f"{self.log_prefix}: {info_msg}")
            return list(records_by_id.values())
        except ForescoutEyeFocusPluginException:
            raise
        except Exception as err:
            error_msg = (
                f"Unexpected error occurred while fetching {entity} records."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Verify the configuration parameters and that the "
                    f"{PLATFORM_NAME} platform is reachable."
                ),
            )
            raise ForescoutEyeFocusPluginException(error_msg)

    # ------------------------------------------------------------------ #
    # Update (no-op)
    # ------------------------------------------------------------------ #
    def update_records(self, entity: str, records: list) -> list:
        """No-op update.

        ``fetch_records`` already returns the complete, current asset record
        (identity, category, IP/MAC addresses and risk fields) in a single
        pass, so there is nothing to refresh or enrich here.
        """
        self._validate_entity(entity)
        self.logger.info(
            f"{self.log_prefix}: No update required for {len(records)} "
            f"{entity.lower()} record(s); all fields are populated during the "
            "fetch."
        )
        return []

    # ------------------------------------------------------------------ #
    # Validation
    # ------------------------------------------------------------------ #
    def _validation_error(
        self, message: str, resolution: str = None
    ) -> ValidationResult:
        """Log a validation failure and build a ValidationResult."""
        self.logger.error(
            message=f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} {message}",
            resolution=resolution,
        )
        return ValidationResult(success=False, message=message)

    @staticmethod
    def _constraint_suffix(
        integer_only: bool, min_value, max_value
    ) -> str:
        """Build the ' Valid value should be ...' suffix for a numeric field.

        Every rejection tells the user what an acceptable value looks like -
        the bounds are never left implicit in the message.
        """
        value_kind = INTEGER_VALUE_KIND if integer_only else ""
        if min_value is not None and max_value is not None:
            return RANGE_ERROR_MESSAGE.format(
                value_kind=value_kind,
                min_value=min_value,
                max_value=max_value,
            )
        if min_value is not None:
            return MIN_VALUE_ERROR_MESSAGE.format(
                value_kind=value_kind, min_value=min_value
            )
        if max_value is not None:
            return MAX_VALUE_ERROR_MESSAGE.format(
                value_kind=value_kind, max_value=max_value
            )
        return INTEGER_ERROR_MESSAGE if integer_only else ""

    def _validate_parameters(
        self,
        parameter_type: str,
        field_name: str,
        field_value,
        field_type,
        is_required: bool = True,
        allowed_values: Optional[list] = None,
        min_value=None,
        max_value=None,
        integer_only: bool = False,
        custom_validation_func: Optional[Callable] = None,
        custom_error_message: str = "",
    ) -> Optional[ValidationResult]:
        """Validate a single configuration / action parameter value.

        Args:
            parameter_type (str): CONFIGURATION or ACTION - used in the
                message so the user knows which form to look at.
            field_name (str): Label exactly as shown in the UI.
            field_value: Value to validate.
            field_type: Expected Python type(s).
            is_required (bool): When False, a blank value is accepted.
            allowed_values (Optional[list]): Permitted values. Every element
                of a list value must be permitted.
            min_value / max_value: Inclusive numeric bounds. Both are quoted
                back in the error message and the resolution.
            integer_only (bool): Reject fractional numbers. Used where a
                fractional value would be silently truncated downstream.
            custom_validation_func (Optional[Callable]): Extra rule run after
                the empty / type / range checks.
            custom_error_message (str): Appended when
                ``custom_validation_func`` rejects the value, so the user is
                told which rule was broken.

        Returns:
            ValidationResult on failure, or ``None`` when the value is valid,
            so it can be used with the walrus operator:
            ``if result := self._validate_parameters(...): return result``.
        """
        if isinstance(field_value, str):
            field_value = field_value.strip()

        # Optional field left blank -> valid.
        if not is_required and (field_value is None or field_value == ""):
            return None

        # Required field missing / empty.
        if field_value is None or field_value == "":
            return self._validation_error(
                EMPTY_ERROR_MESSAGE.format(
                    field_name=field_name, parameter_type=parameter_type
                ),
                f"Provide a value for the '{field_name}' {parameter_type} "
                "parameter.",
            )

        base_err = TYPE_ERROR_MESSAGE.format(
            field_name=field_name, parameter_type=parameter_type
        )
        is_numeric = min_value is not None or max_value is not None

        # Type check (a bool is never a valid number/string here).
        if not isinstance(field_value, field_type) or (
            isinstance(field_value, bool) and field_type is not bool
        ):
            return self._validation_error(
                base_err
                + self._constraint_suffix(
                    integer_only, min_value, max_value
                ),
                f"Provide a valid value for the '{field_name}' "
                f"{parameter_type} parameter.",
            )

        # Whole-number check, where a fraction would be truncated later.
        if integer_only and float(field_value) != int(field_value):
            return self._validation_error(
                base_err
                + self._constraint_suffix(True, min_value, max_value),
                f"Provide a whole number for '{field_name}'"
                + (
                    f" between {min_value} and {max_value}."
                    if is_numeric and min_value is not None
                    and max_value is not None
                    else "."
                ),
            )

        # Inclusive numeric bounds.
        if (min_value is not None and field_value < min_value) or (
            max_value is not None and field_value > max_value
        ):
            resolution = (
                f"Provide a value for '{field_name}' in range "
                f"{min_value} to {max_value}."
                if min_value is not None and max_value is not None
                else f"Provide a valid value for '{field_name}'."
            )
            return self._validation_error(
                base_err
                + self._constraint_suffix(
                    integer_only, min_value, max_value
                ),
                resolution,
            )

        # Field-specific rule.
        if custom_validation_func is not None and not custom_validation_func(
            field_value
        ):
            return self._validation_error(
                base_err + custom_error_message,
                f"Provide a valid value for the '{field_name}' "
                f"{parameter_type} parameter.",
            )

        # Allowed values (each element of a list must be permitted).
        if allowed_values is not None:
            values = (
                field_value
                if isinstance(field_value, list)
                else [field_value]
            )
            if any(value not in allowed_values for value in values):
                allowed = ", ".join(f"'{v}'" for v in allowed_values)
                return self._validation_error(
                    base_err
                    + INVALID_VALUE_ERROR_MESSAGE.format(
                        allowed_values=allowed
                    ),
                    f"Select '{field_name}' only from the allowed values: "
                    f"{allowed}.",
                )
        return None

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the plugin configuration parameters."""
        base_url, api_token = self.forescout_helper.get_credentials(
            configuration
        )

        if result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Base URL",
            field_value=base_url,
            field_type=str,
            custom_validation_func=self.forescout_helper._validate_url,
            custom_error_message=URL_ERROR_MESSAGE,
        ):
            return result

        if result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="API Token",
            field_value=api_token,
            field_type=str,
        ):
            return result

        if result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Asset Categories",
            field_value=configuration.get("asset_categories", []),
            field_type=list,
            is_required=False,
            allowed_values=ALL_CATEGORY_CHOICES,
        ):
            return result

        if result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Pull Strategy",
            field_value=configuration.get("pull_strategy"),
            field_type=str,
            allowed_values=ALL_PULL_STRATEGIES,
        ):
            return result

        if result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Initial Range (in days)",
            field_value=configuration.get("initial_range"),
            field_type=(int, float),
            min_value=MIN_INITIAL_RANGE_DAYS,
            max_value=MAX_INITIAL_RANGE_DAYS,
            integer_only=True,
        ):
            return result

        if result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Pagination Window (in days)",
            field_value=configuration.get("pull_window"),
            field_type=(int, float),
            min_value=MIN_PULL_WINDOW_DAYS,
            max_value=MAX_PULL_WINDOW_DAYS,
            integer_only=True,
        ):
            return result

        if result := self._validate_advanced_filters(configuration):
            return result

        return self._validate_auth_params(configuration)

    def _validate_risk_score(
        self,
        field_name: str,
        raw_value,
        bounds: dict,
        key: str,
    ) -> Optional[ValidationResult]:
        """Validate one risk-score bound entered as text.

        The bounds are "text" configuration fields, so the value arrives as a
        string and needs three distinct checks with three distinct messages:
        it must be a string, it must look like a number, and it must sit within
        the 0-10 scale. Collapsing them into one message would leave the user
        guessing which rule they broke.

        The parsed float is stored in ``bounds[key]`` so the caller can apply
        the min <= max cross-check without re-parsing.

        Returns a ValidationResult on failure, or ``None`` when valid (a blank
        value is valid - the bound is simply not applied).
        """
        if isinstance(raw_value, str):
            raw_value = raw_value.strip()

        # Blank -> the bound is not applied.
        if raw_value is None or raw_value == "":
            bounds[key] = None
            return None

        # A text field must not receive a list / dict from the UI.
        if not isinstance(raw_value, (str, int, float)) or isinstance(
            raw_value, bool
        ):
            return self._validation_error(
                TYPE_ERROR_MESSAGE.format(
                    field_name=field_name, parameter_type=CONFIGURATION
                )
                + RISK_SCORE_FORMAT_ERROR_MESSAGE,
            )

        parsed = self.forescout_helper.parse_risk_score(raw_value)
        if parsed is None:
            return self._validation_error(
                TYPE_ERROR_MESSAGE.format(
                    field_name=field_name, parameter_type=CONFIGURATION
                )
                + RISK_SCORE_FORMAT_ERROR_MESSAGE,
            )

        if not (
            RISK_SCORE_SCALE_MIN <= parsed <= RISK_SCORE_SCALE_MAX
        ):
            return self._validation_error(
                TYPE_ERROR_MESSAGE.format(
                    field_name=field_name, parameter_type=CONFIGURATION
                )
                + RANGE_ERROR_MESSAGE.format(
                    value_kind="",
                    min_value=RISK_SCORE_SCALE_MIN,
                    max_value=RISK_SCORE_SCALE_MAX,
                ),
                f"Provide a value for '{field_name}' in range "
                f"{RISK_SCORE_SCALE_MIN} to {RISK_SCORE_SCALE_MAX}.",
            )

        bounds[key] = parsed
        return None

    def _validate_advanced_filters(
        self, configuration: dict
    ) -> Optional[ValidationResult]:
        """Validate the "Apply Risk Score Filter" toggle and its dynamic fields.

        Returns a ValidationResult on failure, or ``None`` when the advanced
        filter configuration is valid.
        """
        if result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Apply Risk Score Filter",
            field_value=configuration.get("advanced_filters"),
            field_type=str,
            allowed_values=ALL_ADVANCED_FILTER_CHOICES,
        ):
            return result

        if not self.forescout_helper.is_advanced_filters_enabled(
            configuration
        ):
            # The dynamic fields are hidden; whatever they may still hold is
            # ignored by the pull, so there is nothing left to validate.
            return None

        bounds = {}
        for field_name, key in (
            ("Minimum Risk Score", RISK_SCORE_MIN_PARAM),
            ("Maximum Risk Score", RISK_SCORE_MAX_PARAM),
        ):
            if result := self._validate_risk_score(
                field_name=field_name,
                raw_value=configuration.get(key),
                bounds=bounds,
                key=key,
            ):
                return result

        score_min = bounds.get(RISK_SCORE_MIN_PARAM)
        score_max = bounds.get(RISK_SCORE_MAX_PARAM)
        if score_min is None and score_max is None:
            return self._validation_error(
                "'Minimum Risk Score' or 'Maximum Risk Score' is required "
                "when 'Apply Risk Score Filter' is set to 'Yes'.",
                "Provide at least one risk score bound, or set "
                "'Apply Risk Score Filter' to 'No' to fetch assets of "
                "every risk score.",
            )
        if (
            score_min is not None
            and score_max is not None
            and score_min > score_max
        ):
            return self._validation_error(
                "'Minimum Risk Score' must be less than or equal to "
                "'Maximum Risk Score'.",
                f"Provide a 'Minimum Risk Score' ({score_min}) that does not "
                f"exceed the 'Maximum Risk Score' ({score_max}).",
            )
        return None

    def _validate_auth_params(
        self, configuration: dict
    ) -> ValidationResult:
        """Validate credentials (and any advanced filter bounds) with a
        lightweight authenticated API call."""
        try:
            base_url, api_token = self.forescout_helper.get_credentials(
                configuration
            )
            config_params = self.forescout_helper.get_config_params(
                configuration
            )
            self.forescout_helper.validate_connectivity(
                base_url=base_url,
                api_token=api_token,
                verify=self.ssl_validation,
                proxies=self.proxy,
                risk_score_min=config_params["risk_score_min"],
                risk_score_max=config_params["risk_score_max"],
            )
        except ForescoutEyeFocusPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = (
                "Error occurred while validating configuration parameters. "
                "Verify the Base URL and API Token provided."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure the Base URL and API Token are correct and the "
                    f"{PLATFORM_NAME} platform is reachable."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        self.logger.debug(
            f"{self.log_prefix}: Validation completed successfully."
        )
        return ValidationResult(success=True, message="Validation successful.")
