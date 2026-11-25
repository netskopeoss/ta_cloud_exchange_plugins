"""CRE Armis Centrix plugin.

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
"""

import functools
import json
import traceback
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    ActionResult,
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils import constants as CONST
from .utils.exceptions import ArmisPluginException
from .utils.helper import ArmisPluginHelper


def ui_call(method: Callable) -> Callable:
    """Send the Armis requests of a UI-driven method once, without retry.

    Cloud Exchange calls these methods while the user waits in the UI, so
    a request is never retried or delayed there. Pull, refresh and action
    execution keep their retries.

    Args:
        method (Callable): Plugin method.

    Returns:
        Callable: Method that runs in the helper's single_attempt() mode.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self.armis_helper.single_attempt():
            return method(self, *args, **kwargs)
    return wrapper


class ArmisPlugin(PluginBase):
    """Armis CRE plugin implementation."""

    def __init__(self, name, *args, **kwargs):
        """Initialize the plugin.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = self._build_log_prefix(self.plugin_name)
        # execute_actions() receives the id of every action, so a failed
        # device is reported for its own action only.
        self.provide_action_id = True
        self.armis_helper = ArmisPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        # Custom properties of the tenant, read once per plugin instance
        # (one pull, one refresh or one action batch).
        self._custom_properties = None
        # Token cache used when Cloud Exchange passes no storage.
        self._fallback_storage = {}

    def _build_log_prefix(self, plugin_name: str) -> str:
        """Build the prefix of the log messages.

        Args:
            plugin_name (str): Plugin name.

        Returns:
            str: 'CRE <plugin name> [<configuration name>]', without the
                configuration name when there is none.
        """
        log_prefix = CONST.LOG_PREFIX_FORMAT.format(
            module=CONST.MODULE_NAME, plugin=plugin_name
        )
        if self.name:
            log_prefix = CONST.LOG_PREFIX_NAME_FORMAT.format(
                prefix=log_prefix, name=self.name
            )
        return log_prefix

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get the plugin name and version from the manifest.

        Returns:
            Tuple[str, str]: Plugin name and version.
        """
        try:
            metadata = ArmisPlugin.metadata
            return (
                metadata.get(CONST.METADATA_NAME_KEY, CONST.PLUGIN_NAME),
                metadata.get(CONST.METADATA_VERSION_KEY, CONST.PLUGIN_VERSION),
            )
        except Exception:
            log_prefix = self._build_log_prefix(CONST.PLUGIN_NAME)
            self.logger.error(
                message=f"{log_prefix}: {CONST.ERR_GEN_01}",
                details=traceback.format_exc(),
                resolution=CONST.RES_GEN_01,
            )
        return CONST.PLUGIN_NAME, CONST.PLUGIN_VERSION

    def _get_storage(self) -> Dict:
        """Get the storage holding the token cache.

        Returns:
            Dict: Plugin storage, or an instance dict when there is none.
        """
        if self.storage is None:
            return self._fallback_storage
        return self.storage

    # ------------------------------------------------------------------
    # Custom properties
    # ------------------------------------------------------------------
    def _get_custom_properties(self, configuration: Dict) -> List[Dict]:
        """Get the custom properties of the tenant, read once.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            List[Dict]: Custom properties.
        """
        if self._custom_properties is None:
            self._custom_properties = (
                self.armis_helper.list_custom_properties(
                    configuration, self._get_storage()
                )
            )
            debug_msg = CONST.DEBUG_PROPERTIES_CACHED.format(
                count=len(self._custom_properties)
            )
            self.logger.debug(message=f"{self.log_prefix}: {debug_msg}")
        return self._custom_properties

    def _load_custom_properties(
        self, configuration: Dict
    ) -> Optional[List[Dict]]:
        """Get the custom properties without raising.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            Optional[List[Dict]]: Custom properties, or None when they
                cannot be read (the reason is logged).
        """
        if not self.armis_helper.has_credentials(configuration):
            self.logger.info(
                message=f"{self.log_prefix}: {CONST.MSG_CREDENTIALS_MISSING}"
            )
            return None
        try:
            return self._get_custom_properties(configuration)
        except ArmisPluginException as error:
            self.logger.error(
                message=f"{self.log_prefix}: {CONST.ERR_PUL_02}",
                details=str(error),
                resolution=CONST.RES_PUL_02,
            )
        except Exception as error:
            message = CONST.ERR_GEN_02.format(
                logger_msg=CONST.LOGGER_MSG_DYNAMIC_FIELDS, error=error
            )
            self.logger.error(
                message=f"{self.log_prefix}: {message}",
                details=traceback.format_exc(),
                resolution=CONST.RES_GEN_02,
            )
        return None

    def _resolve_selected_properties(self) -> List[Dict]:
        """Get the selected custom properties that exist in Armis.

        Returns:
            List[Dict]: Custom properties to pull; [] when none is
                selected.

        Raises:
            ArmisPluginException: The custom properties cannot be read,
                so the pull fails instead of storing devices without
                the selected custom properties.
        """
        configuration = self.configuration or {}
        if not self.armis_helper.is_pull_custom_properties_enabled(
            configuration
        ):
            return []
        selected = self.armis_helper.get_selected_properties(configuration)
        if not selected:
            return []
        try:
            properties = self._get_custom_properties(configuration)
        except ArmisPluginException as error:
            self.logger.error(
                message=f"{self.log_prefix}: {CONST.ERR_PUL_02}",
                details=str(error),
                resolution=CONST.RES_PUL_02,
            )
            raise
        resolved, missing = self.armis_helper.match_properties(
            selected, properties
        )
        for name in missing:
            message = CONST.ERR_PUL_03.format(name=name)
            self.logger.error(
                message=f"{self.log_prefix}: {message}",
                resolution=CONST.RES_PUL_03,
            )
        return resolved

    @ui_call
    def get_dynamic_fields(self) -> List[Dict]:
        """Get the fields of the trigger that changed.

        'Scopes' is the only trigger in manifest.json. Cloud Exchange
        calls this method with only the trigger's payload_fields as the
        configuration and renders the returned fields after the manifest
        fields, in order. For Scopes it returns Custom Permissions (when
        selected) and then Pull Custom Properties, so that Custom
        Permissions sits right after Scopes. Pull Custom Properties is
        itself a trigger; only its payload holds that key, which tells
        the two triggers apart and returns Custom Properties, which is
        not a trigger, so the chain ends. It never raises: without
        credentials, or when Armis cannot be reached, the Custom
        Properties field is returned without choices.

        Returns:
            List[Dict]: For Scopes, [Custom Permissions,] Pull Custom
                Properties; for Pull Custom Properties, the Custom
                Properties multichoice when it is 'Yes', else [].
        """
        configuration = self.configuration or {}
        if CONST.CONFIG_PULL_CUSTOM_PROPERTIES not in configuration:
            fields = []
            if self.armis_helper.is_custom_scope_selected(configuration):
                fields.append(
                    self.armis_helper.build_custom_permissions_field()
                )
            fields.append(
                self.armis_helper.build_pull_custom_properties_field()
            )
            return fields
        if not self.armis_helper.is_pull_custom_properties_enabled(
            configuration
        ):
            return []
        properties = self._load_custom_properties(configuration) or []
        return [self.armis_helper.build_dynamic_field(properties)]

    # ------------------------------------------------------------------
    # Entities and records
    # ------------------------------------------------------------------
    @ui_call
    def get_entities(self) -> List[Entity]:
        """Get the Devices entity.

        Returns:
            List[Entity]: The Devices entity with the standard fields
                and one field per selected custom property.
        """
        fields = [
            EntityField(
                name=field_name,
                label=field_name,
                type=EntityFieldType(spec[CONST.MAPPING_TYPE]),
                required=field_name in CONST.REQUIRED_ENTITY_FIELDS,
                description=spec[CONST.MAPPING_DESCRIPTION],
            )
            for field_name, spec in CONST.DEVICE_FIELD_MAPPING.items()
        ]
        fields.extend(self._get_custom_property_fields())
        return [
            Entity(
                name=CONST.ENTITY_DEVICES,
                label=CONST.ENTITY_DEVICES_LABEL,
                fields=fields,
            )
        ]

    def _get_custom_property_fields(self) -> List[EntityField]:
        """Build one entity field per selected custom property.

        The type comes from the property type in Armis; when the list
        cannot be read, every selected property is a string field.

        Returns:
            List[EntityField]: Custom property fields.
        """
        configuration = self.configuration or {}
        if not self.armis_helper.is_pull_custom_properties_enabled(
            configuration
        ):
            return []
        selected = self.armis_helper.get_selected_properties(configuration)
        if not selected:
            return []
        field_types = self.armis_helper.get_custom_field_types(
            selected, self._load_custom_properties(configuration)
        )
        return [
            EntityField(
                name=CONST.CUSTOM_ENTITY_FIELD_PREFIX + name,
                label=CONST.CUSTOM_ENTITY_FIELD_PREFIX + name,
                type=EntityFieldType(field_type),
                description=CONST.CUSTOM_FIELD_DESCRIPTION.format(name=name),
            )
            for name, field_type in field_types
        ]

    def _check_entity(self, entity: str):
        """Check that the entity is Devices.

        Args:
            entity (str): Entity name.

        Raises:
            ArmisPluginException: Unsupported entity.
        """
        if entity == CONST.ENTITY_DEVICES:
            return
        message = CONST.ERR_PUL_05.format(entity=entity)
        self.logger.error(
            message=f"{self.log_prefix}: {message}",
            resolution=CONST.RES_PUL_05,
        )
        raise ArmisPluginException(message, resolution=CONST.RES_PUL_05)

    def fetch_records(self, entity: str) -> List[Dict]:
        """Pull all the devices with full visibility.

        Args:
            entity (str): Entity name.

        Returns:
            List[Dict]: Records, one per serial number of each device.
        """
        self._check_entity(entity)
        self.logger.info(message=f"{self.log_prefix}: {CONST.MSG_PULL_START}")
        try:
            properties = self._resolve_selected_properties()
            records, devices = self._pull_devices(properties)
        except ArmisPluginException as error:
            self.logger.error(
                message=f"{self.log_prefix}: {CONST.ERR_PUL_01}",
                details=str(error),
                resolution=CONST.RES_PUL_01,
            )
            raise
        except Exception as error:
            self._raise_unexpected_error(error, CONST.LOGGER_MSG_PULL)
        message = CONST.MSG_PULL_COMPLETE.format(
            records=len(records), devices=devices
        )
        self.logger.info(message=f"{self.log_prefix}: {message}")
        return records

    def _pull_devices(self, properties: List[Dict]) -> Tuple[List[Dict], int]:
        """Pull every page of devices.

        Args:
            properties (List[Dict]): Custom properties to pull.

        Returns:
            Tuple[List[Dict], int]: Records and number of devices.
        """
        fields = self.armis_helper.build_search_fields(properties)
        records = []
        total_devices = 0
        after = CONST.FIRST_PAGE_AFTER
        page = 1
        while True:
            response = self.armis_helper.search_devices_page(
                self.configuration, self._get_storage(), fields, after, page
            )
            page_records, skipped, devices = (
                self.armis_helper.build_records_from_items(
                    self.armis_helper.get_items(response), properties
                )
            )
            if skipped:
                message = CONST.ERR_PUL_04.format(count=skipped)
                self.logger.error(
                    message=f"{self.log_prefix}: {message}",
                    resolution=CONST.RES_PUL_04,
                )
            records.extend(page_records)
            total_devices += devices
            message = CONST.MSG_PAGE_FETCHED.format(
                count=devices, page=page, total=total_devices
            )
            self.logger.info(message=f"{self.log_prefix}: {message}")
            next_after = self.armis_helper.get_next_cursor(response, after)
            if next_after is None:
                return records, total_devices
            after = next_after
            page += 1

    def update_records(
        self, entity: str, records: List[Dict]
    ) -> List[Dict]:
        """Return no updates; fetch_records already pulls every device.

        Cloud Exchange calls this method right after fetch_records in
        the same cycle. fetch_records pulls every device with full
        visibility, including its custom properties, so reading the
        devices again would only double the Armis API calls.

        Args:
            entity (str): Entity name.
            records (List[Dict]): Stored records.

        Returns:
            List[Dict]: Always [].
        """
        self._check_entity(entity)
        return []

    def _raise_unexpected_error(self, error: Exception, logger_msg: str):
        """Log an unexpected error and raise it as a plugin exception.

        Args:
            error (Exception): Unexpected error.
            logger_msg (str): Operation, used in the message.

        Raises:
            ArmisPluginException: Always.
        """
        message = CONST.ERR_GEN_02.format(logger_msg=logger_msg, error=error)
        self.logger.error(
            message=f"{self.log_prefix}: {message}",
            details=traceback.format_exc(),
            resolution=CONST.RES_GEN_02,
        )
        raise ArmisPluginException(message, resolution=CONST.RES_GEN_02)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def get_actions(self) -> List[ActionWithoutParams]:
        """Get the supported actions.

        Returns:
            List[ActionWithoutParams]: 'Set Custom Property Value',
                'Remove Custom Property Value' and 'No action', in that
                order.
        """
        return [
            ActionWithoutParams(label=CONST.ACTION_LABELS[value], value=value)
            for value in CONST.SUPPORTED_ACTIONS
        ]

    @ui_call
    def get_action_params(self, action: Action) -> List[Dict]:
        """Get the parameters of an action.

        Args:
            action (Action): Action.

        Returns:
            List[Dict]: Parameter definitions; [] for 'No action'. The
                Custom Property choice lists the tenant's properties,
                plus 'Create new custom property' for the set action.
        """
        if action.value not in CONST.CUSTOM_PROPERTY_ACTIONS:
            return []
        properties = self._load_custom_properties(self.configuration or {})
        if action.value == CONST.ACTION_REMOVE_CUSTOM_PROPERTY:
            return self.armis_helper.build_remove_action_params(
                properties or []
            )
        return self.armis_helper.build_action_params(properties or [])

    @ui_call
    def validate_action(self, action: Action) -> ValidationResult:
        """Validate an action and its static parameters.

        Parameters from a Source Field are checked when the action is
        executed.

        Args:
            action (Action): Action to validate.

        Returns:
            ValidationResult: Validation result.
        """
        if action.value not in CONST.SUPPORTED_ACTIONS:
            return self._validation_failure(
                (
                    CONST.ERR_ACT_13.format(action=action.value),
                    CONST.RES_ACT_13,
                )
            )
        if action.value in CONST.CUSTOM_PROPERTY_ACTIONS:
            if result := self._validate_action_scopes(action):
                return result
            try:
                result = self._validate_custom_property_action(
                    action.value, action.parameters or {}
                )
            except Exception as error:
                message = CONST.ERR_GEN_02.format(
                    logger_msg=CONST.LOGGER_MSG_VALIDATE_ACTION, error=error
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {message}",
                    details=traceback.format_exc(),
                    resolution=CONST.RES_GEN_02,
                )
                return ValidationResult(success=False, message=message)
            if result:
                return result
        debug_msg = CONST.DEBUG_ACTION_VALIDATED.format(label=action.label)
        self.logger.debug(message=f"{self.log_prefix}: {debug_msg}")
        return ValidationResult(
            success=True, message=CONST.ACTION_VALIDATION_SUCCESS_MESSAGE
        )

    def _validate_custom_property_action(
        self, action_value: str, params: Dict
    ) -> Optional[ValidationResult]:
        """Validate the parameters of a custom property action.

        Set Custom Property Value takes one Custom Property (or the
        create option) and checks the Value against its type; Remove
        Custom Property Value only needs the Device ID and one or more
        existing Custom Properties.

        Args:
            action_value (str): Action value.
            params (Dict): Action parameters.

        Returns:
            Optional[ValidationResult]: Failure, or None when valid.
        """
        is_set_action = action_value == CONST.ACTION_SET_CUSTOM_PROPERTY
        labels = CONST.PARAM_LABELS
        device_id = params.get(CONST.PARAM_DEVICE_ID)
        if result := self._validate_parameters(
            parameter_type=CONST.PARAMETER_TYPE_ACTION,
            field_name=labels[CONST.PARAM_DEVICE_ID],
            field_value=device_id,
            check_source_field=True,
            custom_validation_func=self.armis_helper.is_valid_device_id,
            invalid_error=(
                CONST.ERR_ACT_01.format(
                    value=self.armis_helper.display_value(device_id)
                ),
                CONST.RES_ACT_01,
            ),
        ):
            return result
        # Set takes one Custom Property; Remove takes Custom Properties.
        property_key = (
            CONST.PARAM_CUSTOM_PROPERTY
            if is_set_action
            else CONST.PARAM_CUSTOM_PROPERTIES
        )
        custom_properties = params.get(property_key)
        property_error = (
            CONST.ERR_ACT_02.format(
                name=self.armis_helper.display_value(custom_properties)
            ),
            CONST.RES_ACT_02,
        )
        if result := self._validate_parameters(
            parameter_type=CONST.PARAMETER_TYPE_ACTION,
            field_name=labels[property_key],
            field_value=custom_properties,
            field_type=str if is_set_action else (list, str),
            static_only=True,
            custom_validation_func=self.armis_helper.get_action_properties,
            invalid_error=property_error,
        ):
            return result
        try:
            properties = self._get_custom_properties(self.configuration)
        except ArmisPluginException as error:
            self.logger.error(
                message=f"{self.log_prefix}: {CONST.ERR_PUL_02}",
                details=str(error),
                resolution=CONST.RES_PUL_02,
            )
            return ValidationResult(success=False, message=CONST.ERR_PUL_02)
        allowed_properties = self.armis_helper.get_property_names(properties)
        if is_set_action:
            allowed_properties = allowed_properties + [
                CONST.CREATE_PROPERTY_VALUE
            ]
        names = self.armis_helper.get_action_properties(custom_properties)
        unknown = [name for name in names if name not in allowed_properties]
        if unknown:
            return self._validation_failure(
                (
                    CONST.ERR_ACT_02.format(
                        name=CONST.LIST_VALUE_SEPARATOR.join(unknown)
                    ),
                    CONST.RES_ACT_02,
                )
            )
        if not is_set_action:
            return None
        targets = []
        for name in names:
            if name == CONST.CREATE_PROPERTY_VALUE:
                if result := self._validate_new_property(params):
                    return result
                targets.append(
                    self.armis_helper.get_property_for_create(
                        params, properties
                    )
                )
            else:
                targets.append(
                    self.armis_helper.find_property(properties, name)
                )
        for prop in targets:
            if result := self._validate_action_value(
                params.get(CONST.PARAM_VALUE), prop
            ):
                return result
        return None

    def _validate_new_property(
        self, params: Dict
    ) -> Optional[ValidationResult]:
        """Validate the parameters of the create option.

        Args:
            params (Dict): Action parameters.

        Returns:
            Optional[ValidationResult]: Failure, or None when valid.
        """
        labels = CONST.PARAM_LABELS
        if result := self._validate_parameters(
            parameter_type=CONST.PARAMETER_TYPE_ACTION,
            field_name=labels[CONST.PARAM_NEW_PROPERTY_NAME],
            field_value=params.get(CONST.PARAM_NEW_PROPERTY_NAME),
            static_only=True,
            custom_validation_func=self.armis_helper.is_valid_property_name,
            invalid_error=(CONST.ERR_ACT_05, CONST.RES_ACT_05),
        ):
            return result
        if result := self._validate_parameters(
            parameter_type=CONST.PARAMETER_TYPE_ACTION,
            field_name=labels[CONST.PARAM_NEW_PROPERTY_DESCRIPTION],
            field_value=params.get(CONST.PARAM_NEW_PROPERTY_DESCRIPTION),
            is_required=False,
            static_only=True,
            custom_validation_func=(
                self.armis_helper.is_valid_property_description
            ),
            invalid_error=(CONST.ERR_ACT_06, CONST.RES_ACT_06),
        ):
            return result
        prop_type = params.get(CONST.PARAM_NEW_PROPERTY_TYPE)
        if result := self._validate_parameters(
            parameter_type=CONST.PARAMETER_TYPE_ACTION,
            field_name=labels[CONST.PARAM_NEW_PROPERTY_TYPE],
            field_value=prop_type,
            static_only=True,
            allowed_values=CONST.NEW_PROPERTY_TYPES,
            invalid_error=(CONST.ERR_ACT_15, CONST.RES_ACT_15),
        ):
            return result
        if prop_type.strip() != CONST.PROPERTY_TYPE_ENUM:
            return None
        if result := self._validate_parameters(
            parameter_type=CONST.PARAMETER_TYPE_ACTION,
            field_name=labels[CONST.PARAM_NEW_PROPERTY_ALLOWED_VALUES],
            field_value=params.get(CONST.PARAM_NEW_PROPERTY_ALLOWED_VALUES),
            static_only=True,
            custom_validation_func=self.armis_helper.has_allowed_values,
            invalid_error=(CONST.ERR_ACT_07, CONST.RES_ACT_07),
        ):
            return result
        return None

    def _validate_action_value(
        self, value: Any, prop: Dict
    ) -> Optional[ValidationResult]:
        """Validate a static Value against the property type.

        Args:
            value (Any): Value parameter.
            prop (Dict): Target custom property.

        Returns:
            Optional[ValidationResult]: Failure, or None when valid.
        """
        if result := self._validate_parameters(
            parameter_type=CONST.PARAMETER_TYPE_ACTION,
            field_name=CONST.PARAM_LABELS[CONST.PARAM_VALUE],
            field_value=value,
            check_source_field=True,
            custom_validation_func=(
                lambda candidate: self.armis_helper.is_valid_action_value(
                    candidate, prop
                )
            ),
            invalid_error=self.armis_helper.get_value_error(value, prop),
        ):
            return result
        return None

    def execute_actions(
        self, actions: List[Dict], revert: bool = False
    ) -> ActionResult:
        """Execute a batch of actions.

        The actions do not support revert. Cloud Exchange may send actions
        to perform and actions to revert in one call, with a single revert
        flag taken from the first entry. Hence each entry is routed by its
        own 'performRevert' attribute (the revert argument is used only
        when the attribute is missing): the entries to revert are reported
        as failed without calling Armis Centrix, and the others are
        executed.

        Args:
            actions (List[Dict]): {"params": Action, "id": str} items,
                all with the same action value.
            revert (bool): Revert flag of the first entry of the batch.
                Defaults to False.

        Returns:
            ActionResult: The ids of the failed actions in
                failed_action_ids ([] when none failed). success is False
                only when every action of the batch failed.

        Raises:
            ArmisPluginException: Unsupported action.
        """
        forward_actions, revert_actions = [], []
        for action_dict in actions or []:
            params = action_dict.get(CONST.ACTION_PARAMS_KEY)
            perform_revert = getattr(params, "performRevert", None)
            is_revert = (
                revert if perform_revert is None else bool(perform_revert)
            )
            (revert_actions if is_revert else forward_actions).append(
                action_dict
            )
        if not revert_actions:
            return self._execute_forward_actions(forward_actions)
        revert_label = revert_actions[0][CONST.ACTION_PARAMS_KEY].label
        message = CONST.ERR_ACT_22.format(
            label=revert_label, count=len(revert_actions)
        )
        self.logger.error(
            message=f"{self.log_prefix}: {message}",
            resolution=CONST.RES_ACT_22,
        )
        failed_ids = self.armis_helper.get_action_ids(revert_actions)
        if forward_actions:
            result = self._execute_forward_actions(forward_actions)
            failed_ids.extend(result.failed_action_ids or [])
            message = f"{result.message} {message}"
        all_ids = set(self.armis_helper.get_action_ids(actions))
        return ActionResult(
            success=bool(all_ids - set(failed_ids)),
            message=message,
            failed_action_ids=list(dict.fromkeys(failed_ids)),
        )

    def _execute_forward_actions(self, actions: List[Dict]) -> ActionResult:
        """Execute a batch of actions to perform (not to revert).

        Args:
            actions (List[Dict]): {"params": Action, "id": str} items,
                all with the same action value.

        Returns:
            ActionResult: success True, with the ids of the failed
                actions in failed_action_ids ([] when none failed).

        Raises:
            ArmisPluginException: Unsupported action.
        """
        if not actions:
            return ActionResult(
                success=True,
                message=CONST.MSG_NO_ACTIONS,
                failed_action_ids=[],
            )
        first_action = actions[0].get(CONST.ACTION_PARAMS_KEY)
        action_value, action_label = first_action.value, first_action.label
        if action_value == CONST.ACTION_NO_ACTION:
            message = CONST.MSG_GENERATE.format(
                label=action_label,
                count=len(actions),
            )
            self.logger.debug(message=f"{self.log_prefix}: {message}")
            return ActionResult(
                success=True, message=message, failed_action_ids=[]
            )
        if action_value not in CONST.CUSTOM_PROPERTY_ACTIONS:
            self._raise_unsupported_action(action_value)
        message = CONST.MSG_ACTION_START.format(
            label=action_label,
            count=len(actions),
        )
        self.logger.info(message=f"{self.log_prefix}: {message}")
        try:
            if action_value == CONST.ACTION_SET_CUSTOM_PROPERTY:
                failed_ids = self._set_custom_property(actions)
            else:
                failed_ids = self._clear_custom_property(actions)
        except Exception as error:
            logger_msg = CONST.LOGGER_MSG_EXECUTE.format(label=action_label)
            message = CONST.ERR_GEN_02.format(
                logger_msg=logger_msg, error=error
            )
            self.logger.error(
                message=f"{self.log_prefix}: {message}",
                details=traceback.format_exc(),
                resolution=CONST.RES_GEN_02,
            )
            failed_ids = self.armis_helper.get_action_ids(actions)
        return self._build_action_result(actions, failed_ids, action_label)

    def execute_action(self, action: Action):
        """Execute one action.

        Revert is not supported (see execute_actions).

        Args:
            action (Action): Action with its parameters.

        Raises:
            ArmisPluginException: The action failed.
        """
        result = self.execute_actions(
            [
                {
                    CONST.ACTION_PARAMS_KEY: action,
                    CONST.ACTION_ID_KEY: CONST.SINGLE_ACTION_ID,
                }
            ]
        )
        if CONST.SINGLE_ACTION_ID in (result.failed_action_ids or []):
            logger_msg = CONST.LOGGER_MSG_EXECUTE.format(label=action.label)
            raise ArmisPluginException(
                CONST.ERR_SINGLE_ACTION.format(logger_msg=logger_msg)
            )

    def _raise_unsupported_action(self, action_value: str):
        """Log and raise for an unsupported action value.

        Args:
            action_value (str): Action value.

        Raises:
            ArmisPluginException: Always.
        """
        message = CONST.ERR_ACT_13.format(action=action_value)
        self.logger.error(
            message=f"{self.log_prefix}: {message}",
            resolution=CONST.RES_ACT_13,
        )
        raise ArmisPluginException(message, resolution=CONST.RES_ACT_13)

    def _set_custom_property(self, actions: List[Dict]) -> List:
        """Set the custom property values of a batch.

        The values of every custom property and device are sent in one
        bulk call (split in batches of BULK_BATCH_SIZE items).

        Args:
            actions (List[Dict]): Actions of the batch.

        Returns:
            List: Ids of the failed actions.
        """
        try:
            properties = self._get_custom_properties(self.configuration)
        except ArmisPluginException as error:
            self.logger.error(
                message=f"{self.log_prefix}: {CONST.ERR_PUL_02}",
                details=str(error),
                resolution=CONST.RES_PUL_02,
            )
            return self.armis_helper.get_action_ids(actions)
        failed_ids = []
        items = []
        item_action_ids = []
        buckets = self.armis_helper.build_action_buckets(
            actions, by_name=False
        )
        for key, bucket in buckets.items():
            prop = self._resolve_property(
                key,
                self.armis_helper.get_action_parameters(bucket[0]),
                properties,
            )
            if prop is None:
                failed_ids.extend(self.armis_helper.get_action_ids(bucket))
                continue
            bucket_items, bucket_action_ids, invalid_ids = (
                self.armis_helper.build_set_items(bucket, prop)
            )
            failed_ids.extend(invalid_ids)
            items.extend(bucket_items)
            item_action_ids.extend(bucket_action_ids)
        failed_ids.extend(
            self._execute_bulk_items(
                items, item_action_ids, CONST.BULK_OPERATION_SET
            )
        )
        return failed_ids

    def _clear_custom_property(self, actions: List[Dict]) -> List:
        """Remove the custom property values of a batch.

        Used by Remove Custom Property Value. Each property must exist
        in Armis; the property itself is kept. The values of every
        custom property and device are cleared in one bulk call.

        Args:
            actions (List[Dict]): Actions of the batch.

        Returns:
            List: Ids of the failed actions.
        """
        try:
            property_names = self.armis_helper.get_property_names(
                self._get_custom_properties(self.configuration)
            )
        except ArmisPluginException as error:
            self.logger.error(
                message=f"{self.log_prefix}: {CONST.ERR_PUL_02}",
                details=str(error),
                resolution=CONST.RES_PUL_02,
            )
            return self.armis_helper.get_action_ids(actions)
        failed_ids = []
        items = []
        item_action_ids = []
        buckets = self.armis_helper.build_action_buckets(actions, by_name=True)
        for property_name, bucket in buckets.items():
            if not property_name or property_name not in property_names:
                message = CONST.ERR_ACT_02.format(name=property_name)
                self.logger.error(
                    message=f"{self.log_prefix}: {message}",
                    resolution=CONST.RES_ACT_02,
                )
                failed_ids.extend(self.armis_helper.get_action_ids(bucket))
                continue
            bucket_items, bucket_action_ids, invalid_ids = (
                self.armis_helper.build_unset_items(bucket, property_name)
            )
            failed_ids.extend(invalid_ids)
            items.extend(bucket_items)
            item_action_ids.extend(bucket_action_ids)
        failed_ids.extend(
            self._execute_bulk_items(
                items, item_action_ids, CONST.BULK_OPERATION_UNSET
            )
        )
        return failed_ids

    def _resolve_property(
        self, key: str, params: Dict, properties: List[Dict]
    ) -> Optional[Dict]:
        """Get the property a set bucket targets, creating it if needed.

        Args:
            key (str): Bucket key: a property name or 'create:<name>'.
            params (Dict): Parameters of the first action of the bucket.
            properties (List[Dict]): Custom properties of Armis; a
                created property is added to it.

        Returns:
            Optional[Dict]: Property, or None when it is not found or
                cannot be created (the reason is logged).
        """
        if not self.armis_helper.is_create_bucket_key(key):
            name = key
            prop = self.armis_helper.find_property(properties, name)
            if prop is None:
                message = CONST.ERR_ACT_02.format(name=name)
                self.logger.error(
                    message=f"{self.log_prefix}: {message}",
                    resolution=CONST.RES_ACT_02,
                )
            return prop
        prop = self.armis_helper.get_property_for_create(params, properties)
        name = prop[CONST.PROPERTY_NAME_KEY]
        if self.armis_helper.find_property(properties, name) is not None:
            message = CONST.MSG_PROPERTY_EXISTS.format(name=name)
            self.logger.info(message=f"{self.log_prefix}: {message}")
            return prop
        return self._create_property(prop, properties)

    def _create_property(
        self, prop: Dict, properties: List[Dict]
    ) -> Optional[Dict]:
        """Create a custom property in Armis.

        Args:
            prop (Dict): Property to create.
            properties (List[Dict]): Custom properties; the created
                property is added to it.

        Returns:
            Optional[Dict]: Created property, or None on failure.
        """
        name = prop[CONST.PROPERTY_NAME_KEY]
        try:
            self.armis_helper.create_custom_property(
                self.configuration,
                self._get_storage(),
                name,
                prop.get(CONST.PROPERTY_DESCRIPTION_KEY),
                prop.get(CONST.PROPERTY_TYPE_KEY),
                prop.get(CONST.PROPERTY_ALLOWED_VALUES_KEY),
            )
        except ArmisPluginException as error:
            self._log_write_failure(
                error,
                CONST.SCOPE_CUSTOM_PROPERTIES_MANAGE,
                (CONST.ERR_ACT_10.format(name=name), CONST.RES_ACT_10),
            )
            return None
        properties.append(prop)
        message = CONST.MSG_PROPERTY_CREATED.format(
            name=name, type=prop.get(CONST.PROPERTY_TYPE_KEY)
        )
        self.logger.info(message=f"{self.log_prefix}: {message}")
        return prop

    def _log_write_failure(
        self,
        error: ArmisPluginException,
        scope: str,
        fallback_error: Tuple[str, str],
    ):
        """Log a failed create or bulk call.

        A 403 from a token without the needed scope is E-ACT-12.

        Args:
            error (ArmisPluginException): Error of the call.
            scope (str): Scope the call needs.
            fallback_error (Tuple[str, str]): Message and resolution for
                any other failure.
        """
        message, resolution = fallback_error
        if (
            error.status_code == CONST.FORBIDDEN_STATUS
            and self.armis_helper.is_scope_missing(self._get_storage(), scope)
        ):
            message = CONST.ERR_ACT_12.format(scope=scope)
            resolution = CONST.RES_ACT_12
        self.logger.error(
            message=f"{self.log_prefix}: {message}",
            details=str(error),
            resolution=resolution,
        )

    def _execute_bulk_items(
        self,
        items: List[Dict],
        item_action_ids: List[List],
        operation: str,
    ) -> List:
        """Send the bulk items in batches of BULK_BATCH_SIZE.

        Each item is one custom property value of one device; items of
        several custom properties go in the same batch.

        Args:
            items (List[Dict]): Bulk items.
            item_action_ids (List[List]): Action ids per item.
            operation (str): BULK_OPERATION_SET or BULK_OPERATION_UNSET.

        Returns:
            List: Ids of the failed actions.
        """
        failed_ids = []
        batches = zip(
            self.armis_helper.chunk(items, CONST.BULK_BATCH_SIZE),
            self.armis_helper.chunk(item_action_ids, CONST.BULK_BATCH_SIZE),
        )
        for batch, (chunk, chunk_action_ids) in enumerate(batches, start=1):
            failed_ids.extend(
                self._execute_bulk_chunk(
                    chunk, chunk_action_ids, operation, batch
                )
            )
        return failed_ids

    def _execute_bulk_chunk(
        self,
        chunk: List[Dict],
        chunk_action_ids: List[List],
        operation: str,
        batch: int,
    ) -> List:
        """Send one batch of bulk items and read the per-item results.

        A failed batch is logged and its actions failed; the next batch
        is still sent.

        Args:
            chunk (List[Dict]): Bulk items of the batch.
            chunk_action_ids (List[List]): Action ids per item.
            operation (str): BULK_OPERATION_SET or BULK_OPERATION_UNSET.
            batch (int): Batch number.

        Returns:
            List: Ids of the failed actions.
        """
        is_set = operation == CONST.BULK_OPERATION_SET
        logger_msg_format = (
            CONST.LOGGER_MSG_BULK_SET if is_set
            else CONST.LOGGER_MSG_BULK_UNSET
        )
        logger_msg = logger_msg_format.format(count=len(chunk), batch=batch)
        all_ids = [
            action_id for action_ids in chunk_action_ids
            for action_id in action_ids
        ]
        try:
            response = self.armis_helper.bulk_update(
                self.configuration, self._get_storage(), chunk, logger_msg
            )
        except ArmisPluginException as error:
            self._log_write_failure(
                error,
                CONST.SCOPE_DEVICE_MANAGE_EDIT,
                (CONST.ERR_ACT_09.format(count=len(chunk)), CONST.RES_ACT_09),
            )
            return all_ids
        except Exception as error:
            message = CONST.ERR_GEN_02.format(
                logger_msg=logger_msg, error=error
            )
            self.logger.error(
                message=f"{self.log_prefix}: {message}",
                details=traceback.format_exc(),
                resolution=CONST.RES_GEN_02,
            )
            return all_ids
        results = self.armis_helper.get_items(response)
        if len(results) != len(chunk):
            message = CONST.ERR_ACT_16.format(count=len(chunk))
            self.logger.error(
                message=f"{self.log_prefix}: {message}",
                details=self.armis_helper.sanitize_text(json.dumps(response)),
                resolution=CONST.RES_ACT_16,
            )
            return all_ids
        succeeded, failed_devices, failed_ids = (
            self.armis_helper.evaluate_bulk_results(
                chunk, chunk_action_ids, results
            )
        )
        message = CONST.MSG_BULK_CHUNK.format(
            verb=CONST.VERB_SET if is_set else CONST.VERB_CLEARED,
            count=len(succeeded),
            batch=batch,
        )
        if failed_devices:
            message += CONST.MSG_BULK_CHUNK_FAILED.format(
                count=len(failed_devices)
            )
        self.logger.info(
            message=f"{self.log_prefix}: {message}",
            details=json.dumps({CONST.DETAILS_SUCCEEDED_KEY: succeeded}),
        )
        if failed_devices:
            # One error per batch, with every rejected value in details.
            message = CONST.ERR_ACT_08.format(
                count=len(failed_devices), batch=batch
            )
            self.logger.error(
                message=f"{self.log_prefix}: {message}",
                details=json.dumps(
                    {CONST.DETAILS_FAILED_KEY: failed_devices}, default=str
                ),
                resolution=CONST.RES_ACT_08,
            )
        return failed_ids

    def _build_action_result(
        self,
        actions: List[Dict],
        failed_ids: List,
        action_label: str,
    ) -> ActionResult:
        """Log the outcome of a batch and build its result.

        success stays True: Cloud Exchange fails every action of the
        batch when success is False, and only the listed ids failed.

        Args:
            actions (List[Dict]): Actions of the batch.
            failed_ids (List): Ids of the failed actions.
            action_label (str): Action label.

        Returns:
            ActionResult: The failed action ids; [] when none failed.
        """
        failed_ids = list(
            dict.fromkeys(
                action_id for action_id in failed_ids if action_id is not None
            )
        )
        message = CONST.MSG_ACTION_SUMMARY.format(
            label=action_label,
            success=len(actions) - len(failed_ids),
            total=len(actions),
        )
        if failed_ids:
            message += CONST.MSG_ACTION_SUMMARY_FAILED.format(
                count=len(failed_ids)
            )
        self.logger.info(message=f"{self.log_prefix}: {message}")
        return ActionResult(
            success=True, message=message, failed_action_ids=failed_ids
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def _validation_failure(self, error: Tuple[str, str]) -> ValidationResult:
        """Log a validation error and build the failed result.

        Args:
            error (Tuple[str, str]): Message and resolution.

        Returns:
            ValidationResult: Failed result with the message.
        """
        message, resolution = error
        self.logger.error(
            message=f"{self.log_prefix}: {message}", resolution=resolution
        )
        return ValidationResult(success=False, message=message)

    def _validate_parameters(
        self,
        parameter_type: str,
        field_name: str,
        field_value: Any,
        field_type: type = str,
        is_required: bool = True,
        check_source_field: bool = False,
        static_only: bool = False,
        allowed_values: Optional[Iterable] = None,
        custom_validation_func: Optional[Callable[[Any], bool]] = None,
        empty_error: Optional[Tuple[str, str]] = None,
        type_error: Optional[Tuple[str, str]] = None,
        invalid_error: Optional[Tuple[str, str]] = None,
    ) -> Optional[ValidationResult]:
        """Validate a configuration or action parameter.

        Checks, in order: Source Field, empty value, type, whitespace,
        custom rule and allowed values. Text values are stripped before
        the custom rule and the allowed values.

        Args:
            parameter_type (str): PARAMETER_TYPE_CONFIGURATION or
                PARAMETER_TYPE_ACTION.
            field_name (str): Parameter label.
            field_value (Any): Value.
            field_type (type): Expected type.
            is_required (bool): An empty value is an error.
            check_source_field (bool): A Source Field value is checked
                when the action is executed.
            static_only (bool): A Source Field value is an error.
            allowed_values (Optional[Iterable]): Accepted values.
            custom_validation_func (Optional[Callable[[Any], bool]]):
                Rule the value must pass.
            empty_error (Optional[Tuple[str, str]]): Message and
                resolution for an empty value.
            type_error (Optional[Tuple[str, str]]): Message and
                resolution for a wrong type or a blank text.
            invalid_error (Optional[Tuple[str, str]]): Message and
                resolution for a value failing the rule or not allowed.

        Returns:
            Optional[ValidationResult]: Failure, or None when valid.
        """
        if self.armis_helper.is_source_value(field_value):
            if static_only:
                return self._validation_failure(
                    (
                        CONST.ERR_ACT_14.format(field=field_name),
                        CONST.RES_ACT_14.format(field=field_name),
                    )
                )
            if check_source_field:
                message = CONST.MSG_SOURCE_FIELD.format(field=field_name)
                self.logger.info(message=f"{self.log_prefix}: {message}")
                return None
        if parameter_type == CONST.PARAMETER_TYPE_CONFIGURATION:
            empty_error = empty_error or (
                CONST.ERR_VAL_04.format(field=field_name),
                CONST.RES_VAL_04.format(field=field_name),
            )
            type_error = type_error or (
                CONST.ERR_VAL_05.format(field=field_name),
                CONST.RES_VAL_05.format(field=field_name),
            )
        type_error = type_error or invalid_error
        empty_error = empty_error or type_error
        invalid_error = invalid_error or type_error
        is_blank = isinstance(field_value, str) and not field_value.strip()
        if field_value is None or field_value in ("", []) or (
            is_blank and not is_required
        ):
            return None if not is_required else self._validation_failure(
                empty_error
            )
        if isinstance(field_value, bool) or not isinstance(
            field_value, field_type
        ):
            return self._validation_failure(type_error)
        if is_blank:
            return self._validation_failure(type_error)
        if isinstance(field_value, str):
            field_value = field_value.strip()
        if custom_validation_func and not custom_validation_func(field_value):
            return self._validation_failure(invalid_error)
        if allowed_values is not None and field_value not in allowed_values:
            return self._validation_failure(invalid_error)
        return None

    def _validate_required_field_in_entity_mappings(
        self,
    ) -> Optional[ValidationResult]:
        """Check that the required fields are mapped for Devices.

        Returns:
            Optional[ValidationResult]: Failure, or None when valid.
        """
        mapped_entities = (
            getattr(self, CONST.MAPPED_ENTITIES_ATTRIBUTE, None) or []
        )
        for mapped_entity in mapped_entities:
            if not isinstance(mapped_entity, dict) or (
                mapped_entity.get(CONST.MAPPING_ENTITY_KEY)
                != CONST.ENTITY_DEVICES
            ):
                continue
            sources = {
                field.get(CONST.MAPPING_SOURCE_KEY)
                for field in mapped_entity.get(CONST.MAPPING_FIELDS_KEY) or []
                if isinstance(field, dict)
            }
            missing = [
                CONST.QUOTED_VALUE_FORMAT.format(value=field_name)
                for field_name in CONST.REQUIRED_ENTITY_FIELDS
                if field_name not in sources
            ]
            if missing:
                return self._validation_failure(
                    (
                        CONST.ERR_VAL_09.format(
                            fields=CONST.LIST_VALUE_SEPARATOR.join(missing)
                        ),
                        CONST.RES_VAL_09,
                    )
                )
        return None

    @ui_call
    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the configuration parameters and the credentials.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        labels = CONST.CONFIG_LABELS
        if result := self._validate_parameters(
            parameter_type=CONST.PARAMETER_TYPE_CONFIGURATION,
            field_name=labels[CONST.CONFIG_API_BASE_URL],
            field_value=configuration.get(CONST.CONFIG_API_BASE_URL),
            empty_error=(CONST.ERR_VAL_01, CONST.RES_VAL_01),
            type_error=(CONST.ERR_VAL_02, CONST.RES_VAL_02),
        ):
            return result
        if result := self._validate_parameters(
            parameter_type=CONST.PARAMETER_TYPE_CONFIGURATION,
            field_name=labels[CONST.CONFIG_TENANT_URL],
            field_value=configuration.get(CONST.CONFIG_TENANT_URL),
            custom_validation_func=self.armis_helper.is_valid_url,
            invalid_error=(CONST.ERR_VAL_03, CONST.RES_VAL_03),
        ):
            return result
        for key in (
            CONST.CONFIG_CLIENT_ID,
            CONST.CONFIG_CLIENT_SECRET,
            CONST.CONFIG_VENDOR_ID,
        ):
            if result := self._validate_parameters(
                parameter_type=CONST.PARAMETER_TYPE_CONFIGURATION,
                field_name=labels[key],
                field_value=configuration.get(key),
            ):
                return result
        scopes_error = (CONST.ERR_VAL_06, CONST.RES_VAL_06)
        if result := self._validate_parameters(
            parameter_type=CONST.PARAMETER_TYPE_CONFIGURATION,
            field_name=labels[CONST.CONFIG_SCOPES],
            field_value=configuration.get(CONST.CONFIG_SCOPES),
            field_type=list,
            custom_validation_func=(
                self.armis_helper.is_valid_scope_selection
            ),
            type_error=scopes_error,
            invalid_error=scopes_error,
        ):
            return result
        if self.armis_helper.is_custom_scope_selected(
            configuration
        ) and (
            result := self._validate_parameters(
                parameter_type=CONST.PARAMETER_TYPE_CONFIGURATION,
                field_name=labels[CONST.CONFIG_CUSTOM_PERMISSIONS],
                field_value=configuration.get(
                    CONST.CONFIG_CUSTOM_PERMISSIONS
                ),
                custom_validation_func=(
                    self.armis_helper.is_valid_custom_permissions
                ),
                invalid_error=(CONST.ERR_VAL_11, CONST.RES_VAL_11),
            )
        ):
            return result
        if result := self._validate_custom_property_parameters(configuration):
            return result
        if result := self._validate_scope_combination(configuration):
            return result
        if result := self._validate_required_field_in_entity_mappings():
            return result
        return self._validate_auth_params(configuration)

    def _validate_custom_property_parameters(
        self, configuration: Dict
    ) -> Optional[ValidationResult]:
        """Validate Pull Custom Properties and Custom Properties.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            Optional[ValidationResult]: Failure, or None when valid.
        """
        labels = CONST.CONFIG_LABELS
        pull_error = (CONST.ERR_VAL_10, CONST.RES_VAL_10)
        if result := self._validate_parameters(
            parameter_type=CONST.PARAMETER_TYPE_CONFIGURATION,
            field_name=labels[CONST.CONFIG_PULL_CUSTOM_PROPERTIES],
            field_value=configuration.get(
                CONST.CONFIG_PULL_CUSTOM_PROPERTIES,
                CONST.PULL_CUSTOM_PROPERTIES_NO,
            ),
            allowed_values=CONST.PULL_CUSTOM_PROPERTIES_VALUES,
            empty_error=pull_error,
            type_error=pull_error,
            invalid_error=pull_error,
        ):
            return result
        if not self.armis_helper.is_pull_custom_properties_enabled(
            configuration
        ):
            return None
        properties_error = (CONST.ERR_VAL_07, CONST.RES_VAL_07)
        if result := self._validate_parameters(
            parameter_type=CONST.PARAMETER_TYPE_CONFIGURATION,
            field_name=labels[CONST.CONFIG_CUSTOM_PROPERTIES],
            field_value=configuration.get(CONST.CONFIG_CUSTOM_PROPERTIES, []),
            field_type=list,
            is_required=False,
            custom_validation_func=(
                self.armis_helper.is_valid_property_selection
            ),
            type_error=properties_error,
            invalid_error=properties_error,
        ):
            return result
        return None

    def _validate_auth_params(self, configuration: Dict) -> ValidationResult:
        """Request a token and check its scopes.

        A fresh token is requested, without retry and without the cache.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        try:
            access_token, _ = self.armis_helper.request_token(
                self.armis_helper.get_config_params(configuration),
                is_validation=True,
            )
            if result := self._validate_token_scopes(
                configuration, access_token
            ):
                return result
        except ArmisPluginException as error:
            return ValidationResult(success=False, message=str(error))
        except Exception as error:
            message = CONST.ERR_GEN_02.format(
                logger_msg=CONST.LOGGER_MSG_VALIDATE, error=error
            )
            self.logger.error(
                message=f"{self.log_prefix}: {message}",
                details=traceback.format_exc(),
                resolution=CONST.RES_GEN_02,
            )
            return ValidationResult(success=False, message=message)
        self.logger.debug(
            message=f"{self.log_prefix}: {CONST.VALIDATION_SUCCESS_MESSAGE}"
        )
        return ValidationResult(
            success=True, message=CONST.VALIDATION_SUCCESS_MESSAGE
        )

    def _validate_token_scopes(
        self, configuration: Dict, access_token: str
    ) -> Optional[ValidationResult]:
        """Check that Armis granted the permissions of the Scopes options.

        Every permission of a Scopes option that is requested (selected,
        or provided in Custom Permissions) must be in the token. Other
        Custom Permissions are not checked.

        Args:
            configuration (Dict): Configuration parameters.
            access_token (str): Access token.

        Returns:
            Optional[ValidationResult]: Failure, or None when valid.
        """
        granted = self.armis_helper.get_token_scopes(access_token)
        if granted is None:
            self.logger.info(
                message=f"{self.log_prefix}: {CONST.MSG_SCOPE_CHECK_SKIPPED}"
            )
            return None
        requested = self.armis_helper.get_scopes(configuration)
        missing = [
            permission
            for group in self.armis_helper.get_scope_groups(requested)
            for permission in CONST.SCOPE_GROUPS[group]
            if permission not in granted
        ]
        if missing:
            return self._validation_failure(
                (
                    CONST.ERR_VAL_08.format(
                        scopes=CONST.LIST_VALUE_SEPARATOR.join(missing)
                    ),
                    CONST.RES_VAL_08,
                )
            )
        return None

    def _validate_scope_combination(
        self, configuration: Dict
    ) -> Optional[ValidationResult]:
        """Check that the requested scopes cover the configured features.

        The Scopes options are taken from the requested permissions, so
        an option provided through Custom Permissions counts as selected.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            Optional[ValidationResult]: Failure, or None when valid.
        """
        groups = self.armis_helper.get_scope_groups(
            self.armis_helper.get_scopes(configuration)
        )
        has_device_pull = CONST.SCOPE_DEVICE_PULL in groups
        has_properties_pull = CONST.SCOPE_CUSTOM_PROPERTIES_PULL in groups
        has_actions = CONST.SCOPE_CUSTOM_ACTIONS in groups
        if (
            self.armis_helper.is_pull_custom_properties_enabled(configuration)
            and not has_properties_pull
        ):
            return self._validation_failure(
                (CONST.ERR_VAL_12, CONST.RES_VAL_12)
            )
        if has_properties_pull and not (has_device_pull or has_actions):
            return self._validation_failure(
                (CONST.ERR_VAL_13, CONST.RES_VAL_13)
            )
        if has_actions and not has_properties_pull:
            return self._validation_failure(
                (CONST.ERR_VAL_14, CONST.RES_VAL_14)
            )
        if not has_device_pull and self.armis_helper.is_devices_entity_mapped(
            getattr(self, CONST.MAPPED_ENTITIES_ATTRIBUTE, None)
        ):
            return self._validation_failure(
                (CONST.ERR_VAL_15, CONST.RES_VAL_15)
            )
        return None

    def _validate_action_scopes(
        self, action: Action
    ) -> Optional[ValidationResult]:
        """Check that the configuration requests the scopes of an action.

        Args:
            action (Action): Action to validate.

        Returns:
            Optional[ValidationResult]: Failure, or None when valid.
        """
        groups = self.armis_helper.get_scope_groups(
            self.armis_helper.get_scopes(self.configuration or {})
        )
        missing = [
            group
            for group in CONST.ACTION_REQUIRED_SCOPES.get(action.value, ())
            if group not in groups
        ]
        if not missing:
            return None
        scopes = self.armis_helper.get_scope_labels(missing)
        return self._validation_failure(
            (
                CONST.ERR_ACT_21.format(scopes=scopes, label=action.label),
                CONST.RES_ACT_21.format(scopes=scopes),
            )
        )
