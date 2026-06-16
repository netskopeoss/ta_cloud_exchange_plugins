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

CTE Microsoft Defender for Endpoint plugin.
"""

import traceback
import jwt
from datetime import datetime, timedelta, timezone
from pydantic import ValidationError
from typing import (
    Dict,
    Generator,
    List,
    Literal,
    Set,
    Tuple,
    Type,
    Union,
)

from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
    TagIn,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from .utils.constants import (
    ACTIONS,
    BATCH_DELETE_ENDPOINT,
    DATE_TIME_FORMAT,
    DAYS_LIMIT,
    EMPTY_ERROR_MESSAGE,
    INVALID_VALUE_ERROR_MESSAGE,
    INDICATOR_ENDPOINT,
    IOC_GENERATED_ALERT,
    IOC_SOURCE_LENGTH,
    MODULE_NAME,
    PAGE_SIZE,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RETRACTION,
    RETRACTION_FETCH_BATCH_SIZE,
    RETRACTION_DELETE_BATCH_SIZE,
    THREAT_TYPES,
    TYPE_ERROR_MESSAGE,
    VALID_BASE_URLS,
    VALIDATION_ERROR_MSG,
    YES_NO_PARAMETER
)
from .utils.helper import (
    MicrosoftDefenderPluginException,
    MicrosoftDefenderPluginHelper,
)


class MicrosoftDefenderEndpointPluginV2(PluginBase):
    """CTE Microsoft Defender for Endpoint Plugin."""

    def __init__(self, name, *args, **kwargs):
        """Plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.mde_helper = MicrosoftDefenderPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            Tuple[str, str]: Plugin name and version pulled from manifest.
        """
        try:
            metadata = MicrosoftDefenderEndpointPluginV2.metadata
            plugin_name = metadata.get("name", PLUGIN_NAME)
            plugin_version = metadata.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Returns:
            List[ActionWithoutParams]: List of available actions.
        """
        return [
            ActionWithoutParams(label="Perform Action", value="action"),
        ]

    def get_action_fields(self, action: Action) -> List[Dict]:
        """Get fields required for an action.

        Args:
            action (Action): Action object which is selected as Target.

        Returns:
            List[Dict]: List of configurable fields based on selected action.
        """
        if action.value == "action":
            return [
                {
                    "label": "Action",
                    "key": "action",
                    "type": "choice",
                    "choices": [
                        {"key": act, "value": act} for act in ACTIONS.values()
                    ],
                    "default": "Audit",
                    "mandatory": True,
                    "description": (
                        "The action that is taken if the indicator "
                        "is discovered in the organization."
                    ),
                },
                {
                    "label": "Generate Alert",
                    "key": "generate_alert",
                    "type": "choice",
                    "choices": [
                        {"key": ad, "value": ad}
                        for ad in sorted(YES_NO_PARAMETER.values())
                    ],
                    "default": "No",
                    "mandatory": True,
                    "description": "Generate alerts for the indicators.",
                },
                {
                    "label": "Allow Existing Indicators to be deleted?",
                    "key": "allow_deletion",
                    "type": "choice",
                    "choices": [
                        {"key": ad, "value": ad}
                        for ad in sorted(YES_NO_PARAMETER.values())
                    ],
                    "default": "No",
                    "mandatory": True,
                    "description": (
                        "Whether or not to delete the existing indicator(s) "
                        f"from the {PLUGIN_NAME} platform to "
                        "insert new indicator(s). If Yes selected, oldest "
                        "indicator will be deleted when max capacity of 15000 "
                        "active indicators per tenant is exceeded."
                    ),
                },
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate action parameters.

        This method validates the action and their parameters. Makes sure
        mandatory parameters have a valid value and unsupported values are
        rejected.

        Args:
            action (Action): Action object to validate.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        if action.value not in ["action"]:
            err_msg = (
                "Unsupported action provided. "
                "Allowed value is 'Perform Action'."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg
            )

        # Validate Actions
        push_action = action.parameters.get("action", "")
        if validation_result := self._validate_parameters(
            parameter_type="action",
            field_name="Action",
            field_value=push_action,
            field_type=str,
            allowed_values=ACTIONS,
        ):
            return validation_result

        # Validate Generate Alert
        generate_alert = action.parameters.get("generate_alert", "")
        if validation_result := self._validate_parameters(
            parameter_type="action",
            field_name="Generate Alert",
            field_value=generate_alert,
            field_type=str,
            allowed_values=YES_NO_PARAMETER,
        ):
            return validation_result

        # Validate Allow Existing Indicators to be deleted?
        allow_deletion = action.parameters.get("allow_deletion", "")
        if validation_result := self._validate_parameters(
            parameter_type="action",
            field_name="Allow Existing Indicators to be deleted?",
            field_value=allow_deletion,
            field_type=str,
            allowed_values=YES_NO_PARAMETER,
        ):
            return validation_result

        log_msg = (
            "Successfully validated action parameters."
        )
        self.logger.debug(
            f"{self.log_prefix}: {log_msg}"
        )
        return ValidationResult(
            success=True,
            message=log_msg,
        )

    def _create_tags(self, tag_name: str) -> Tuple[str, bool]:
        """Create a tag in Netskope using TagUtils.

        Args:
            tag_name (str): Name of the tag to create.

        Returns:
            Tuple[str, bool]: Tuple of tag name and success flag.
        """
        tag_utils = TagUtils()
        try:
            if not tag_utils.exists(tag_name.strip()):
                tag_utils.create_tag(
                    TagIn(name=tag_name.strip(), color="#ED3347")
                )
            return tag_name, True
        except ValueError:
            return tag_name, False
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred while"
                    f" creating tag '{tag_name}'. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            return tag_name, False

    def _get_storage(self) -> Dict:
        """Get storage object.

        Returns:
            Dict: Storage object.
        """
        storage = self.storage if self.storage is not None else {}
        return storage

    def get_access_token_and_storage(
        self,
        base_url: str,
        tenant_id: str,
        app_id: str,
        app_secret: str,
        is_validation: bool = False,
    ) -> Tuple[Dict, Dict]:
        """
        Get authentication header and storage.

        Args:
            base_url (str): Base URL.
            tenant_id (str): Tenant ID.
            app_id (str): App ID.
            app_secret (str): App secret.
            is_validation (bool): Whether this is called from validate
                method. Defaults to False.

        Returns:
            Tuple[Dict, Dict]: Authentication header and storage.
        """
        storage = self._get_storage()
        auth_header = storage.get("auth_header")
        stored_config_hash = storage.get("config_hash")

        current_config_hash = self.mde_helper.hash_string(
            string=(
                f"{base_url}{tenant_id}{app_id}{app_secret}"
            )
        )
        if auth_header and stored_config_hash == current_config_hash:
            return auth_header, storage
        else:
            auth_header = self.mde_helper.generate_auth_token(
                tenant_id=tenant_id,
                app_id=app_id,
                app_secret=app_secret,
                base_url=base_url,
                proxies=self.proxy,
                is_validation=is_validation
            )
            storage.update(
                {
                    "auth_header": auth_header,
                    "config_hash": current_config_hash,
                }
            )
            return auth_header, storage

    def create_indicator(
        self,
        indicator: Dict,
        threat_data_type: List,
        is_retraction: bool,
    ) -> Union[Tuple[Indicator, str], Tuple[str, str], Tuple[bool, str]]:
        """Create an Indicator object from a raw API response indicator.

        Args:
            indicator (Dict): Raw indicator dictionary from API response.
            threat_data_type (List): List of selected indicator types from
                configuration (e.g. ["IpAddressV4", "FileSha256"]). Empty list
                means all types are accepted — no filtering is applied.
            is_retraction (bool): When True, returns (ioc_value, "") instead of
                building a full Indicator object.

        Returns:
            Union[Tuple[Indicator, str], Tuple[str, str], Tuple[bool, str]]:
                - (Indicator, indicator_type) for a success indicator.
                - (ioc_value, "") when is_retraction is True.
                - (False, indicator_type) when the resolved IP version is not
                  in the selected threat_data_type (indicator skipped).
        """
        (
            type_conversion,
            severity_conversion
        ) = self.mde_helper.ioc_type_severity_conversion()

        ioc_value = indicator.get("indicatorValue", "")
        if is_retraction:
            return ioc_value, ""
        indicator_type = indicator.get("indicatorType", "")
        severity = indicator.get("severity", "")

        if indicator_type == "IpAddress":
            indicator_type = self.mde_helper.determine_ip_version(
                ip_address_str=ioc_value
            )
            if threat_data_type and indicator_type not in threat_data_type:
                return False, indicator_type

        ioc_type = type_conversion.get(indicator_type, IndicatorType.URL)
        ioc_severity = severity_conversion.get(severity, SeverityType.UNKNOWN)
        first_seen = self.mde_helper.parse_date_time(
            indicator.get("creationTimeDateTimeUtc", "")
        )
        last_seen = self.mde_helper.parse_date_time(
            indicator.get("lastUpdateTime", "")
        )
        title = (
            indicator.get("title") or "No title available"
        )
        description = (
            indicator.get("description") or "No description available"
        )
        comments = title + " | " + description
        tag_name = (
            f"Defender_{indicator.get('action', 'Unknown')}"
        )
        tag_name, tag_success = self._create_tags(tag_name)
        if not tag_success:
            tag_name = []
        else:
            tag_name = [tag_name]

        try:
            indicator_obj = Indicator(
                value=ioc_value,
                type=ioc_type,
                firstSeen=first_seen,
                lastSeen=last_seen,
                comments=comments,
                severity=ioc_severity,
                tags=tag_name,
            )
        except ValidationError as e:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error while creating "
                    f"indicator for value '{ioc_value}'. Skipping."
                ),
                details=str(e),
            )
            return False, indicator_type
        except Exception:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error while creating "
                    f"indicator for value '{ioc_value}'. Skipping."
                ),
                details=str(traceback.format_exc()),
            )
            return False, indicator_type

        return indicator_obj, indicator_type

    def _prepare_params(
        self,
        last_pull_dt: datetime,
        actions_to_be_pulled: List[str],
        threat_data_type: List[str],
    ) -> Dict:
        """Build OData query params dict for the pull API.

        Combines up to three filter clauses joined by 'and':
        - Date filter: creationTimeDateTimeUtc >= last_pull_dt
        - Action filter: action eq 'X' or action eq 'Y' ...
        - Type filter: indicatorType eq 'X' or indicatorType eq 'Y' ...

        Args:
            last_pull_dt (datetime): Start datetime for the pull window.
                Pass an empty string to skip date filtering.
            actions_to_be_pulled (List[str]): Action values to filter on.
                Pass an empty list to skip action filtering.
            threat_data_type (List[str]): Indicator type values to filter on
                (e.g. "FileSha256", "FileMd5", "DomainName", "Url",
                "IpAddressV4", "IpAddressV6"). Pass an empty list to skip
                type filtering.

        Returns:
            Dict: Query parameter dict with "$filter" and "$top" keys,
                ready to pass as params to api_helper.
        """

        def normalize_types(types):
            types = set(types)
            if {"IpAddressV4", "IpAddressV6"} & types:
                types -= {"IpAddressV4", "IpAddressV6"}
                types.add("IpAddress")
            return types

        clauses = []
        if last_pull_dt:
            date_filter = (
                "creationTimeDateTimeUtc ge "
                f"{last_pull_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )
            clauses.append(date_filter)

        if actions_to_be_pulled:
            action_clause = " or ".join(
                f"action eq '{act}'" for act in actions_to_be_pulled
            )
            clauses.append(f"({action_clause})")

        if threat_data_type:
            api_types = normalize_types(threat_data_type)

            type_clause = " or ".join(
                f"indicatorType eq '{t}'" for t in api_types
            )
            clauses.append(f"({type_clause})")

        filter_value = " and ".join(clauses)
        params = {"$top": PAGE_SIZE}
        if filter_value:
            params["$filter"] = filter_value
        return params

    def _process_indicators_response(
        self,
        page_results: List[Dict],
        generate_alert_field: str,
        threat_data_type: List,
        is_retraction: bool,
    ) -> Tuple[Union[List[Indicator], Set[str]], int, Dict]:
        """Process raw API response and build Indicator objects.

        Skips indicators created by the Netskope CTE push method, filters by
        the generateAlert field if configured, and delegates IP version
        resolution and type filtering to create_indicator.

        Args:
            page_results (List[Dict]): List of raw indicator dicts from API.
            generate_alert_field (str): "Both", True, or False — controls
                which indicators to include based on generateAlert flag.
            threat_data_type (List): List of selected indicator types from
                configuration. Passed through to create_indicator for IP
                version filtering. Empty list means all types are accepted.
            is_retraction (bool): When True, collects raw indicator value
                strings into a set instead of building Indicator objects.

        Returns:
            Tuple[Union[List[Indicator], Set[str]], int, Dict]: Tuple of
                (page_indicators, skipped_count, ioc_type_counts) where
                ioc_type_counts is a dict mapping indicator type names to
                their pull counts.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        page_indicators = set() if is_retraction else []
        skipped_count = 0
        ioc_type_counts = {
            "FileSha256": 0,
            "FileMd5": 0,
            "DomainName": 0,
            "Url": 0,
            "IpAddressV4": 0,
            "IpAddressV6": 0,
        }

        for indicator in page_results:
            try:
                # Skip indicators created by Netskope CTE push method
                indicator_description = indicator.get("description")
                if (
                    indicator_description is not None
                    and "Netskope-CTE" in indicator_description
                ):
                    skipped_count += 1
                    continue

                # Filter by generateAlert if not "Both"
                if generate_alert_field != "Both" and (
                    indicator.get("generateAlert", False)
                    != generate_alert_field
                ):
                    skipped_count += 1
                    continue

                indicator_obj, indicator_type = self.create_indicator(
                    indicator=indicator,
                    threat_data_type=threat_data_type,
                    is_retraction=is_retraction
                )
                if not indicator_obj:
                    if indicator_type in ["IpAddressV4", "IpAddressV6"]:
                        continue
                    skipped_count += 1
                    continue

                if is_retraction:
                    page_indicators.add(indicator_obj)
                else:
                    page_indicators.append(indicator_obj)

                if indicator_type in ioc_type_counts:
                    ioc_type_counts[indicator_type] += 1

            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while processing "
                        f"indicator. Skipping. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_count += 1
                continue

        return page_indicators, skipped_count, ioc_type_counts

    def _pull_indicators(
        self,
        is_retraction: bool = False,
        is_sharing: bool = False,
    ) -> Generator[Tuple[List[Indicator], Dict], None, None]:
        """Pull indicators from Microsoft Defender for Endpoint.

        Args:
            is_retraction (bool, optional):
                When True, pull modified indicators for retraction.
                Defaults to False.
            is_sharing (bool, optional): When True, return whole response.

        Yields:
            Tuple[List[Indicator], Dict]: Batch of Indicator objects and
                an empty checkpoint dict (checkpoint is time-based, not
                page-based, so no per-page state is needed).
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        (
            base_url,
            tenant_id,
            app_id,
            app_secret,
            _,
            threat_data_type,
            actions_to_be_pulled,
            generate_alert_field,
            _,
            retraction_interval,
            initial_range,
        ) = self.mde_helper.get_configuration_parameters(
            self.configuration
        )

        actions_to_be_pulled = actions_to_be_pulled or list(ACTIONS.values())
        threat_data_type = threat_data_type or list(THREAT_TYPES.values())

        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if is_sharing:
            last_pull_dt = ""
            actions_to_be_pulled = []
            threat_data_type = []
        elif is_retraction:
            last_pull_dt = datetime.now(timezone.utc) - timedelta(
                days=retraction_interval
            )
        elif sub_checkpoint and sub_checkpoint.get("checkpoint"):
            last_pull_dt = sub_checkpoint.get("checkpoint")
        elif self.last_run_at:
            last_pull_dt = self.last_run_at
        else:
            self.logger.info(
                f"{self.log_prefix}: This is initial data pull since "
                "checkpoint is empty. Querying indicators for "
                f"last {initial_range} days."
            )
            last_pull_dt = datetime.now(timezone.utc) - timedelta(
                days=initial_range
            )

        url = INDICATOR_ENDPOINT.format(base_url=base_url)
        params = self._prepare_params(
            last_pull_dt=last_pull_dt,
            actions_to_be_pulled=actions_to_be_pulled,
            threat_data_type=threat_data_type,
        )

        total_pulled = 0
        total_skipped = 0
        skip_count = 0
        page_count = 0
        next_page = True
        checkpoint = ""

        modified_logger = (
            "modified indicator(s)" if is_retraction else "indicator(s)"
        )
        if not is_sharing:
            self.logger.info(
                f"{self.log_prefix}: Pulling {modified_logger} "
                f"from checkpoint: {str(last_pull_dt)}."
            )

        try:
            auth_headers, storage = self.get_access_token_and_storage(
                base_url=base_url,
                tenant_id=tenant_id,
                app_id=app_id,
                app_secret=app_secret,
            )

            while next_page:
                page_count += 1
                page_indicators = set() if is_retraction else []
                self.logger.debug(
                    f"{self.log_prefix}: Pulling {modified_logger} for "
                    f"page {page_count} from {PLUGIN_NAME} platform."
                )
                params["$skip"] = skip_count

                resp_json = self.mde_helper.api_helper(
                    logger_msg=(
                        f"pulling {modified_logger} for page {page_count}"
                    ),
                    url=url,
                    method="GET",
                    params=params,
                    headers=auth_headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                    is_retraction=is_retraction
                )
                resp_list = resp_json.get("value", [])
                resp_count = len(resp_list)

                if resp_list and is_sharing:
                    yield resp_list
                    if resp_count < PAGE_SIZE:
                        next_page = False
                    else:
                        skip_count += PAGE_SIZE
                elif resp_list:
                    page_indicators, skipped_count, ioc_type_counts = (
                        self._process_indicators_response(
                            resp_list,
                            generate_alert_field,
                            threat_data_type,
                            is_retraction
                        )
                    )
                    page_indicator_count = len(page_indicators)
                    total_pulled += page_indicator_count
                    total_skipped += skipped_count

                    if resp_count < PAGE_SIZE:
                        next_page = False
                    else:
                        skip_count += PAGE_SIZE

                    checkpoint = resp_list[-1].get("creationTimeDateTimeUtc")

                    self.logger.info(
                        f"{self.log_prefix}: Successfully pulled "
                        f"{page_indicator_count} {modified_logger} "
                        f"and skipped {skipped_count} indicator(s) "
                        f"for page {page_count} from {PLUGIN_NAME} platform. "
                        f"Pull Stats: {ioc_type_counts.get('Url')} URLs, "
                        f"{ioc_type_counts.get('DomainName')} Domains, "
                        f"{ioc_type_counts.get('IpAddressV4')} IPv4, "
                        f"{ioc_type_counts.get('IpAddressV6')} IPv6, "
                        f"{ioc_type_counts.get('FileMd5')} MD5, "
                        f"{ioc_type_counts.get('FileSha256')} SHA256. "
                        f"Total {modified_logger} pulled - {total_pulled}."
                    )
                else:
                    next_page = False

                if not next_page and not is_sharing:
                    log_msg = (
                        "Successfully pulled "
                        f"{total_pulled} indicator(s) "
                        f"from {PLUGIN_NAME} platform"
                    )
                    if total_skipped:
                        log_msg += (
                            f" and skipped {total_skipped} "
                            "indicator(s) due to "
                            "filter provided in the plugin configuration "
                            "or already shared from Netskope CE"
                        )
                    self.logger.info(
                        f"{self.log_prefix}: {log_msg}."
                    )

                if page_indicators:
                    if hasattr(self, "sub_checkpoint") and not is_retraction:
                        yield page_indicators, {"checkpoint": checkpoint}
                    else:
                        yield page_indicators, None

        except MicrosoftDefenderPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while pulling "
                f"indicator(s) from {PLUGIN_NAME} platform. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftDefenderPluginException(err_msg)

    def pull(self) -> List[Indicator]:
        """Pull indicator data stored on the user's tenant.

        Returns:
            List[Indicator]: List of pulled Indicator objects.
        """
        try:
            is_pull_required = self.configuration.get(
                "is_pull_required", "Yes"
            )
            if is_pull_required.lower() == "no":
                self.logger.info(
                    f"{self.log_prefix}: Polling is disabled in configuration "
                    "parameter hence skipping pulling of indicators from "
                    f"{PLUGIN_NAME}."
                )
                return []

            if hasattr(self, "sub_checkpoint"):
                def wrapper(self):
                    yield from self._pull_indicators()
                return wrapper(self)
            else:
                indicators = []
                for batch, _ in self._pull_indicators():
                    indicators.extend(batch)
                self.logger.info(
                    f"{self.log_prefix}: Total {len(indicators)} "
                    f"indicator(s) pulled from {PLUGIN_NAME} platform."
                )
                return indicators
        except MicrosoftDefenderPluginException:
            raise
        except Exception as err:
            err_msg = (
                "Error occurred while pulling indicators "
                f"from {PLUGIN_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftDefenderPluginException(err_msg)

    def push(
        self, indicators: List[Indicator], action_dict: Dict
    ) -> PushResult:
        """Push the Indicator list to Microsoft Defender for Endpoint.

        Args:
            indicators (List[Indicator]): List of Indicators to be pushed.
            action_dict (Dict): Action parameters dictionary.

        Returns:
            PushResult: PushResult object with success flag and message.
        """
        action_dict = action_dict.get("parameters")

        (
            base_url,
            tenant_id,
            app_id,
            app_secret,
            source,
            *_,
        ) = self.mde_helper.get_configuration_parameters(
            self.configuration
        )
        try:
            auth_header, storage = self.get_access_token_and_storage(
                base_url=base_url,
                tenant_id=tenant_id,
                app_id=app_id,
                app_secret=app_secret,
            )
            payload_list = self.prepare_payload(
                indicators=indicators,
                action_dict=action_dict,
                source=source
            )
            return self.push_indicators_to_defender(
                base_url=base_url,
                headers=auth_header,
                json_payload=payload_list,
                action_dict=action_dict,
                storage=storage,
            )
        except MicrosoftDefenderPluginException as exp:
            return PushResult(
                success=False,
                message=str(exp),
            )
        except Exception as exp:
            err_msg = (
                "Error occurred while sharing "
                f"indicator(s) to {PLUGIN_NAME} platform."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {repr(exp)}"
            )
            return PushResult(
                success=False,
                message=err_msg,
            )

    def push_indicators_to_defender(
        self,
        base_url: str,
        headers: Dict,
        json_payload: List[Dict],
        action_dict: Dict,
        storage: Dict
    ) -> PushResult:
        """Push indicators to Microsoft Defender for Endpoint.

        Pulls the full current indicator list first (to support the
        allow_deletion capacity logic), then pushes each payload item.

        Args:
            base_url (str): Base URL for API calls.
            headers (Dict): HTTP headers including Authorization token.
            json_payload (List[Dict]): List of indicator payloads to push.
            action_dict (Dict): Action parameters dictionary.
            storage (Dict): Storage dict.

        Returns:
            PushResult: PushResult object with success flag and message.
        """
        try:
            allow_deletion = action_dict.get("allow_deletion", "No")
            indicators_url = INDICATOR_ENDPOINT.format(
                base_url=base_url
            )
            ioc_in_defender = []
            success_count = 0
            failed_iocs = set()

            if allow_deletion == "Yes":
                # Pull all existing indicators to get their IDs for deletion
                for resp_list in self._pull_indicators(is_sharing=True):
                    for ioc in resp_list:
                        ioc_in_defender.append(
                            {
                                "id": ioc.get("id"),
                                "creationTimeDateTimeUtc": ioc.get(
                                    "creationTimeDateTimeUtc"
                                ),
                            }
                        )

                # Sort descending; earliest creation time at the end
                sorted_defender_ioc_list = sorted(
                    ioc_in_defender,
                    key=lambda i: i["creationTimeDateTimeUtc"] or "",
                    reverse=True,
                )

            self.logger.info(
                f"{self.log_prefix}: Sharing {len(json_payload)} indicator(s) "
                f"to {PLUGIN_NAME} platform."
            )
            for ioc in json_payload:
                ioc_value = ioc.get('indicatorValue', "")
                push_resp = self.mde_helper.api_helper(
                    logger_msg=(
                        f"sharing indicator '{ioc_value}'"
                    ),
                    url=indicators_url,
                    method="POST",
                    headers=headers,
                    json=ioc,
                    configuration=self.configuration,
                    storage=storage,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=False,
                )
                if push_resp.status_code == 200:
                    self.logger.debug(
                        f"{self.log_prefix}: Successfully shared "
                        f"indicator '{ioc_value}'."
                    )
                    success_count += 1
                    continue
                if push_resp.status_code == 400:
                    push_resp_json = push_resp.json()
                    error_message = push_resp_json.get(
                        "error", {}
                    ).get("message", "")

                    if "Max capacity exceeded" in error_message:
                        if (
                            allow_deletion == "Yes"
                            and sorted_defender_ioc_list
                        ):
                            del_ioc = sorted_defender_ioc_list.pop()
                            ioc_id = del_ioc.get('id', "")
                            del_resp = self._delete_indicators_from_defender(
                                indicator_id=ioc_id,
                                base_url=base_url,
                                headers=headers,
                                storage=storage
                            )
                            if not del_resp:
                                err_msg = (
                                    "Unable to share "
                                    f"indicator {ioc_value}."
                                )
                                self.logger.error(
                                    f"{self.log_prefix}: {err_msg}"
                                )
                                failed_iocs.add(ioc_value)
                                continue

                            # Retry push after deletion
                            retry_resp = self.mde_helper.api_helper(
                                logger_msg=(
                                    "retry sharing indicator "
                                    f"'{ioc_value}'"
                                ),
                                url=indicators_url,
                                method="POST",
                                headers=headers,
                                json=ioc,
                                configuration=self.configuration,
                                storage=storage,
                                verify=self.ssl_validation,
                                proxies=self.proxy,
                                is_handle_error_required=False,
                            )
                            if retry_resp.status_code != 200:
                                retry_error = retry_resp.json().get(
                                    "error", {}
                                ).get("message", "")
                                err_msg = (
                                    "Unable to share "
                                    f"indicator {ioc_value}."
                                )
                                self.logger.error(
                                    message=f"{self.log_prefix}: {err_msg}",
                                    details=str(retry_error)
                                )
                                failed_iocs.add(ioc_value)
                                continue
                            success_count += 1
                        else:
                            err_msg = (
                                f"Failed to share more indicator(s) "
                                f"to {PLUGIN_NAME} platform due to maximum "
                                "capacity is exceeded."
                            )
                            self.logger.error(
                                message=f"{self.log_prefix}: {err_msg}",
                                resolution=(
                                    "Delete indicators from "
                                    f"{PLUGIN_NAME} platform to share more "
                                    "indicator(s)."
                                )
                            )
                            return PushResult(
                                success=False,
                                message=err_msg,
                            )
                    else:
                        err_msg = (
                            f"Failed to share indicator '{ioc_value}' "
                            f"to {PLUGIN_NAME} platform."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=str(push_resp_json)
                        )
                        failed_iocs.add(ioc_value)
                        continue
                else:
                    push_resp_json = push_resp.json()
                    err_msg = (
                        f"Failed to share indicator '{ioc_value}' "
                        f"to {PLUGIN_NAME} platform."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=str(push_resp_json)
                    )
                    failed_iocs.add(ioc_value)
                    continue

            log_msg = (
                f"Successfully shared {success_count} "
                f"indicator(s) to {PLUGIN_NAME} platform."
            )
            if failed_iocs:
                log_msg += (
                    f" Failed to share {len(failed_iocs)} "
                    "indicator(s)."
                )
            self.logger.info(
                f"{self.log_prefix}: {log_msg}"
            )
            if failed_iocs and "failed_iocs" in PushResult.model_fields:
                return PushResult(
                    success=True,
                    message=log_msg,
                    failed_iocs=list(failed_iocs),
                )
            return PushResult(
                success=True,
                message=log_msg,
            )
        except MicrosoftDefenderPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while sharing indicator(s)."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            return PushResult(
                success=False,
                message=err_msg,
            )

    def prepare_payload(
        self,
        indicators: List[Indicator],
        action_dict: Dict,
        source: str
    ) -> List[Dict]:
        """Prepare the JSON payload for Push.

        Args:
            indicators (List[Indicator]): List of Indicator objects to push.
            action_dict (Dict): Action parameters dictionary.
            source (str): Source will be added in indicator description.

        Returns:
            List[Dict]: List of indicator payload dictionaries as per
                Defender API format.
        """
        generate_alert_conversion = {
            "Yes": True,
            "No": False,
        }
        action_conversion = {
            "unknown": "Audit",
            "allow": "Allowed",
            "block": "Block",
            "alert": "Audit",
            "Alert": "Audit",
            "AlertAndBlock": "Block",
        }

        (
            type_conversion,
            severity_conversion
        ) = self.mde_helper.ioc_type_severity_conversion(is_sharing=True)

        payload_list = []

        action = action_dict.get("action", "Audit")
        generate_alert = action_dict.get("generate_alert", "No")
        generate_alert_action = generate_alert_conversion.get(
            generate_alert, True
        )

        if action in action_conversion:
            if action == "AlertAndBlock":
                generate_alert_action = True
            action = action_conversion[action]

        for indicator in indicators:
            ioc_value = indicator.value
            ioc_type = type_conversion.get(indicator.type, "DomainName")
            json_body = {
                "indicatorValue": ioc_value,
                "action": action,
                "description": (
                    f"Netskope-CTE | {source} | {indicator.comments}"
                ),
            }

            if severity := severity_conversion.get(indicator.severity):
                json_body["severity"] = severity

            json_body["generateAlert"] = (
                True if action == "Audit" else generate_alert_action
            )

            if ioc_type in ["Url", "IpAddress", "DomainName"]:
                ioc_type = self.mde_helper.check_url_domain_ip(ioc_value)
            json_body["indicatorType"] = ioc_type

            json_body["title"] = (
                f"Indicator {ioc_value} of type {ioc_type}"
            )
            payload_list.append(json_body.copy())

        return payload_list

    def _validate_parameters(
        self,
        parameter_type: Literal["configuration", "action"],
        field_name: str,
        field_value: Union[str, int, List],
        field_type: Type,
        allowed_values: Dict = None,
        max_value: int = None,
        is_required: bool = True,
        should_strip_str: bool = True,
    ):
        """Validate plugin parameters generically.

        Args:
            parameter_type (Literal["configuration", "action"]): Type of
                parameter being validated.
            field_name (str): Name of the field for error messages.
            field_value (Union[str, int, List]): Value of the field to
                validate.
            field_type (Type): Expected type of the field value.
            allowed_values (Dict, optional): List of allowed values.
                Defaults to None.
            max_value (int, optional): Maximum allowed integer value.
                Defaults to None.
            is_required (bool): Whether the field is required.
                Defaults to True.
            should_strip_str (bool): Whether to strip string values before
                validation. Set to False for password fields.
                Defaults to True.

        Returns:
            ValidationResult: ValidationResult with success=False if
                invalid, or None if valid.
        """
        if isinstance(field_value, str) and should_strip_str:
            field_value = field_value.strip()

        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = EMPTY_ERROR_MESSAGE.format(
                field_name=field_name, parameter_type=parameter_type
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG} {err_msg}"
                ),
                resolution=(
                    f"Ensure that {field_name} value is provided in the "
                    f"{parameter_type} parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if is_required and not isinstance(field_value, field_type):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG} {err_msg}"
                ),
                resolution=(
                    f"Ensure that a valid value for {field_name} is "
                    f"provided in the {parameter_type} parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if allowed_values:
            allowed_values_str = ', '.join(allowed_values.keys())
            err_msg = (
                TYPE_ERROR_MESSAGE.format(
                    field_name=field_name, parameter_type=parameter_type
                )
                + INVALID_VALUE_ERROR_MESSAGE.format(
                    allowed_values=allowed_values_str
                )
            )
            resolution = (
                f"Ensure that a valid value for {field_name} is "
                f"provided in the {parameter_type} parameters "
                f"and it should be one of {allowed_values_str}."
            )
            if (
                field_type is str
                and field_value not in allowed_values.values()
            ):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MSG} "
                        f"{err_msg}"
                    ),
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)
            elif field_type is list:
                for value in field_value:
                    if value not in allowed_values.values():
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {VALIDATION_ERROR_MSG} "
                                f"{err_msg}"
                            ),
                            resolution=resolution,
                        )
                        return ValidationResult(
                            success=False, message=err_msg
                        )

        if (
            max_value
            and isinstance(field_value, int)
            and (field_value > max_value or field_value <= 0)
        ):
            err_msg = (
                f"Invalid value for {field_name} provided in "
                f"{parameter_type} parameters. Valid value should be an "
                f"integer greater than 0 and less than {max_value}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG} {err_msg}"
                ),
                resolution=(
                    f"Ensure that the value for {field_name} is an integer "
                    f"greater than 0 and less than {max_value}."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

    def _validate_credentials(
        self,
        tenant_id: str,
        app_id: str,
        app_secret: str,
        base_url: str,
        configuration: dict
    ) -> ValidationResult:
        """Validate Azure AD application credentials.

        Args:
            tenant_id (str): Azure AD Tenant ID.
            app_id (str): Azure AD Application ID.
            app_secret (str): Azure AD Application Secret.
            base_url (str): Microsoft Defender for Endpoint base URL.
            configuration (dict): Configuration Dict.

        Returns:
            ValidationResult: Validation result with success flag and
                message.
        """
        try:
            is_valid = False
            auth_header, storage = self.get_access_token_and_storage(
                base_url=base_url,
                tenant_id=tenant_id,
                app_id=app_id,
                app_secret=app_secret,
                is_validation=True,
            )

            auth_token = auth_header.get("Authorization")
            if auth_token and auth_token.startswith("Bearer "):
                auth_token = auth_token.removeprefix("Bearer ")

            if not auth_token:
                self.logger.error(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG} "
                    "Could not retrieve access token."
                )
                return ValidationResult(
                    success=False,
                    message="Could not verify credentials.",
                )

            alg = jwt.get_unverified_header(auth_token).get("alg")
            decoded_auth_token = jwt.decode(
                auth_token,
                algorithms=alg,
                options={"verify_signature": False},
            )
            roles = set(decoded_auth_token.get("roles", []))
            if "Ti.ReadWrite" in roles or "Ti.ReadWrite.All" in roles:
                is_valid = True
            if is_valid:
                creation_time = (
                    datetime.now(timezone.utc).strftime(DATE_TIME_FORMAT)
                )
                params = {
                    "$filter": (
                        f"creationTimeDateTimeUtc ge {creation_time}"
                    )
                }
                url = INDICATOR_ENDPOINT.format(
                    base_url=base_url
                )
                logger_msg = (
                    f"validating connectivity with {PLUGIN_NAME} platform"
                )

                self.mde_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method="GET",
                    params=params,
                    headers=auth_header,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=configuration,
                    storage=storage,
                    is_validation=True,
                )

                logger_msg = (
                    "Successfully validated configuration "
                    f"parameters for {PLUGIN_NAME} platform."
                )
                self.logger.debug(
                    f"{self.log_prefix}: {logger_msg}"
                )
                return ValidationResult(
                    success=True, message=logger_msg,
                )
            else:
                err_msg = (
                    "Required API roles 'Ti.ReadWrite or "
                    "Ti.ReadWrite.All' not found in the access token."
                )
                resolution = (
                    "Ensure that the Entra application has 'Ti.ReadWrite or "
                    "Ti.ReadWrite.All' roles assigned."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MSG} {err_msg}"
                    ),
                    resolution=resolution
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        except MicrosoftDefenderPluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{str(exp)} Check logs for more details."
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

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the plugin configuration parameters.

        Args:
            configuration (Dict): Dict object having all plugin configuration
                parameters.

        Returns:
            ValidationResult: ValidationResult object with success flag and
                message.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration parameters."
        )
        (
            base_url,
            tenant_id,
            app_id,
            app_secret,
            source,
            threat_data_type,
            actions_to_be_pulled,
            generate_alert_val,
            is_pull_required,
            retraction_interval,
            initial_range,
        ) = self.mde_helper.get_configuration_parameters(configuration)

        # Validate Base URL
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Base URL",
            field_value=base_url,
            field_type=str,
            allowed_values=VALID_BASE_URLS,
        ):
            return validation_result

        # Validate Tenant ID
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Tenant ID",
            field_value=tenant_id,
            field_type=str,
        ):
            return validation_result

        # Validate Application ID
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Application ID",
            field_value=app_id,
            field_type=str,
        ):
            return validation_result

        # Validate Application Secret (do not strip — password field)
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Application Secret",
            field_value=app_secret,
            field_type=str,
            should_strip_str=False,
        ):
            return validation_result

        # Validate IOC Source length (optional field)
        if source and len(source) > IOC_SOURCE_LENGTH:
            err_msg = (
                f"IOC Source length exceeding {IOC_SOURCE_LENGTH}"
                " characters."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG} {err_msg}"
                ),
                resolution=(
                    f"Ensure that IOC Source does not exceed"
                    f" {IOC_SOURCE_LENGTH} characters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Type of Threat data to pull
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Type of Threat data to pull",
            field_value=threat_data_type,
            field_type=list,
            allowed_values=THREAT_TYPES,
            is_required=False,
        ):
            return validation_result

        # Validate Actions
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Actions",
            field_value=actions_to_be_pulled,
            field_type=list,
            allowed_values=ACTIONS,
            is_required=False,
        ):
            return validation_result

        # Validate Indicators with Generated Alert
        field_name = "Indicators with Generated Alert"
        parameter_type = "configuration"
        if generate_alert_val is None:
            err_msg = EMPTY_ERROR_MESSAGE.format(
                field_name=field_name, parameter_type=parameter_type
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG} {err_msg}"
                ),
                resolution=(
                    f"Ensure that {field_name} value is provided in the "
                    f"{parameter_type} parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if generate_alert_val not in IOC_GENERATED_ALERT.values():
            allowed_values_str = ', '.join(IOC_GENERATED_ALERT.keys())
            err_msg = (
                TYPE_ERROR_MESSAGE.format(
                    field_name=field_name, parameter_type=parameter_type
                )
                + INVALID_VALUE_ERROR_MESSAGE.format(
                    allowed_values=allowed_values_str
                )
            )
            resolution = (
                f"Ensure that a valid value for {field_name} is "
                f"provided in the {parameter_type} parameters "
                f"and it should be one of {allowed_values_str}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG} "
                    f"{err_msg}"
                ),
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Enable Polling
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Enable Polling",
            field_value=is_pull_required,
            field_type=str,
            allowed_values=YES_NO_PARAMETER,
        ):
            return validation_result

        # Validate Retraction Interval (in days)
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Retraction Interval (in days)",
            field_value=retraction_interval,
            field_type=int,
            max_value=DAYS_LIMIT,
            is_required=False
        ):
            return validation_result

        # Validate Initial Range
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Initial Range (in days)",
            field_value=initial_range,
            field_type=int,
            max_value=DAYS_LIMIT,
        ):
            return validation_result

        # Validate credentials via connectivity check
        return self._validate_credentials(
            tenant_id, app_id, app_secret, base_url, configuration
        )

    def _delete_indicators_from_defender(
        self,
        indicator_id: str,
        base_url: str,
        headers: dict,
        storage: dict
    ):
        """Delete a single indicator from Microsoft Defender for Endpoint.

        Used by the push flow when MDE reports "Max capacity exceeded" — the
        oldest existing indicator is deleted to make room for a new one.

        Args:
            indicator_id (str): MDE indicator ID to delete.
            base_url (str): Microsoft Defender for Endpoint base URL.
            headers (dict): Authorization headers for the request.
            storage (dict): Token storage dict passed through to api_helper.

        Returns:
            bool: True if the indicator was deleted successfully,
                False otherwise.
        """
        indicators_url = INDICATOR_ENDPOINT.format(
            base_url=base_url
        )
        del_url = f"{indicators_url}/{indicator_id}"
        try:
            _ = self.mde_helper.api_helper(
                logger_msg=(
                    f"deleting indicator from {PLUGIN_NAME} platform"
                ),
                url=del_url,
                method="DELETE",
                headers=headers,
                configuration=self.configuration,
                storage=storage,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
            return True
        except MicrosoftDefenderPluginException:
            return False
        except Exception as exp:
            err_msg = (
                "Error occurred while deleting indicators "
                f"from {PLUGIN_NAME} platform."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            return False

    def get_modified_indicators(
        self, source_indicators: List[List[Dict]]
    ) -> Generator[Tuple[List[str], bool], None, None]:
        """Get all modified IoCs status.

        Args:
            source_indicators (List[List[Dict]]): Source IoCs.

        Yields:
            List of retracted IoCs, Status (List, bool): List of
                retracted IoCs values. Status of execution.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        (
            *_,
            retraction_interval,
            _,
        ) = self.mde_helper.get_configuration_parameters(
            self.configuration
        )

        if not (retraction_interval and isinstance(retraction_interval, int)):
            log_msg = (
                "Retraction Interval is not available for the configuration "
                f"'{self.config_name}'. Skipping retraction of indicator(s) "
                f"from {PLUGIN_NAME} platform."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True
            return

        self.logger.info(
            message=(
                f"{self.log_prefix}: Pulling modified indicator(s) "
                f"from {PLUGIN_NAME} platform."
            )
        )

        try:
            modified_indicators_gen = self._pull_indicators(is_retraction=True)
        except MicrosoftDefenderPluginException:
            raise
        except Exception as err:
            err_msg = (
                "Error occurred while pulling modified "
                f"indicator(s) from {PLUGIN_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftDefenderPluginException(err_msg)

        modified_iocs = set()
        for ioc_values_set, _ in modified_indicators_gen:
            modified_iocs.update(ioc_values_set)

        for source_ioc_list in source_indicators:
            try:
                total_iocs = len(source_ioc_list)
                iocs = {
                    ioc.value for ioc in source_ioc_list
                    if ioc and ioc.value not in modified_iocs
                }

                self.logger.info(
                    f"{self.log_prefix}: {len(iocs)} indicator(s) will "
                    f"be marked as retracted from {total_iocs} total "
                    "indicator(s) present in Cloud Exchange for "
                    f"{PLUGIN_NAME}."
                )
                yield list(iocs), False
            except Exception as err:
                err_msg = (
                    f"Error while pulling modified indicator(s) from "
                    f"{PLUGIN_NAME} platform."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                    details=traceback.format_exc(),
                )
                raise MicrosoftDefenderPluginException(err_msg)

    def _fetch_indicator_ids_by_value(
        self,
        indicator_values: List[str],
        base_url: str,
        auth_headers: Dict,
        storage: dict,
    ) -> List[str]:
        """Fetch Microsoft Defender indicator IDs for given indicator values.

        Queries the Indicators API using OData filter clauses in batches of
        RETRACTION_FETCH_BATCH_SIZE (20) and paginates results using $top
        and $skip.

        Args:
            indicator_values (List[str]): Indicator values to look up.
            base_url (str): Base URL for API calls.
            auth_headers (Dict): Authorization headers.
            storage (dict): Storage dict for token refresh.

        Returns:
            List[str]: Deduplicated list of indicator IDs found.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        url = INDICATOR_ENDPOINT.format(base_url=base_url)
        ids = []

        for i in range(0, len(indicator_values), RETRACTION_FETCH_BATCH_SIZE):
            batch = indicator_values[
                i: i + RETRACTION_FETCH_BATCH_SIZE
            ]
            filter_clause = " or ".join(
                f"indicatorValue eq '{v}'" for v in batch
            )
            skip = 0
            while True:
                params = {
                    "$filter": filter_clause,
                    "$top": PAGE_SIZE,
                    "$skip": skip,
                }
                try:
                    resp_json = self.mde_helper.api_helper(
                        logger_msg=(
                            "fetching indicator IDs for retraction "
                            f"batch {i // RETRACTION_FETCH_BATCH_SIZE + 1}"
                        ),
                        url=url,
                        method="GET",
                        params=params,
                        headers=auth_headers,
                        configuration=self.configuration,
                        storage=storage,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        is_retraction=True,
                    )
                except MicrosoftDefenderPluginException:
                    raise
                except Exception as exp:
                    err_msg = (
                        "Error occurred while fetching indicator IDs "
                        f"for retraction from {PLUGIN_NAME} platform."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {err_msg} Error: {exp}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    raise MicrosoftDefenderPluginException(err_msg)

                page_values = resp_json.get("value", [])
                ids.extend(item["id"] for item in page_values if "id" in item)

                if len(page_values) < PAGE_SIZE:
                    break
                skip += PAGE_SIZE

        return list(set(ids))

    def _batch_delete_indicators(
        self,
        indicator_ids: List[str],
        base_url: str,
        auth_headers: Dict,
        storage: dict,
    ) -> Tuple[int, int]:
        """Delete Microsoft Defender indicators in batches via BatchDelete API.

        Args:
            indicator_ids (List[str]): List of indicator IDs to delete.
            base_url (str): Base URL for API calls.
            auth_headers (Dict): Authorization headers.
            storage (dict): Storage dict for token refresh.

        Returns:
            Tuple[int, int]: (deleted_count, failed_count).
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        delete_url = BATCH_DELETE_ENDPOINT.format(base_url=base_url)
        deleted_count = 0
        failed_count = 0

        for i in range(0, len(indicator_ids), RETRACTION_DELETE_BATCH_SIZE):
            batch = indicator_ids[i: i + RETRACTION_DELETE_BATCH_SIZE]
            batch_num = i // RETRACTION_DELETE_BATCH_SIZE + 1
            try:
                self.mde_helper.api_helper(
                    logger_msg=(
                        f"retracting {len(batch)} indicator(s) in "
                        f"batch {batch_num} from {PLUGIN_NAME} platform."
                    ),
                    url=delete_url,
                    method="POST",
                    json={"IndicatorIds": batch},
                    headers=auth_headers,
                    configuration=self.configuration,
                    storage=storage,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_retraction=True,
                )
                deleted_count += len(batch)
                self.logger.debug(
                    f"{self.log_prefix}: Successfully retracted {len(batch)} "
                    f"indicator(s) in batch {batch_num}."
                )
            except MicrosoftDefenderPluginException as exp:
                failed_count += len(batch)
                self.logger.error(
                    f"{self.log_prefix}: Failed to retract {len(batch)} "
                    f"indicator(s) in batch {batch_num} from {PLUGIN_NAME}. "
                    f"Error: {exp}"
                )

        return deleted_count, failed_count

    def retract_indicators(
        self,
        retracted_indicators_lists: List[List[Indicator]],
        list_action_dict: List[Action],
    ):
        """Retract/Delete Indicators from Microsoft Defender for Endpoint.

        Fetches indicator IDs from MDE by value (OData filter, batches of
        RETRACTION_FETCH_BATCH_SIZE) then deletes via BatchDelete API
        (batches of RETRACTION_DELETE_BATCH_SIZE).

        Args:
            retracted_indicators_lists (List[List[Indicator]]):
                Retract indicators list.
            list_action_dict (List[Action]): List of action dict.

        Yields:
            ValidationResult: Validation result per batch.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        self.logger.info(
            f"{self.log_prefix}: Starting retraction of indicator(s) from "
            f"{PLUGIN_NAME} platform."
        )

        (
            base_url,
            tenant_id,
            app_id,
            app_secret,
            *_,
        ) = self.mde_helper.get_configuration_parameters(self.configuration)

        auth_headers, storage = self.get_access_token_and_storage(
            base_url=base_url,
            tenant_id=tenant_id,
            app_id=app_id,
            app_secret=app_secret,
        )

        total_retracted = 0
        total_failed = 0

        for batch_num, retraction_batch in enumerate(
            retracted_indicators_lists, start=1
        ):
            try:
                values = [
                    ioc.value
                    for ioc in retraction_batch
                    if ioc and ioc.value
                ]
                if not values:
                    log_msg = (
                        f"No indicator values in batch {batch_num}. "
                        "Skipping batch."
                    )
                    self.logger.info(
                        f"{self.log_prefix}: {log_msg}"
                    )
                    yield ValidationResult(
                        success=True,
                        message=log_msg,
                    )
                    continue

                self.logger.debug(
                    f"{self.log_prefix}: Fetching indicator IDs for "
                    f"{len(values)} indicator(s) in batch {batch_num}."
                )

                ids = self._fetch_indicator_ids_by_value(
                    indicator_values=values,
                    base_url=base_url,
                    auth_headers=auth_headers,
                    storage=storage,
                )

                if not ids:
                    log_msg = (
                        "No matching indicator IDs "
                        f"found in {PLUGIN_NAME} for batch {batch_num}. "
                        "Skipping retraction."
                    )
                    self.logger.info(
                        f"{self.log_prefix}: {log_msg}"
                    )
                    yield ValidationResult(
                        success=True,
                        message=log_msg,
                    )
                    continue

                self.logger.debug(
                    f"{self.log_prefix}: Found {len(ids)} indicator ID(s) "
                    f"to retract for batch {batch_num}."
                )

                deleted, failed = self._batch_delete_indicators(
                    indicator_ids=ids,
                    base_url=base_url,
                    auth_headers=auth_headers,
                    storage=storage,
                )
                total_retracted += deleted
                total_failed += failed

                log_msg = (
                    f"Successfully retracted {deleted} indicator(s)"
                )
                if failed > 0:
                    log_msg += (
                        f" and failed {failed} indicator(s)"
                    )
                self.logger.debug(
                    f"{self.log_prefix}: {log_msg} in retraction "
                    f"batch {batch_num} from {PLUGIN_NAME} platform."
                )
                yield ValidationResult(
                    success=True,
                    message=log_msg,
                )

            except MicrosoftDefenderPluginException as exp:
                err_msg = (
                    f"Error occurred while retracting "
                    f"indicator(s) in batch {batch_num}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg} Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                yield ValidationResult(
                    success=False,
                    message=err_msg,
                )
            except Exception as exp:
                err_msg = (
                    f"Unexpected error occurred while retracting "
                    f"indicator(s) in batch {batch_num}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg} Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                yield ValidationResult(
                    success=False,
                    message=err_msg,
                )

        log_msg = (
            f"Successfully retracted {total_retracted} indicator(s)"
        )
        if total_failed > 0:
            log_msg += (
                f" and failed to retract {total_failed} indicator(s)"
            )
        self.logger.info(
            f"{self.log_prefix}: {log_msg} from {PLUGIN_NAME} platform."
        )
