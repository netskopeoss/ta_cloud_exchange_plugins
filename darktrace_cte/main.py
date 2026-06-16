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

CTE Darktrace Plugin main file
"""

import re
import traceback
from collections import defaultdict
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import (
    Callable,
    Dict,
    Generator,
    List,
    Literal,
    Set,
    Tuple,
    Type,
    Union,
)

from netskope.common.api import __version__ as CE_VERSION
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.business_rule import Action, ActionWithoutParams
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)
from packaging import version

from .utils.exception import exception_handler, DarktracePluginException

from .utils.constants import (
    DARKTRACE_TO_INTERNAL_TYPE,
    DOMAIN_REGEX,
    DOMAIN_REGEX_2,
    EMPTY_ERROR_MESSAGE,
    FQDN_REGEX,
    INDICATOR_LIST_LIMIT,
    INTELFEED_API_ENDPOINT,
    INVALID_VALUE_ERROR_MESSAGE,
    MAXIMUM_CE_VERSION,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PUSH_BATCH_SIZE,
    RETRACTION,
    SOURCE_LABEL,
    TYPE_ERROR_MESSAGE,
    VALIDATION_ERROR_MESSAGE,
)
from .utils.helper import DarktracePluginHelper


class DarktracePlugin(PluginBase):
    """The Darktrace cte plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Darktrace plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        # Flag to check if CE version is more than v5.1.2
        self._is_ce_post_v512 = self._check_ce_version()
        # Method to decide which logger to use with or without
        # resolutions based on the CE version
        self._patch_error_logger()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.darktrace_helper = DarktracePluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = DarktracePlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _check_ce_version(self) -> bool:
        """Check if CE version is greater than v5.1.2.

        Returns:
            bool: True if CE version is greater than v5.1.2, False otherwise.
        """
        return version.parse(CE_VERSION) > version.parse(MAXIMUM_CE_VERSION)

    def _patch_error_logger(self):
        """Monkey patch logger methods to handle resolution parameter
        compatibility.
        """
        # Store original methods
        original_error = self.logger.error

        def patched_error(
            message=None,
            details=None,
            resolution=None,
            **kwargs,
        ):
            """Patched error method that handles resolution compatibility."""
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self._is_ce_post_v512:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        # Replace logger methods with patched versions
        self.logger.error = patched_error

    def _get_storage(self) -> Dict:
        """Get storage object.

        Returns:
            Dict: Storage object.
        """
        storage = self.storage if self.storage is not None else {}
        return storage

    def _validate_parameters(
        self,
        parameter_type: Literal["configuration", "action"],
        field_name: str,
        field_value: Union[str, int, List],
        field_type: Type,
        allowed_values: Union[Set, List] = None,
        custom_validation_func: Callable = None,
        should_strip_str: bool = True,
    ):
        """
        Validate the plugin parameters.

        Args:
            parameter_type (Literal["configuration", "action"]): Type of
                parameter.
            field_name (str): Name of the field.
            field_value (Union[str, int, List]): Value of the field.
            field_type (Type): Type of the field.
            allowed_values (Set, optional): List of allowed values. Defaults
                to None.
            custom_validation_func (Callable, optional): Custom validation
                function. Defaults to None.

        Returns:
            ValidationResult: ValidationResult object.
        """
        if isinstance(field_value, str) and should_strip_str:
            field_value = field_value.strip()
        if not field_value:
            err_msg = EMPTY_ERROR_MESSAGE.format(
                field_name=field_name, parameter_type=parameter_type
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} {err_msg}"
                ),
                resolution=(
                    "Ensure that some value is provided for field"
                    f" {field_name}."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(field_value, field_type) or (
            custom_validation_func and not custom_validation_func(field_value)
        ):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} {err_msg}"
                ),
                resolution=(
                    f"Ensure that a valid value is provided for {field_name}"
                    " field."
                )
            )
            return ValidationResult(success=False, message=err_msg)
        if allowed_values and field_value not in allowed_values:
            allowed_values_str = ", ".join(
                f"'{allowed_value}'" for allowed_value in allowed_values
            )
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            )
            err_msg += INVALID_VALUE_ERROR_MESSAGE.format(
                allowed_values=allowed_values_str
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} {err_msg}"
                ),
                resolution=(
                    "Ensure that a valid value is provided from the allowed"
                    f" values.\nAllowed values: {allowed_values_str}"
                )
            )
            return ValidationResult(success=False, message=err_msg)

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with
            success flag and message.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration parameters."
        )
        base_url, public_token, private_token, source, is_pull_enabled = (
            self.darktrace_helper.get_configuration_parameters(
                configuration=configuration
            )
        )

        # Validate Base URL
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Base URL",
            field_value=base_url,
            field_type=str,
            custom_validation_func=self.darktrace_helper.validate_url
        ):
            return validation_result

        # Validate Public Token
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Public Token",
            field_value=public_token,
            field_type=str,
            should_strip_str=False,
        ):
            return validation_result

        # Validate Private Token
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Private Token",
            field_value=private_token,
            field_type=str,
            should_strip_str=False,
        ):
            return validation_result

        # Validate Enable Polling
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Enable Polling",
            field_value=is_pull_enabled,
            field_type=str,
            allowed_values=["Yes", "No"],
        ):
            return validation_result

        # Validate Source Name and test connectivity with
        sources_on_darktrace = self._fetch_source_names(
            configuration=configuration,
            is_validation=True,
            context={}
        )
        if isinstance(sources_on_darktrace, ValidationResult):
            return sources_on_darktrace

        # Validate Source Name only when Enable Polling is set to Yes
        if is_pull_enabled == "Yes":
            if validation_result := self._validate_parameters(
                parameter_type="configuration",
                field_name="Source Name",
                field_value=source,
                field_type=str,
                allowed_values=sources_on_darktrace,
            ):
                return validation_result

        return ValidationResult(
            success=True,
            message=(
                f"Successfully validated connectivity with {PLATFORM_NAME}"
                " platform."
            ),
        )

    @exception_handler
    def _fetch_source_names(
        self,
        configuration: Dict,
        is_validation: bool = False,
        context: Dict = {},
    ) -> Set[str]:
        """Fetch available Darktrace intel feed source names.

        Args:
            configuration (Dict): Plugin configuration parameters.
            is_validation (bool, optional): Whether called during validation
                to tailor error handling. Defaults to False.
            context (Dict, optional): Context dictionary to enrich log
                messages. Defaults to {}.

        Returns:
            Set[str]: Set of source names available on Darktrace, or a
            ValidationResult when invoked in validation mode and an error
            occurs.
        """
        base_url, public_token, private_token, _, _ = (
            self.darktrace_helper.get_configuration_parameters(
                configuration=configuration
            )
        )
        if is_validation:
            logger_msg = (
                f"validating connectivity with {PLATFORM_NAME} platform"
            )
        else:
            logger_msg = "fetching Intel Feed source names"
        context["logger_msg"] = logger_msg
        endpoint = f"{INTELFEED_API_ENDPOINT}?sources=true"
        headers = self.darktrace_helper.get_auth_headers(
            public_token=public_token,
            private_token=private_token,
            endpoint=endpoint,
            query_parameters=None,
            request_body={},
            method="GET",
        )
        try:
            response = self.darktrace_helper.api_helper(
                logger_msg=logger_msg,
                url=f"{base_url}{endpoint}",
                method="GET",
                headers=headers,
                params={},
                data=None,
                json=None,
                proxy=self.proxy,
                verify=self.ssl_validation,
                is_handle_error_required=True,
                is_validation=is_validation,
                is_retraction=False,
            )
            sources = set()
            for source_name in response:
                if source_name:
                    sources.add(source_name)
            if is_validation:
                self.logger.debug(
                    f"{self.log_prefix}: Successfully validated connectivity"
                    f" with {PLATFORM_NAME} platform."
                )
            return sources
        except DarktracePluginException as err:
            err_msg = (
                f"Error occurred while {logger_msg}. Error: {err}."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            if is_validation:
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            else:
                raise
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
                f" Error: {err}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            if is_validation:
                return ValidationResult(
                    success=False,
                    message=f"{err_msg} Check logs for more details.",
                )
            else:
                raise DarktracePluginException(err)

    def determine_ioc_type(
        self, ioc_value, is_hostname: bool
    ) -> Literal["hostname", "ipv4", "ipv6", "domain", "fqdn", "url"]:
        """Determine indicator type based on value and hostname hint.

        Args:
            ioc_value (str): Indicator value to classify.
            is_hostname (bool): Flag indicating Darktrace hostname field.

        Returns:
            Literal["hostname", "ipv4", "ipv6", "domain", "fqdn", "url"]:
            Derived indicator type.
        """
        if is_hostname:
            return "hostname"
        try:
            ip = ip_address(ioc_value)
            if isinstance(ip, IPv4Address):
                return "ipv4"
            if isinstance(ip, IPv6Address):
                return "ipv6"
        except Exception:
            pass
        fqdn = re.fullmatch(FQDN_REGEX, ioc_value)
        if fqdn:
            return "fqdn"
        domain = re.fullmatch(DOMAIN_REGEX, ioc_value)
        if domain:
            return "domain"
        domain = re.fullmatch(DOMAIN_REGEX_2, ioc_value)
        if domain:
            return "domain"
        else:
            return "url"

    def _pull(
        self,
        is_retraction: bool = False,
        context: Dict = {},
    ) -> Generator[
        Union[Set[str], Tuple[List[Indicator], Dict]],
        None,
        None,
    ]:
        """Pull indicators or retractions from Darktrace intel feed.

        Args:
            is_retraction (bool, optional):
                When True, fetch modified indicators for retraction.
                Defaults to False.
            context (Dict, optional):
                Context dictionary for logging. Defaults to {}.

        Yields:
            Generator[
                Union[Set[str], Tuple[List[Indicator], Dict]],
                None,
                None,
            ]: Sets of indicator values when processing retractions.
                Otherwise tuples of indicator batches and an empty
                context dict.
        """
        base_url, public_token, private_token, source, _ = (
            self.darktrace_helper.get_configuration_parameters(
                configuration=self.configuration
            )
        )
        modified_logger = "modified " if is_retraction else ""
        logger_msg = (
            f"fetching {modified_logger}indicators from Intel Feed"
            f" source {source}"
        )
        context["logger_msg"] = logger_msg
        endpoint = f"{INTELFEED_API_ENDPOINT}?source={source}&fulldetails=true"
        headers = self.darktrace_helper.get_auth_headers(
            public_token=public_token,
            private_token=private_token,
            endpoint=endpoint,
            query_parameters=None,
            request_body={},
            method="GET",
        )
        response = self.darktrace_helper.api_helper(
            logger_msg=logger_msg,
            url=f"{base_url}{endpoint}",
            method="GET",
            headers=headers,
            params={},
            proxy=self.proxy,
            verify=self.ssl_validation,
            is_handle_error_required=True,
            is_validation=False,
            is_retraction=is_retraction,
        )
        checkpoint_counter = 0
        indicators = set() if is_retraction else []
        ioc_counts = {
            "hostname": 0,
            "ipv4": 0,
            "ipv6": 0,
            "domain": 0,
            "url": 0,
            "fqdn": 0,
        }
        total_success = 0
        total_skip = 0
        batch_success = 0
        for ioc_data in response:
            ioc_description = ioc_data.get("description", "")
            if f"{SOURCE_LABEL} |" in ioc_description:
                total_skip += 1
                continue
            ioc_value = ioc_data.get("name")
            ioc_values = ioc_value.split(",")
            for ioc_value in ioc_values:
                try:
                    if not ioc_value:
                        total_skip += 1
                        continue
                    ioc_type = self.determine_ioc_type(
                        ioc_value=ioc_value,
                        is_hostname=ioc_data.get("hostname", False)
                    )
                    # Default value is kept as 50 because the normalization
                    # function will normalize it to 5 which is default value
                    # set by core
                    ioc_confidence = int(ioc_data.get("strength", 50))
                    if is_retraction:
                        indicators.add(ioc_value)
                    else:
                        indicator_obj = Indicator(
                            value=ioc_value,
                            type=DARKTRACE_TO_INTERNAL_TYPE.get(ioc_type),
                            comments=(
                                f"{ioc_description}\nStrength: {ioc_confidence}"
                            ),
                            reputation=(
                                self.darktrace_helper.calculate_ce_reputation(
                                    value=ioc_confidence
                                )
                            ),
                        )
                        indicators.append(indicator_obj)
                    ioc_counts[ioc_type] += 1
                    checkpoint_counter += 1
                    if checkpoint_counter >= INDICATOR_LIST_LIMIT:
                        batch_success = sum(ioc_counts.values())
                        total_success += batch_success
                        self.logger.info(
                            f"{self.log_prefix}: Fetched {batch_success}"
                            f" {modified_logger}indicator(s) from"
                            f" Watched Domains and IPs page of the"
                            f" {PLATFORM_NAME} platform. Pull Stats: "
                            f"Domains: {ioc_counts.get('domain')}, "
                            f"FQDN: {ioc_counts.get('fqdn')}, "
                            f"IPv4: {ioc_counts.get('ipv4')}, "
                            f"IPv6: {ioc_counts.get('ipv6')}, "
                            f"Hostnames: {ioc_counts.get('hostname')}, "
                            f"URLs: {ioc_counts.get('url')}. "
                            f"Total {modified_logger}indicator(s) fetched"
                            f" - {total_success}."
                        )
                        ioc_counts = {
                            "hostname": 0,
                            "ipv4": 0,
                            "ipv6": 0,
                            "domain": 0,
                            "url": 0,
                            "fqdn": 0
                        }
                        if is_retraction:
                            yield indicators
                        else:
                            yield indicators, {}
                        indicators = set() if is_retraction else []
                        checkpoint_counter = 0
                except Exception as err:
                    total_skip += 1
                    self.logger.error(
                        f"{self.log_prefix}: Failed to create indicator object"
                        f" for {ioc_value}. Error: {err}"
                    )
                    continue
        if indicators:
            batch_success = sum(ioc_counts.values())
            total_success += batch_success
            self.logger.info(
                f"{self.log_prefix}: Fetched {batch_success}"
                f" {modified_logger}indicator(s) from"
                f" Watched Domains and IPs page of the {PLATFORM_NAME}"
                " platform. Pull Stats: "
                f"Domains: {ioc_counts.get('domain')}, "
                f"FQDN: {ioc_counts.get('fqdn')}, "
                f"IPv4: {ioc_counts.get('ipv4')}, "
                f"IPv6: {ioc_counts.get('ipv6')}, "
                f"Hostnames: {ioc_counts.get('hostname')}, "
                f"URLs: {ioc_counts.get('url')}. "
                f"Total {modified_logger}indicator(s) fetched"
                f" - {total_success}."
            )
            if is_retraction:
                yield indicators
            else:
                yield indicators, {}
        final_logger = (
            f"Successfully fetched {total_success} {modified_logger}"
            f"indicator(s) from Watched Domains and IPs page of "
            f"{PLATFORM_NAME} platform."
        )
        if total_skip > 0:
            final_logger += (
                f" Skipped fetching {total_skip} {modified_logger}"
                f"indicator(s) as they were of invalid type or"
                " were shared from Cloud Exchange."
            )
        self.logger.info(
            f"{self.log_prefix}: {final_logger}"
        )

    def pull(self) -> List[Indicator]:
        """Fetch indicators when polling is enabled.

        Returns:
            List[Indicator]: List of fetched indicators when polling is
            enabled, an empty list when disabled, or a generator when
            sub-checkpointing is supported by the host environment.
        """
        *_, is_pull_enabled = (
            self.darktrace_helper.get_configuration_parameters(
                configuration=self.configuration
            )
        )
        if is_pull_enabled == "Yes":
            if hasattr(self, "sub_checkpoint"):

                def wrapper(self):
                    yield from self._pull()

                return wrapper(self)
            else:
                indicators = []
                for batch, _ in self._pull():
                    indicators.extend(batch)
                self.logger.info(
                    f"Successfully fetched {len(indicators)} indicator(s) "
                    f"from {PLATFORM_NAME}."
                )
                return indicators
        else:
            self.logger.info(
                f"{self.log_prefix}: Polling is disabled in configuration "
                "parameter hence skipping pulling of indicators from "
                f"{PLATFORM_NAME}."
            )
            return []

    @exception_handler
    def get_modified_indicators(
        self,
        source_indicators: List[List[Indicator]]
    ) -> Generator[Tuple[set, bool], None, None]:
        """Get all modified indicators status.

        Args:
            source_indicators (List[List[Dict]]): Source Indicators.

        Yields:
            tuple: Modified Indicators and Status.
        """
        self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        self.logger.info(
            f"{self.log_prefix}: Getting all modified indicators status"
            f" from Watched Domains and IPs page of {PLATFORM_NAME} platform."
        )
        modified_ioc_batches = []
        for modified_iocs in self._pull(is_retraction=True, context={}):
            modified_ioc_batches.append(modified_iocs)

        for ioc_list in source_indicators:
            source_iocs = set()
            for ioc in ioc_list:
                source_iocs.add(ioc.value)
            source_ioc_len = len(source_iocs)
            for modified_iocs in modified_ioc_batches:
                source_iocs = source_iocs - modified_iocs
            self.logger.info(
                f"{self.log_prefix}: {len(source_iocs)}"
                " indicator(s) will be marked as retracted "
                f"from total {source_ioc_len} indicator(s)."
            )
            yield list(source_iocs), False

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Add IOC to Intel Feed Source",
                value="add",
            )
        ]

    @exception_handler
    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        action_value = action.value
        sources = list(
            self._fetch_source_names(
                configuration=self.configuration,
                is_validation=False,
                context={},
            )
        )
        if action_value == "add":
            sources.append("Create New Source")
            return [
                {
                    "label": "Source Name",
                    "key": "source",
                    "type": "choice",
                    "choices": [
                        {
                            "key": source_name,
                            "value": source_name,
                        }
                        for source_name in sources
                    ],
                    "default": sources[0],
                    "mandatory": True,
                    "description": (
                        "Intel feed source name where IOC are to be"
                        f" {action_value}ed."
                    ),
                },
                {
                    "label": "Custom Source",
                    "key": "custom_source",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Name of the custom source to create if it does not"
                        " exist."
                    ),
                },
                {
                    "label": "Exact Hostnames",
                    "key": "exact_hostnames",
                    "type": "choice",
                    "choices": [
                        {"key": "True", "value": "True"},
                        {"key": "False", "value": "False"},
                    ],
                    "default": "False",
                    "mandatory": True,
                    "description": (
                        "Set to true to treat the added items as hostnames"
                        " rather than domains. Does not apply to IOC of"
                        " type IP."
                    ),
                },
                {
                    "label": "Flag for Response",
                    "key": "iagn",
                    "type": "choice",
                    "choices": [
                        {"key": "True", "value": "True"},
                        {"key": "False", "value": "False"},
                    ],
                    "default": "False",
                    "mandatory": True,
                    "description": (
                        "Enable automatic triggering of a Darktrace Autonomous"
                        " Response Action if the entry is seen."
                    ),
                },
            ]
        else:
            return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate darktrace configuration.

        Args:
            action (Action): Action to perform on IoCs.

        Returns:
            ValidationResult: Validation result.
        """
        action_value = action.value
        if action_value not in ["add"]:
            err_msg = (
                "Unsupported action provided. Plugin only "
                "supports 'Add IOC to Intel Feed Source' actions."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        source_name = action.parameters.get("source")
        custom_source = action.parameters.get("custom_source")
        exact_hostnames = action.parameters.get("exact_hostnames")
        iagn = action.parameters.get("iagn")

        sources_on_darktrace = self._fetch_source_names(
            configuration=self.configuration,
            is_validation=False,
            context={}
        )
        sources_on_darktrace.add("Create New Source")
        if validation_result := self._validate_parameters(
            parameter_type="action",
            field_name="Source Name",
            field_value=source_name,
            field_type=str,
            allowed_values=sources_on_darktrace,
        ):
            return validation_result

        if source_name == "Create New Source":
            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Custom Source",
                field_value=custom_source,
                field_type=str,
            ):
                return validation_result
            sources_on_darktrace = [source.lower() for source in sources_on_darktrace]
            if custom_source.lower() in sources_on_darktrace:
                self.logger.error(
                    f"{self.log_prefix}: Intel Feed Source {custom_source}"
                    " already exists on {PLATFORM_NAME}.",
                    resolution=(
                        f"Source already exists on {PLATFORM_NAME} platform."
                        " Select it directly in the Source Name action"
                        " parameter."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=(
                        f"Intel Feed Source {custom_source} already exists on"
                        f" {PLATFORM_NAME}. Select it directly in the Source"
                        " Name action parameter."
                    ),
                )

        # Validate Exact Hostnames
        if validation_result := self._validate_parameters(
            parameter_type="action",
            field_name="Exact Hostnames",
            field_value=exact_hostnames,
            field_type=str,
            allowed_values=["True", "False"]
        ):
            return validation_result

        # Validate Flag for Response
        if validation_result := self._validate_parameters(
            parameter_type="action",
            field_name="Flag for Response",
            field_value=iagn,
            field_type=str,
            allowed_values=["True", "False"]
        ):
            return validation_result

        log_msg = f"Validation successful for '{action.label}' action."
        self.logger.debug(f"{self.log_prefix}: {log_msg}")
        return ValidationResult(success=True, message=log_msg)

    def expand_ipv6_address(self, ipv6: str) -> str:
        """Return the expanded IPv6 representation if valid.

        Args:
            ipv6 (str): IPv6 address string.

        Returns:
            str: Fully expanded IPv6 address, or the original string if
            parsing fails.
        """
        try:
            return IPv6Address(ipv6).exploded
        except Exception:
            return ipv6

    def process_and_batch(
        self,
        indicator_list: List[Indicator],
        other_types: List[IndicatorType],
        hostname_types: List[IndicatorType],
        batch_size: int,
    ) -> Tuple[Dict, Dict, Set, int]:
        """Group indicators by reputation and batch them for pushing.

        Args:
            indicator_list (List[Indicator]): Indicators to process.
            other_types (List[IndicatorType]): Indicator types treated as
                non-hostname.
            hostname_types (List[IndicatorType]): Indicator types treated as
                hostnames.
            batch_size (int): Maximum batch size per request.

        Returns:
            Tuple[Dict, Dict, Set, int]: Batches for other and hostname types,
            set of skipped invalid types, and total indicators processed.
        """
        # Temporary grouping dictionaries to collect lists before batching
        other = {}
        hostname = {}
        other_group = defaultdict(list)
        hostname_group = defaultdict(list)
        invalid_type_set = set()
        total_iocs = 0

        # Step 1: Filter and Group by Reputation
        for obj in indicator_list:
            total_iocs += 1
            ioc_value = obj.value
            ioc_type = obj.type
            if ioc_type == IndicatorType.URL:
                # If the IOC Type is URL then using regex determine the
                # actual type of the IOC
                ioc_type_str = self.determine_ioc_type(
                    ioc_value=ioc_value,
                    is_hostname=False,
                )
                ioc_type = DARKTRACE_TO_INTERNAL_TYPE.get(ioc_type_str)
            if ioc_type in other_types:
                if ioc_type == IndicatorType.IPV6:
                    # Darktrace does not except compressed IPv6 addresses
                    ioc_value = self.expand_ipv6_address(ioc_value)
                other_group[obj.reputation].append(ioc_value)
            elif ioc_type in hostname_types:
                hostname_group[obj.reputation].append(ioc_value)
            else:
                invalid_type_set.add(ioc_value)
            # Other types are ignored per your requirement

        # Step 2: Batch Type A
        for rep, items in other_group.items():
            other[rep] = {}
            for i in range(0, len(items), batch_size):
                batch_num = (i // batch_size) + 1
                other[rep][batch_num] = items[i : i + batch_size]

        # Step 3: Batch Type B
        for rep, items in hostname_group.items():
            hostname[rep] = {}
            for i in range(0, len(items), batch_size):
                batch_num = (i // batch_size) + 1
                hostname[rep][batch_num] = items[i : i + batch_size]

        return other, hostname, invalid_type_set, total_iocs

    @exception_handler
    def _push(
        self,
        base_url: str,
        public_token: str,
        private_token: str,
        batch_number: int,
        iocs_to_push: List[str],
        is_hostname: bool,
        ioc_reputation: int,
        description: str,
        source_name: str,
        iagn: str,
        context: Dict = {},
    ) -> Tuple[int, int, Set]:
        """Push a batch of indicators to Darktrace intel feed.

        Args:
            base_url (str): Darktrace base URL.
            public_token (str): Public token for authentication.
            private_token (str): Private token for signing requests.
            batch_number (int): Batch sequence number for logging.
            iocs_to_push (List[str]): Indicators to add/update.
            is_hostname (bool): Treat indicators as hostnames when True.
            ioc_reputation (int): CE reputation value to convert to strength.
            description (str): Indicator description/comment.
            source_name (str): Intel feed source name.
            iagn (str): Flag controlling Darktrace Autonomous Response.
            context (Dict, optional): Context dictionary for logging.

        Returns:
            Tuple[int, int, Set]: Counts of successfully processed, failed IOCs
            in this batch and a set of failed IOCs
        """
        failed_set = set()
        iocs_to_push_len = len(iocs_to_push)
        iocs_to_push_str = ','.join([str(ioc) for ioc in iocs_to_push])
        strength = self.darktrace_helper.calculate_darktrace_strength(
            ioc_reputation
        )
        request_body = {
            "addlist": iocs_to_push_str,
            "description": description,
            "source": source_name,
            "strength": strength,
        }
        hostname_logger = ""
        if is_hostname:
            request_body["hostname"] = True
            hostname_logger = "hostname "
        if iagn == "True":
            request_body["iagn"] = True
        logger_msg = (
            f"adding {iocs_to_push_len} {hostname_logger}indicator(s)"
            f" with strength {strength} in batch {batch_number} to"
            f" {PLATFORM_NAME} Intel Feed source {source_name}"
        )
        context["logger_msg"] = logger_msg
        headers = self.darktrace_helper.get_auth_headers(
            public_token=public_token,
            private_token=private_token,
            endpoint=INTELFEED_API_ENDPOINT,
            query_parameters=None,
            request_body=request_body,
            method="POST",
        )
        response = self.darktrace_helper.api_helper(
            logger_msg=logger_msg,
            url=f"{base_url}{INTELFEED_API_ENDPOINT}",
            method="POST",
            headers=headers,
            params={},
            json=request_body,
            proxy=self.proxy,
            verify=self.ssl_validation,
            is_handle_error_required=True,
            is_validation=False,
        )
        added_list = response.get("addedList", [])
        updated_list = response.get("updatedList", [])
        # A source has 4 iocs already present, now when some one calls the
        # push API with 5 iocs (4 already existing + 1 new) the api responds
        # with added = 5 and updated = 4 instead of added = 1 and updated = 4
        # Therefore to maintain the correct count of added and updated IOCS
        # the below set subtraction logic is implemented
        added_ioc_set = set(added_list)
        updated_ioc_set = set(updated_list)
        actual_added = added_ioc_set - updated_ioc_set
        added = len(actual_added)
        updated = len(updated_ioc_set)
        total_success = added + updated
        failed = iocs_to_push_len - total_success
        final_logger = (
            f"Successfully added {added} {hostname_logger}indicator(s),"
            f" updated {updated} {hostname_logger}indicator(s)"
        )
        if failed > 0:
            success_set = set(added_ioc_set).union(updated_ioc_set)
            failed_set = set(iocs_to_push) - success_set
            final_logger += (
                f", failed to share {failed} {hostname_logger}indicator(s)"
            )
        self.logger.info(
            f"{self.log_prefix}: {final_logger} with strength {strength} in"
            f" batch {batch_number} to {PLATFORM_NAME} Intel Feed source"
            f" {source_name}."
        )
        return total_success, failed, failed_set

    def push(
        self,
        indicators: List[Indicator],
        action_dict: Dict,
        source: str = None,
        business_rule: str = None,
        plugin_name: str = None,
    ) -> PushResult:
        """Push indicators to the Darktrace.

        Args:
            indicators (List[Indicator]): List of Indicators
            action_dict (dict): Action dictionary
            source (str): Source configuration name.
            business_rule (str): Business rule name.
            plugin_name (str): Source plugin name.

        Returns:
            PushResult: return PushResult with success and message parameters.
        """
        action_label = action_dict.get("label")
        action_params = action_dict.get("parameters", {})

        self.logger.info(
            f"{self.log_prefix}: Executing push method for "
            f'"{action_label}" target action.'
        )
        base_url, public_token, private_token, _, _ = (
            self.darktrace_helper.get_configuration_parameters(
                configuration=self.configuration
            )
        )
        exact_hostnames = action_params.get("exact_hostnames")
        iagn = action_params.get("iagn")
        source_name = action_params.get("source")
        if source_name == "Create New Source":
            source_name = action_params.get("custom_source")

        other_batch = {}
        hostname_batch = {}
        hostname_types = [IndicatorType.HOSTNAME]
        other_types = [IndicatorType.IPV4, IndicatorType.IPV6]
        domain_types = [IndicatorType.DOMAIN, IndicatorType.FQDN]
        if exact_hostnames == "True":
            hostname_types.extend(domain_types)
        else:
            other_types.extend(domain_types)
        (
            other_batch,
            hostname_batch,
            invalid_type_set,
            total_iocs
        ) = self.process_and_batch(
            indicator_list=indicators,
            other_types=other_types,
            hostname_types=hostname_types,
            batch_size=PUSH_BATCH_SIZE,
        )
        invalid_type_skip = len(invalid_type_set)
        self.logger.info(
            f"{self.log_prefix}: Executing '{action_label}' action for"
            f" {total_iocs - invalid_type_skip} indicator(s)."
            f" {invalid_type_skip} indicator(s) will be skipped as they are"
            " of invalid types."
        )
        description = f"{SOURCE_LABEL} | {plugin_name}"
        success = 0
        failed = 0
        failed_iocs = set()
        for ioc_reputation, ioc_batch in other_batch.items():
            for batch_number, ioc_list in ioc_batch.items():
                try:
                    batch_success, batch_failed, failed_set = self._push(
                        base_url=base_url,
                        public_token=public_token,
                        private_token=private_token,
                        batch_number=int(batch_number),
                        iocs_to_push=ioc_list,
                        is_hostname=False,
                        ioc_reputation=ioc_reputation,
                        description=description,
                        source_name=source_name,
                        iagn=iagn,
                        context={},
                    )
                    success += batch_success
                    failed += batch_failed
                    failed_iocs.update(failed_set)
                except DarktracePluginException as err:
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while pushing"
                        f" indicators for batch {batch_number}: {err}"
                    )
                    failed += len(ioc_list)
                    failed_iocs.update(ioc_list)
                    continue
                except Exception as err:
                    self.logger.error(
                        f"{self.log_prefix}: {err}."
                    )
                    failed += len(ioc_list)
                    failed_iocs.update(ioc_list)
                    continue

        for ioc_reputation, ioc_batch in hostname_batch.items():
            for batch_number, ioc_list in ioc_batch.items():
                try:
                    batch_success, batch_failed, failed_set = self._push(
                        base_url=base_url,
                        public_token=public_token,
                        private_token=private_token,
                        batch_number=int(batch_number),
                        iocs_to_push=ioc_list,
                        is_hostname=True,
                        ioc_reputation=ioc_reputation,
                        description=description,
                        source_name=source_name,
                        iagn=iagn,
                        context={},
                    )
                    success += batch_success
                    failed += batch_failed
                    failed_iocs.update(failed_set)
                except DarktracePluginException as err:
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while pushing"
                        f" hostname indicators for batch {batch_number}: {err}"
                    )
                    failed += len(ioc_list)
                    failed_iocs.update(ioc_list)
                    continue
                except Exception as err:
                    self.logger.error(
                        f"{self.log_prefix}: {err}."
                    )
                    failed += len(ioc_list)
                    failed_iocs.update(ioc_list)
                    continue

        success_logger = (
            f"Successfully added {success} indicator(s) to {PLATFORM_NAME}"
            f" Intel Feed source {source_name}."
        )
        failed_logger = (
            f"Failed to add {failed} indicator(s) to {PLATFORM_NAME} Intel"
            f" Feed source {source_name}."
        )
        self.logger.info(
            f"{self.log_prefix}: {success_logger}"
        )
        if failed > 0:
            self.logger.info(
                f"{self.log_prefix}: {failed_logger}"
            )
        failed_iocs_list = list(failed_iocs.union(invalid_type_set))
        return PushResult(
            success=True,
            message=f"Successfully executed {action_label} action.",
            failed_iocs=failed_iocs_list
        )

    def _retract_indicator(
        self,
        base_url: str,
        public_token: str,
        private_token: str,
        ioc_value: str,
        source_name: str,
        success: int,
        failed: int,
    ):
        """Retract a single indicator from a Darktrace source.

        Args:
            base_url (str): Darktrace base URL.
            public_token (str): Public token for authentication.
            private_token (str): Private token for signing requests.
            ioc_value (str): Indicator value to remove.
            source_name (str): Intel feed source name.
            success (int): Current success counter.
            failed (int): Current failed counter.

        Returns:
            Tuple[int, int]: Updated success and failed counters.
        """
        logger_msg = (
            f"deleting indicator {ioc_value} from {PLATFORM_NAME} Intel"
            f" Feed source {source_name}"
        )
        request_body = {
            "removeentry": ioc_value,
            "source": source_name
        }
        headers = self.darktrace_helper.get_auth_headers(
            public_token=public_token,
            private_token=private_token,
            endpoint=INTELFEED_API_ENDPOINT,
            query_parameters=None,
            request_body=request_body,
            method="POST",
        )
        try:
            self.darktrace_helper.api_helper(
                logger_msg=logger_msg,
                url=f"{base_url}{INTELFEED_API_ENDPOINT}",
                method="POST",
                headers=headers,
                params={},
                json=request_body,
                proxy=self.proxy,
                verify=self.ssl_validation,
                is_handle_error_required=True,
                is_validation=False,
            )
            success += 1
        except DarktracePluginException as err:
            self.logger.error(
                f"Error occurred while {logger_msg}. Error: {err}."
            )
            failed += 1
        except Exception as err:
            self.logger.error(
                f"Unexpected error occurred while {logger_msg}. Error: {err}."
            )
            failed += 1
        return success, failed

    def retract_indicators(
        self,
        retracted_indicators_lists: List[List[Indicator]],
        list_action_dict: List[Action],
    ) -> Generator[ValidationResult, None, None]:
        """Retract/Delete Indicators from Darktrace Watched Domains
        and IPs page.

        Args:
            retracted_indicators_lists (List[List[Indicator]]):
                Retract indicators list
            list_action_dict (List[Action]): List of action dict

        Yields:
            ValidationResult: Validation result.
        """
        self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        self.logger.info(
            f"{self.log_prefix}: Starting retraction of indicator(s) "
            f"from Watched Domains and IPs page of {PLATFORM_NAME} platform."
        )
        base_url, public_token, private_token, _, _ = (
            self.darktrace_helper.get_configuration_parameters(
                configuration=self.configuration
            )
        )
        configured_action_source_names = []
        for action in list_action_dict:
            action_source_name = action.parameters.get("source")
            if not action_source_name:
                continue
            if action_source_name == "Create New Source":
                custom_source = action.parameters.get("custom_source")
                if not custom_source:
                    continue
                configured_action_source_names.append(custom_source)
                continue
            configured_action_source_names.append(action_source_name)
        success = 0
        failed = 0
        skipped = 0
        for ioc_list in retracted_indicators_lists:
            for ioc_obj in ioc_list:
                ioc_value = ioc_obj.value
                ioc_type = ioc_obj.type
                if ioc_type == IndicatorType.URL:
                    # If the IOC Type is URL then using regex determine the
                    # actual type of the IOC
                    ioc_type_str = self.determine_ioc_type(
                        ioc_value=ioc_value,
                        is_hostname=False,
                    )
                    ioc_type = DARKTRACE_TO_INTERNAL_TYPE.get(ioc_type_str)
                if ioc_type not in [
                    IndicatorType.HOSTNAME,
                    IndicatorType.DOMAIN,
                    IndicatorType.FQDN,
                    IndicatorType.IPV4,
                    IndicatorType.IPV6,
                ]:
                    skipped += 1
                    continue
                if ioc_type == IndicatorType.IPV6:
                    ioc_value = self.expand_ipv6_address(ioc_value)
                for source_name in configured_action_source_names:
                    success, failed = self._retract_indicator(
                        base_url=base_url,
                        public_token=public_token,
                        private_token=private_token,
                        ioc_value=ioc_value,
                        source_name=source_name,
                        success=success,
                        failed=failed,
                    )
        success_logger = (
            f"Successfully deleted {success} indicator(s) across "
            f"{len(configured_action_source_names)} {PLATFORM_NAME} Intel"
            " Feed source(s)."
        )
        if skipped > 0:
            success_logger += (
                f" Skipped deleting {skipped} indicator(s) as they"
                f" are not supported by {PLATFORM_NAME} platform."
            )
        self.logger.info(f"{self.log_prefix}: {success_logger}")
        if failed > 0:
            self.logger.info(
                f"{self.log_prefix}: Failed to delete {failed} indicator(s)"
                f" across {len(configured_action_source_names)}"
                f" {PLATFORM_NAME} Intel Feed source(s) from as they were"
                " not present on the Intel Feed source or were of invalid"
                " type."
            )
        yield ValidationResult(
            success=True,
            message=(
                f"Successfully deleted retracted IOCs from {PLATFORM_NAME}"
                " platform."
            )
        )
