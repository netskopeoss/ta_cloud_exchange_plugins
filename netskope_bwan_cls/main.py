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

CLS Netskope Borderless plugin.
"""

import traceback
from typing import List

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)

from .utils.constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    EVENT_TYPES,
    ALERT_TYPES,
)

# from netskope.common.utils import DBConnector, AlertsHelper
from netskope.common.utils.alerts_helper import AlertsHelper
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper

helper = AlertsHelper()
plugin_provider_helper = PluginProviderHelper()


class NetskopeBWANCLSPlugin(PluginBase):
    """The Netskope Borderless WAN CLS plugin implementation class."""

    def __init__(
        self,
        name,
        configuration,
        storage,
        last_run_at,
        logger,
        use_proxy=False,
        ssl_validation=True,
        source=None,
        mappings=None,
    ):
        """Initialize."""
        super().__init__(
            name,
            configuration,
            storage,
            last_run_at,
            logger,
            use_proxy,
            ssl_validation,
            source=source,
            mappings=mappings,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = NetskopeBWANCLSPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLUGIN_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform."""
        pass

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw Netskope JSON data into target platform \
        supported data formats."""
        pass

    def get_types_to_pull(self, data_type):
        """Get the types of data to pull.

        Returns:
            List of sub types to pull
        """
        if data_type == "events":
            return self.configuration.get("events_types", [])
        elif data_type == "alerts":
            return self.configuration.get("alert_types", [])
        return []

    def validate(
        self, configuration: dict, tenant_name=None
    ) -> ValidationResult:
        """Validate the configuration parameters dict."""

        event_types = configuration.get("events_types", [])
        alert_types = configuration.get("alert_types", [])
        if not event_types and not alert_types:
            err_msg = (
                "At least one Event Type or Alert Type is required in the "
                "configuration parameters."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if event_types and (not isinstance(event_types, list) or not (
            all(
                indicator_type in EVENT_TYPES
                for indicator_type in event_types
            )
        )):
            error_msg = (
                "Invalid Event Types provided in the "
                "configuration parameters. Please select the "
                "Event Types from the available options."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                f"{error_msg}",
            )
            return ValidationResult(success=False, message=error_msg)

        if alert_types and (not isinstance(alert_types, list) or not (
            all(
                indicator_type in ALERT_TYPES
                for indicator_type in alert_types
            )
        )):
            error_msg = (
                "Invalid Alert Types provided in the "
                "configuration parameters. Please select the "
                "Alert Types from the available options."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                f"{error_msg}",
            )
            return ValidationResult(success=False, message=error_msg)

        hours = configuration.get("hours", 0)
        # 'hours' is the Initial Range for Events, so it is validated only
        # when at least one Event Type is selected (Event Types is optional).
        if event_types:
            if hours is None:
                err_msg = (
                    "Initial Range for Events (in hours) is a required "
                    "configuration parameter."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            # bool is a subclass of int, so exclude it explicitly: True/False
            # must not pass as 1/0.
            elif isinstance(hours, bool) or not isinstance(hours, int):
                err_msg = (
                    "Invalid Initial Range for Events (in hours) provided "
                    "in the configuration parameters."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif hours < 0 or hours > 8760:
                err_msg = (
                    "Invalid Initial Range for Events (in hours) provided "
                    "in the configuration parameters. The value should be "
                    "in range 0 to 8760."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

        days = configuration.get("days", 0)
        # 'days' is the Initial Range for Alerts, so it is validated only
        # when at least one Alert Type is selected (Alert Types is optional).
        if alert_types:
            if days is None:
                err_msg = (
                    "Initial Range for Alerts (in days) is a required "
                    "configuration parameter."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            # bool is a subclass of int, so exclude it explicitly: True/False
            # must not pass as 1/0.
            elif isinstance(days, bool) or not isinstance(days, int):
                err_msg = (
                    "Invalid Initial Range for Alerts (in days) provided "
                    "in the configuration parameters."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif days < 0 or days > 365:
                err_msg = (
                    "Invalid Initial Range for Alerts (in days) provided "
                    "in the configuration parameters. The value should be "
                    "in range 0 to 365."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

        if not tenant_name:
            tenant = helper.get_tenant_cls(self.name)
            if not tenant:
                err_msg = (
                    "Unable to resolve the Netskope Borderless WAN Tenant "
                    "for this configuration."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            tenant_name = tenant.name

        # Verify the Auth Token can read the selected dedicated endpoints
        # (Monitor > Flows and Alerts (V2)). The tenant's validate_token only
        # probes /v2/auditevents, so without this a token missing those
        # permissions would pass validation and then fail silently at pull
        # time (and, with the per-subtype isolation, be skipped).
        try:
            provider = plugin_provider_helper.get_provider(
                tenant_name=tenant_name
            )
            provider.permission_check(
                {"events": event_types, "alerts": alert_types},
                plugin_name=self.plugin_name,
                configuration_name=self.name,
            )
        except Exception as exp:
            return ValidationResult(success=False, message=str(exp))

        return ValidationResult(success=True, message="Validation successful.")
