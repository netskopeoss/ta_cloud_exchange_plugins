"""Netskope Plugin."""
import traceback
from typing import List

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)

from netskope.common.utils import DBConnector, AlertsHelper
from netskope.common.utils.alerts_helper import AlertsHelper
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper

helper = AlertsHelper()

connector = DBConnector()
alerts_helper = AlertsHelper()
plugin_provider_helper = PluginProviderHelper()

MODULE_NAME = "CLS"
PLUGIN_NAME = "Netskope CLS"
PLUGIN_VERSION = "2.0.0"


class NetskopeCLSPlugin(PluginBase):
    """The Netskope CLS plugin implementation class."""

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
            manifest_json = NetskopeCLSPlugin.metadata
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
        """Transform the raw netskope JSON data into target platform supported data formats."""
        pass

    def get_types_to_pull(self, data_type):
        """Get the types of data to pull.

        Returns:
            List of sub types to pull
        """
        if data_type == "alerts":
            return self.configuration.get("alert_types", [])
        else:
            return self.configuration.get("event_type", [])

    def validate(self, configuration: dict, tenant_name=None) -> ValidationResult:
        """Validate the configuration parameters dict."""
        if (
            "event_type" not in configuration
            or type(configuration["event_type"]) is not list
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Invalid event type found in the configuration parameters.",
                error_code="CLS_1016",
            )
            return ValidationResult(
                success=False, message="Invalid event type provided."
            )

        if (
            "alert_types" not in configuration
            or type(configuration["alert_types"]) is not list
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Invalid alert types found in the configuration parameters.",
                error_code="CLS_1016",
            )
            return ValidationResult(
                success=False, message="Invalid alert type provided."
            )

        if not configuration["event_type"] and not configuration.get("alert_types"):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Event types and alert types both can not be empty.",
                error_code="CLS_1017",
            )
            return ValidationResult(
                success=False,
                message="Event types and alert types both can not be empty.",
            )

        hours = configuration.get("hours")
        if hours is None:
            err_msg = "Initial Range for Events is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(hours, int):
            err_msg = (
                "Invalid Initial Range for Events provided in configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif hours < 0 or hours > 8760:
            err_msg = (
                "Invalid Initial Range for Events provided in configuration"
                " parameters. Valid value should be in range 0 to 8760."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range for Alerts is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(days, int):
            err_msg = (
                "Invalid Initial Range for Alerts provided in configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif days < 0 or days > 365:
            err_msg = (
                "Invalid Initial Range for Alerts provided in configuration"
                " parameters. Valid value should be in range 0 to 365."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not tenant_name:
            tenant_name = helper.get_tenant_cls(self.name).name
        provider = plugin_provider_helper.get_provider(tenant_name=tenant_name)
        type_map = {
            'events': configuration['event_type'],
            'alerts': configuration['alert_types'],
        }
        provider.permission_check(type_map, plugin_name=self.plugin_name, configuration_name=self.name)

        return ValidationResult(success=True, message="Validation successful.")
