"""Netskope Plugin."""
import traceback
import inspect
from typing import List, Literal

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)

from netskope.common.utils import DBConnector, AlertsHelper
from netskope.common.utils.alerts_helper import AlertsHelper
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper

from .utils.netskope_cls_constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION
)

helper = AlertsHelper()

connector = DBConnector()
alerts_helper = AlertsHelper()
plugin_provider_helper = PluginProviderHelper()


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
        # Validate alert types and event types
        if (
            "event_type" not in configuration
            or type(configuration["event_type"]) is not list
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Invalid Event Types found in the configuration parameters.",
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
                "Invalid Alert Types found in the configuration parameters.",
                error_code="CLS_1016",
            )
            return ValidationResult(
                success=False, message="Invalid alert type provided."
            )

        if not configuration["event_type"] and not configuration.get("alert_types"):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Event Types and Alert Types both can not be empty.",
                error_code="CLS_1017",
            )
            return ValidationResult(
                success=False,
                message="Event Types and Alert Types both can not be empty.",
            )
        # Validate initial range for events
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
        # Validate initial range for alerts
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
        
        # Validate incident_forensics
        incident_forensics = configuration.get("incident_forensics", "")
        if (
            not isinstance(incident_forensics, str) 
            or not incident_forensics
            or incident_forensics not in ["yes", "no"]
        ):
            err_msg = (
                "Invalid DLP Incident Forensics option "
                "provided in configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not tenant_name:
            tenant_name = helper.get_tenant_cls(self.name).name

        # Get the tenant configuration if self.name exists  - not the first plugin save
        tenant_configuration = {}
        try:
            tenant_configuration = helper.get_tenant_cls(self.name).parameters
        except Exception as e:
            tenant_configuration = {}
        provider = plugin_provider_helper.get_provider(tenant_name=tenant_name)
        type_map = {
            "events": configuration.get("event_type", []),
            "alerts": configuration.get("alert_types", []),
        }

        modified_type_map = type_map.copy()
        if "events" in modified_type_map and "clientstatus" in modified_type_map.get("events", []):
            try:
                provider.client_status_validation()
                modified_type_map["events"] = [
                    event_type
                    for event_type in modified_type_map.get("events", [])
                    if event_type != "clientstatus"
                ]
            except Exception as e:
                return ValidationResult(success=False, message=str(e))
        elif tenant_configuration:
            try:
                cleanup_params = inspect.signature(provider.cleanup).parameters
                cleanup_kwargs = {'is_validation': True} if 'is_validation' in cleanup_params else {}
            except Exception as e:
                cleanup_kwargs = {}

            provider.cleanup(tenant_configuration, **cleanup_kwargs)

        # use the modified_type_map for the permission check
        provider.permission_check(
            modified_type_map,
            plugin_name=self.plugin_name,
            configuration_name=self.name,
        )

        # If all validations are successful, update tenant storage with incident 
        # enrichment option
        provider.update_incident_enrichment_option_to_storage(
            tenant_name=tenant_name,
            module_name="cls",
            plugin_name=self.name,
            incident_enrichment_option=incident_forensics,
            operation="set",
        )

        return ValidationResult(success=True, message="Validation successful.")

    def cleanup(self, action_type: str):
        """Unsert Incident option"""
        tenant_name = helper.get_tenant_cls(self.name).name
        provider = plugin_provider_helper.get_provider(
            tenant_name=tenant_name
        )

        provider.update_incident_enrichment_option_to_storage(
            tenant_name=tenant_name,
            module_name="cls",
            plugin_name=self.name,
            incident_enrichment_option="no",
            operation="unset",
        )
