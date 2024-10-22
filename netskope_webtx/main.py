"""Netskope Plugin."""
import requests
import traceback
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper
from netskope.common.utils import Notifier

plugin_provider_helper = PluginProviderHelper()
notifier = Notifier()
HOURS = 1
WEBTX_METRICS_URL = "{}/api/v2/events/metrics/transactionevents"

MODULE_NAME = "CLS"
PLUGIN_NAME = "Netskope Webtx"
PLUGIN_VERSION = "2.0.0"

class NetskopeWebtxPlugin(PluginBase):
    """The Netskope CLS plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize AmazonSecurityLakePlugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.error_banner_id = f"BANNER_ERROR_9999_{self.name.replace(' ', '_').upper()}"

    def _validate_metrics_api_permission(self, tenant_name, v2token, user_agent, forbidden_endpoints):
        """Validate metrics api permission."""
        try:
            url = WEBTX_METRICS_URL.format(tenant_name)
            headers = {
                "Netskope-Api-Token": v2token,
                **user_agent
            }
            response = requests.get(url, headers=headers, params={"hours": HOURS})
            if response.status_code in [200, 409]:
                self.cleanup()
                return True
            elif response.status_code == 401:
                self.logger.error(
                    message="{}: Incorrect tenant name/API token provided.".format(self.log_prefix),
                    error_code="CLS_1029",
                )
                return ValidationResult(
                    success=False, message="Incorrect tenant name/API token provided.",
                )
            elif response.status_code == 403:
                self.logger.error(
                    message="{}: Please add permission for endpoint '/api/v2/events/metrics/transactionevents' to v2 token.".format(self.log_prefix),
                    error_code="CLS_1028",
                )
                forbidden_endpoints.append("/api/v2/events/metrics/transactionevents")
                return False
            else:
                self.logger.error(
                    message="{}: Received status code {} from Netskope Tenant. please try after some time.".format(self.log_prefix, response.status_code),
                    error_code="CLS_1027",
                    details=response.text,
                )
                return ValidationResult(
                    success=False, message=f'Received status code {response.status_code} from Netskope Tenant. please try after some time.'
                )
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix} error occured while validating metrics api permissions, {e}", 
                error_code="CLS_1026",
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False, message=f'error occured while validating metrics api permissions, {e}.'
            )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = NetskopeWebtxPlugin.metadata
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

    def get_types_to_pull(self, data_type):
        """Get the types of data to pull.

        Returns:
            List of sub types to pull
        """
        return []

    def validate(self, configuration: dict, tenant_name=None) -> ValidationResult:
        """Validate the configuration parameters dict."""
        tenant = plugin_provider_helper.get_tenant_details(
            tenant_name
        )
        from netskope.common.utils import resolve_secret, add_user_agent
        from netskope_api.iterator.const import Const
        from netskope_api.token_management.netskope_management import NetskopeTokenManagement
        v2token = resolve_secret(tenant["parameters"].get("v2token"))
        params = {
            Const.NSKP_TOKEN: v2token,
            Const.NSKP_TENANT_HOSTNAME: tenant["parameters"]
            .get("tenantName")
            .removeprefix("https://"),
            Const.NSKP_USER_AGENT: add_user_agent({}).get("User-Agent"),
        }
        token_management = NetskopeTokenManagement(params)
        token_management_response = token_management.get()
        forbidden_endpoints = []
        if(token_management_response.get("ok") == 1):
            pass
        elif(token_management_response.get("status") == 401):
            self.logger.error(
                message="{}: Incorrect tenant name/API token provided.".format(self.log_prefix),
            )
            return ValidationResult(
                success=False, message="Incorrect tenant name/API token provided."
            )
        elif(token_management_response.get("status") == 403):
            self.logger.error(
                message="{}: Please add permission for endpoint '/api/v2/events/token/transaction_events' to v2 token.".format(self.log_prefix)
            )
            forbidden_endpoints.append("/api/v2/events/token/transaction_events")
        elif(token_management_response.get("status") == 429):
            self.logger.error(
                message="{}: Received status code {} from Netskope Tenant for url "
                "/api/v2/events/token/transaction_events."
                " please try after some time.".format(self.log_prefix, token_management_response.get("status"))
            )
            return ValidationResult(
                success=False,
                message=f'Received status code {token_management_response.get("status")} from Netskope Tenant for url '
                '/api/v2/events/token/transaction_events.'
                ' please try after some time.'
            )
        elif(token_management_response.get("status", 500) >= 500):
            self.logger.error(
                message="{}: Received internal server error from Netskope Tenant. please try after some time.".format(self.log_prefix)
            )
            return ValidationResult(
                success=False, message="Received internal server error from Netskope Tenant. please try after some time."
            )
        else:
            self.logger.error(
                message=(
                    "{}: Error occurred while"
                    "validating tenant. Error: {}".format(
                        self.log_prefix, token_management_response
                    )
                ),
            )
            return ValidationResult(
                success=False, message="Error occurred while validating tenant credentials"
            )
        metrics_api_permission_validation = self._validate_metrics_api_permission(
            tenant["parameters"].get("tenantName"),
            v2token,
            add_user_agent({}),
            forbidden_endpoints
        )
        if forbidden_endpoints:
            message = (
                "The Netskope tenant API V2 token does not have the necessary permissions configured. " +
                "Refer to the list of endpoints for which the token is missing permissions: " +
                f"{', '.join(forbidden_endpoints)}"
            )
            return ValidationResult(
                success=False, message=message
            )
        if isinstance(metrics_api_permission_validation, ValidationResult):
            return metrics_api_permission_validation
        return ValidationResult(success=True, message="Validation successful.")

    def cleanup(self):
        """Cleanup any resources."""
        banner = notifier.get_banner_details(self.error_banner_id)
        if banner:
            notifier.update_banner_acknowledged(self.error_banner_id, True)
