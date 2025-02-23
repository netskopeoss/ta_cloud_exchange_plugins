"""Netskope Plugin implementation to push and pull the data from Netskope Tenant."""

import datetime
import gzip
import re
import threading
import time
import traceback
from typing import Dict, List
from urllib.parse import urlparse

import requests
from netskope.common.models import NetskopeFieldType
from netskope.common.models.other import NotificationType
from netskope.common.utils import (
    Notifier,
    add_user_agent,
    get_sub_type_config_mapping,
)
from netskope.common.utils.handle_exception import (
    handle_exception,
    handle_status_code,
)
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper
from netskope.common.utils.provider_plugin_base import (
    PluginBase,
    ValidationResult,
)

from .utils.iterator_helper import (
    EVENTS,
    NetskopeClient,
    NetskopeIteratorBuilder,
)
from .utils.router_helper import get_all_subtypes
from .utils.webtx_metrics_collector import get_webtx_metrics_data
from .utils.webtx_parser import WebtxParser

MODULE_NAME = "TENANT"
PLUGIN_VERSION = "1.1.0"
PLATFORM_NAME = "Netskope"
DOCS_URL = "https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/get-started-with-cloud-exchange/configure-netskope-tenants/#v2-rest-api-scopes"  # NOQA

plugin_provider_helper = PluginProviderHelper()
notifier = Notifier()

NOTIFIER_TYPE_MAPPING = {
    NotificationType.BANNER_INFO: notifier.banner_info,
    NotificationType.BANNER_WARNING: notifier.banner_warning,
    NotificationType.BANNER_ERROR: notifier.banner_error,
}

DATA_TYPE_MAPPING = {"alerts": "alert", "events": "event"}


class NetskopeProviderPlugin(PluginBase):
    """NetskopePlugin class having concrete implementation for pulling and pushing threat information."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init function.

        Args:
            name (str): Configuration Name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
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
            manifest_json = NetskopeProviderPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    @classmethod
    def supported_subtypes(cls):
        """Get the subtypes defined in router_helper."""
        return get_all_subtypes()

    def _transform_webtx_data(self, data, fields, allow_empty_values):
        """Transform webtx data."""
        try:
            all_logs = []
            parser = WebtxParser(allow_empty_values)
            for message, message_fields in zip(data, fields):
                message = gzip.decompress(message).decode("utf-8")
                parser.fields = message_fields
                for log in message.split("\n"):
                    all_logs.append(parser.parse(log))
            return all_logs
        except Exception as exp:
            self.logger.error(
                "{}: Error occurred while transforming webtx data. Error: {}".format(
                    self.log_prefix, exp
                ),
                details=traceback.format_exc(),
            )
            raise exp

    def transform(self, raw_data, data_type, subtype, **kwargs) -> List:
        """Transform the raw netskope target platform supported."""
        if (
            data_type == "webtx"
            and "fields" in kwargs
            and "allow_empty_values" in kwargs
        ):
            fields = kwargs.get("fields")
            allow_empty_values = kwargs.get("allow_empty_values", False)
            return self._transform_webtx_data(
                raw_data, fields, allow_empty_values
            )
        return raw_data

    def call_api_endpoint_for_validation(
        self,
        tenant_name,
        type,
        sub_type,
        it_name,
        update_forbidden_data=False,
        additional_error_msg="",
    ):
        """Call Netskope api endpoint to check permissions."""
        try:
            # calling with future epoch time, to reduce the response time.
            tenant = {
                "name": tenant_name,
                "parameters": self.configuration,
                "storage": self.storage,
                "checkpoint": self.last_run_at,
                "use_proxy": self.use_proxy,
                "proxy": self.proxy,
            }
            headers = add_user_agent({})
            iterator = NetskopeIteratorBuilder(
                tenant,
                type,
                sub_type,
                it_name,
                return_response=True,
                epoch=int(time.time()) + 60,
                headers=headers,
            )
            # Reduce the response wait time for 401 or 403 status codes while validating v2 token.
            iterator.client.TOKEN_ERROR_WAIT_TIME = 0
            response = iterator.pull()
            uri = urlparse(response.url).path
            if response.status_code in [200, 409]:
                update_set = {"is_v2_token_expired": False}
                update_unset = {f"forbidden_endpoints.{sub_type}": ""}

                plugin_provider_helper.update_tenant_storage(
                    self.name, update_set, update_unset
                )
                return True, uri
            elif response.status_code == 401:
                if update_forbidden_data:
                    update_set = {"is_v2_token_expired": True}

                    plugin_provider_helper.update_tenant_storage(
                        self.name, update_set
                    )
                raise ValueError("Incorrect tenant URL/API token provided.")
            elif response.status_code == 403:
                # TODO : We receive 403 when invalid token is passed!
                if update_forbidden_data:
                    update_set = {
                        "is_v2_token_expired": False,
                        f"forbidden_endpoints.{sub_type}": uri,
                    }
                    plugin_provider_helper.update_tenant_storage(
                        self.name, update_set
                    )
                return False, uri
            elif response.status_code == 429:
                raise ValueError(
                    f"Received status code {response.status_code} from Netskope "
                    f"for url {response.url}. "
                    "please try after some time."
                )
            elif 400 <= response.status_code < 500:
                raise ValueError(
                    f"Received client side error. Status code: {response.status_code} Response: "
                    f"{response.json()}"
                )
            elif 500 <= response.status_code < 600:
                raise ValueError(
                    "Received internal server error from Netskope. please try after some time."
                )
        except requests.exceptions.ProxyError:
            raise ValueError("Invalid proxy or tenant URL provided.")
        except requests.ConnectionError:
            raise ValueError(
                "Connection Error. Check the tenant URL and network settings."
            )
        except Exception as e:
            if isinstance(additional_error_msg, str):
                additional_error_msg = f" {additional_error_msg.strip()}"
            else:
                additional_error_msg = ""
            self.logger.error(
                f"{self.log_prefix}: Error occurred while validating credentials{additional_error_msg}. {e}",
                details=traceback.format_exc(),
                error_code="CE_1125",
            )
            raise ValueError(f"Unable to validate credentials. {e}")

    def remove_tenant_from_banner(self, banner_id, new_message, tenant_name):
        """Remove a specific tenant from the banner based on the given banner ID, new message, and tenant name.

        Parameters:
            banner_id (str): The ID of the banner
            new_message (str): The new message to update the banner
            tenant_name (str): The name of the tenant to be removed

        Returns:
            None
        """
        current_tenant = f"[{self.name}]({tenant_name}/ns#/settings)"
        banner_details = notifier.get_banner_details(id=banner_id)
        if banner_details and banner_details.get("message"):
            message = banner_details.get("message")
            existing_urls = re.findall(r"\[.*?\]\(https://.*?\)", message)
            existing_tenants = [
                url
                for url in existing_urls
                if "https://docs.netskope.com" not in url
            ]
            if current_tenant in existing_tenants:
                existing_tenants.remove(current_tenant)
                if existing_tenants:
                    NOTIFIER_TYPE_MAPPING[banner_details.get("type")](
                        id=banner_id,
                        message=new_message.format(
                            {", ".join(existing_tenants)}
                        ),
                    )
                else:
                    NOTIFIER_TYPE_MAPPING[banner_details.get("type")](
                        id=banner_id, message=""
                    )
                    notifier.update_banner_acknowledged(
                        id=banner_id, acknowledged=True
                    )

    def update_banner(self, tenant_name):
        """Remove tenant from banner."""
        new_message = (
            "Configure tenant(s) **{}** "
            "with V2 token. Navigate to Settings > Netskope Tenants to update tenants with V2 token. "
        )
        self.remove_tenant_from_banner(
            banner_id="BANNER_ERROR_1000",
            new_message=new_message,
            tenant_name=tenant_name,
        )
        new_message = (
            "Netskope API token of tenant **{}** has been revoked, deleted or has insufficient privileges "
            "to continue pulling alerts and events from Netskope."
            + f" Please check the **[required privileges]({DOCS_URL})** and ensure that your API token has "
            "the necessary permissions to access the required resources."
        )
        self.remove_tenant_from_banner(
            banner_id="BANNER_ERROR_1003",
            new_message=new_message,
            tenant_name=tenant_name,
        )

        new_message = (
            "The Netskope tenant API token has expired for **{}**. "
            "Generate the new token or re-issue the token and update the tenant configuration "
            "to resume communication between Netskope Tenant and Cloud Exchange."
        )
        self.remove_tenant_from_banner(
            banner_id="BANNER_ERROR_0999",
            new_message=new_message,
            tenant_name=tenant_name,
        )

    def threaded_permissions_check(
        self,
        type,
        sub_type,
        it_name,
        forbidden_endpoints,
        additional_error_msg="",
    ):
        """Check permissions for the given type and sub_types."""
        try:
            success, uri = self.call_api_endpoint_for_validation(
                self.name,
                type,
                sub_type,
                it_name,
                additional_error_msg=additional_error_msg,
            )
            if not success:
                forbidden_endpoints.append(uri)
        except Exception as e:
            threading.current_thread().exception = e

    def permission_check(
        self,
        type_map: Dict[str, List[str]],
        plugin_name: str = None,
        configuration_name: str = None,
    ):
        """Check permissions for the given type and sub_types.

        Parameters:
            type: Alert or Event to check permissions.
            sub_types: A list of sub-types to validate.
            plugin_name: Name of the plugin. Default is None.
            configuration_name: Name of the configuration. Default is None.

        Raises:
            ValueError: In case endpoints is/are forbidden.

        Returns:
            True if permission check is successful.
        """
        additional_error_msg = ""
        if plugin_name:
            additional_error_msg = (
                f"for {plugin_name} [{configuration_name}]"
                if configuration_name
                else f"for {plugin_name}"
            )
        forbidden_endpoints = []
        threads = []
        for type, sub_types in type_map.items():
            iterator_name = f"{self.name}_{type}_%s_validate_token"
            for sub_type in sub_types:
                it_name = iterator_name % (sub_type)
                it_name = it_name.replace(" ", "_")
                t = threading.Thread(
                    target=self.threaded_permissions_check,
                    args=(type, sub_type, it_name, forbidden_endpoints),
                    kwargs={"additional_error_msg": additional_error_msg},
                )
                t.exception = None
                t.start()
                threads.append(t)

        for t in threads:
            t.join()
            if t.exception:
                raise t.exception
        if forbidden_endpoints:
            self.logger.warn(
                f"{self.log_prefix}: {additional_error_msg}, received 403 error for following endpoint(s)",
                details=", ".join(forbidden_endpoints),
            )
            raise ValueError(
                "The Netskope tenant API V2 token does not have the necessary permissions configured."
                " Refer to the list of endpoints for which the token "
                f"is missing permissions: {', '.join(forbidden_endpoints)}"
            )
        self.update_banner(self.name)
        return True

    def _pull_webtx_data(self, configuration_name):
        """Pull indicators from Netskope."""
        from .utils import webtx_helper

        try:
            self.logger.debug(
                f"{self.log_prefix}: Executing webtx task for {configuration_name}"
            )
            ret_val = webtx_helper.main(configuration_name, self.log_prefix)
            return {
                "message": f"WebTx task completed. Return value is {ret_val}."
            }

        except Exception:
            self.logger.info(
                f"{self.log_prefix}: Soft time limit exceeded while "
                f"pulling the WebTx logs for {configuration_name}, Rescheduling the task.."
            )
            webtx_helper.handle_interrupt()
            for thread in webtx_helper.threads:
                thread.join()
            return {
                "message": f"Soft time limit exceeded while pulling the "
                f"WebTx logs for {self.name}, Rescheduling the task."
            }

    def _pull_webtx_metrics(self):
        try:
            existing_data = plugin_provider_helper.get_webtx_metrics(
                self.name
            )
            if existing_data and "latest_utc_hour" in existing_data:
                try:
                    latest_datetime = existing_data["latest_utc_hour"]
                    latest_datetime = datetime.datetime.strptime(
                        latest_datetime, "%Y-%m-%dT%H:%M:%S.%fZ"
                    )
                    latest_datetime = latest_datetime.replace(
                        tzinfo=datetime.timezone.utc
                    )
                    if datetime.datetime.now(
                        datetime.timezone.utc
                    ) - latest_datetime < datetime.timedelta(hours=1):
                        return existing_data, 200
                except ValueError:
                    pass
            data, status_code = get_webtx_metrics_data(
                self.log_prefix,
                self.configuration["tenantName"],
                self.configuration["v2token"],
                self.proxy,
            )
            if data and status_code == 200:
                plugin_provider_helper.replace_webtx_metrics(
                    self.configuration["tenantName"], self.name, data
                )
                data = plugin_provider_helper.get_webtx_metrics(self.name)
            elif existing_data:
                return existing_data, 200
            return data, status_code
        except Exception:
            self.logger.error(
                f"{self.log_prefix}: Failed to pull webtx metrics",
                error_code="CE_1139",
                details=traceback.format_exc(),
            )
            return {}, 500

    def pull(
        self,
        data_type,
        iterator_name=None,
        pull_type=NetskopeClient.MAINTENANCE_PULLING,
        configuration_name=None,
        start_time=None,
        end_time=None,
        destination_configuration=None,
        business_rule=None,
        override_subtypes=None,
        compress_historical_data=False,
        handle_forbidden=True,
    ):
        """Pull the Threat information from Netskope Tenant.

        Parameters:
            data_type (str): The type of data to pull.
            iterator_name (str, optional): The name of the iterator. Defaults to None.
            pull_type (str, optional): The type of pulling. Defaults to NetskopeClient.MAINTENANCE_PULLING.
            configuration_name (str, optional): The name of the configuration. Defaults to None.
            start_time (datetime, optional): The start time for pulling. Defaults to None.
            end_time (datetime, optional): The end time for pulling. Defaults to None.
            destination_configuration (str, optional): The destination configuration. Defaults to None.
            business_rule (str, optional): The business rule to apply. Defaults to None.
            override_subtypes (list, optional): List of overridden subtypes (For historical). Defaults to None.

        Returns:
            GeneratorObject: List of indicator objects received from Netskope along with types.
        """
        if data_type == "webtx":
            return self._pull_webtx_data(configuration_name)
        elif data_type == "webtx_metrics":
            yield self._pull_webtx_metrics()
            return
        tenant = {
            "name": self.name,
            "parameters": self.configuration,
            "storage": self.storage,
            "checkpoint": self.last_run_at,
            "use_proxy": self.use_proxy,
            "proxy": self.proxy,
        }
        iterator_name = iterator_name or f"{self.name}_%s"
        other_parameters = {}
        if configuration_name:
            other_parameters["source_configuration"] = configuration_name
        if start_time:
            other_parameters["start_time"] = start_time
        if end_time:
            other_parameters["end_time"] = end_time
        if destination_configuration:
            other_parameters["destination_configuration"] = (
                destination_configuration
            )
        if business_rule:
            other_parameters["business_rule"] = business_rule
        headers = add_user_agent({})

        client = NetskopeClient(
            tenant,
            iterator_name,
            DATA_TYPE_MAPPING[data_type],
            pulling_type=pull_type,
            handle_forbidden=handle_forbidden,
            **other_parameters,
            headers=headers,
            compress_historical_data=compress_historical_data,
        )
        if not override_subtypes:
            sub_type_config_mapping, latest_checked = (
                get_sub_type_config_mapping(self.name, data_type)
            )

            client.sub_types = sub_type_config_mapping.keys()
        else:
            client.sub_types = override_subtypes

        for (
            data,
            sub_type,
            should_apply_expo_backoff,
            should_exec_lifecycle,
        ) in client.create_job():
            if not override_subtypes:
                sub_type_config_mapping, latest_checked = (
                    get_sub_type_config_mapping(
                        self.name,
                        data_type,
                        latest_checked,
                        sub_type_config_mapping,
                    )
                )
                client.sub_types = sub_type_config_mapping.keys()
                if should_exec_lifecycle:
                    yield data, sub_type, sub_type_config_mapping, should_apply_expo_backoff
            elif should_exec_lifecycle:
                yield data, sub_type, None, should_apply_expo_backoff

    def extract_and_store_fields(
        self,
        items: List[dict],
        typeOfField=NetskopeFieldType.ALERT,
        sub_type=None,
    ):
        """Extract and store keys from list of dictionaries.

        Args:
            items (List[dict]): List of dictionaries. i.e. alerts, or events.
            typeOfField (str): Alert or Event
            sub_type (str): Subtype of alerts or events.
        """
        typeOfField = typeOfField.rstrip("s")
        fields = set()
        for item in items:
            if not isinstance(item, dict):
                item = item.dict()
            item_id = item.get("_id", None)
            if not sub_type and typeOfField == NetskopeFieldType.ALERT:
                sub_type = item.get("alert_type", None)
            elif not sub_type and typeOfField == NetskopeFieldType.EVENT:
                sub_type = item.get("event_type", None)
            if not item_id:
                item_id = item.get("id")
            for field in item.keys():
                if field in fields:
                    continue
                field_obj = plugin_provider_helper.get_stored_field(field)
                if (
                    typeOfField == NetskopeFieldType.WEBTX
                    and field_obj is None
                ):
                    self.logger.info(
                        f"{self.log_prefix}: The CE platform has detected new field '{field}' in the WebTx log"
                        f" with id {item_id}. Configure CLS to use this field if you wish to sent it to the SIEM."
                    )
                    notifier.info(
                        f"The CE platform has detected new field '{field}' in the WebTx log"
                        f" with id {item_id}. Configure CLS to use this field if you wish to sent it to the SIEM."
                    )
                elif sub_type not in EVENTS.keys() and field_obj is None:
                    self.logger.info(
                        f"{self.log_prefix}: The CE platform has detected new field '{field}' in the {sub_type}"
                        f" alert with id {item_id}. Configure CLS to use this field if you wish to sent it to the SIEM."
                    )
                    notifier.info(
                        f"The CE platform has detected new field '{field}' in the {sub_type}"
                        f" alert with id {item_id}. Configure CLS to use this field if you wish to sent it to the SIEM."
                    )
                    self.logger.info(
                        f"{self.log_prefix}: The CE platform has detected new field '{field}' in the {sub_type}"
                        f" alert with id {item_id}. Configure CTO to use this field if you wish to map to a ticket."
                    )
                    notifier.info(
                        f"The CE platform has detected new field '{field}' in the {sub_type}"
                        f" alert with id {item_id}. Configure CTO to use this field if you wish to map to a ticket."
                    )
                elif field_obj is None:
                    self.logger.info(
                        f"{self.log_prefix}: The CE platform has detected new field '{field}' in the {sub_type}"
                        f" event with id {item_id}. Configure CLS to use this field if you wish to sent it to the SIEM."
                    )
                    notifier.info(
                        f"The CE platform has detected new field '{field}' in the {sub_type}"
                        f" event with id {item_id}. Configure CLS to use this field if you wish to sent it to the SIEM."
                    )

                plugin_provider_helper.store_new_field(field, typeOfField)

            fields = fields.union(item.keys())

    def validate_token(self, token, tenant_name):
        """Validate v1 API Token."""
        alert_endpoint = f"{tenant_name}/api/v1/app_instances"
        params = {"op": "list", "limit": 1}
        try:
            success, response = handle_exception(
                requests.post,
                error_code="CE_1025",
                custom_message="Error occurred while validating v1 token",
                url=alert_endpoint,
                params=params,
                headers=add_user_agent({}),
                proxies=self.proxy,
                data={"token": token},
            )
            if not success:
                return success, str(response)

            if response.status_code == 403:
                err_msg = "Incorrect tenant URL/API token provided."
                return False, err_msg

            resp_json = handle_status_code(
                response,
                error_code="CE_1045",
                custom_message=f"Error occurred while validating v1 token for the tenant {self.name}",
                notify=False,
            )

            if resp_json.get("status") == "success":
                return True, resp_json
        except requests.exceptions.ProxyError:
            return False, "Invalid proxy provided."
        except requests.ConnectionError:
            return (
                False,
                "Connection Error. Check the tenant URL and network settings.",
            )
        except Exception:
            pass
        return False, "Error occurred while validating V1 token."

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.debug(
            f"{self.log_prefix}: Netskope Executing validate method for Netskope plugin"
        )

        checkpoint = None

        validation_err_msg = "Validation error occurred."

        tenant_name = configuration.get("tenantName", "").strip()
        if not tenant_name:
            err_msg = (
                "Tenant must have a Tenant URL. Please provide a Tenant URL."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg, checkpoint=checkpoint
            )
        elif not isinstance(tenant_name, str):
            err_msg = "Invalid Tenant URL provided."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg, checkpoint=checkpoint
            )

        parsedUrl = urlparse(tenant_name.strip().strip("/").strip())
        if (
            parsedUrl.path
            or parsedUrl.params
            or parsedUrl.query
            or parsedUrl.fragment
        ):
            err_msg = "Invalid Tenant URL provided. It should follow the format: https://demo.goskope.com."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg, checkpoint=checkpoint
            )

        token = configuration.get("token", "")
        if token:
            success, message = self.validate_token(token, tenant_name)
            if not success:
                self.logger.error(
                    re.sub(
                        r"(token=)[^&]+",
                        r"\1***************",
                        f"{self.log_prefix}: {validation_err_msg} {message}",
                    ),
                    error_code="CE_1126",
                )
                return ValidationResult(
                    success=False,
                    message=re.sub(
                        r"(token=)[^&]+", r"\1***************", message
                    ),
                    checkpoint=checkpoint,
                )

        v2_token = configuration.get("v2token", "")
        if not v2_token:
            err_msg = "Tenant must have V2 token. Please provide V2 token."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg, checkpoint=checkpoint
            )
        elif not isinstance(tenant_name, str):
            err_msg = "Invalid v2 token provided."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg, checkpoint=checkpoint
            )

        if not self.permission_check(
            {"events": ["alert"]},
            plugin_name=self.plugin_name,
            configuration_name=self.name,
        ):
            message = "Error occurred while validating v2 token"
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {message}",
                error_code="CE_1127",
            )
            return ValidationResult(
                success=False, message=message, checkpoint=checkpoint
            )

        tenant_creation = True
        if self.storage and self.storage.get(
            "existing_configuration", {}
        ).get("tenantName"):
            tenant_creation = False
            existing_tenant_name = self.storage.get(
                "existing_configuration", {}
            ).get("tenantName")
            if existing_tenant_name != tenant_name:
                err_msg = (
                    f" Tenant URL '{tenant_name}' is mismatched with"
                    f" '{existing_tenant_name}'"
                )
                return ValidationResult(
                    success=False, message=err_msg, checkpoint=checkpoint
                )

        if tenant_creation:
            checkpoint = {
                "alerts": datetime.datetime.now(),
                "events": datetime.datetime.now(),
            }
            self.storage["existing_configuration"] = {
                "tenantName": tenant_name
            }
        else:
            self.update_banner(tenant_name)

        return ValidationResult(
            success=True,
            message="Validation Successful for Netskope plugin",
            checkpoint=checkpoint,
        )

    def cleanup(self, configuration) -> None:
        """Remove all related dependencies of the record before its deletion, ensuring data integrity."""
        tenant_name = configuration.get("tenantName")
        tenants = plugin_provider_helper.list_tenants()

        if len(tenants) == 1:
            banners = [
                "BANNER_ERROR_0999",
                "BANNER_ERROR_1000",
                "BANNER_ERROR_1001",
                "BANNER_ERROR_1002",
                "BANNER_ERROR_1003",
                "BANNER_WARN_1000",
            ]
            for banner in banners:
                notifier.update_banner_acknowledged(
                    id=banner, acknowledged=True
                )
        else:
            self.update_banner(tenant_name)
