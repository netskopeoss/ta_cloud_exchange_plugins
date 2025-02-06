"""Netskope Plugin implementation to pull the data from Netskope Tenant."""

import traceback
import re
from typing import List
import time
import threading
from datetime import datetime, timedelta, timezone
from netskope.common.utils import resolve_secret


from .utils.router_helper import get_all_subtypes

from urllib.parse import urlparse

from netskope.common.utils.provider_plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.common.utils import back_pressure
from netskope.common.utils import Notifier, get_sub_type_config_mapping
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper
from netskope.common.models.other import NotificationType
from .utils.helper import (
    BWANPluginHelper,
    NetskopeBWANProviderPluginException,
    BWANForbiddenException
)
from .utils import constants

plugin_provider_helper = PluginProviderHelper()
notifier = Notifier()

NOTIFIER_TYPE_MAPPING = {
    NotificationType.BANNER_INFO: notifier.banner_info,
    NotificationType.BANNER_WARNING: notifier.banner_warning,
    NotificationType.BANNER_ERROR: notifier.banner_error,
}


class NetskopeBWANProviderPlugin(PluginBase):
    """NetskopePlugin class having concrete implementation for pulling \
    and pushing threat information."""

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
        self.should_exit = threading.Event()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{constants.MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

        self.bwan_provider_helper = BWANPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = NetskopeBWANProviderPlugin.metadata
            plugin_name = manifest_json.get("name", constants.PLATFORM_NAME)
            plugin_version = manifest_json.get(
                "version",
                constants.PLUGIN_VERSION
            )
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        constants.MODULE_NAME, constants.PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (constants.PLATFORM_NAME, constants.PLUGIN_VERSION)

    @classmethod
    def supported_subtypes(cls):
        """Get the subtypes defined in router_helper."""
        return get_all_subtypes()

    def transform(self, raw_data, data_type, subtype, **kwargs) -> List:
        """Transform the raw netskope target platform supported."""
        return raw_data

    def remove_tenant_from_banner(self, banner_id, new_message, tenantName):
        """Remove a specific tenant from the banner based on the given banner \
        ID, new message, and tenant name.

        Parameters:
            banner_id (str): The ID of the banner
            new_message (str): The new message to update the banner
            tenantName (str): The name of the tenant to be removed

        Returns:
            None
        """
        current_tenant = f"[{self.name}]({tenantName}/ns#/settings)"
        banner_details = notifier.get_banner_details(id=banner_id)
        if banner_details and banner_details.get("message"):
            message = banner_details.get("message")
            existing_urls = re.findall(r"\[.*?\]\(https://.*?\)", message)
            existing_tenants = [
                url for url in existing_urls
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
                        id=banner_id,
                        acknowledged=True
                    )

    def update_banner(self, tenantName):
        """Remove tenant from banner."""
        new_message = (
            "Configure tenant(s) **{}** "
            "with Netskope Borderless WAN Auth Token token. "
            "Navigate to Settings > Netskope Tenants to "
            "update tenants with the Auth Token. "
        )
        self.remove_tenant_from_banner(
            banner_id="BANNER_ERROR_1000",
            new_message=new_message,
            tenantName=tenantName,
        )
        new_message = (
            "Netskope Borderless WAN Auth Token of tenant **{}** has been "
            "revoked, deleted or has insufficient privileges "
            "to continue pulling alerts and events from Netskope. "
            "Please check the required privileges and ensure that your "
            "Auth Token has "
            "the necessary permissions to access the required resources."
        )
        self.remove_tenant_from_banner(
            banner_id="BANNER_ERROR_1003",
            new_message=new_message,
            tenantName=tenantName,
        )

        new_message = (
            "The Netskope Borderless WAN Auth Token has expired for **{}**. "
            "Generate the new token or re-issue the token and update "
            "the tenant configuration "
            "to resume communication between "
            "Netskope Borderless WAN and Cloud Exchange."
        )
        self.remove_tenant_from_banner(
            banner_id="BANNER_ERROR_0999",
            new_message=new_message,
            tenantName=tenantName,
        )

    def extract_and_store_fields(
        self,
        items: List[dict],
        typeOfField=constants.TYPE_EVENT,
        sub_type=None
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
            if not sub_type and typeOfField == constants.TYPE_EVENT:
                sub_type = item.get("type", None)
            for field in item.keys():
                if field in fields:
                    continue

                plugin_provider_helper.store_new_field(field, typeOfField)

            fields = fields.union(item.keys())

    def bifurcate_sub_type_data(self, response_data):
        """Bifurcate the response data based on sub type.

        Args:
            response_data (dict): Response data from Netskope API.

        Returns:
            dict: Dictionary with sub type as key and list of items as value.
        """
        bifurcated_data = {}
        for item in response_data.get("data", []):
            item_type = item["type"]
            if item_type not in bifurcated_data:
                bifurcated_data[item_type] = []
            bifurcated_data[item_type].append(item)
        return bifurcated_data

    def log_message(
        self,
        data,
        sub_type,
        pull_type,
        configuration_name,
        destination_configuration,
        business_rule,
        start_time,
        end_time,
        page
    ):
        """Log the message for pulling data from Netskope API.

        Args:
            data (List[dict]): List of dictionaries of data pulled from Netskope API.
            sub_type (str): Subtype of the data.
            pull_type (str): Type of pulling (maintenance, historical, real-time).
            configuration_name (str): Name of the configuration.
            destination_configuration (str): Name of the destination configuration.
            business_rule (str): Name of the business rule.
            start_time (datetime): Start time of the pull window.
            end_time (datetime): End time of the pull window.
            page (int): Page number of the data.
        """
        if configuration_name and destination_configuration and business_rule:
            log_msg = (
                f"Pulled {len(data)} {sub_type.lower()} event(s) from "
                f"{pull_type} (PAGE: {page}) in JSON format for SIEM Mapping "
                f"{configuration_name} to {destination_configuration} "
                f"according to rule business rule {business_rule}."
            )
        else:
            log_msg = (
                f"Pulled {len(data)} {sub_type.lower()} event(s) "
                f"from {pull_type} in JSON format."
            )
        detail_log = (
            f"Pull Type: {pull_type}. "
            f"Pull window (start time): {start_time}. "
            f"Pull window (end time): {end_time}."
        )
        self.logger.info(
            message=f"{self.log_prefix}: {log_msg}", details=detail_log
        )

    def format_to_iso8601(self, date_input):
        """
        Format a given date input to ISO8601 format.

        Args:
            date_input (datetime or str): The input date to be formatted.

        Returns:
            str: The formatted date in ISO8601 format.

        Raises:
            ValueError: If the input is not a string or a datetime object.
        """
        if isinstance(date_input, datetime):
            date_object = date_input
        elif isinstance(date_input, str):
            # Convert the string to a datetime object
            date_object = datetime.strptime(
                date_input,
                constants.DATE_FORMAT
            )
        else:
            raise ValueError("Input must be a string or a datetime object")
        return date_object.strftime(constants.DATE_FORMAT)

    # Now format the datetime object to the desired format
    def paginate(
        self,
        sub_type_list,
        start_time,
        end_time,
        pull_type,
    ):
        """
        Paginate through the Netskope BWAN tenant and pull data accordingly.

        Args:
            sub_type_list (list): A list of subtypes to pull.
            start_time (datetime or str): The start time for pulling.
            end_time (datetime or str): The end time for pulling.

        Yields:
            tuple: A tuple containing the page of data, subtype and page count.
        """
        #
        tenantName = self.configuration.get("tenantName", "").strip().rstrip()
        token = resolve_secret(self.configuration.get("v2token"))
        event_endpoint = f"{tenantName}{constants.AUDIT_RECORDS_ENDPOINT}"
        start_time = self.format_to_iso8601(start_time)
        end_time = self.format_to_iso8601(end_time)

        headers = {"Authorization": f"Bearer {token}"}
        params = {
            "first": 100
        }
        sub_types = (
            " AND (type: "
            + " OR type:".join([sub_type.upper() for sub_type in sub_type_list])  # noqa
            + ")"
            if sub_type_list
            else ""
        )
        params["filter"] = (
            f"event_time>'{start_time}' "
            f"AND event_time<'{end_time}'{sub_types}"
        )
        next_page = True
        page_count = 1
        while next_page:
            if back_pressure.STOP_PULLING:
                self.logger.debug(
                    f"{pull_type} of {sub_types} event(s) for tenant {tenantName} "
                    "is paused due to back pressure."
                )
                time.sleep(constants.BACK_PRESSURE_WAIT_TIME)
                continue
            logger_msg = (
                f"fetching event(s) of  type(S) - "
                f"[{sub_type_list}], PAGE: {page_count}"
            )
            resp_json = self.bwan_provider_helper.api_helper(
                logger_msg=logger_msg,
                url=event_endpoint,
                method="GET",
                params=params,
                headers=headers,
                proxies=self.proxy,
                is_handle_error_required=True,
                is_validation=False,
            )
            page_info = resp_json.get("page_info", {})
            next_page = page_info.get("has_next", False)
            if next_page:
                params["after"] = page_info.get("end_cursor", "")

            bifurcated_data = self.bifurcate_sub_type_data(resp_json)
            for sub_type, data in bifurcated_data.items():
                if data:
                    yield data, sub_type.lower(), page_count
            page_count += 1
                
    def update_storage_checkpoint(self, end_time):
        """
        Updates the checkpoint in storage for the given tenant.

        Args:
            end_time (datetime or str): The new checkpoint time.

        Returns:
            None
        """
        self.storage["events_checkpoint"] = end_time
        plugin_provider_helper.update_tenant_storage(
            self.name, self.storage
        )
        
    def load_maintenance(
        self,
        sub_type_list,
        pull_type,
    ):
        """
        This function is used for maintenance pulling. It pulls the data by
        comparing the current time with the stored checkpoint time. If the
        difference is more than 1 hour, it stops pulling and returns success.
        Otherwise, it continues pulling until the difference is more than 1
        hour.

        Args:
            sub_type_list (list): A list of sub types to be pulled.

        Yields:
            page (list): A list of events of the given sub type.
            sub_type (str): The sub type of the events.
            start_time (datetime): The start time of the pulling.
            end_time (datetime): The end time of the pulling.
            page_count (int): The page count of the pulling.
        """
        
        tenant_name = self.name if self.name else ""
        initial_start_time = datetime.now()
        storage_dict = self.storage or {}
        if storage_dict and storage_dict.get("events_checkpoint"):
            start_time = storage_dict.get("events_checkpoint", datetime.now())
        else:
            start_time = self.last_run_at or datetime.now()

        while True:
            try:
                tenant = plugin_provider_helper.get_tenant_details(
                    tenant_name, constants.TYPE_EVENT
                )
            except Exception:
                error_msg = (
                     f"Tenant with name {tenant_name} no longer exists.",
                )
                self.logger.error(
                    f"{self.log_prefix}: {error_msg}",
                    error_code="CE_1030",
                )
                return {"success": False}
            
            if not (
                plugin_provider_helper.is_netskope_plugin_enabled(
                    tenant.get("name")
                )
                and plugin_provider_helper.is_module_enabled()
            ):
                self.logger.info(
                    f"{self.log_prefix}: The Plugin or the Module is Disabled "
                    "hence pulling will be skipped."
                )
                return {"success": True}

            now = datetime.now()
            time_delta = now - initial_start_time
            hours = time_delta.total_seconds() // 3600
            if hours >= 1:
                return {"success": True}
            end_time = now
            for page, sub_type, page_count in self.paginate(
                sub_type_list,
                start_time,
                end_time,
                pull_type,
            ):
                yield page, sub_type, start_time, end_time, page_count
            
            self.update_storage_checkpoint(end_time)
            time.sleep(constants.DEFAULT_WAIT_TIME)
            start_time = end_time

    def load_historical(
        self,
        sub_type_list,
        start_time,
        end_time,
        pull_type,
    ):
        """Pull historical data from Netskope Tenant.

        Parameters:
            sub_type_list (list): List of subtypes to pull.
            start_time (datetime): The start time for pulling.
            end_time (datetime): The end time for pulling.

        Yields:
            tuple: A tuple containing the page of data, subtype and page count.
        """
        tenant_name = self.name if self.name else ""
        start_time = start_time or datetime.now()
        start_time = start_time.strftime(constants.DATE_FORMAT)
        end_time = end_time or datetime.now()
        end_time = end_time.strftime(constants.DATE_FORMAT)
        try:
            tenant = plugin_provider_helper.get_tenant_details(
                tenant_name, constants.TYPE_EVENT
            )
        except Exception:
            error_msg = (
                    f"Tenant with name {tenant_name} no longer exists.",
            )
            self.logger.error(
                f"{self.log_prefix}: {error_msg}",
                error_code="CE_1030",
            )
            return {"success": False}
    
        if not (
            plugin_provider_helper.is_netskope_plugin_enabled(
                tenant.get("name")
            )
            and plugin_provider_helper.is_module_enabled()
        ):
            self.logger.info(
                f"{self.log_prefix}: The Plugin or the Module is Disabled "
                "hence pulling will be skipped."
            )
            return {"success": True}
        for page, sub_type, page_count in self.paginate(
            sub_type_list,
            start_time,
            end_time,
            pull_type
        ):
            yield page, sub_type, start_time, end_time, page_count

    def pull(
        self,
        data_type,
        iterator_name=None,
        pull_type=constants.MAINTENANCE_PULL,
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
            iterator_name (str, optional): The name of the iterator.
            Defaults to None.
            pull_type (str, optional): The type of pulling.
            Defaults to NetskopeClient.MAINTENANCE_PULLING.
            configuration_name (str, optional): The name of the configuration.
            Defaults to None.
            start_time (datetime, optional): The start time for pulling.
            Defaults to None.
            end_time (datetime, optional): The end time for pulling.
            Defaults to None.
            destination_configuration (str, optional): The destination
            configuration. Defaults to None.
            business_rule (str, optional): The business rule to apply.
            Defaults to None.
            override_subtypes (list, optional): List of overridden subtypes
            (For historical). Defaults to None.

        Returns:
            GeneratorObject: List of indicator objects received from
            Netskope along with types.
        """
        if data_type != constants.TYPE_EVENT:
            error_msg = f"The {constants.PLATFORM_NAME} only supports events."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}",
                details=f"Received Data Type: {data_type}",
            )
            raise NetskopeBWANProviderPluginException(error_msg)

        try:
            page_data = []
            sub_type_config_mapping = {}
            sub_type = ""

            if not override_subtypes:
                sub_type_config_mapping, _ = get_sub_type_config_mapping(
                    self.name, data_type
                )
                sub_type_list = sub_type_config_mapping.keys()
            else:
                sub_type_list = override_subtypes

            self.should_exit.clear()
            back_pressure_thread = threading.Thread(
                target=back_pressure.should_stop_pulling,
                daemon=True,
                args=(self.should_exit,),
            )
            back_pressure_thread.start()

            if pull_type == constants.HISTORICAL_PULL:
                for page_data, sub_type, start_time, end_time, page in self.load_historical(  # noqa
                    sub_type_list,
                    start_time,
                    end_time,
                    pull_type,
                ):
                    self.log_message(
                        page_data,
                        sub_type,
                        pull_type,
                        configuration_name,
                        destination_configuration,
                        business_rule,
                        start_time,
                        end_time,
                        page
                    )
                    yield page_data, sub_type, sub_type_config_mapping, False
            else:
                for page_data, sub_type, start_time, end_time, page in self.load_maintenance(  # noqa
                    sub_type_list,
                    pull_type
                ):
                    self.log_message(
                        page_data,
                        sub_type,
                        pull_type,
                        configuration_name,
                        destination_configuration,
                        business_rule,
                        start_time,
                        end_time,
                        page
                    )
                    yield page_data, sub_type, sub_type_config_mapping, False

        except BWANForbiddenException:
            yield page_data, sub_type, sub_type_config_mapping, True

        except NetskopeBWANProviderPluginException:
            raise

        except Exception as err:
            error_msg = (
                "Error occurred while fetching events "
                f"from {constants.PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{error_msg}. Error: {err}",
                details=traceback.format_exc()
            )
            raise NetskopeBWANProviderPluginException(error_msg)

    def validate_token(self, token, tenantName):
        """
        Validate the given Auth Token for the Netskope Tenant.

        Args:
            token (str): The Auth Token to validate.
            tenantName (str): The name of the Netskope Tenant.

        Returns:
            tuple: A tuple containing a boolean indicating
            whether the Token is valid or not and a success/error
            message.
        """
        alert_endpoint = f"{tenantName}{constants.AUDIT_RECORDS_ENDPOINT}"
        current_time = datetime.now(timezone.utc)
        current_time = current_time.strftime(constants.DATE_FORMAT)
        params = {
            "first": 1,
            "filter": (
                f"event_time>'{current_time}' AND "
                f"event_time<'{current_time}'"
            ),
        }
        headers = {"Authorization": f"Bearer {token}"}
        try:
            logger_msg = "validating Auth Token"
            self.bwan_provider_helper.api_helper(
                logger_msg=logger_msg,
                url=alert_endpoint,
                method="GET",
                params=params,
                headers=headers,
                proxies=self.proxy,
                is_validation=True,
                is_handle_error_required=True,
            )
            success_msg = (
                "Successfully validated the Auth "
                f"Token for {constants.PLATFORM_NAME} plugin."
            )
            return (
                True,
                success_msg
            )
        except BWANForbiddenException as err:
            return False, str(err)
        except NetskopeBWANProviderPluginException as err:
            return False, str(err)
        except Exception as err:
            error_msg = "Error occurred while validating Auth Token."
            self.logger.error(
                message=f"{self.log_prefix} {error_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            return False, error_msg

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            - url (str): Given URL.

        Returns:
            - bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url.strip())
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the
            Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object
            with success flag and message.
        """
        self.logger.debug(
            f"{self.log_prefix}: Executing validate "
            f"method for {constants.PLATFORM_NAME}."
        )

        checkpoint = None

        validation_err_msg = "Validation error occurred."

        tenantName = configuration.get("tenantName", "").strip()
        if not tenantName:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: "
                f"{validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg, checkpoint=checkpoint
            )
        elif (
            not isinstance(tenantName, str)
            or not self._validate_url(tenantName)
        ):
            err_msg = (
                "Invalid Base URL provided in the configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg, checkpoint=checkpoint
            )

        token = configuration.get("v2token")
        if not token:
            err_msg = "Auth Token is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg, checkpoint=checkpoint
            )
        else:
            success, message = self.validate_token(token, tenantName)
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
                        r"(token=)[^&]+", r"\1***************",
                        message
                    ),
                    checkpoint=checkpoint,
                )

        tenant_creation = True
        if self.storage and self.storage.get("existing_configuration", {}).get(
            "tenantName"
        ):
            tenant_creation = False
            existing_tenantName = self.storage.get(
                "existing_configuration", {}
            ).get(
                "tenantName"
            )
            if existing_tenantName != tenantName:
                err_msg = (
                    f" Tenant URL '{tenantName}' is mismatched with"
                    f" '{existing_tenantName}'"
                )
                return ValidationResult(
                    success=False, message=err_msg, checkpoint=checkpoint
                )

        if tenant_creation:
            checkpoint = {"events": datetime.now()}
            self.storage["existing_configuration"] = {"tenantName": tenantName}
        else:
            self.update_banner(tenantName)
        return ValidationResult(
            success=True,
            message=(
                f"Validation Successful for "
                f"{constants.PLATFORM_NAME} plugin."
            ),
            checkpoint=checkpoint,
        )

    def cleanup(self, configuration) -> None:
        """Remove all related dependencies of the record before its deletion,
        ensuring data integrity."""
        tenantName = configuration.get("tenantName")
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
                    id=banner,
                    acknowledged=True
                )
        else:
            self.update_banner(tenantName)
