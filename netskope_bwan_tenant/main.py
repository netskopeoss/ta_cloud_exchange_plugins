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
from netskope.common.models import FieldDataType
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
        # The configured Auth Token, resolved once per pull cycle and reused
        # across every page and every subtype (O-3). resolve_secret decrypts
        # the stored value, so calling it per page was needless work. The
        # plugin object is recreated each cycle, so this never goes stale.
        self._token = None
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
        for item in items:
            if not isinstance(item, dict):
                item = item.dict()
            if not sub_type and typeOfField == constants.TYPE_EVENT:
                sub_type = item.get("type", None)
            for field, value in item.items():
                # Skip empty values so a field is not registered as TEXT
                # from an empty payload; a later non-empty value still
                # registers it with the right type.
                if value is None or (
                    isinstance(value, (str, list, dict, tuple, set))
                    and not value
                ):
                    continue
                # Infer the field type. 'bool' is a subclass of 'int', so it
                # is tested first; everything that is not a bool/number is
                # stored as TEXT.
                if isinstance(value, bool):
                    datatype = FieldDataType.BOOLEAN
                elif isinstance(value, (int, float)):
                    datatype = FieldDataType.NUMBER
                else:
                    datatype = FieldDataType.TEXT
                plugin_provider_helper.store_new_field(
                    field, typeOfField, datatype
                )

    def bifurcate_sub_type_data(self, response_data):
        """Bifurcate the response data based on sub type.

        Args:
            response_data (dict): Response data from Netskope API.

        Returns:
            dict: Dictionary with sub type as key and list of items as value.
        """
        bifurcated_data = {}
        for item in response_data.get("data", []):
            item_type = constants.SUBTYPE_RESPONSE_MAPPING.get(item["type"])
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
        page,
        data_type,
    ):
        """Log the message for pulling data from Netskope API.

        Args:
            data (List[dict]): List of dictionaries of data pulled
            from Netskope API.
            sub_type (str): Subtype of the data.
            pull_type (str): Type of pulling (maintenance,
            historical, real-time).
            configuration_name (str): Name of the configuration.
            destination_configuration (str): Name of the
            destination configuration.
            business_rule (str): Name of the business rule.
            start_time (datetime): Start time of the pull window.
            end_time (datetime): End time of the pull window.
            page (int): Page number of the data.
            data_type (str): Data type being pulled (events or alerts); decides
            whether the record is logged as an "alert" or an "event".
        """
        item_label = (
            "alert" if data_type == constants.TYPE_ALERT else "event"
        )
        entity_display = constants.ENTITY_SUBTYPE_DISPLAY.get(sub_type)
        if entity_display:
            # CRE entities are records, not events/alerts.
            log_msg = (
                f"Pulled {len(data)} {entity_display} record(s) during "
                f"{pull_type} in JSON format."
            )
        elif configuration_name and destination_configuration and business_rule:
            log_msg = (
                f"Pulled {len(data)} {sub_type.lower()} {item_label}(s) from "
                f"{pull_type} (PAGE: {page}) in JSON format for SIEM Mapping "
                f"{configuration_name} to {destination_configuration} "
                f"according to rule business rule {business_rule}."
            )
        else:
            log_msg = (
                f"Pulled {len(data)} {sub_type.lower()} {item_label}(s) "
                f"from {pull_type} in JSON format."
            )
        detail_log = (
            f"Pull Type: {pull_type}. "
            f"Pull window (start time): {start_time}. "
            f"Pull window (end time): {end_time}."
        )
        # Zero-count summaries are logged at DEBUG so an idle tenant does
        # not flood the logs every window; a subtype that returned records
        # is logged at INFO.
        log = self.logger.info if data else self.logger.debug
        log(message=f"{self.log_prefix}: {log_msg}", details=detail_log)

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

    def build_dedicated_endpoint_filter(self, config, start_time, end_time):
        """Build the API filter expression for a dedicated-endpoint subtype.

        Args:
            config (dict): Entry from constants.DEDICATED_ENDPOINT_CONFIG.
            start_time (str): ISO8601 lower bound of the pull window.
            end_time (str): ISO8601 upper bound of the pull window.

        Returns:
            str: The filter expression for the endpoint.

        Raises:
            NetskopeBWANProviderPluginException: On an unknown filter type.
        """
        filter_type = config.get("filter_type")
        if filter_type == constants.FILTER_RANGE:
            time_field = config.get("time_field")
            # Half-open window [start, end): '>=' start, '<' end, so a record
            # stamped exactly on a boundary is pulled by one window only.
            return (
                f"{time_field}>='{start_time}' "
                f"AND {time_field}<'{end_time}'"
            )
        elif filter_type == constants.FILTER_ALERT:
            return (
                f"(opened_at>='{start_time}' AND opened_at<'{end_time}')"
                f" OR (closed_at>='{start_time}' AND closed_at<'{end_time}')"
            )
        elif filter_type == constants.FILTER_NONE:
            # No time filter: pull the entity in full each cycle.
            return None
        error_msg = (
            "Unable to build the API filter for an unknown "
            f"filter type '{filter_type}'."
        )
        self.logger.error(message=f"{self.log_prefix}: {error_msg}")
        raise NetskopeBWANProviderPluginException(error_msg)

    def _get_token(self):
        """Return the resolved Auth Token, decrypting it once per cycle.

        resolve_secret decrypts the stored secret, so it is resolved on the
        first use and cached on the instance for the rest of the pull cycle
        (every page and every subtype reuse it). The plugin object is
        recreated each cycle, so the cache never goes stale (O-3).

        Returns:
            str: The resolved Auth Token.
        """
        if self._token is None:
            self._token = resolve_secret(self.configuration.get("v2token"))
        return self._token

    def paginate_dedicated_endpoint(
        self,
        mapped_sub_type,
        start_time,
        end_time,
        pull_type,
        data_type,
    ):
        """Paginate through a subtype served by its own endpoint.

        Used for the subtypes in constants.DEDICATED_ENDPOINT_CONFIG. Each
        of these endpoints returns exactly one subtype and its records carry
        no "type" field, so the response is yielded as-is without
        bifurcation.

        Args:
            mapped_sub_type (str): SUBTYPE_LIST_MAPPING value of the subtype.
            start_time (str): ISO8601 start of the pull window.
            end_time (str): ISO8601 end of the pull window.
            pull_type (str): The type of pulling.
            data_type (str): Data type being pulled (events or alerts).

        Yields:
            tuple: A tuple containing the page of data, subtype and page count.
        """
        config = constants.DEDICATED_ENDPOINT_CONFIG[mapped_sub_type]
        sub_type = config.get("sub_type")
        item_label = (
            "alert" if data_type == constants.TYPE_ALERT else "event"
        )
        tenantName = self.configuration.get("tenantName", "").strip().rstrip()
        token = self._get_token()
        event_endpoint = f"{tenantName}{config.get('endpoint')}"

        headers = {"Authorization": f"Bearer {token}"}
        params = {"first": constants.PAGE_SIZE}
        filter_type = config.get("filter_type")
        checkpoint_key = config.get("checkpoint_key")
        is_historical = pull_type == constants.HISTORICAL_PULL
        # A dedicated subtype that keeps its own checkpoint sources its
        # window start from it, so a failed subtype re-pulls only its own
        # window. On the first run (no stored checkpoint) it falls back to
        # the shared maintenance window start.
        stored_checkpoint = (
            (self.storage or {}).get(checkpoint_key) if checkpoint_key else None
        )
        if filter_type == constants.FILTER_ENTITY:
            # Incremental on 'modified_at'. The first run (no stored
            # checkpoint) has no filter and pulls the entity in full.
            time_field = config.get(
                "time_field", constants.ENTITY_PULL_SORT_FIELD
            )
            params["sort"] = time_field
            if stored_checkpoint:
                params["filter"] = (
                    f"{time_field}>='{stored_checkpoint}' "
                    f"AND {time_field}<'{end_time}'"
                )
        else:
            # Range (network_event) and alert (bwan_alert_v2) maintenance
            # windows start at this subtype's own checkpoint when it has one.
            # A historical pull always uses the requested window: the
            # checkpoint belongs to maintenance and is already past a
            # historical window's end.
            window_start = (
                start_time
                if is_historical
                else (stored_checkpoint or start_time)
            )
            if window_start >= end_time:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping the '{sub_type}' "
                        f"{pull_type} pull as its window start "
                        f"({window_start}) is not before its window end "
                        f"({end_time})."
                    )
                )
                return
            dedicated_filter = self.build_dedicated_endpoint_filter(
                config, window_start, end_time
            )
            if dedicated_filter is not None:
                params["filter"] = dedicated_filter
        next_page = True
        page_count = 1
        total_records = 0
        # Accumulate up to BATCH_PAGE_COUNT pages (100 records each) into one
        # yielded batch so a high-volume subtype produces fewer, larger CE
        # batches instead of one per page (O-2).
        batch = []
        pages_in_batch = 0
        while next_page:
            if back_pressure.STOP_PULLING:
                self.logger.debug(
                    f"{pull_type} of {sub_type} {item_label}(s) for tenant "
                    f"{tenantName} is paused due to back pressure."
                )
                time.sleep(constants.BACK_PRESSURE_WAIT_TIME)
                continue
            logger_msg = (
                f"fetching {item_label}(s) of type(s) - "
                f"[{sub_type}], PAGE: {page_count}"
            )
            try:
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
            except Exception:
                # Hand over the pages accumulated before this failure so they
                # are not lost, then let the error propagate to the
                # per-subtype isolation in paginate() (O-2). The checkpoint is
                # not advanced (the loop is abandoned), so the window re-pulls.
                if batch:
                    yield batch, sub_type.lower(), page_count
                raise
            page_info = resp_json.get("page_info", {})
            next_page = page_info.get("has_next", False)
            cursor = page_info.get("end_cursor")
            if next_page and (not cursor or cursor == params.get("after")):
                # 'has_next' is true but the cursor did not advance; stop so
                # the same page is not requested forever.
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Pagination stopped for "
                        f"{sub_type}; 'has_next' is true without a new "
                        "cursor."
                    ),
                    details=f"page_info: {page_info}",
                )
                break
            if next_page:
                params["after"] = cursor

            data = resp_json.get("data", [])
            if data:
                total_records += len(data)
                if data_type == constants.TYPE_ALERT:
                    # CE core groups alerts by record["alert_type"] and uses
                    # that value as the subtype for routing and the
                    # destination mapping. The /v2/alerts records carry no
                    # type field, so stamp the CE subtype on each one, or
                    # core drops the batch with a swallowed KeyError.
                    for record in data:
                        if isinstance(record, dict):
                            record["alert_type"] = sub_type
                batch.extend(data)
                pages_in_batch += 1
                if pages_in_batch >= constants.BATCH_PAGE_COUNT:
                    yield batch, sub_type.lower(), page_count
                    batch = []
                    pages_in_batch = 0
            page_count += 1
        if batch:
            # Flush the final partial batch (fewer than BATCH_PAGE_COUNT
            # pages, or the pages left after the last full batch).
            yield batch, sub_type.lower(), page_count
        if checkpoint_key and (
            not is_historical or filter_type == constants.FILTER_ENTITY
        ):
            # Advance this subtype's own high water mark to the end of the
            # window. A historical window is never recorded, as it would
            # rewind the maintenance checkpoint and re-deliver data (entity
            # pulls are incremental and keep their existing behaviour). It
            # is advanced here, after the page loop, so a subtype
            # that failed earlier (and never reached this point) re-pulls its
            # window on the next cycle. 'storage' is a read-only property,
            # hence it is mutated in place; the value is also persisted on
            # the tenant (the source of truth), and the entity checkpoints
            # are cleared by the CRE plugin cleanup on delete.
            if isinstance(self.storage, dict):
                self.storage[checkpoint_key] = end_time
            plugin_provider_helper.update_tenant_storage(
                self.name, {checkpoint_key: end_time}
            )
        if total_records == 0:
            # No records returned for this window. Emit an explicit
            # zero-pull summary so idle subtypes (e.g. bwan_alert_v2) remain
            # visible in the logs instead of silently producing no output.
            self.log_message(
                [], sub_type, pull_type, None, None, None,
                start_time, end_time, max(page_count - 1, 1), data_type,
            )

    # Now format the datetime object to the desired format
    def paginate(
        self,
        sub_type_list,
        start_time,
        end_time,
        pull_type,
        data_type,
    ):
        """
        Paginate through the Netskope BWAN tenant and pull data accordingly.

        Args:
            sub_type_list (list): A list of subtypes to pull.
            start_time (datetime or str): The start time for pulling.
            end_time (datetime or str): The end time for pulling.
            data_type (str): Data type being pulled (events or alerts).

        Yields:
            tuple: A tuple containing the page of data, subtype and page count.
        """
        #
        tenantName = self.configuration.get("tenantName", "").strip().rstrip()
        token = self._get_token()
        event_endpoint = f"{tenantName}{constants.AUDIT_RECORDS_ENDPOINT}"
        start_time = self.format_to_iso8601(start_time)
        end_time = self.format_to_iso8601(end_time)
        item_label = (
            "alert" if data_type == constants.TYPE_ALERT else "event"
        )

        # Subtypes served by their own endpoint are pulled separately, then
        # removed from the list so the audit flow below is untouched. When no
        # audit subtype is configured there is nothing left to pull here, and
        # returning early avoids an unfiltered pull of every audit event.
        dedicated_sub_types = [
            sub_type
            for sub_type in sub_type_list
            if sub_type in constants.DEDICATED_ENDPOINT_CONFIG
        ]
        for mapped_sub_type in dedicated_sub_types:
            # Isolate each dedicated endpoint: a permission or transport
            # error on one subtype (e.g. Flows) must not stop the others or
            # the audit pull below. The failed subtype's checkpoint is not
            # advanced, so it re-pulls its window once the issue is resolved.
            try:
                yield from self.paginate_dedicated_endpoint(
                    mapped_sub_type,
                    start_time,
                    end_time,
                    pull_type,
                    data_type,
                )
            except BWANForbiddenException:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Access was denied for the "
                        f"'{mapped_sub_type}' endpoint; skipping it for this "
                        "window and continuing with the other subtypes."
                    ),
                    details=traceback.format_exc(),
                )
            except Exception:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while pulling "
                        f"the '{mapped_sub_type}' endpoint; skipping it for "
                        "this window and continuing with the other subtypes."
                    ),
                    details=traceback.format_exc(),
                )
        sub_type_list = [
            sub_type
            for sub_type in sub_type_list
            if sub_type not in constants.DEDICATED_ENDPOINT_CONFIG
        ]
        if not sub_type_list:
            return

        headers = {"Authorization": f"Bearer {token}"}
        params = {"first": constants.PAGE_SIZE}
        sub_types = (
            " AND (type: "
            + " OR type:".join([sub_type.upper() for sub_type in sub_type_list])  # noqa
            + ")"
            if sub_type_list
            else ""
        )
        params["filter"] = (
            f"event_time>='{start_time}' "
            f"AND event_time<'{end_time}'{sub_types}"
        )
        reverse_sub_type_mapping = constants.REVERSE_SUBTYPE_LIST_MAPPING
        seen_sub_types = set()

        def flush_buffers(buffers, page):
            # Yield one combined batch per buffered audit subtype.
            for buffered_sub_type, buffered_data in buffers.items():
                if buffered_data:
                    yield buffered_data, buffered_sub_type, page

        # Accumulate up to BATCH_PAGE_COUNT pages into per-subtype buffers so
        # each audit subtype yields fewer, larger CE batches instead of one
        # per page (O-2). The /v2/auditevents call returns mixed subtypes, so
        # buffer them separately and flush every BATCH_PAGE_COUNT pages.
        buffers = {}
        pages_in_batch = 0
        next_page = True
        page_count = 1
        while next_page:
            if back_pressure.STOP_PULLING:
                self.logger.debug(
                    f"{pull_type} of {sub_types} {item_label}(s) for tenant "
                    f"{tenantName} is paused due to back pressure."
                )
                time.sleep(constants.BACK_PRESSURE_WAIT_TIME)
                continue
            logger_msg = (
                f"fetching {item_label}(s) of type(s) - "
                f"[{sub_type_list}], PAGE: {page_count}"
            )
            try:
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
            except Exception:
                # Hand over the pages accumulated before this failure so they
                # are not lost, then let the error propagate (O-2).
                yield from flush_buffers(buffers, page_count)
                raise
            page_info = resp_json.get("page_info", {})
            next_page = page_info.get("has_next", False)
            cursor = page_info.get("end_cursor")
            if next_page and (not cursor or cursor == params.get("after")):
                # 'has_next' is true but the cursor did not advance; stop so
                # the same page is not requested forever.
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Pagination stopped for "
                        f"{sub_type_list}; 'has_next' is true without a new "
                        "cursor."
                    ),
                    details=f"page_info: {page_info}",
                )
                break
            if next_page:
                params["after"] = cursor

            bifurcated_data = self.bifurcate_sub_type_data(resp_json)
            for sub_type, data in bifurcated_data.items():
                if data:
                    seen_sub_types.add(sub_type.lower())
                    buffers.setdefault(sub_type.lower(), []).extend(data)
            pages_in_batch += 1
            if pages_in_batch >= constants.BATCH_PAGE_COUNT:
                yield from flush_buffers(buffers, page_count)
                buffers = {}
                pages_in_batch = 0
            page_count += 1
        # Flush the final partial batch for every buffered subtype.
        yield from flush_buffers(buffers, page_count)
        # Emit an explicit zero-pull summary for every configured audit subtype
        # that returned no records in this window, mirroring the non-empty
        # "Pulled N ..." logs so idle subtypes stay visible.
        for mapped_sub_type in sub_type_list:
            display_sub_type = reverse_sub_type_mapping.get(
                mapped_sub_type, mapped_sub_type
            )
            if display_sub_type.lower() not in seen_sub_types:
                self.log_message(
                    [], display_sub_type, pull_type, None, None, None,
                    start_time, end_time, max(page_count - 1, 1), data_type,
                )

    def update_storage_checkpoint(
        self, end_time, data_type
    ):
        """
        Updates the checkpoint in storage for the given tenant.

        Args:
            end_time (datetime or str): The new checkpoint time.
            data_type (str): Data type the checkpoint belongs to. Events and
            alerts are pulled independently and share one storage dict, so
            each keeps its own checkpoint key.

        Returns:
            None
        """
        checkpoint_key = f"{data_type}_checkpoint"
        self.storage[checkpoint_key] = end_time
        # Write only this data type's key. The events and alerts tasks run
        # concurrently and each holds a stale snapshot of the other's key,
        # so writing the whole dict would roll the other task's checkpoint
        # back and cause duplicate delivery.
        plugin_provider_helper.update_tenant_storage(
            self.name, {checkpoint_key: end_time}
        )

    def load_maintenance(
        self,
        sub_type_list,
        pull_type,
        data_type,
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
        checkpoint_key = f"{data_type}_checkpoint"
        if storage_dict and storage_dict.get(checkpoint_key):
            start_time = storage_dict.get(checkpoint_key, datetime.now())
        else:
            start_time = self.last_run_at or datetime.now()

        while True:
            try:
                tenant = plugin_provider_helper.get_tenant_details(
                    tenant_name, data_type
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
                data_type,
            ):
                yield page, sub_type, start_time, end_time, page_count

            self.update_storage_checkpoint(end_time, data_type)
            time.sleep(constants.DEFAULT_WAIT_TIME)
            start_time = end_time

    def load_historical(
        self,
        sub_type_list,
        start_time,
        end_time,
        pull_type,
        data_type,
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
                tenant_name, data_type
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
            pull_type,
            data_type,
        ):
            yield page, sub_type, start_time, end_time, page_count

    def resolve_sub_types(
        self,
        sub_type_config_mapping,
        override_subtypes,
        data_type,
        pull_type,
        configuration_name,
        unknown_sub_types,
    ):
        """Resolve the sub types to pull and map them to their API names.

        Args:
            sub_type_config_mapping (dict): Sub type to configuration names,
            as returned by get_sub_type_config_mapping().
            override_subtypes (list): Sub types the caller asked for, if any.
            data_type (str): Data type being pulled (events or alerts).
            pull_type (str): The type of pulling.
            configuration_name (str): Name of the configuration that the pull
            was triggered for. Only set for a historical pull.
            unknown_sub_types (set): Sub types already reported as unknown.
            Mutated in place so the same sub type is not logged again on
            every refresh of the mapping.

        Returns:
            list: SUBTYPE_LIST_MAPPING values of the sub types to pull.
        """
        if override_subtypes:
            selected_sub_types = list(override_subtypes)
        else:
            # Core passes the CLS parameters "event_type"/"alert_types" as
            # the historical override; this plugin stores them under other
            # keys, so a historical pull arrives with []. Scope the fallback
            # to the source configuration instead of the tenant-wide union,
            # so a historical pull ingests only the sub types that this
            # configuration selected.
            selected_sub_types = [
                sub_type
                for sub_type, config_names in (
                    sub_type_config_mapping.items()
                )
                if pull_type != constants.HISTORICAL_PULL
                or configuration_name in config_names
            ]

        mapped_sub_types = []
        for sub_type in selected_sub_types:
            mapped_sub_type = constants.SUBTYPE_LIST_MAPPING.get(sub_type)
            if mapped_sub_type is None:
                # Skip a sub type that is missing from the mapping table
                # instead of raising a KeyError, which would abort the pull
                # for every configuration on this tenant.
                if sub_type not in unknown_sub_types:
                    unknown_sub_types.add(sub_type)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Skipping the unsupported "
                            f"sub type '{sub_type}' of {data_type} while "
                            f"pulling from {constants.PLATFORM_NAME}."
                        ),
                        details=(
                            "Supported sub types: "
                            f"{list(constants.SUBTYPE_LIST_MAPPING.keys())}."
                        ),
                    )
                continue
            mapped_sub_types.append(mapped_sub_type)
        return mapped_sub_types

    def refresh_sub_type_config_mapping(
        self,
        sub_type_config_mapping,
        sub_type_list,
        latest_checked,
        data_type,
        pull_type,
        configuration_name,
        unknown_sub_types,
    ):
        """Refresh the sub type to configuration mapping mid-pull.

        A pull task runs for an hour, so a mapping resolved once at the start
        is stale for the rest of it: core routes each page with the mapping
        the plugin yields, so a configuration that deselects a sub type keeps
        receiving it, and a newly selected sub type is not pulled at all.
        get_sub_type_config_mapping() only queries the database once every
        DB_LOOKUP_INTERVAL, so this is safe to call on every page.

        Args:
            sub_type_config_mapping (dict): The mapping resolved so far.
            sub_type_list (list): The sub types the pull is iterating over.
            Updated in place, because load_maintenance() passes this same
            list object to paginate() on every window.
            latest_checked (datetime): When the mapping was last read from
            the database.
            data_type (str): Data type being pulled (events or alerts).
            pull_type (str): The type of pulling.
            configuration_name (str): Name of the configuration that the
            pull was triggered for.
            unknown_sub_types (set): Sub types already reported as unknown.

        Returns:
            tuple: The refreshed mapping and the new latest_checked.
        """
        sub_type_config_mapping, latest_checked = (
            get_sub_type_config_mapping(
                self.name,
                data_type,
                latest_checked,
                sub_type_config_mapping,
            )
        )
        sub_type_list[:] = self.resolve_sub_types(
            sub_type_config_mapping,
            None,
            data_type,
            pull_type,
            configuration_name,
            unknown_sub_types,
        )
        return sub_type_config_mapping, latest_checked

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
        if data_type not in (constants.TYPE_EVENT, constants.TYPE_ALERT):
            error_msg = (
                f"The {constants.PLATFORM_NAME} only supports events "
                "and alerts."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}",
                details=f"Received Data Type: {data_type}",
            )
            raise NetskopeBWANProviderPluginException(error_msg)

        item_label = (
            "alert" if data_type == constants.TYPE_ALERT else "event"
        )
        try:
            page_data = []
            sub_type_config_mapping = {}
            sub_type = ""

            latest_checked = None
            unknown_sub_types = set()
            # The mapping is only owned by this plugin when the caller did
            # not override the sub types; only then is it refreshed and
            # yielded to core for routing.
            refresh_mapping = not override_subtypes
            if refresh_mapping:
                sub_type_config_mapping, latest_checked = (
                    get_sub_type_config_mapping(self.name, data_type)
                )
            sub_type_list = self.resolve_sub_types(
                sub_type_config_mapping,
                override_subtypes,
                data_type,
                pull_type,
                configuration_name,
                unknown_sub_types,
            )
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
                    data_type,
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
                        page,
                        data_type,
                    )
                    if refresh_mapping:
                        sub_type_config_mapping, latest_checked = (
                            self.refresh_sub_type_config_mapping(
                                sub_type_config_mapping,
                                sub_type_list,
                                latest_checked,
                                data_type,
                                pull_type,
                                configuration_name,
                                unknown_sub_types,
                            )
                        )
                    yield page_data, sub_type, sub_type_config_mapping, False
            else:
                for page_data, sub_type, start_time, end_time, page in self.load_maintenance(  # noqa
                    sub_type_list,
                    pull_type,
                    data_type,
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
                        page,
                        data_type,
                    )
                    if refresh_mapping:
                        sub_type_config_mapping, latest_checked = (
                            self.refresh_sub_type_config_mapping(
                                sub_type_config_mapping,
                                sub_type_list,
                                latest_checked,
                                data_type,
                                pull_type,
                                configuration_name,
                                unknown_sub_types,
                            )
                        )
                    yield page_data, sub_type, sub_type_config_mapping, False

        except BWANForbiddenException:
            # The last page was already yielded, so yield an empty page here.
            # Re-yielding it would deliver the same records twice before core
            # backs off for the rest of the hour.
            yield [], sub_type, sub_type_config_mapping, True

        except NetskopeBWANProviderPluginException:
            raise

        except Exception as err:
            error_msg = (
                f"Error occurred while fetching {item_label}(s) "
                f"from {constants.PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise NetskopeBWANProviderPluginException(error_msg)
        finally:
            # Stop the back pressure thread, which otherwise keeps probing
            # the disk and the database every BACK_PRESSURE_WAIT_TIME for
            # the lifetime of the worker process.
            self.should_exit.set()

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

    def permission_check(
        self, type_map, plugin_name=None, configuration_name=None
    ):
        """Verify the Auth Token can read the selected dedicated endpoints.

        validate_token probes only /v2/auditevents, so a token that can read
        Audit but not Monitor > Flows or Alerts (V2) would pass validation
        and then fail silently at pull time (and, with the per-subtype
        isolation, be skipped). Each selected dedicated endpoint is therefore
        probed here with a GET ...?first=1 at configuration time.

        Args:
            type_map (dict): {"events": [subtypes], "alerts": [subtypes]} —
                the CE subtypes the configuration selected.
            plugin_name (str, optional): Calling plugin name, for messages.
            configuration_name (str, optional): Configuration name, for
                messages.

        Returns:
            bool: True when every selected dedicated endpoint is readable.

        Raises:
            NetskopeBWANProviderPluginException: When a selected dedicated
                endpoint is forbidden or cannot be reached.
        """
        tenantName = (
            self.configuration.get("tenantName", "").strip().rstrip("/")
        )
        token = resolve_secret(self.configuration.get("v2token"))
        headers = {"Authorization": f"Bearer {token}"}
        # Only the dedicated endpoints need an explicit probe. The audit
        # subtypes share /v2/auditevents (already covered by validate_token)
        # and are not in DEDICATED_ENDPOINT_CONFIG, so they fall through. The
        # entity endpoints (/v2/clients, /v2/gateways) are probed when a CRE
        # configuration passes their subtypes.
        endpoints = {}
        for sub_types in (type_map or {}).values():
            for sub_type in sub_types or []:
                sub_type_mapping = constants.SUBTYPE_LIST_MAPPING.get(
                    sub_type, ""
                )
                config = constants.DEDICATED_ENDPOINT_CONFIG.get(
                    sub_type_mapping
                )
                if config:
                    # ended_at query parameter is mandatory while making
                    # /v2/networkevents API call
                    if sub_type_mapping == "network_event":
                        current_time = datetime.strftime(
                            datetime.now(timezone.utc) - timedelta(seconds=1),
                            constants.DATE_FORMAT,
                        )
                        endpoints[
                            config["sub_type"]
                        ] = (config["endpoint"], f"ended_at>'{current_time}'")
                    else:
                        endpoints[
                            config["sub_type"]
                        ] = (config["endpoint"], None)
        forbidden = []
        for sub_type, (endpoint, filter) in endpoints.items():
            try:
                params = {"first": 1}
                if filter:
                    params["filter"] = filter
                self.bwan_provider_helper.api_helper(
                    logger_msg=(
                        f"validating access to the {sub_type} endpoint"
                    ),
                    url=f"{tenantName}{endpoint}",
                    method="GET",
                    params=params,
                    headers=headers,
                    proxies=self.proxy,
                    is_validation=True,
                    is_handle_error_required=True,
                )
            except BWANForbiddenException:
                forbidden.append(endpoint)
        if forbidden:
            suffix = ""
            if plugin_name:
                suffix = (
                    f" for {plugin_name} [{configuration_name}]"
                    if configuration_name
                    else f" for {plugin_name}"
                )
            err_msg = (
                f"The Auth Token cannot read {', '.join(sorted(forbidden))}"
                f"{suffix}. Grant access to Monitor > Flows and Alerts (V2) "
                "on the Netskope Borderless WAN tenant, or deselect those "
                "types."
            )
            self.logger.error(message=f"{self.log_prefix}: {err_msg}")
            raise NetskopeBWANProviderPluginException(err_msg)
        return True

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
