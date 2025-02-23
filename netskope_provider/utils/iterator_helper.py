"""Pulling mechanism using iterator."""

import os
import threading
import time
import re
import gzip
import json
from queue import Queue
import traceback
from datetime import datetime
from typing import List
from urllib.parse import urlparse

import requests.exceptions
from celery.exceptions import SoftTimeLimitExceeded
from netskope_api.iterator.const import Const
from netskope_api.iterator.netskope_iterator import NetskopeIterator
from netskope.common.api import __version__
from netskope.common.utils import (
    Logger,
    DBConnector,
    Collections,
    Notifier,
    back_pressure,
)
from netskope.common.utils.decorator import retry
from netskope.common.utils.exceptions import IncompleteTransactionError, ForbiddenError
from netskope.common.utils.handle_exception import handle_status_code
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper

DB_LOOKUP_INTERVAL = 120

connector = DBConnector()
logger = Logger()
notifier = Notifier()
plugin_provider_helper = PluginProviderHelper()

ALERTS = {
    "Compromised Credential": Const.ALERT_TYPE_COMPROMISEDC_CREDENTIALS,
    "policy": Const.ALERT_TYPE_POLICY,
    "malsite": Const.ALERT_TYPE_MALSITE,
    "Malware": Const.ALERT_TYPE_MALWARE,
    "DLP": Const.ALERT_TYPE_DLP,
    "Security Assessment": Const.ALERT_TYPE_SECURITY_ASSESSMENT,
    "watchlist": Const.ALERT_TYPE_WATCHLIST,
    "quarantine": Const.ALERT_TYPE_QUARANTINE,
    "Remediation": Const.ALERT_TYPE_REMEDIATION,
    "uba": Const.ALERT_TYPE_UBA,
    "ctep": Const.ALERT_TYPE_CTEP,
}
EVENTS = {
    "page": Const.EVENT_TYPE_PAGE,
    "infrastructure": Const.EVENT_TYPE_INFRASTRUCTURE,
    "network": Const.EVENT_TYPE_NETWORK,
    "audit": Const.EVENT_TYPE_AUDIT,
    "application": Const.EVENT_TYPE_APPLICATION,
    "incident": Const.EVENT_TYPE_INCIDENT,
    "endpoint": "endpoint",
}

ITERATORS = {
    key.lower(): list({x.strip() for x in value.split(',') if x.strip() != ""})
    for key, value in os.environ.items()
    if key.lower().startswith("iterator_")
}

RESOURCES = {"alert": ALERTS, "event": EVENTS}

DATA_TYPE = {"alert": "alerts", "event": "events"}

OK_PATTERN = rb"\"ok\"\s*:\s*(\d+)"
TIMESTAMP_HWM_PATTERN = rb"\"timestamp_hwm\"\s*:\s*(\d+)"
WAIT_TIME_PATTERN = rb"\"wait_time\"\s*:\s*(\d+)"
ID_PATTERN = rb'\"_id"\s*:'
RESULT = "result"
TIMESTAMP_HWM = "timestamp_hwm"
QUEUE_SIZE = 10
DEFAULT_WAIT_TIME = 30
EXPONENTIAL_WAIT_TIME = 180
WAIT_TIME = "wait_time"
DEFAULT_RETRY_COUNT = 3
RETRY_COUNT_FOR_PULLING = os.environ.get("RETRY_COUNT_FOR_PULLING")
if isinstance(RETRY_COUNT_FOR_PULLING, str) and RETRY_COUNT_FOR_PULLING.isnumeric():
    RETRY_COUNT_FOR_PULLING = int(RETRY_COUNT_FOR_PULLING)
    if RETRY_COUNT_FOR_PULLING < 1:
        RETRY_COUNT_FOR_PULLING = DEFAULT_RETRY_COUNT
else:
    RETRY_COUNT_FOR_PULLING = DEFAULT_RETRY_COUNT


class NetskopeIteratorBuilder(NetskopeIterator):
    """Extends pulling utilities of Netskope Iterator."""

    def __init__(
        self,
        tenant,
        type_,
        sub_type,
        iterator_name,
        handle_forbidden=False,
        return_response=False,
        epoch=None,
        source_configuration=None,
        destination_configuration=None,
        business_rule=None,
        headers=None,
    ):
        """Initialize Netskope iterator."""
        from netskope.common.utils import get_installation_id

        self.tenant = tenant
        self.tenant_name = tenant.get("name") if tenant else ""
        tenant_config_parameters = tenant.get("parameters", {})
        iterator_name = iterator_name.replace(" ", "")
        proxy = {}
        if tenant.get("use_proxy"):
            proxy = tenant.get("proxy")
        self.epoch = epoch
        self.index_name = iterator_name
        self.type = type_
        self.sub_type = sub_type
        self.source_configuration = source_configuration
        self.destination_configuration = destination_configuration
        self.business_rule = business_rule
        self.time = 0
        self.handle_forbidden = handle_forbidden
        self.return_response = return_response
        self.timestamp_hwm = None
        self.should_apply_expo_backoff = False
        from netskope.common.utils import resolve_secret

        if headers is None:
            headers = {}

        params = {
            Const.NSKP_TOKEN: resolve_secret(tenant_config_parameters.get("v2token")),
            Const.NSKP_TENANT_HOSTNAME: tenant_config_parameters.get(
                "tenantName"
            ).removeprefix("https://"),
            Const.NSKP_PROXIES: proxy,
            Const.NSKP_ITERATOR_NAME: iterator_name,
            Const.NSKP_USER_AGENT: headers.get(
                "User-Agent", f"netskope-ce-{__version__}"
            ),
        }

        if sub_type in EVENTS:
            params[Const.NSKP_EVENT_TYPE] = sub_type
        else:
            params[Const.NSKP_EVENT_TYPE] = Const.EVENT_TYPE_ALERT
            params[Const.NSKP_ALERT_TYPE] = ALERTS.get(sub_type)
        super().__init__(params)

        self.client.session.headers.update(
            {"X-CE-Installation-Id": get_installation_id()}
        )

    def set_timestamp(self, epoch):
        """Set epoch timestamp."""
        self.epoch = epoch

    @retry(
        times=RETRY_COUNT_FOR_PULLING,
        exceptions=(
            ConnectionError,
            IncompleteTransactionError,
            requests.exceptions.ConnectionError,
        ),
        sleep=DEFAULT_WAIT_TIME,
    )
    def pull(self, parse_response=True, return_schema_headers=False):
        """Pull data from Netskope."""
        from netskope.common.utils.forbidden_notifier import (
            create_or_ack_forbidden_error_banner,
        )

        content = {}
        while True:
            if not self.tenant:
                logger.error(
                    f"Tenant with name {self.tenant_name} no longer exists.",
                    error_code="CE_1032",
                )
                return {"success": False}
            index_names = []
            for sub_type_indexes in ITERATORS.values():
                index_names.extend(sub_type_indexes)
            if self.epoch and self.index_name not in index_names:
                data = self.download(self.epoch)
            else:
                data = self.next()
            if self.return_response:
                return data
            uri = urlparse(data.url).path
            try:
                if (
                    not data.content
                    and data.headers.get("Content-Type", "").lower()
                    != "text/csv"
                ):
                    raise IncompleteTransactionError("Received empty response.")
                content = handle_status_code(
                    data,
                    error_code="CE_1061",
                    custom_message=(
                        f"Error occurred while fetching {self.sub_type} {self.type} "
                        f"from the tenant {self.tenant_name}"
                    ),
                    notify=False,
                    handle_forbidden=self.handle_forbidden,
                    parse_response=parse_response,
                )
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code in [409, 429]:
                    logger.error(
                        f"Received status code {e.response.status_code} while pulling {self.sub_type} "
                        f"{self.type} for the tenant {self.tenant_name}. "
                        f"Performing retry for url {e.response.url}. "
                        f"Retrying in {DEFAULT_WAIT_TIME} seconds."
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                    continue
                elif e.response is not None and e.response.status_code == 401:
                    self.should_apply_expo_backoff = True
                    update_set = {"is_v2_token_expired": True}
                    plugin_provider_helper.update_tenant_storage(
                        self.tenant_name, update_set
                    )
                    create_or_ack_forbidden_error_banner()
                raise IncompleteTransactionError(
                    f"Received error while pulling "
                    f"{self.sub_type} {self.type}. Error: {e}"
                )
            except (ConnectionError, IncompleteTransactionError) as e:
                raise ConnectionError(
                    f"Connection error occurred while pulling {self.sub_type} {self.type}. "
                    f"Error: {e}"
                )
            except ForbiddenError as e:
                self.should_apply_expo_backoff = True
                update_set = {
                    f"forbidden_endpoints.{self.sub_type}": uri,
                    "is_v2_token_expired": False,
                }
                plugin_provider_helper.update_tenant_storage(
                    self.tenant_name, update_set
                )
                create_or_ack_forbidden_error_banner()
                raise e
            except Exception as e:
                logger.error(
                    f"Error occurred while pulling {self.sub_type} {self.type} "
                    f"for the tenant {self.tenant_name}. {e}",
                    details=traceback.format_exc(),
                    error_code="CE_1112",
                )  # TODO: Need to confirm error code
                raise e
            self.epoch = None

            update_set = {"is_v2_token_expired": False}
            update_unset = {f"forbidden_endpoints.{self.sub_type}": ""}
            new_document = plugin_provider_helper.update_tenant_storage(
                self.tenant_name, update_set, update_unset, True
            )
            new_forbidden_endpoints = new_document.get("storage", {}).get("forbidden_endpoints") if new_document else {}
            current_forbidden_endpoints = self.tenant.get("storage", {}).get(
                "forbidden_endpoints"
            ) if self.tenant else {}
            is_forbidden_value_changed = new_forbidden_endpoints != current_forbidden_endpoints
            if (
                (
                    self.tenant and 
                    self.tenant.get("storage", {}).get("is_v2_token_expired")
                )
                or is_forbidden_value_changed
            ):
                create_or_ack_forbidden_error_banner()
            if not return_schema_headers:
                return content
            else:
                headers = data.headers.get("schema_headers")
                if headers:
                    try:
                        headers = json.loads(headers.replace("'", '"'))
                    except json.decoder.JSONDecodeError:
                        return content, None
                return content, headers


class NetskopeClient:
    """Netskope client to pull data."""

    ALERT = "alert"
    EVENT = "event"
    MAINTENANCE_PULLING = "maintenance_pulling"
    HISTORICAL_PULLING = "historical_pulling"
    BACK_PRESSURE_WAIT_TIME = 300

    def __init__(
        self,
        tenant,
        iterator_name,
        type_,
        pulling_type=MAINTENANCE_PULLING,
        start_time=None,
        end_time=None,
        handle_forbidden=False,
        source_configuration=None,
        destination_configuration=None,
        business_rule=None,
        compress_historical_data=False,
        headers=None,
    ):
        """Initialize netskope client."""
        self.tenant = tenant
        self.tenant_name = tenant.get("name") if tenant else ""
        self.type = type_

        self.start_time, self.end_time = None, None
        if start_time:
            self.start_time = int(start_time.strftime("%s"))
        if end_time:
            self.end_time = int(end_time.strftime("%s"))

        self.message_queue = Queue(maxsize=QUEUE_SIZE)
        self.lock = threading.Lock()
        self.running_thread = 0
        self.should_exit = threading.Event()
        self.iterator_name = iterator_name
        self.iterators = {}
        self.threads = set()
        self._sub_types = []
        self.pulling_type = pulling_type
        self.handle_forbidden = handle_forbidden
        self.pulling_started = False
        self.source_configuration = source_configuration
        self.destination_configuration = destination_configuration
        self.business_rule = business_rule
        self.compress_historical_data = compress_historical_data
        self.headers = headers

    def get_iterator(
        self, sub_type, iterator_name, is_historical=False
    ) -> NetskopeIteratorBuilder:
        """Return an iterator subtype."""
        if not self.iterators.get(iterator_name):
            self.iterators[iterator_name] = NetskopeIteratorBuilder(
                self.tenant,
                self.type,
                sub_type,
                iterator_name,
                handle_forbidden=self.handle_forbidden,
                source_configuration=self.source_configuration,
                destination_configuration=self.destination_configuration,
                business_rule=self.business_rule,
                headers=self.headers,
            )
        return self.iterators[iterator_name]

    def get_target_function(self):
        """Get target function to pull the data."""
        if self.pulling_type == NetskopeClient.MAINTENANCE_PULLING:
            return self.load
        if self.pulling_type == NetskopeClient.HISTORICAL_PULLING:
            return self.load_historical

    @property
    def sub_types(self):
        """Return all sub_types."""
        return self._sub_types

    def get_indexes(self, sub_types):
        iterator_subtype_indexes = {}
        iterator_indexes = []
        for sub_type in set(sub_types):
            indexes = (
                [self.iterator_name % sub_type]
                if self.pulling_type == NetskopeClient.HISTORICAL_PULLING
                else (
                    ITERATORS.get(f"iterator_{self.type.lower()}_{sub_type.lower().replace(' ', '_')}")
                    or [self.iterator_name % sub_type]
                )
            )
            iterator_subtype_indexes[sub_type] = indexes
            iterator_indexes.extend(indexes)
        return iterator_subtype_indexes, iterator_indexes

    @sub_types.setter
    def sub_types(self, sub_types):
        """Spawn dedicated thread for pulling."""
        iterator_subtype_indexes, iterator_indexes = self.get_indexes(sub_types)
        if set(iterator_indexes) == self.threads:
            self._sub_types = iterator_indexes
            return
        self._sub_types = iterator_indexes
        for sub_type, iterator_names in iterator_subtype_indexes.items():
            for iterator_name in iterator_names:
                iterator_name = iterator_name.strip()
                if iterator_name not in self.threads:
                    self.threads.add(iterator_name)
                    thread_process = threading.Thread(
                        target=self.get_target_function(), args=(sub_type, iterator_name, )
                    )
                    thread_process.start()
                    self.running_thread += 1

        for type_ in self.threads.copy():
            if type_ not in iterator_indexes:
                self.threads.remove(type_)

    def create_job(self):
        """Create queue and threads for pull alerts."""
        try:
            start_time = self.start_time or int(datetime.now().timestamp())
            while self.running_thread:
                yield self.message_queue.get()
            while not self.message_queue.empty():
                yield self.message_queue.get()
            end_time = self.end_time or int(datetime.now().timestamp())
            logger.info(
                f"Completed pull task for {datetime.fromtimestamp(start_time)} "
                f"to {datetime.fromtimestamp(end_time)} time interval, "
                f"Pulled {self.type} from {self.tenant_name} tenant."
            )
        except SoftTimeLimitExceeded as ex:
            raise ex
        except Exception as ex:
            logger.error(
                "Error occurred while running the pull threads for "
                f"{self.type} for the tenant {self.tenant_name}. {ex}",
                details=traceback.format_exc(),
                error_code="CE_1112",
            )

    def update_pull_status(self, sub_type):
        """Update first alert pull in database."""
        name = f"first_{self.type}_pull"
        sub_name = f"first_{sub_type}_pull"
        tenant_storage = self.tenant.get("storage", {}) if self.tenant else {}
        if tenant_storage.get(name, {}).get(sub_name, True):
            update_set = {
                f"{name}.{sub_name}": False,
                f"disabled_{self.type}_pull.disabled_{sub_type}_pull": None,
            }
            plugin_provider_helper.update_tenant_storage(
                self.tenant_name, update_set
            )
            # connector.collection(Collections.NETSKOPE_TENANTS).update_one(
            #     {"name": f"{self.tenant.name}"},
            #     {"$set": {
            #         f"{name}.{sub_name}": False,
            #         f"disabled_{self.type}_pull.disabled_{sub_type}_pull": None
            #     }
            #     },
            # )

    def load(self, sub_type: str, iterator_name: str):
        """Pull mechanism."""
        try:
            start_time = datetime.now()
            iterator = self.get_iterator(sub_type, iterator_name)

            tenant_dict_storage = self.tenant.get("storage", {})
            if tenant_dict_storage.get(f"first_{self.type}_pull", {}).get(
                f"first_{sub_type}_pull", True
            ):
                if (
                    type(
                        tenant_dict_storage.get(f"disabled_{self.type}_pull", {}).get(
                            f"disabled_{sub_type}_pull"
                        )
                    )
                    == int
                ):
                    iterator.set_timestamp(
                        tenant_dict_storage.get(f"disabled_{self.type}_pull", {}).get(
                            f"disabled_{sub_type}_pull"
                        )
                    )
                else:
                    initial_pull = self.tenant.get("checkpoint")
                    if not initial_pull:
                        initial_pull = datetime.now()

                    initial_pull = initial_pull.replace(
                        minute=0, second=0, microsecond=0
                    ).strftime("%s")
                    iterator.set_timestamp(initial_pull)

            self.should_exit.clear()
            back_pressure_thread = threading.Thread(
                target=back_pressure.should_stop_pulling,
                daemon=True,
                args=(self.should_exit,),
            )
            back_pressure_thread.start()

            while True:
                if not self.tenant:
                    logger.error(
                        f"Tenant with name {self.tenant_name} no longer exists.",
                        error_code="CE_1030",
                    )
                    return {"success": False}
                now = datetime.now()
                time_delta = now - start_time
                hours = time_delta.total_seconds() // 3600
                if hours >= 1:
                    return {"success": True}

                if back_pressure.STOP_PULLING:
                    logger.debug(
                        f"Pulling of {sub_type} {self.type}(s) for tenant {self.tenant_name} "
                        "is stopped due to back pressure."
                    )
                    return {"success": False}

                try:
                    self.tenant = plugin_provider_helper.get_tenant_details(
                        self.tenant_name, DATA_TYPE[self.type]
                    )
                except Exception:
                    logger.error(
                        f"Tenant with name {self.tenant_name} no longer exists.",
                        error_code="CE_1033",
                    )
                    return {"success": False}

                if not (
                    plugin_provider_helper.is_netskope_plugin_enabled(
                        self.tenant.get("name")
                    )
                    and plugin_provider_helper.is_module_enabled()
                ):
                    update_set_data = {
                        f"first_{self.type}_pull.first_{sub_type}_pull": True,
                    }
                    if iterator.timestamp_hwm:
                        update_set_data[
                            f"disabled_{self.type}_pull.disabled_{sub_type}_pull"
                        ] = iterator.timestamp_hwm

                    plugin_provider_helper.update_tenant_storage(
                        self.tenant.get("name"), update_set_data
                    )

                    return {"success": True}

                if iterator_name not in self.sub_types:
                    return {"success": True}

                self.pulling_started = True
                response, headers = iterator.pull(
                    parse_response=False, return_schema_headers=True
                )
                if headers:  # data is in CSV format
                    wait_time = headers.get("wait_time", DEFAULT_WAIT_TIME)
                    schema_headers = {
                        key.encode(): b"version," + value.encode()
                        for key, value in headers.items()
                        if key.lower().startswith("v")
                    }
                    if response:
                        response = response.splitlines()
                        logger.info(
                            f"Pulled {len(response)} {sub_type} {self.type}(s) for tenant "
                            f"{self.tenant.get('name')} in CSV format using {iterator_name} index."
                        )
                        for key, header in schema_headers.items():
                            batch = b"\n".join(
                                [
                                    header,
                                    b"\n".join(
                                        filter(
                                            lambda x: x.startswith(key),
                                            response,
                                        )
                                    ),
                                ]
                            )
                            content = gzip.compress(batch, compresslevel=3)
                            self.message_queue.put((content, sub_type, False, True))
                    else:
                        logger.info(
                            f"Pulled 0 {sub_type} {self.type}(s) for tenant "
                            f"{self.tenant.get('name')} in CSV format using {iterator_name} index."
                        )
                else:
                    number_of_alerts = len(re.findall(ID_PATTERN, response))
                    ok_match = re.search(OK_PATTERN, response)
                    timestamp_hwm_match = re.search(
                        TIMESTAMP_HWM_PATTERN, response
                    )
                    if timestamp_hwm_match:
                        iterator.timestamp_hwm = int(
                            timestamp_hwm_match.group(1).decode()
                        )
                    wait_time_match = re.search(WAIT_TIME_PATTERN, response)
                    if not response or (
                        ok_match and int(ok_match.group(1).decode()) != 1
                    ):
                        message = (
                            f"Error occurred while pulling {sub_type} {self.type} from {self.tenant} tenant. "
                            f"Response: {response}"
                        )
                        notifier.error(message)
                        logger.error(message)
                        return {"success": False}
                    pull_message = (
                        f", pulled data till {datetime.fromtimestamp(int(timestamp_hwm_match.group(1).decode()))}."
                        if timestamp_hwm_match
                        else "."
                    )
                    logger.info(
                        f"Pulled {number_of_alerts} {sub_type} {self.type}(s) for tenant "
                        f"{self.tenant.get('name')} in JSON format using {iterator_name} index{pull_message}"
                    )
                    content = gzip.compress(response, compresslevel=3)
                    self.message_queue.put(
                        (
                            content,
                            sub_type,
                            False,
                            number_of_alerts != 0
                        )
                    )
                    wait_time = DEFAULT_WAIT_TIME
                    if wait_time_match:
                        wait_time = int(wait_time_match.group(1).decode())
                self.update_pull_status(sub_type)
                time.sleep(wait_time)

        except Exception as ex:
            logger.error(
                f"Error occurred while pulling {sub_type} {self.type}(s) "
                f"for the tenant {self.tenant_name}. {ex}",
                error_code="CE_1111",
                details=traceback.format_exc(),
            )
        finally:
            should_apply_expo_backoff = False
            if iterator and iterator.should_apply_expo_backoff:
                should_apply_expo_backoff = should_apply_expo_backoff or iterator.should_apply_expo_backoff
            update_set_data = {
                f"first_{self.type}_pull.first_{sub_type}_pull": True,
            }
            if iterator and iterator.timestamp_hwm:
                update_set_data[
                    f"disabled_{self.type}_pull.disabled_{sub_type}_pull"
                ] = iterator.timestamp_hwm

            plugin_provider_helper.update_tenant_storage(
                self.tenant.get("name"), update_set_data
            )
            self.should_exit.set()
            with self.lock:
                self.running_thread -= 1
                self.message_queue.put(([], sub_type, should_apply_expo_backoff, True))

    def filter_data(self, data: List) -> List:
        """Return filtered data."""
        filtered = []
        for i in range(len(data)):
            timestamp = data[i].get("timestamp", 0)
            if timestamp > self.end_time:
                return filtered
            filtered.append(data[i])
        return filtered

    def load_historical(self, sub_type: str, iterator_name: str):
        """Pull historical data from Netskope."""
        iterator = self.get_iterator(sub_type, iterator_name, is_historical=True)
        # registered = connector.collection(Collections.ITERATOR).find_one(
        #     {"name": self.iterator_name % sub_type}
        # )

        # if not registered:
        iterator.set_timestamp(self.start_time)

        pull_time = None
        try:
            self.should_exit.clear()
            back_pressure_thread = threading.Thread(
                target=back_pressure.should_stop_pulling,
                daemon=True,
                args=(self.should_exit,),
            )
            back_pressure_thread.start()

            while True:
                if not self.tenant:
                    logger.error(
                        f"Tenant with name {self.tenant_name} no longer exists.",
                        error_code="CE_1034",
                    )
                    return {"success": False}
                if back_pressure.STOP_PULLING:
                    logger.debug(
                        f"Historical pulling of {sub_type} {self.type}(s) for tenant {self.tenant_name} "
                        "is paused due to back pressure."
                    )
                    time.sleep(NetskopeClient.BACK_PRESSURE_WAIT_TIME)
                    continue

                self.tenant = connector.collection(Collections.NETSKOPE_TENANTS).find_one(
                    {"name": self.tenant.get("name")}
                )
                if not self.tenant:
                    logger.error(
                        f"Tenant with name {self.tenant_name} no longer exists.",
                        error_code="CE_1029",
                    )
                    return {"success": False}

                response = iterator.pull()

                if not response or response.get("ok") != 1:
                    logger.error(
                        f"Error occurred while pulling {sub_type} {self.type}(s) "
                        f"from {self.tenant.get('name')} tenant. "
                        f"Response: {response}"
                    )
                    return {"success": False}

                if response.get(TIMESTAMP_HWM, 0) > self.end_time or (
                    pull_time == response.get(TIMESTAMP_HWM, 0)
                    and not len(response.get(RESULT, []))
                ):
                    logger.info(
                        f"Historical pulling of {sub_type} {self.type}(s) for tenant {self.tenant.get('name')} "
                        f"is done for time window {datetime.fromtimestamp(self.start_time)} "
                        f"to {datetime.fromtimestamp(self.end_time)}."
                    )
                    return {"success": True}

                filtered_data = self.filter_data(response.get(RESULT, []))
                pull_time = response.get(TIMESTAMP_HWM, 0)
                pull_message = (
                    f" until {datetime.fromtimestamp(pull_time)} " if pull_time else " "
                )
                if (
                    self.source_configuration
                    and self.destination_configuration
                    and self.business_rule
                ):
                    logger.info(
                        f"Pulled {len(filtered_data)} {sub_type} {self.type}(s) from historical "
                        f"{self.type}s in JSON format using {iterator_name} index{pull_message}"
                        f"for SIEM Mapping {self.source_configuration} to {self.destination_configuration} "
                        f"according to rule business rule {self.business_rule}."
                    )
                else:
                    logger.info(
                        f"Pulled {len(filtered_data)} {sub_type} {self.type}(s) from historical "
                        f"{self.type}s in JSON format using {iterator_name} index{pull_message}"
                        f"for configuration {self.source_configuration}."
                    )
                if self.compress_historical_data and filtered_data:
                    filtered_data = gzip.compress(json.dumps({RESULT: filtered_data}).encode('utf-8'), compresslevel=3)
                self.message_queue.put((filtered_data, sub_type, False, True))
                # if not registered:
                #     connector.collection(Collections.ITERATOR).insert_one(
                #         {"name": self.iterator_name % sub_type}
                #     )
                #     registered = True
                wait_time = DEFAULT_WAIT_TIME
                if len(response.get(RESULT, [])) != 0:
                    wait_time = response.get(WAIT_TIME, DEFAULT_WAIT_TIME)
                time.sleep(wait_time)

        except Exception as ex:
            logger.error(
                f"Error occurred while pulling {sub_type} {self.type}(s) for "
                f"the tenant {self.tenant_name}. {ex}",
                error_code="CE_1111",
                details=traceback.format_exc(),
            )
        finally:
            self.should_exit.set()
            with self.lock:
                self.running_thread -= 1
                self.message_queue.put(([], sub_type, False, True))

    # def get_configured_alerts_in_tenant(self, alerts=None, latest_checked=None):
    #     """Return the latest configured alerts from tenant."""
    #     now = datetime.now()
    #     if (
    #         not latest_checked
    #         or (now - latest_checked).total_seconds() >= DB_LOOKUP_INTERVAL
    #     ):
    #         latest_checked = datetime.now()
    #         tenant = connector.collection(Collections.NETSKOPE_TENANTS).find_one(
    #             {"name": self.tenant.name}
    #         )
    #         if not tenant:
    #             return [], latest_checked
    #         tenant = TenantDB(**tenant)
    #         alerts = tenant.alert_types
    #     return alerts, latest_checked
