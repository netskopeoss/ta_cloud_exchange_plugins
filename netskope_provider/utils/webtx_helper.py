"""WebTx helper."""

import json
import os
import signal
import queue
import sys
import threading
import time
import traceback
import logging
import requests
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from threading import Thread
from typing import List

from google.cloud.pubsublite.cloudpubsub import SubscriberClient
from google.cloud.pubsublite.types import FlowControlSettings
from google.api_core.exceptions import Unauthenticated, Unauthorized, PermissionDenied
from google.oauth2 import service_account

from netskope.common.utils.webtx_plugin_helper import WebTxPluginHelper
from netskope.integrations.cls.models import Batch, ConfigurationDB
from netskope_api.iterator.const import Const
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper
from netskope.common.utils import Notifier
from netskope_api.token_management.netskope_management import NetskopeTokenManagement
from .message_transforms import message_transformer

source = None
webtx_plugin_helper = WebTxPluginHelper()
plugin_provider_helper = PluginProviderHelper()
notifier = Notifier()
logger = webtx_plugin_helper.logger
data = queue.Queue(maxsize=1000)
push_queue = queue.Queue(maxsize=8)
batch_event = threading.Event()
timeout_event = threading.Event()
back_pressure = threading.Event()
should_exit = False
should_exit_push = False
should_restart = False
streaming_pull_future = None
push_thread_pool = ThreadPoolExecutor(max_workers=8)
total_batches = 1
THREAD_COUNT = 256
SIGKILL_WAIT_SEC = 300
MAX_MESSAGES_OUTSTANDING = 1000
MAX_BYTES_OUTSTANDING = 10 * 1024 * 1024
MIN_IDLE_CONNECTION_TIMEOUT = 300
ENABLE_DEBUG = os.getenv("ENABLE_DEBUG", "false").lower() == "true"
SOURCE = None
BACK_PRESSURE_CHECK_INTERVAL = 60
threads = []
WEBTX_SUBSCRIPTION_KEY_REFRESH_INTERVAL = 24 # IN HOURS
WEBTX_SUBSCRIPTION_KEY_REFRESH_HOUR = 3 # 3 AM UTC

logging_formatter = logging.Formatter(
    "[%(asctime)s: %(levelname)s] %(filename)s:%(lineno)d "
    "fn=%(funcName)s pid=%(process)d  tid=%(thread)d tn=%(threadName)s %(message)s"
)
logging_handler = logging.StreamHandler(stream=sys.stdout)
logging_handler.setFormatter(logging_formatter)
stdout_logger = logging.getLogger("netskope.webtx")
stdout_logger.setLevel(logging.DEBUG if ENABLE_DEBUG else logging.ERROR)
stdout_logger.addHandler(logging_handler)
DOCS_URL = "https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/get-started-with-cloud-exchange/configure-netskope-tenants/#v2-rest-api-scopes" # NOQA


def make_default_thread_pool_executor(thread_count=THREAD_COUNT):
    """Initialize default thread pool."""
    executor_kwargs = {}
    if sys.version_info[:2] == (2, 7) or sys.version_info[:2] >= (3, 6):
        executor_kwargs["thread_name_prefix"] = "CallbackThread"
    return ThreadPoolExecutor(max_workers=thread_count, **executor_kwargs)


class WebTxHelper:
    """Web transaction helper class."""

    def __init__(self, name: str, log_prefix: str):
        """Initialize.

        Args:
            name (str): Name of the source configuration.
        """
        self.name = name
        self.batches: List[Batch] = []
        self.log_prefix = log_prefix

    def callback(self, message):
        """Perform callback.

        Args:
            message ([type]): Message received from the publisher.
        """
        global should_restart
        try:
            timeout_event.set()
            if should_exit:
                stdout_logger.debug("Discarding message.")
                handle_interrupt()
                return
            # If the message contains a unicode error, ignore it and ack the message.
            atributes = dict(message.attributes)
            if atributes.get("is_unicode_decode_error", "false") == "true":
                msg = "Received an unparseable message with a non-utf8 character. This message will be dropped."
                if atributes.get("unparseable_message_file_path"):
                    msg += f" Invalid message has been written to file '{atributes.get('unparseable_message_file_path')}'."
                logger.error(
                    f"{self.log_prefix} : {msg}"
                )
                stdout_logger.debug(
                    f"{self.log_prefix} : {msg}"
                )
            else:
                data.put((message.data, atributes.get("Fields")))
            message.ack()
            stdout_logger.debug(
                f"mlen={len(message.data)}, qlen={data.qsize()}, should_exit={should_exit}"
            )
        except TypeError:
            handle_interrupt()
        except Exception as ex:
            stdout_logger.debug(f"{str(repr(ex))} {traceback.format_exc()}")
            should_restart = True
            handle_interrupt()

    def unset_webtx_subscription_details(self, tenant_name):
        """Unset webtx subscription details."""
        try:
            update_set = {}
            update_unset = {
                "last_fetched_sub_at": "",
                "subscription_key": "",
                "subscription_endpoint": ""
            }
            result = plugin_provider_helper.update_tenant_storage(
                tenant_name, update_set, update_unset
            ) is not None
            return result
        except Exception as ex:
            stdout_logger.debug(f"{str(repr(ex))} {traceback.format_exc()}")
            return False

    def get_plugin_subscription_configuration(self, tenant_name, configuration_name):
        try:
            from netskope.common.utils import resolve_secret, add_user_agent
            global WEBTX_SUBSCRIPTION_KEY_REFRESH_INTERVAL, WEBTX_SUBSCRIPTION_KEY_REFRESH_HOUR
            tenant = plugin_provider_helper.get_tenant_details(
                tenant_name
            )
            banner_id = f"BANNER_ERROR_9999_{configuration_name.replace(' ', '_').upper()}"
            params = {
                Const.NSKP_TOKEN: resolve_secret(tenant["parameters"].get("v2token")),
                Const.NSKP_TENANT_HOSTNAME: tenant["parameters"]
                .get("tenantName")
                .removeprefix("https://"),
                Const.NSKP_USER_AGENT: add_user_agent({}).get("User-Agent"),
            }
            sub_path_response = None
            sub_key_response = None
            token_management_response = None
            is_subscription_details_not_in_db = not (
                tenant["storage"].get("last_fetched_sub_at") and
                tenant["storage"].get("subscription_key") and
                tenant["storage"].get("subscription_endpoint")
            )
            if is_subscription_details_not_in_db:
                # call the sdk
                token_management = NetskopeTokenManagement(params)
                token_management_response = token_management.get()
                if token_management_response.get("ok") == 1 and token_management_response.get("subscription") and token_management_response.get("subscription-key"):
                    sub_path_response = token_management_response["subscription"]
                    sub_key_response = token_management_response["subscription-key"]
                    update_set = {
                        "subscription_key": sub_key_response,
                        "subscription_endpoint": sub_path_response,
                        "last_fetched_sub_at": datetime.utcnow(),
                    }
                    plugin_provider_helper.update_tenant_storage(
                        tenant_name, update_set
                    )
                    banner = notifier.get_banner_details(banner_id)
                    if banner:
                        notifier.update_banner_acknowledged(banner_id, True)
                    return sub_key_response, sub_path_response
                elif(token_management_response.get("status") == 401):
                    stdout_logger.error(
                        "{}: Error occurred while retrieving subscription details for {}. Error: {}".format(
                            self.log_prefix, tenant_name, token_management_response.get("error_msg")
                        )
                    )
                    logger.error(
                        "{}: Error occurred while retrieving subscription details for {}. Error: {}".format(
                            self.log_prefix, tenant_name, token_management_response.get("error_msg")
                        )
                    )
                    tenant_banner = f"[{tenant.get('name')}](https://{params.get(Const.NSKP_TENANT_HOSTNAME)})"
                    message = (
                        "The Netskope tenant API token has expired for %s or Event Streaming feature is disabled, to enable it please contact Netskope support to purchase. "
                        "If Event Streaming feature is enabled, please generate the new token or re-issue the token and update the tenant configuration "
                        "to resume Event Streaming."
                        % ("**" + tenant_banner +"**")
                    )
                    notifier.banner_error(banner_id, message)
                elif(token_management_response.get("status") == 403):
                    stdout_logger.error(
                        "{}: Error occurred while retrieving subscription details for {}. Error: {}".format(
                            self.log_prefix, tenant_name, token_management_response.get("error_msg")
                        )
                    )
                    logger.error(
                        "{}: Error occurred while retrieving subscription details for {}. Error: {}".format(
                            self.log_prefix, tenant_name, token_management_response.get("error_msg")
                        )
                    )
                    tenant_banner = f"[{tenant.get('name')}](https://{params.get(Const.NSKP_TENANT_HOSTNAME)})"
                    message = (
                        "Netskope API token of tenant %s has been revoked, deleted or has insufficient privileges "
                        "to continue the streaming of WebTx events from Netskope. Ensure that your API token has permissions to access "
                        "**/api/v2/events/token/transaction_events** and **/api/v2/events/metrics/transactionevents** endpoints. "
                        " Please check the **[required privileges](%s)** for more details." % ("**" + tenant_banner +"**", DOCS_URL)
                    )
                    notifier.banner_error(banner_id, message)
                elif(token_management_response.get("status") == 429):
                    stdout_logger.error(
                        (
                            "{}: Error occurred while retrieving subscription details for {}. "
                            "For URL: /api/v2/events/token/transaction_events."
                            " Error: {}"
                        ).format(
                            self.log_prefix, tenant_name, token_management_response.get("error_msg")
                        )
                    )
                    logger.error(
                        "{}: Error occurred while retrieving subscription details for {}. Error: {}".format(
                            self.log_prefix, tenant_name, token_management_response.get("error_msg")
                        )
                    )
                elif(token_management_response.get("status", 500) >= 500):
                    stdout_logger.error(
                        "{}: Error occurred while retrieving subscription details for {}. Error: {}".format(
                            self.log_prefix, tenant_name, token_management_response.get("error_msg")
                        )
                    )
                    logger.error(
                        "{}: Error occurred while retrieving subscription details for {}. Error: {}".format(
                            self.log_prefix, tenant_name, token_management_response.get("error_msg")
                        )
                    )
                raise requests.HTTPError(f'Error occurred while subscription details for {tenant_name}. {token_management_response}')        
            else:
                tenant = plugin_provider_helper.get_tenant_details(
                    tenant_name
                )
                sub_key_response = tenant["storage"].get("subscription_key")
                sub_path_response = tenant["storage"].get("subscription_endpoint")
                return sub_key_response, sub_path_response
        except Exception as e:
            raise e

    def run(self):
        """Start polling.

        Args:
            name (str): Name of the Netskope configuration.
        """
        global should_exit, streaming_pull_future, should_restart, batch_event
        configuration = webtx_plugin_helper.find_cls_configuraions(
            {"name": self.name, "active": True}, many=False
        )
        if not configuration:
            stdout_logger.debug(f"Could not find configuration {self.name}.")
            handle_interrupt()
            return

        configuration = ConfigurationDB(**configuration)
        if not configuration.active:
            stdout_logger.debug(f"Configuration {self.name} is inactive.")
            handle_interrupt()
            return
        try:
            subscription_key, subscription_path = self.get_plugin_subscription_configuration(configuration.tenant, configuration.name)
            credentials = (
                service_account.Credentials.from_service_account_info(
                    json.loads(subscription_key)
                )
            )
            per_partition_flow_control_settings = FlowControlSettings(
                # 1,000 outstanding messages. Must be >0.
                # messages_outstanding=1000,
                messages_outstanding=MAX_MESSAGES_OUTSTANDING,
                # 10 MiB. Must be greater than the allowed size of the largest message (1 MiB).
                bytes_outstanding=MAX_BYTES_OUTSTANDING,
            )

            batch_event.wait()
            if should_exit:
                return
            with SubscriberClient(
                credentials=credentials, message_transformer=message_transformer
            ) as subscriber_client:
                streaming_pull_future = subscriber_client.subscribe(
                    subscription_path,
                    callback=self.callback,
                    per_partition_flow_control_settings=per_partition_flow_control_settings,
                )
                logger.info(
                    f"Web transaction process for source {self.name}, "
                    f"Listening for messages on {subscription_path}."
                )

                streaming_pull_future.result()
            stdout_logger.debug("Exiting thread.")
        except TypeError:
            handle_interrupt()
        except Unauthenticated or Unauthorized or PermissionDenied as ex:
            self.unset_webtx_subscription_details(configuration.tenant)
            should_restart = True
            logger.error(
                f"Error occurred while subscribing to WebTx path, credentials will be refreshed in next execution. If you have regenerated endpoint please 'GENERATE AND DOWNLOAD KEY' from Netskope tenant UI > Settings > Tools > Event Streaming. Error : {str(ex)}.",
                error_code="CLS_1030",
                details=traceback.format_exc(),
            )
            handle_interrupt()

        except Exception as ex:
            stdout_logger.debug(f"{str(repr(ex))} {traceback.format_exc()}")
            logger.error(
                f"Error occurred while subscribing to WebTx path, {str(ex)}",
                error_code="CLS_1025",
                details=traceback.format_exc(),
            )
            should_restart = True
            handle_interrupt()


def terminate_on_timeout(timeout, source):
    """Send SIGINT after 5 minutes."""
    global timeout_event, should_restart

    while timeout_event.wait(timeout):
        if should_exit:
            stdout_logger.debug("Exiting thread.")
            return
        timeout_event.clear()

    if should_exit:
        stdout_logger.debug("Exiting thread.")
        return

    should_restart = True
    logger.info(
        f"Web transaction process for source {source} exiting due to timeout."
    )
    stdout_logger.debug("Exiting thread.")
    handle_interrupt()


def is_due_by_time(batch: Batch) -> bool:
    """Check if a given batch is due for push.

    Args:
        batch (Batch): Batch object.

    Returns:
        bool: Whether batch is due for push or not.
    """
    if (datetime.now() - batch.started_at).seconds > batch.limit_time:
        stdout_logger.debug("Batch due by time.")
        return True
    return False


def is_due_by_size(batch: Batch, next_message: bytes = None) -> bool:
    """Check if a batch is due by suze."""
    if batch.size >= batch.limit_size * 1024 * 1024 or (
        next_message
        and batch.size != 0
        and (batch.size + len(next_message)) > batch.limit_size * 1024 * 1024
    ):
        stdout_logger.debug(f"Batch due by size, {batch.size}")
        return True
    return False


def create_from_existing(batch: Batch) -> Batch:
    """Reset a batch.

    Args:
        batch (Batch): Batch to be resetted.

    Returns:
        Batch: Resetted batch.
    """
    new_batch = Batch()
    new_batch.destination = batch.destination
    new_batch.limit_time = batch.limit_time
    new_batch.limit_size = batch.limit_size
    new_batch.messages = []
    new_batch.started_at = datetime.now()
    new_batch.size = 0
    new_batch.fields = []
    new_batch.locks = []
    new_batch.rule = batch.rule
    new_batch.isSIEM = batch.isSIEM
    return new_batch


def add_message_to_batch(
    batch: Batch, message_data: bytes, message_fields: str
):
    """Add a message to batch."""
    batch.messages.append(message_data)
    batch.fields.append(message_fields)
    batch.size += len(message_data)


def evaluate_batch(batch: Batch, message: tuple = None) -> Batch:
    """Evaluate a batch."""
    message_data = None
    if message:
        message_data, message_fields = message
        add_message_to_batch(batch, message_data, message_fields)

    if is_due_by_size(batch, message_data) or is_due_by_time(batch):
        push_queue.put(batch)
        stdout_logger.debug(f"Adding to push queue qlen={push_queue.qsize()}")
        batch = create_from_existing(batch)
    return batch


# thread
def check_batches(source: str):
    """Check batches thread."""
    global should_exit_push, total_batches
    try:
        webtx_destination_plugins = webtx_plugin_helper.get_webtx_destination_plugin_ids()
        webtx_destination_configurations = webtx_plugin_helper.get_webtx_destination_configurations(
            webtx_destination_plugins)
        configured_plugins = webtx_plugin_helper.get_configured_plugins(
            source, webtx_destination_configurations
        )
        stdout_logger.debug(f"Found {configured_plugins} configured plugin(s).")
        batches = []
        for rule, configuration in configured_plugins:
            params = configuration.get("parameters")
            batch = Batch()
            batch.destination = configuration.get("name")
            batch.messages = []
            batch.locks = []
            batch.started_at = datetime.now()
            batch.size = 0
            batch.rule = rule
            batch.isSIEM = (
                "max_file_size" not in params and "max_duration" not in params
            )
            batch.limit_size = params.get("max_file_size", 5)
            batch.limit_time = params.get("max_duration", 30)
            batches.append(batch)
        if not batches:
            should_exit_push = True
            batch_event.set()
            handle_interrupt()
            return
        total_batches = len(batches)
        batch_event.set()
        stdout_logger.debug(f"Created {len(batches)} batche(s).")
        while not data.empty() or not should_exit:
            message = None
            try:
                message = data.get_nowait()
                data.task_done()
            except queue.Empty:
                time.sleep(0.5)
            finally:
                batches = [evaluate_batch(batch, message) for batch in batches]
        if should_exit and batches:
            for batch in batches:
                push_queue.put(batch)
    except Exception:
        should_exit_push = True
        handle_interrupt()
    finally:
        should_exit_push = True
        stdout_logger.debug("Exiting thread.")


# thread
def push_batches(source):
    """Push batches thread."""
    global should_exit_push

    stdout_logger.debug("Starting.")
    while not push_queue.empty() or not should_exit_push:
        try:
            batch: Batch = push_queue.get_nowait()
            if batch.messages:
                if not batch.isSIEM:
                    webtx_plugin_helper.execute_cls_ingest_task(
                        args=[
                            source,
                            batch.destination,
                            batch.messages,
                            "webtx",
                            "2.0.0",
                        ]
                    )
                else:
                    webtx_plugin_helper.execute_cls_parse_and_ingest_task(
                        args=[
                            source,
                            batch.destination,
                            batch.rule,
                            batch.messages,
                            batch.fields,
                        ]
                    )
            stdout_logger.debug("Batch pushed.")
            push_queue.task_done()
        except queue.Empty:
            time.sleep(0.5)
        except Exception as ex:
            stdout_logger.debug(f"{str(repr(ex))} {traceback.format_exc()}")
    stdout_logger.debug("Exiting thread.")


def handle_interrupt(signum=None, frame=None):
    """Handle interrupt."""
    global streaming_pull_future, should_exit
    try:
        stdout_logger.debug("Cancelling the subscription.")
        batch_event.set()
        if streaming_pull_future:
            streaming_pull_future.cancel()
            streaming_pull_future.result()
    except Exception as ex:
        stdout_logger.debug(f"{str(repr(ex))} {traceback.format_exc()}")
    stdout_logger.debug("Setting should_exit.")
    stdout_logger.debug("Terminating WebTx process.")
    should_exit = True
    timeout_event.set()


def monitor_back_pressure():
    """Monitor back pressure constantly."""
    while True:
        global should_restart
        if not webtx_plugin_helper.back_pressure_mechanism(True):
            stdout_logger.debug("Back pressure hit. Pulling will be stopped.")
            back_pressure.set()
            should_restart = True
            logger.info(
                "Web transaction process exiting due to back pressure."
            )
            stdout_logger.debug("Exiting thread.")
            handle_interrupt()
        else:
            stdout_logger.debug("Back pressure is normal.")
            back_pressure.clear()
        if should_exit:
            stdout_logger.debug("Exiting thread.")
            return
        time.sleep(BACK_PRESSURE_CHECK_INTERVAL)


def main(source, log_prefix):
    """Web transaction workflow."""
    logger.info(f"Starting web transaction process for source {source}.")
    global SOURCE
    SOURCE = source
    try:
        signal.signal(signal.SIGINT, handle_interrupt)

        webtx = WebTxHelper(source, log_prefix)
        back_pressure_thread = Thread(target=monitor_back_pressure)
        threads.append(back_pressure_thread)
        back_pressure_thread.start()
        check_thread = Thread(target=check_batches, args=(source,))
        threads.append(check_thread)
        check_thread.start()
        timeout_thread = Thread(
            target=terminate_on_timeout,
            args=(MIN_IDLE_CONNECTION_TIMEOUT, source),
            daemon=True,
        )
        threads.append(timeout_thread)
        timeout_thread.start()
        push_thread = Thread(target=push_batches, args=(source,))
        threads.append(push_thread)
        push_thread.start()
        subscriber_thread = Thread(target=webtx.run)
        threads.append(subscriber_thread)
        stdout_logger.debug("Subscriber thread starting.")
        subscriber_thread.start()
        subscriber_thread.join()
        check_thread.join()
        push_thread.join()
        timeout_thread.join()
        back_pressure_thread.join()
    except KeyboardInterrupt:
        handle_interrupt()
        return 0

    logger.info(
        f"Terminating the web transaction process for source {source}."
    )
    if should_restart:
        return 1
    return 0
