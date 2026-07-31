"""Pulling mechanism using iterator."""

import threading
import time
import random
import re
import gzip
import json
from queue import Queue
import collections
import traceback
from datetime import datetime
from typing import Dict, List
from urllib.parse import urlparse
from collections import defaultdict
import pandas as pd
import numpy as np
from io import StringIO

import requests.exceptions
from celery.exceptions import SoftTimeLimitExceeded
from netskope_api.iterator.const import Const
from netskope_api.iterator.netskope_iterator import NetskopeIterator
from . import constants as CONST
from .iterator_api_helper import (
    NetskopePluginHelper,
    NetskopeProviderPluginException,
)
from netskope.common.api import __version__
from netskope.common.utils import (
    Logger,
    DBConnector,
    Collections,
    Notifier,
    back_pressure,
)
from netskope.common.utils.exceptions import (
    IncompleteTransactionError,
    ForbiddenError,
)
from netskope.common.utils.handle_exception import handle_status_code
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper

connector = DBConnector()
logger = Logger()
notifier = Notifier()
plugin_provider_helper = PluginProviderHelper()


class PullRetriesExhaustedError(Exception):
    """Raised when the retry budget for a failure episode is spent.

    A pull retries one failing batch for at most CONST.BACKOFF_MAX_TOTAL
    seconds (default 1 hour, counted from the first failure). When that
    budget runs out without a success, this error ends the pull so the
    caller can report an actionable failure instead of retrying forever.
    """

    pass


class PullWindowElapsedError(Exception):
    """Raised when the maintenance pull window ends while retrying.

    This signals a graceful stop, not a failure: the owning maintenance
    pull task is scheduled for a fixed window
    (CONST.MAINTENANCE_PULL_WINDOW_SECONDS), and retries must never
    overrun it. The caller ends the cycle normally and the next scheduled
    pull cycle takes over (with the 'resend' operation when a broken
    batch is still owed).
    """

    pass


class PullRetryController:
    """Paces and bounds the retries of a single pull() call.

    Every transient failure is retried with exponential backoff:
    CONST.BACKOFF_INITIAL_DELAY seconds, doubling per attempt
    (CONST.BACKOFF_FACTOR) up to CONST.BACKOFF_MAX_DELAY, with a
    +/- CONST.BACKOFF_JITTER_RATIO jitter so parallel sub-type threads do
    not retry in lockstep.

    Two independent bounds decide when to stop retrying:

    * The **pull window** (`window_deadline`) — the wall-clock moment the
      owning maintenance pull task's window ends. A retry is never
      scheduled past it, and when it is the reason to stop, the give-up
      reason is ``WINDOW`` (graceful stop). ``None`` for historical pulls
      and other callers without a fixed window.
    * The **episode budget** — at most CONST.BACKOFF_MAX_TOTAL seconds of
      retrying, counted from the first failure of the current episode.
      When it is the reason to stop, the give-up reason is ``BUDGET``.

    The controller only computes delays and sleeps; error classification
    and logging stay with the caller.
    """

    WINDOW = "window"
    BUDGET = "budget"

    def __init__(self, window_deadline=None):
        """Initialize for one pull() call.

        Args:
            window_deadline (float | None): epoch seconds at which the
                owning pull window ends, or None when there is no window.
        """
        self.window_deadline = window_deadline
        self.attempt = 0
        self._episode_start = None

    def window_elapsed(self):
        """Return True when the pull window is already over."""
        return (
            self.window_deadline is not None
            and time.time() >= self.window_deadline
        )

    def _give_up_deadline(self):
        """Epoch seconds after which no further retry may be scheduled."""
        deadline = self._episode_start + CONST.BACKOFF_MAX_TOTAL
        if self.window_deadline is not None:
            deadline = min(deadline, self.window_deadline)
        return deadline

    def give_up_reason(self):
        """Return which bound stopped the retries (WINDOW or BUDGET)."""
        if self.window_deadline is None:
            return self.BUDGET
        episode_start = (
            self._episode_start
            if self._episode_start is not None
            else time.time()
        )
        budget_deadline = episode_start + CONST.BACKOFF_MAX_TOTAL
        return (
            self.WINDOW
            if self.window_deadline <= budget_deadline
            else self.BUDGET
        )

    def next_delay(self):
        """Return the next backoff delay in seconds, or None to give up.

        None means sleeping the computed delay would cross the pull window
        or exceed the per-episode retry budget.
        """
        now = time.time()
        if self._episode_start is None:
            self._episode_start = now
        delay = min(
            CONST.BACKOFF_INITIAL_DELAY * (CONST.BACKOFF_FACTOR**self.attempt),
            CONST.BACKOFF_MAX_DELAY,
        )
        jitter = delay * CONST.BACKOFF_JITTER_RATIO
        delay = delay + random.uniform(-jitter, jitter)
        if now + delay > self._give_up_deadline():
            return None
        self.attempt += 1
        return delay

    def sleep(self, delay):
        """Sleep `delay` seconds in CONST.BACKOFF_SLEEP_TICK chunks.

        Returns False when the give-up deadline passes mid-sleep so the
        caller stops promptly instead of finishing a long wait.
        """
        slept = 0
        while slept < delay:
            tick = min(CONST.BACKOFF_SLEEP_TICK, delay - slept)
            time.sleep(tick)
            slept += tick
            if time.time() > self._give_up_deadline():
                return False
        return True


def convert_numpy_types(obj):
    """Convert numpy datatype into python datatype."""
    if isinstance(obj, dict):
        return {k: convert_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(v) for v in obj]
    elif isinstance(obj, np.generic):  # catches np.int64, np.float64, etc.
        return obj.item()
    else:
        return obj


def parse_csv_response(df: pd.DataFrame):
    """Parse complex datatype in CSV response."""

    # Step 1: Group columns by root key
    column_groups = collections.defaultdict(list)
    for col in df.columns:
        if '.' in col:
            root = col.split('.')[0]
            column_groups[root].append(col)

    # Step 2: Create a new dataframe column-wise
    result = pd.DataFrame()

    def parse_complex_obj(val):
        if isinstance(val, str) and '|' in val:
            parts = val.split('|')
            if any('=' not in segment for segment in parts):
                return parts
            else:
                result_dict = {}
                for segment in parts:
                    key, value = segment.split('=', 1)
                    result_dict[key] = value
                return result_dict
        return val

    # Direct (non-nested) columns and check for list conversion
    for col in df.columns:
        if '.' not in col:
            result[col] = df[col].apply(parse_complex_obj)

    # Nested columns
    for root, cols in column_groups.items():
        nested_values = []
        for i in range(len(df)):
            temp = {}
            for col in cols:
                keys = col.split('.')[1:]  # exclude root
                val = df.at[i, col]

                # Convert comma-separated strings to list
                val = parse_complex_obj(val)

                cur = temp
                for k in keys[:-1]:
                    cur = cur.setdefault(k, {})
                cur[keys[-1]] = val

            nested_values.append(convert_numpy_types(temp))

        result[root] = nested_values
    return result.to_dict(orient="records")


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
        log_prefix=None,
    ):
        """Initialize Netskope iterator."""
        from netskope.common.utils import get_installation_id

        self.tenant = tenant
        self.tenant_name = tenant.get("name") if tenant else ""
        tenant_config_parameters = tenant.get("parameters", {})
        self.tenant_hostname = tenant_config_parameters.get("tenantName", "")
        iterator_name = iterator_name.replace(" ", "")
        proxy = {}
        if tenant.get("use_proxy"):
            proxy = tenant.get("proxy")
        self.proxy = proxy
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
        self.log_prefix = log_prefix
        # Unified retry mechanism state. Retries are disabled by default so
        # direct callers (e.g. token validation) keep fail-fast behavior;
        # load()/load_historical() enable them. Pacing and bounds live in a
        # per-pull() PullRetryController.
        self.retry_enabled = False
        self.persist_pending_resend = False
        # The iterator name becomes a MongoDB key in tenant storage.
        self._storage_key = re.sub(r"[.$]", "_", iterator_name)
        pending_map = (tenant.get("storage") or {}).get("pending_resend") or {}
        self.pending_resend = bool(
            isinstance(pending_map, dict)
            and pending_map.get(self._storage_key)
        )
        from netskope.common.utils import resolve_secret

        if headers is None:
            headers = {}
        self.headers = headers
        self.headers["Authorization"] = "Bearer {}".format(
            resolve_secret(tenant_config_parameters.get("v2token"))
        )
        params = {
            Const.NSKP_TOKEN: resolve_secret(
                tenant_config_parameters.get("v2token")
            ),
            Const.NSKP_TENANT_HOSTNAME: tenant_config_parameters.get(
                "tenantName"
            ).removeprefix("https://"),
            Const.NSKP_PROXIES: self.proxy,
            Const.NSKP_ITERATOR_NAME: iterator_name,
            Const.NSKP_USER_AGENT: self.headers.get(
                "User-Agent", f"netskope-ce-{__version__}"
            ),
        }

        if sub_type in CONST.EVENTS:
            params[Const.NSKP_EVENT_TYPE] = sub_type
        else:
            params[Const.NSKP_EVENT_TYPE] = Const.EVENT_TYPE_ALERT
            params[Const.NSKP_ALERT_TYPE] = CONST.ALERTS.get(sub_type)
        super().__init__(params)

        self.client.session.headers.update(
            {"X-CE-Installation-Id": get_installation_id()}
        )

        self.netskope_api_plugin_helper = NetskopePluginHelper(
            logger=logger,
            log_prefix=self.log_prefix,
            plugin_name=CONST.PLATFORM_NAME,
            plugin_version=CONST.PLUGIN_VERSION,
        )

    def fetch_client_status_data(self):
        """
        Fetch client status data form the stored
        Client Status iterator.
        """
        client_status_storage = self.tenant.get("storage", {}).get(
            "client_status_iterator", ""
        )
        if client_status_storage:
            # Check the iterator status
            iterator_name = client_status_storage
        else:
            iterator_name = self.netskope_api_plugin_helper.create_iterator(
                tenant_url=self.tenant_hostname,
                tenant_configuration_name=self.tenant_name,
                headers=self.headers,
                iterator_name=CONST.CLIENT_STATUS_ITERATOR_NAME,
                proxies=self.proxy,
            )
        client_status_csv_endpoint = CONST.CLIENT_STATUS_CSV.format(
            self.tenant_hostname, iterator_name
        )
        params = {
            "operation": "next",
        }
        logger_msg = "fetching client status data for iterator"
        resp = self.netskope_api_plugin_helper.api_helper(
            logger_msg=logger_msg,
            url=client_status_csv_endpoint,
            method="GET",
            headers=self.headers,
            params=params,
            proxies=self.proxy,
            is_handle_error_required=False,
            is_validation=False,
        )
        if resp.status_code == 200:
            return resp
        else:
            self.netskope_api_plugin_helper.handle_error(
                resp=resp,
                logger_msg=logger_msg,
                is_validation=False,
            )

    def download(self, timestamp):
        if self.sub_type == CONST.EVENTS.get("clientstatus"):
            # Your custom implementation here
            return self.fetch_client_status_data()
        else:
            return super().download(timestamp)

    def next(self):
        if self.sub_type == CONST.EVENTS.get("clientstatus"):
            # Your custom implementation here
            return self.fetch_client_status_data()
        else:
            return super().next()

    def resend(self):
        # clientstatus has no Data Export alert/event type, so the base
        # resend() would build the wrong URL (.../dataexport/events/clientstatus
        # ?operation=resend) instead of the CSV endpoint. Mirror next()/download()
        # and re-fetch via the client-status CSV path. (Currently dormant: the
        # clientstatus fetch goes through api_helper, which masks stream breaks
        # as NetskopeProviderPluginException so pending_resend is never set for
        # clientstatus — this override keeps the code correct-by-construction if
        # that ever changes.)
        if self.sub_type == CONST.EVENTS.get("clientstatus"):
            return self.fetch_client_status_data()
        else:
            return super().resend()

    def set_timestamp(self, epoch):
        """Set epoch timestamp."""
        self.epoch = epoch

    def _next_operation(self):
        """Name the Data Export operation _fetch() will use next.

        Single source of truth shared by _fetch() and the retry log so the
        logged operation never disagrees with the one actually issued:

        * ``resend`` — a committed-200 body broke mid-stream, so the
          server-side iterator has advanced past that batch and it must be
          re-fetched (``next`` would skip it);
        * ``download`` — (re)establish the first batch from the start epoch.
          The epoch is cleared only after a successful fetch, so a failed
          first pull is retried with ``download``, not ``next``;
        * ``next`` — advance the cursor to the following batch.
        """
        if self.retry_enabled and self.pending_resend:
            return "resend"
        index_names = []
        for sub_type_indexes in CONST.ITERATORS.values():
            index_names.extend(sub_type_indexes)
        if self.epoch and self.index_name not in index_names:
            return "download"
        return "next"

    def _fetch(self):
        """Fetch a batch using the appropriate iterator operation.

        The operation is chosen by _next_operation(); see it for the rules.
        """
        operation = self._next_operation()
        if operation == "resend":
            return self.resend()
        if operation == "download":
            return self.download(self.epoch)
        return self.next()

    def _set_pending_resend(self, value):
        """Track (and for maintenance pulls, persist) the pending resend flag.

        Persistence guarantees the broken chunk is re-fetched with 'resend' on
        the next pull cycle even if this cycle gives up retrying.
        """
        if self.pending_resend == value:
            return
        self.pending_resend = value
        if not self.persist_pending_resend:
            return
        key = f"pending_resend.{self._storage_key}"
        try:
            if value:
                plugin_provider_helper.update_tenant_storage(
                    self.tenant_name, {key: True}
                )
            else:
                plugin_provider_helper.update_tenant_storage(
                    self.tenant_name, {}, {key: ""}
                )
        except Exception as e:
            logger.error(
                f"{self.log_prefix}: "
                f"Error occurred while updating the pending resend state for "
                f"{self.sub_type} {self.type} of tenant {self.tenant_name}. {e}",
                details=traceback.format_exc(),
            )

    def _retry_or_give_up(self, retry_ctrl, error):
        """Pace one retry of a transient pull failure.

        Returns normally after sleeping the backoff delay (the caller then
        retries). Raises instead of retrying when:

        * retries are disabled on this iterator (fail-fast callers such as
          token validation) -> the original error;
        * the maintenance pull window is ending -> PullWindowElapsedError
          (graceful stop, the next pull cycle takes over);
        * the per-episode retry budget is spent -> PullRetriesExhaustedError.
        """
        if not self.retry_enabled:
            raise error
        delay = retry_ctrl.next_delay()
        if delay is not None:
            operation = self._next_operation()
            logger.error(
                f"{self.log_prefix}: "
                f"Error occurred while pulling {self.sub_type} {self.type} "
                f"for the tenant {self.tenant_name}. Retrying (attempt "
                f"{retry_ctrl.attempt}) with operation '{operation}' in "
                f"{round(delay)} seconds. Error: {error}",
                details=traceback.format_exc(),
            )
            if retry_ctrl.sleep(delay):
                return
        if retry_ctrl.give_up_reason() == PullRetryController.WINDOW:
            logger.error(
                f"{self.log_prefix}: "
                f"Stopping retries for {self.sub_type} {self.type} of tenant "
                f"{self.tenant_name} after {retry_ctrl.attempt} retry "
                f"attempt(s): the pull window is ending. Pulling will resume "
                f"in the next pull cycle. Last error: {error}"
            )
            raise PullWindowElapsedError(
                f"The pull window elapsed while retrying {self.sub_type} "
                f"{self.type} for the tenant {self.tenant_name}. "
                f"Last error: {error}"
            )
        logger.error(
            f"{self.log_prefix}: "
            f"Giving up retries for {self.sub_type} {self.type} of tenant "
            f"{self.tenant_name} after {retry_ctrl.attempt} retry attempt(s): "
            f"the retry budget ({CONST.BACKOFF_MAX_TOTAL} seconds) is "
            f"exhausted. Last error: {error}"
        )
        raise PullRetriesExhaustedError(
            f"Retries exhausted while pulling {self.sub_type} {self.type} "
            f"for the tenant {self.tenant_name}. Last error: {error}"
        )

    def pull(
        self,
        parse_response=True,
        return_schema_headers=False,
        pull_start_time=None,
    ):
        """Pull one batch of data from Netskope.

        Unified retry mechanism: every transient failure — stream breaks
        (ChunkedEncodingError/ContentDecodingError), connection errors,
        every HTTP error status except 401/403, and any unexpected error —
        is retried in place with exponential backoff (see
        PullRetryController). Only 401 (authentication) and 403 (permission)
        are raised immediately, keeping their banner/storage side effects,
        because repeating the same request cannot succeed until the token or
        its scopes are fixed.

        Args:
            parse_response (bool): parse JSON responses into dicts.
            return_schema_headers (bool): also return response headers
                (CSV pulls).
            pull_start_time (datetime): start of the owning maintenance
                pull window. When provided, no retry is scheduled past
                pull_start_time + CONST.MAINTENANCE_PULL_WINDOW_SECONDS;
                if the window ends first, PullWindowElapsedError is raised
                so the caller can end the cycle gracefully. Omit for
                historical pulls (bounded by the retry budget only) and
                for fail-fast callers.
        """
        from netskope.common.utils.forbidden_notifier import (
            create_or_ack_forbidden_error_banner,
        )

        window_deadline = None
        if pull_start_time is not None:
            window_deadline = (
                pull_start_time.timestamp()
                + CONST.MAINTENANCE_PULL_WINDOW_SECONDS
            )
        retry_ctrl = PullRetryController(window_deadline=window_deadline)
        content = {}
        while True:
            if not self.tenant:
                logger.error(
                    f"{self.log_prefix}: "
                    f"Tenant with name {self.tenant_name} no longer exists.",
                    error_code="CE_1032",
                )
                return {"success": False}
            if retry_ctrl.window_elapsed():
                # The owning maintenance task has reached the end of its
                # scheduled window; do not start another request against it.
                raise PullWindowElapsedError(
                    f"The pull window elapsed while pulling {self.sub_type} "
                    f"{self.type} for the tenant {self.tenant_name}."
                )
            uri = ""
            try:
                data = self._fetch()
                if self.return_response:
                    return data
                uri = urlparse(data.url).path
                if (
                    not data.content
                    and data.headers.get("Content-Type", "").lower()
                    != "text/csv"
                ):
                    raise IncompleteTransactionError(
                        "Received empty response."
                    )
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
                status_code = (
                    e.response.status_code if e.response is not None else None
                )
                if status_code == 401:
                    # Authentication failures are never retried: pulling
                    # cannot succeed until the token is fixed.
                    self.should_apply_expo_backoff = True
                    plugin_provider_helper.update_tenant_storage(
                        self.tenant_name, {"is_v2_token_expired": True}
                    )
                    create_or_ack_forbidden_error_banner()
                    logger.error(
                        f"{self.log_prefix}: "
                        f"Received authentication error (401) while pulling "
                        f"{self.sub_type} {self.type} from the tenant "
                        f"{self.tenant_name}; Update "
                        f"the V2 token to resume pulling. Error: {e}",
                        error_code="CE_1061",
                        details=traceback.format_exc(),
                    )
                    raise IncompleteTransactionError(
                        f"Received error while pulling "
                        f"{self.sub_type} {self.type}. Error: {e}"
                    )
                if (
                    status_code is not None
                    and status_code not in CONST.RETRYABLE_HTTP_STATUS_CODES
                ):
                    # The only non-retryable status reaching this handler is
                    # 403 when it surfaces as an HTTPError (401 is handled
                    # above; 403 is normally raised as ForbiddenError).
                    # Everything else is retryable, so this repeats only
                    # requests that cannot succeed until permissions are fixed.
                    logger.error(
                        f"{self.log_prefix}: "
                        f"Received non-retryable status code {status_code} "
                        f"while pulling {self.sub_type} {self.type} from the "
                        f"tenant {self.tenant_name}; this is not retried. "
                        f"Error: {e}",
                        error_code="CE_1061",
                        details=traceback.format_exc(),
                    )
                    raise IncompleteTransactionError(
                        f"Received error while pulling "
                        f"{self.sub_type} {self.type}. Error: {e}"
                    )
                # Retryable status (anything except 401/403): the server did
                # not deliver this batch, so the iterator did not advance and
                # the same operation is retried.
                self._retry_or_give_up(retry_ctrl, e)
                continue
            except ForbiddenError as e:
                # 403 is never retried; record the forbidden endpoint so
                # the platform can surface the missing permission.
                self.should_apply_expo_backoff = True
                update_set = {
                    f"forbidden_endpoints.{self.sub_type}": uri,
                    "is_v2_token_expired": False,
                }
                plugin_provider_helper.update_tenant_storage(
                    self.tenant_name, update_set
                )
                create_or_ack_forbidden_error_banner()
                logger.error(
                    f"{self.log_prefix}: "
                    f"Received permission error (403 Forbidden) while "
                    f"pulling {self.sub_type} {self.type} from the tenant "
                    f"{self.tenant_name} for the endpoint {uri}; "
                    f"Grant the missing V2 token scope to "
                    f"resume pulling. Error: {e}",
                    error_code="CE_1061",
                    details=traceback.format_exc(),
                )
                raise e
            except (
                requests.exceptions.ChunkedEncodingError,
                requests.exceptions.ContentDecodingError,
            ) as e:
                # The response body broke mid-transfer. A chunked body is
                # only produced after the server has committed a 200
                # response, so the server-side iterator has advanced past
                # this batch: recover with 'resend' (re-fetch the same
                # batch); 'next' would silently skip it. The flag is
                # persisted (maintenance) so the batch survives even a
                # give-up and is re-fetched in the next pull cycle.
                if self.retry_enabled:
                    self._set_pending_resend(True)
                self._retry_or_give_up(retry_ctrl, e)
                continue
            except SoftTimeLimitExceeded:
                # Celery is terminating the owning task; never swallow or
                # retry this — propagate immediately.
                raise
            except Exception as e:
                # Anything else — connection errors, timeouts, empty
                # responses, unexpected failures — is treated as transient
                # and retried within the same bounds.
                self._retry_or_give_up(retry_ctrl, e)
                continue
            if self.pending_resend:
                self._set_pending_resend(False)
            self.epoch = None

            update_set = {"is_v2_token_expired": False}
            update_unset = {f"forbidden_endpoints.{self.sub_type}": ""}
            new_document = plugin_provider_helper.update_tenant_storage(
                self.tenant_name, update_set, update_unset, True
            )
            new_forbidden_endpoints = (
                new_document.get("storage", {}).get("forbidden_endpoints")
                if new_document
                else {}
            )
            current_forbidden_endpoints = (
                self.tenant.get("storage", {}).get("forbidden_endpoints")
                if self.tenant
                else {}
            )
            is_forbidden_value_changed = (
                new_forbidden_endpoints != current_forbidden_endpoints
            )
            if (
                self.tenant
                and self.tenant.get("storage", {}).get("is_v2_token_expired")
            ) or is_forbidden_value_changed:
                create_or_ack_forbidden_error_banner()
            if not return_schema_headers:
                return content
            else:
                headers = data.headers
                if headers.get("Content-Type", "").lower() == "text/csv":
                    return content, headers
                else:
                    return content, None


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
        log_prefix=None,
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
        self.proxy = {}
        if tenant.get("use_proxy"):
            self.proxy = tenant.get("proxy")
        tenant_config_parameters = tenant.get("parameters", {})
        self.tenant_hostname = tenant_config_parameters.get("tenantName", "")
        from netskope.common.utils import resolve_secret

        self.message_queue = Queue(maxsize=CONST.QUEUE_SIZE)
        self.lock = threading.Lock()
        self.running_thread = 0
        self.should_exit = threading.Event()
        self.iterator_name = iterator_name
        self.iterators = {}
        self.threads = set()
        self._sub_types = []
        self._incident_enrichment = False
        self.pulling_type = pulling_type
        self.handle_forbidden = handle_forbidden
        self.pulling_started = False
        self.source_configuration = source_configuration
        self.destination_configuration = destination_configuration
        self.business_rule = business_rule
        self.compress_historical_data = compress_historical_data
        self.headers = headers
        self.headers["Authorization"] = "Bearer {}".format(
            resolve_secret(tenant_config_parameters.get("v2token"))
        )
        self.log_prefix = log_prefix

        self.netskope_api_plugin_helper = NetskopePluginHelper(
            logger=logger,
            log_prefix=self.log_prefix,
            plugin_name=CONST.PLATFORM_NAME,
            plugin_version=CONST.PLUGIN_VERSION,
        )

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
                log_prefix=self.log_prefix,
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
                    CONST.ITERATORS.get(
                        f"iterator_{self.type.lower()}_{sub_type.lower().replace(' ', '_')}"
                    )
                    or [self.iterator_name % sub_type]
                )
            )
            iterator_subtype_indexes[sub_type] = indexes
            iterator_indexes.extend(indexes)
        return iterator_subtype_indexes, iterator_indexes

    @sub_types.setter
    def sub_types(self, sub_types):
        """Spawn dedicated thread for pulling."""
        iterator_subtype_indexes, iterator_indexes = self.get_indexes(
            sub_types
        )
        if set(iterator_indexes) == self.threads:
            self._sub_types = iterator_indexes
            return
        self._sub_types = iterator_indexes
        for sub_type, iterator_names in iterator_subtype_indexes.items():
            if sub_type == CONST.EVENTS.get("clientstatus"):
                if self.pulling_type == NetskopeClient.HISTORICAL_PULLING:
                    logger.debug(
                        f"{self.log_prefix}: "
                        f"Skipping {sub_type} subtype for historical pull "
                        "as the Client Status does not support historical pulling."
                    )
                    continue
                else:
                    is_iterator_ready = (
                        self.netskope_api_plugin_helper.check_iterator_status(
                            tenant_hostname=self.tenant_hostname,
                            tenant_configuration_name=self.tenant_name,
                            headers=self.headers,
                            proxies=self.proxy,
                            tenant_storage=self.tenant.get("storage", {}),
                        )
                    )
                    if not is_iterator_ready:
                        continue
            for iterator_name in iterator_names:
                iterator_name = iterator_name.strip()
                if iterator_name not in self.threads:
                    self.threads.add(iterator_name)
                    thread_process = threading.Thread(
                        target=self.get_target_function(),
                        args=(
                            sub_type,
                            iterator_name,
                        ),
                    )
                    thread_process.start()
                    self.running_thread += 1

        for type_ in self.threads.copy():
            if type_ not in iterator_indexes:
                self.threads.remove(type_)

    @property
    def incident_enrichment(self) -> bool:
        """Return all sub_sub_types."""
        return self._incident_enrichment

    @incident_enrichment.setter
    def incident_enrichment(self, incident_enrichment: bool):
        self._incident_enrichment = incident_enrichment

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
                f"{self.log_prefix}: "
                f"Completed pull task for {datetime.fromtimestamp(start_time)} "
                f"to {datetime.fromtimestamp(end_time)} time interval, "
                f"pulled {self.type} from {self.tenant_name} tenant."
            )
        except SoftTimeLimitExceeded as ex:
            raise ex
        except Exception as ex:
            logger.error(
                f"{self.log_prefix}: "
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
            iterator.retry_enabled = True
            iterator.persist_pending_resend = True

            tenant_dict_storage = self.tenant.get("storage", {})
            first_pull_state = tenant_dict_storage.get(
                f"first_{self.type}_pull", {}
            )
            first_subtype_pull = f"first_{sub_type}_pull"
            if (
                isinstance(first_pull_state, dict)
                and first_subtype_pull not in first_pull_state
            ):
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
                        f"{self.log_prefix}: "
                        f"Tenant with name {self.tenant_name} no longer exists.",
                        error_code="CE_1030",
                    )
                    return {"success": False}
                now = datetime.now()
                time_delta = now - start_time
                if (
                    time_delta.total_seconds()
                    >= CONST.MAINTENANCE_PULL_WINDOW_SECONDS
                ):
                    return {"success": True}

                if back_pressure.STOP_PULLING:
                    logger.debug(
                        f"{self.log_prefix}: "
                        f"Pulling of {sub_type} {self.type}(s) for tenant {self.tenant_name} "
                        "is stopped due to back pressure."
                    )
                    return {"success": False}

                try:
                    self.tenant = plugin_provider_helper.get_tenant_details(
                        self.tenant_name, CONST.DATA_TYPE[self.type]
                    )
                except Exception:
                    logger.error(
                        f"{self.log_prefix}: "
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
                    return {"success": True}

                if iterator_name not in self.sub_types:
                    return {"success": True}

                self.pulling_started = True
                # pull_start_time bounds in-pull retries to this thread's
                # pull window: retries never overrun the window, and a
                # window ending mid-retry raises PullWindowElapsedError
                # (handled below as a graceful end of this cycle).
                response, headers = iterator.pull(
                    parse_response=False,
                    return_schema_headers=True,
                    pull_start_time=start_time,
                )
                if headers:  # data is in CSV format Client status + index name
                    schema_header = headers.get("schema_headers", "")
                    wait_time = CONST.DEFAULT_WAIT_TIME
                    if schema_header:
                        try:
                            schema_header = json.loads(
                                schema_header.replace("'", '"')
                            )
                        except json.decoder.JSONDecodeError:
                            error_msg = (
                                "Error occurred while fetching the schema headers. "
                                "Please check the logs for more details."
                            )
                            logger.error(
                                f"{self.log_prefix}: {error_msg} Error: {error_msg}",
                                details=traceback.format_exc(),
                            )
                            return {"success": False}
                        wait_time = schema_header.get(
                            "wait_time", CONST.DEFAULT_WAIT_TIME
                        )
                        schema_headers = {
                            key.encode(): b"version," + value.encode()
                            for key, value in schema_header.items()
                            if key.lower().startswith("v")
                        }
                        if response and schema_headers:
                            response = response.splitlines()
                            logger.info(
                                f"{self.log_prefix}: "
                                f"Pulled {len(response)} {sub_type} {self.type}(s) for tenant "
                                f"{self.tenant.get('name')} in CSV format using {iterator_name} index."
                            )
                            # Try enrichment if needed
                            if (
                                sub_type == CONST.EVENTS.get("incident")
                                and self.incident_enrichment
                            ):
                                response_decoded = [
                                    (
                                        line.decode()
                                        if isinstance(line, bytes)
                                        else line
                                    )
                                    for line in response
                                    if line
                                ]
                                enriched_batches = (
                                    self._enrich_csv_incident_data(
                                        response_decoded,
                                        sub_type,
                                        iterator_name,
                                        schema_headers=schema_headers,
                                    )
                                )
                                if enriched_batches:
                                    for batch in enriched_batches:
                                        self.message_queue.put(batch)
                                else:
                                    # Fallback to original logic
                                    for key, header in schema_headers.items():
                                        batch = b"\n".join(
                                            [
                                                header,
                                                b"\n".join(
                                                    filter(
                                                        lambda x: x.startswith(
                                                            key
                                                        ),
                                                        response,
                                                    )
                                                ),
                                            ]
                                        )
                                        content = gzip.compress(
                                            batch, compresslevel=3
                                        )
                                        self.message_queue.put(
                                            (content, sub_type, False, True)
                                        )
                            else:
                                # Original logic for non-incident data
                                for key, header in schema_headers.items():
                                    batch = b"\n".join(
                                        [
                                            header,
                                            b"\n".join(
                                                filter(
                                                    lambda x: x.startswith(
                                                        key
                                                    ),
                                                    response,
                                                )
                                            ),
                                        ]
                                    )
                                    content = gzip.compress(
                                        batch, compresslevel=3
                                    )
                                    self.message_queue.put(
                                        (content, sub_type, False, True)
                                    )
                        else:
                            logger.info(
                                f"{self.log_prefix}: "
                                f"Pulled 0 {sub_type} {self.type}(s) for tenant "
                                f"{self.tenant.get('name')} in CSV format using {iterator_name} index."
                            )
                    elif response:
                        wait_time = headers.get(
                            "wait_time", CONST.DEFAULT_WAIT_TIME
                        )
                        # Try enrichment if needed
                        if (
                            sub_type == CONST.EVENTS.get("incident")
                            and self.incident_enrichment
                        ):
                            enriched_batches = self._enrich_csv_incident_data(
                                response, sub_type, iterator_name
                            )
                            if enriched_batches:
                                for batch in enriched_batches:
                                    self.message_queue.put(batch)
                            else:
                                # Fallback to original logic
                                content = gzip.compress(
                                    response, compresslevel=3
                                )
                                logger.info(
                                    f"{self.log_prefix}: "
                                    f"Pulled {len(response.splitlines())-1} {sub_type} {self.type}(s) for tenant "
                                    f"{self.tenant.get('name')} in CSV format using {iterator_name} index (enrichment failed)."
                                )
                                self.message_queue.put(
                                    (content, sub_type, False, True)
                                )
                        else:
                            # Original logic for non-incident data
                            content = gzip.compress(response, compresslevel=3)
                            logger.info(
                                f"{self.log_prefix}: "
                                f"Pulled {len(response.splitlines())-1} {sub_type} {self.type}(s) for tenant "
                                f"{self.tenant.get('name')} in CSV format using {iterator_name} index."
                            )
                            self.message_queue.put(
                                (content, sub_type, False, True)
                            )
                    else:
                        logger.info(
                            f"{self.log_prefix}: "
                            f"Pulled 0 {sub_type} {self.type}(s) for tenant "
                            f"{self.tenant.get('name')} in CSV format using {iterator_name} index."
                        )
                else:  # data is in json
                    number_of_alerts = len(
                        re.findall(CONST.ID_PATTERN, response)
                    )
                    ok_match = re.search(CONST.OK_PATTERN, response)
                    timestamp_hwm_match = re.search(
                        CONST.TIMESTAMP_HWM_PATTERN, response
                    )
                    if timestamp_hwm_match:
                        iterator.timestamp_hwm = int(
                            timestamp_hwm_match.group(1).decode()
                        )
                    wait_time_match = re.search(
                        CONST.WAIT_TIME_PATTERN, response
                    )
                    if not response or (
                        ok_match and int(ok_match.group(1).decode()) != 1
                    ):
                        message = (
                            f"Error occurred while pulling {sub_type} {self.type} from {self.tenant} tenant. "
                            f"Response: {response}"
                        )
                        notifier.error(message)
                        logger.error(message=f"{self.log_prefix}: {message}")
                        return {"success": False}
                    pull_message = (
                        f", pulled data till {datetime.fromtimestamp(int(timestamp_hwm_match.group(1).decode()))}."
                        if timestamp_hwm_match
                        else "."
                    )
                    logger.info(
                        f"{self.log_prefix}: "
                        f"Pulled {number_of_alerts} {sub_type} {self.type}(s) for tenant "
                        f"{self.tenant.get('name')} in JSON format using {iterator_name} index{pull_message}"
                    )
                    if (
                        sub_type == CONST.EVENTS.get("incident")
                        and self.incident_enrichment
                    ):
                        response = response.decode()
                        response = json.loads(response)
                        response[CONST.RESULT] = self.enrich_incident_data(
                            response.get(CONST.RESULT, [])
                        )
                        response = json.dumps(response).encode("utf-8")
                    content = gzip.compress(response, compresslevel=3)
                    self.message_queue.put(
                        (content, sub_type, False, number_of_alerts != 0)
                    )
                    wait_time = CONST.DEFAULT_WAIT_TIME
                    if wait_time_match:
                        wait_time = int(wait_time_match.group(1).decode())
                self.update_pull_status(sub_type)
                time.sleep(int(wait_time))
        except PullWindowElapsedError:
            # Graceful end of this maintenance cycle: the pull window
            # elapsed while a failing batch was being retried. Any owed
            # 'resend' is persisted, so the next scheduled pull cycle
            # recovers the batch and continues.
            logger.info(
                f"{self.log_prefix}: "
                f"The maintenance pull window elapsed while retrying "
                f"{sub_type} {self.type}(s) for the tenant "
                f"{self.tenant_name}; pulling will resume in the next "
                f"pull cycle."
            )
            return {"success": True}
        except Exception as ex:
            logger.error(
                f"{self.log_prefix}: "
                f"Error occurred while pulling {sub_type} {self.type}(s) "
                f"for the tenant {self.tenant_name}. {ex}",
                error_code="CE_1111",
                details=traceback.format_exc(),
            )
        finally:
            should_apply_expo_backoff = False
            if iterator and iterator.should_apply_expo_backoff:
                should_apply_expo_backoff = (
                    should_apply_expo_backoff
                    or iterator.should_apply_expo_backoff
                )

            self.should_exit.set()
            with self.lock:
                self.running_thread -= 1
                self.message_queue.put(
                    ([], sub_type, should_apply_expo_backoff, True)
                )

    def filter_data(self, data: List, sub_type: str) -> List:
        """Return filtered data within the time range [start_time, end_time]."""
        filtered = []
        filtered_out_after = 0

        for record in data:
            timestamp = record.get("timestamp", 0)
            if timestamp <= self.end_time:
                filtered.append(record)
            if timestamp > self.end_time:
                filtered_out_after += 1
        # Log only if records were filtered out (helps debugging without noise)
        if filtered_out_after > 0:
            logger.info(
                f"{self.log_prefix}: Filtered out {filtered_out_after} {sub_type} {self.type}(s)"
                f" as they were outside the historical pull time range."
            )

        return filtered

    def load_historical(self, sub_type: str, iterator_name: str):
        """Pull historical data from Netskope."""
        start_details = (
            f"Historical Pull Configuration:\n"
            f"  - Sub Type: {sub_type}\n"
            f"  - Data Type: {self.type}\n"
            f"  - Iterator Name: {iterator_name}\n"
            f"  - Start Time: {self.start_time} ({datetime.fromtimestamp(self.start_time)})\n"
            f"  - End Time: {self.end_time} ({datetime.fromtimestamp(self.end_time)})\n"
        )
        logger.debug(
            message=(
                f"{self.log_prefix}: Starting historical pull for {sub_type} {self.type}(s)."
            ),
            details=start_details,
        )
        iterator = self.get_iterator(
            sub_type, iterator_name, is_historical=True
        )
        # Historical pulling is a one-shot task with no pull window, so no
        # pull_start_time is passed to pull(): each failure episode is
        # retried for at most BACKOFF_MAX_TOTAL seconds (default 1 hour)
        # before the pull gives up with PullRetriesExhaustedError. The
        # resend flag is not persisted because every historical run
        # repositions the iterator via set_timestamp().
        iterator.retry_enabled = True
        # registered = connector.collection(Collections.ITERATOR).find_one(
        #     {"name": self.iterator_name % sub_type}
        # )

        # if not registered:
        iterator.set_timestamp(self.start_time)

        # Track total records for summary

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
                        f"{self.log_prefix}: "
                        f"Tenant with name {self.tenant_name} no longer exists.",
                        error_code="CE_1034",
                    )
                    return {"success": False}
                if back_pressure.STOP_PULLING:
                    logger.debug(
                        f"{self.log_prefix}: "
                        f"Historical pulling of {sub_type} {self.type}(s) for tenant {self.tenant_name} "
                        "is paused due to back pressure."
                    )
                    time.sleep(NetskopeClient.BACK_PRESSURE_WAIT_TIME)
                    continue

                self.tenant = connector.collection(
                    Collections.NETSKOPE_TENANTS
                ).find_one({"name": self.tenant.get("name")})
                if not self.tenant:
                    logger.error(
                        f"{self.log_prefix}: "
                        f"Tenant with name {self.tenant_name} no longer exists.",
                        error_code="CE_1029",
                    )
                    return {"success": False}

                response = iterator.pull()

                if not response or response.get("ok") != 1:
                    logger.error(
                        f"{self.log_prefix}: "
                        f"Error occurred while pulling {sub_type} {self.type}(s) "
                        f"from {self.tenant.get('name')} tenant. "
                        f"Response: {response}"
                    )
                    return {"success": False}

                current_hwm = response.get(CONST.TIMESTAMP_HWM, 0)
                current_result = response.get(CONST.RESULT, [])

                # Check if we should terminate AFTER processing this batch
                should_terminate = current_hwm > self.end_time or (
                    pull_time == current_hwm and not len(current_result)
                )

                # FIX: Even if HWM > end_time, we should still process the current batch
                # because it may contain records that are within the time range
                if should_terminate and current_result:
                    # Process the final batch before terminating
                    filtered_data = self.filter_data(current_result, sub_type)
                    if filtered_data:
                        # If sub type is incident and forensics enabled, enrich
                        if (
                            sub_type == CONST.EVENTS.get("incident")
                            and self.incident_enrichment
                        ):
                            filtered_data = self.enrich_incident_data(
                                filtered_data
                            )
                        if self.compress_historical_data:
                            filtered_data = gzip.compress(
                                json.dumps(
                                    {CONST.RESULT: filtered_data}
                                ).encode("utf-8"),
                                compresslevel=3,
                            )
                        self.message_queue.put(
                            (filtered_data, sub_type, False, True)
                        )

                    logger.info(
                        f"{self.log_prefix}: "
                        f"Historical pulling of {sub_type} {self.type}(s) for tenant {self.tenant.get('name')} "
                        f"is done for time window {datetime.fromtimestamp(self.start_time)} "
                        f"to {datetime.fromtimestamp(self.end_time)}."
                    )
                    return {"success": True}

                # If we should terminate but no data in current batch, just return
                if should_terminate:
                    logger.info(
                        f"{self.log_prefix}: "
                        f"Historical pulling of {sub_type} {self.type}(s) for tenant {self.tenant.get('name')} "
                        f"is done for time window {datetime.fromtimestamp(self.start_time)} "
                        f"to {datetime.fromtimestamp(self.end_time)}."
                    )
                    return {"success": True}

                filtered_data = self.filter_data(current_result, sub_type)
                pull_time = response.get(CONST.TIMESTAMP_HWM, 0)
                pull_message = (
                    f" until {datetime.fromtimestamp(pull_time)} "
                    if pull_time
                    else " "
                )
                if (
                    self.source_configuration
                    and self.destination_configuration
                    and self.business_rule
                ):
                    logger.info(
                        f"{self.log_prefix}: "
                        f"Pulled {len(filtered_data)} {sub_type} {self.type}(s) from historical "
                        f"{self.type}s in JSON format using {iterator_name} index{pull_message}"
                        f"for Log Delivery from {self.source_configuration} to {self.destination_configuration} "
                        f"according to rule business rule {self.business_rule}."
                    )
                else:
                    logger.info(
                        f"{self.log_prefix}: "
                        f"Pulled {len(filtered_data)} {sub_type} {self.type}(s) from historical "
                        f"{self.type}s in JSON format using {iterator_name} index{pull_message}"
                        f"for configuration {self.source_configuration}."
                    )
                # If sub type is incident and forensics enabled, enrich
                if (
                    sub_type == CONST.EVENTS.get("incident")
                    and self.incident_enrichment
                ):
                    filtered_data = self.enrich_incident_data(filtered_data)
                if self.compress_historical_data and filtered_data:
                    filtered_data = gzip.compress(
                        json.dumps({CONST.RESULT: filtered_data}).encode(
                            "utf-8"
                        ),
                        compresslevel=3,
                    )
                self.message_queue.put((filtered_data, sub_type, False, True))
                # if not registered:
                #     connector.collection(Collections.ITERATOR).insert_one(
                #         {"name": self.iterator_name % sub_type}
                #     )
                #     registered = True
                wait_time = CONST.DEFAULT_WAIT_TIME
                if len(response.get(CONST.RESULT, [])) != 0:
                    wait_time = response.get(
                        CONST.WAIT_TIME, CONST.DEFAULT_WAIT_TIME
                    )
                time.sleep(wait_time)
        except PullRetriesExhaustedError as ex:
            logger.error(
                f"{self.log_prefix}: "
                f"Retries exhausted while pulling {sub_type} {self.type}(s) for "
                f"the tenant {self.tenant_name}. The historical pull for the "
                f"time window {datetime.fromtimestamp(self.start_time)} to "
                f"{datetime.fromtimestamp(self.end_time)} is incomplete for "
                f"{sub_type} {self.type}(s) and needs to be triggered again. "
                f"{ex}",
                error_code="CE_1111",
                details=traceback.format_exc(),
            )
        except Exception as ex:
            logger.error(
                f"{self.log_prefix}: "
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

    def _enrich_csv_incident_data(
        self,
        response_data,
        sub_type,
        iterator_name,
        schema_headers=None,
        header=None,
    ):
        """
        Enrich CSV incident data with forensics information.
        And return compressed json.
        Args:
            response_data: Raw CSV response data (bytes or string)
            sub_type: The sub type of data being processed
            iterator_name: Name of the iterator
            schema_headers: Dict of schema headers for versioned CSV (optional)
                key, value in bytes
            header: Single header for simple CSV (optional)

        Returns:
            List of tuples (content, sub_type, False, True) for message queue
        """

        enriched_batches = []

        try:
            if schema_headers:
                # Handle versioned CSV format
                for key_bytes, header_bytes in schema_headers.items():
                    key = (
                        key_bytes.decode()
                        if isinstance(key_bytes, bytes)
                        else key_bytes
                    )
                    header = (
                        header_bytes.decode()
                        if isinstance(header_bytes, bytes)
                        else header_bytes
                    )
                    # Filter lines for the current version and decode from bytes to string
                    response_data = [
                        line.decode() if isinstance(line, bytes) else line
                        for line in response_data
                    ]
                    csv_data = "\n".join(
                        [
                            line
                            for line in response_data
                            if line.startswith(key)
                        ]
                    )
                    if not csv_data:
                        continue

                    # Get column names from the original schema_header dict
                    columns = [h.strip() for h in header.split(",")]
                    # Read CSV with version column
                    df = pd.read_csv(
                        StringIO(csv_data), header=None, names=columns
                    )

                    # Convert to dict format and enrich
                    # incidents_list = df.to_dict('records')
                    incidents_list = parse_csv_response(df)

                    enriched_incidents = self.enrich_incident_data(
                        incidents_list
                    )

                    if enriched_incidents:
                        content = gzip.compress(
                            json.dumps(
                                {CONST.RESULT: enriched_incidents}
                            ).encode("utf-8"),
                            compresslevel=3,
                        )

                        enriched_batches.append(
                            (content, sub_type, False, True)
                        )

                        logger.info(
                            f"{self.log_prefix}: "
                            f"Pulled and enriched {len(enriched_incidents)} {sub_type} {self.type}(s) for tenant "
                            f"{self.tenant.get('name')} in CSV format using {iterator_name} index."
                        )
            else:
                # Handle simple CSV format
                response_lines = (
                    response_data.splitlines()
                    if isinstance(response_data, str)
                    else response_data.decode().splitlines()
                )
                if (
                    len(response_lines) > 1
                ):  # Must have at least header + 1 data row
                    # Read CSV data using pandas
                    csv_string = (
                        response_data
                        if isinstance(response_data, str)
                        else response_data.decode()
                    )
                    df = pd.read_csv(StringIO(csv_string), sep=",")

                    # Convert to dict format and enrich
                    # incidents_list = df.to_dict('records')
                    incidents_list = parse_csv_response(df)
                    enriched_incidents = self.enrich_incident_data(
                        incidents_list
                    )

                    if enriched_incidents:
                        content = gzip.compress(
                            json.dumps(
                                {CONST.RESULT: enriched_incidents}
                            ).encode("utf-8"),
                            compresslevel=3,
                        )

                        enriched_batches.append(
                            (content, sub_type, False, True)
                        )

                        logger.info(
                            f"{self.log_prefix}: "
                            f"Pulled and enriched {len(enriched_incidents)} {sub_type} {self.type}(s) for tenant "
                            f"{self.tenant.get('name')} in CSV format using {iterator_name} index."
                        )
                    else:
                        # No enrichment needed, return original
                        return None
                else:
                    # Empty or header-only response
                    return None

        except Exception as e:
            logger.error(
                f"{self.log_prefix}: Error enriching CSV data: {e}",
                details=traceback.format_exc(),
            )
            # Return None to indicate fallback to original logic
            return None

        return enriched_batches if enriched_batches else None

    def _fetch_forensics_data(self, incident_id: str):
        """Fetch forensics data for a specific incident ID.

        Args:
            incident_id: The DLP incident ID to fetch forensics data for

        Returns:
            Dictionary containing parsed forensics data or empty dict if failed
        """
        logger.info(
            "Enriching incident data with forensics "
            f"data for incident id: {incident_id}."
        )
        logger_msg = f"fetching forensics data for incident {incident_id}"
        try:
            forensics_data = self.netskope_api_plugin_helper.api_helper(
                logger_msg=logger_msg,
                url=CONST.DLP_INCIDENT_FORENSICS_ENDPOINT.format(
                    base_url=self.tenant_hostname, dlp_incident_id=incident_id
                ),
                method="GET",
                headers=self.headers,
                proxies=self.proxy,
                is_validation=False,
                handle_rate_limit=True,
            )

            # Extract the different components we want to return
            result = {
                "forensics_content": forensics_data.get("data", {}).get(
                    "content", ""
                ),
            }

            # Parse the meta field if it exists
            meta_data = forensics_data.get("data", {}).get("meta")
            if meta_data:
                try:
                    parsed_meta = json.loads(meta_data)
                    result["forensics_metadata_content"] = parsed_meta.get(
                        "metadata_content", ""
                    )
                    result["forensics_dlp_match_info"] = parsed_meta.get(
                        "dlp_match_info", []
                    )
                except json.JSONDecodeError:
                    logger.error(
                        f"{self.log_prefix}: Error parsing meta data JSON for incident {incident_id}",
                        details=traceback.format_exc(),
                    )

            return result

        except NetskopeProviderPluginException as err:
            error_message = str(err)
            if "403" in error_message and "forbidden" in error_message.lower():
                logger.error(
                    message=(
                        f"{self.log_prefix}: Received 403 while accessing the "
                        "forensics API. Please verify the configured token has "
                        "required permissions for Forensics API endpoint."
                    ),
                    details=(
                        f"Incident ID: {incident_id}. Original error: {error_message}"
                    ),
                    resolution=(
                        "If using V2 API token, please verify that you have "
                        "configured Read access for the "
                        "/api/v2/incidents/dlpincidents endpoint."
                    ),
                )
                raise ForbiddenError(error_message) from err
            if (
                "400" in error_message
                and "http client error" in error_message.lower()
            ):
                logger.error(
                    message=(
                        f"{self.log_prefix}: Received 400 while accessing the "
                        "forensics API. Please verify the service is enabled in "
                        "your tenant."
                    ),
                    details=(
                        f"Incident ID: {incident_id}. Original error: {error_message}"
                    ),
                    resolution=(
                        "Please verify the Forensics service is enabled "
                        "on your Netskope Tenant."
                    ),
                )
                raise ForbiddenError(error_message) from err
            logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while {logger_msg}."
                    f" Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            return {}
        except Exception as err:
            logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred while"
                    f" {logger_msg}. Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            return {}

    def _get_unique_incident_ids(self, data: List[Dict]):
        incident_ids_dict = defaultdict(list)
        for dlp_incident in data:
            dlp_id = dlp_incident.get("dlp_incident_id")
            if dlp_id:
                incident_ids_dict[dlp_id].append(dlp_incident)
        return incident_ids_dict

    def enrich_incident_data(self, incident_data: List[Dict]):
        """Enrich incident data with forensics information in-place, keeping all incidents.

        Args:
            incident_data: List of incident dictionaries to enrich.

        Returns:
            The same incident_data list with enriched information.
        """
        # Group incidents by 'dlp_incident_id'
        incident_ids_dict = self._get_unique_incident_ids(incident_data)

        # Fetch forensics data and update incidents
        for incident_id, incidents in incident_ids_dict.items():
            try:
                forensics_data = self._fetch_forensics_data(incident_id)
            except ForbiddenError:
                logger.info(
                    f"{self.log_prefix}: Skipping incident enrichment due to "
                    "error received from the forensics API."
                )
                return incident_data
            if not forensics_data:
                continue
            for incident in incidents:
                # Add each field from the forensics data to the incident
                for key, value in forensics_data.items():
                    incident[key] = value

        # For incidents without 'dlp_incident_id', they remain unchanged in incident_data

        return incident_data
