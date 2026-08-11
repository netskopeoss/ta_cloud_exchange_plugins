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

CRE Forescout eyeFocus REM plugin helper.
"""

import math
import re
import time
import traceback
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import requests
from netskope.common.utils import add_user_agent

from .constants import (
    ADVANCED_FILTERS_YES,
    CONNECTION_RETRY_BACKOFF_SECONDS,
    DEFAULT_ADVANCED_FILTERS,
    DEFAULT_INITIAL_RANGE_DAYS,
    DEFAULT_PULL_STRATEGY,
    DEFAULT_PULL_WINDOW_DAYS,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_WAIT_TIME,
    MAX_API_RETRIES,
    MAX_BISECT_DEPTH,
    MAX_SCORE_SPLIT_DEPTH,
    MAX_WAIT_TIME,
    MIN_WINDOW_SECONDS,
    MIN_WINDOW_STEP_MILLISECONDS,
    MODULE_NAME,
    NO_MORE_RETRIES_ERROR_MSG,
    ORDER_BY_FIELD,
    PLATFORM_NAME,
    REM_ASSET_SEARCH_ENDPOINT,
    RESPONSE_HARD_CAP,
    RETRY_ERROR_MSG,
    RISK_SCORE_MAX_PARAM,
    RISK_SCORE_MIN_PARAM,
    RISK_SCORE_REGEX,
    RISK_SCORE_TENTHS_MAX,
    RISK_SCORE_TENTHS_MIN,
    RISK_SCORE_TENTHS_PER_POINT,
    SORT_ORDER,
    WINDOW_FILL_TARGET,
    ZERO_SCORE_PROBE_ORDER_BY,
)
from .exceptions import ForescoutEyeFocusPluginException

# Compiled once: every risk-score bound is matched against it during
# validation and configuration extraction.
RISK_SCORE_PATTERN = re.compile(RISK_SCORE_REGEX)

# Smallest datetime step any split may produce (see the constant).
MIN_WINDOW_STEP = timedelta(milliseconds=MIN_WINDOW_STEP_MILLISECONDS)

# Immutable per-call request context, so the recursive pagination helpers do
# not have to thread five unchanging arguments through every level.
_SearchContext = namedtuple(
    "_SearchContext",
    ["base_url", "api_token", "verify", "proxies", "logger_msg"],
)


class ForescoutEyeFocusPluginHelper:
    """Helper for Forescout eyeFocus REM Asset Search API operations."""

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """Initialize the helper.

        Args:
            logger: Logger object (patched by the plugin for ``resolution``).
            log_prefix (str): Log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    # ------------------------------------------------------------------ #
    # Headers / auth
    # ------------------------------------------------------------------ #
    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add a Netskope CE User-Agent to outbound request headers."""
        if headers and "User-Agent" in headers:
            return headers
        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def _build_headers(self, api_token: str) -> Dict:
        """Build request headers with Bearer auth + CE user agent."""
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
        }
        return self._add_user_agent(headers)

    # ------------------------------------------------------------------ #
    # Configuration extraction
    # ------------------------------------------------------------------ #
    def get_credentials(self, configuration: Dict) -> Tuple[str, str]:
        """Extract and normalize base URL and API token from configuration.

        The Base URL is trimmed of surrounding whitespace / trailing slashes;
        the API Token (a secret) is returned as-is (never stripped).
        """
        base_url = configuration.get("base_url", "")
        if isinstance(base_url, str):
            base_url = base_url.strip().strip("/")
        api_token = configuration.get("api_token", "")
        return base_url, api_token

    def get_config_params(self, configuration: Dict) -> Dict:
        """Extract the pull-behavior configuration parameters.

        The risk-score bounds are only honoured when the "Advanced Filters"
        toggle is set to Yes, so switching the toggle off disables them
        without the (now hidden) dynamic fields having to be cleared first.
        """
        advanced_filters_enabled = self.is_advanced_filters_enabled(
            configuration
        )
        risk_score_min = risk_score_max = None
        if advanced_filters_enabled:
            # Strict parsing so a value the API would reject with HTTP 400 can
            # never reach the query string, even if the configuration was
            # somehow stored without passing validate().
            risk_score_min = self.parse_risk_score(
                configuration.get(RISK_SCORE_MIN_PARAM)
            )
            risk_score_max = self.parse_risk_score(
                configuration.get(RISK_SCORE_MAX_PARAM)
            )
        return {
            "asset_categories": (
                configuration.get("asset_categories", []) or []
            ),
            "pull_strategy": (
                configuration.get("pull_strategy") or DEFAULT_PULL_STRATEGY
            ),
            "initial_range": int(
                configuration.get("initial_range")
                or DEFAULT_INITIAL_RANGE_DAYS
            ),
            "pull_window_days": float(
                configuration.get("pull_window") or DEFAULT_PULL_WINDOW_DAYS
            ),
            "advanced_filters_enabled": advanced_filters_enabled,
            "risk_score_min": risk_score_min,
            "risk_score_max": risk_score_max,
        }

    @staticmethod
    def is_advanced_filters_enabled(configuration: Dict) -> bool:
        """Return True when the "Advanced Filters" toggle is set to Yes."""
        value = configuration.get("advanced_filters")
        if isinstance(value, str):
            value = value.strip().lower()
        return (value or DEFAULT_ADVANCED_FILTERS) == ADVANCED_FILTERS_YES

    @staticmethod
    def parse_risk_score(value) -> Optional[float]:
        """Parse a risk-score bound entered as text into a float.

        The Advanced Filter bounds are "text" configuration fields (the CE
        number widget drops the decimal separator, turning 1.2 into 12), so the
        raw value arrives as a string and has to be parsed here.

        Accepts an optionally signed plain decimal - ``"1.2"``, ``"3"``,
        ``".5"``, ``"2."`` - with surrounding whitespace tolerated, and also
        accepts a real int/float so a configuration saved before the field
        became text still works.

        Returns None when the value is blank or is not a plain decimal number.
        Exponent forms (``"1e1"``), ``"nan"`` / ``"inf"`` and anything else
        ``float()`` would happily swallow are rejected on purpose - silently
        accepting them would send a bound the user never intended.
        """
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if not isinstance(value, str):
            return None
        text = value.strip()
        if not text or not RISK_SCORE_PATTERN.match(text):
            return None
        try:
            return float(text)
        except ValueError:
            return None

    def _validate_url(self, url: str) -> bool:
        """Return True when the URL has a scheme and a network location."""
        if not isinstance(url, str):
            return False
        parsed = urlparse(url.strip())
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    @staticmethod
    def format_datetime(value: datetime) -> str:
        """Format a datetime as an ISO-8601 UTC string with milliseconds and a
        trailing ``Z`` (e.g. ``2026-05-06T11:45:11.633Z``), the format the
        Forescout REM API uses."""
        dt = value.astimezone(timezone.utc)
        millis = dt.microsecond // 1000
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis:03d}Z"

    # ------------------------------------------------------------------ #
    # Core API call with retries
    # ------------------------------------------------------------------ #
    def _get_retry_after(self, response_headers: Dict) -> int:
        """Determine how long to wait before retrying a throttled request.

        Honors the ``Retry-After`` header (seconds) but never waits longer than
        ``MAX_WAIT_TIME`` and never less than 1 second.
        """
        value = response_headers.get("Retry-After")
        wait_time = DEFAULT_WAIT_TIME
        if value:
            try:
                wait_time = int(float(value))
            except (TypeError, ValueError):
                wait_time = DEFAULT_WAIT_TIME
        return max(1, min(wait_time, MAX_WAIT_TIME))

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str = "GET",
        params: Dict = None,
        data: Dict = None,
        headers: Dict = None,
        json: Dict = None,
        verify: bool = True,
        proxies: Dict = None,
        is_validation: bool = False,
        is_handle_error_required: bool = True,
    ):
        """Make an API call with retries on rate-limit (429), 5xx errors and
        transient connection failures.

        Connection timeouts are retried because a long pull makes hundreds of
        calls and a single dropped connection would otherwise abandon the
        whole sweep - observed live, a connect timeout ended a 14-day pull
        after 104 calls. A ProxyError is NOT retried: that is a configuration
        fault, not a transient one. During validation nothing is retried, so
        a wrong Base URL fails fast.

        Raises:
            ForescoutEyeFocusPluginException: On terminal / unrecoverable
                errors.
        """
        headers = self._add_user_agent(headers)
        debug_log_msg = (
            f"{self.log_prefix}: API Request for {logger_msg}. "
            f"Endpoint: {method} {url}"
        )
        if params:
            debug_log_msg += f", params: {params}."
        self.logger.debug(debug_log_msg)
        try:
            for retry_count in range(MAX_API_RETRIES):
                try:
                    response = requests.request(
                        url=url,
                        method=method,
                        params=params,
                        data=data,
                        headers=headers,
                        json=json,
                        verify=verify,
                        proxies=proxies,
                        timeout=DEFAULT_REQUEST_TIMEOUT,
                    )
                except requests.exceptions.ProxyError:
                    raise
                except (
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                ) as error:
                    if is_validation or retry_count == MAX_API_RETRIES - 1:
                        raise
                    wait_time = min(
                        CONNECTION_RETRY_BACKOFF_SECONDS * (2**retry_count),
                        MAX_WAIT_TIME,
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Connection error occurred "
                            f"while {logger_msg}. Retrying after "
                            f"{wait_time} second(s). "
                            f"{MAX_API_RETRIES - 1 - retry_count} retries "
                            "left."
                        ),
                        details=f"Error: {error}",
                    )
                    time.sleep(wait_time)
                    continue
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )
                if not is_validation and (
                    status_code == 429 or 500 <= status_code < 600
                ):
                    if retry_count == MAX_API_RETRIES - 1:
                        err_msg = NO_MORE_RETRIES_ERROR_MSG.format(
                            status_code=status_code,
                            logger_msg=logger_msg,
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"API response: {response.text}",
                            resolution=(
                                "The Forescout platform may be rate-limiting "
                                "or temporarily unavailable. Retry later or "
                                "reduce the Data Pull Window."
                            ),
                        )
                        raise ForescoutEyeFocusPluginException(err_msg)
                    error_reason = (
                        "API rate limit exceeded"
                        if status_code == 429
                        else "HTTP server error occurred"
                    )
                    retry_after = self._get_retry_after(response.headers)
                    err_msg = RETRY_ERROR_MSG.format(
                        status_code=status_code,
                        error_reason=error_reason,
                        logger_msg=logger_msg,
                        wait_time=retry_after,
                        retry_remaining=MAX_API_RETRIES - 1 - retry_count,
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=f"API response: {response.text}",
                    )
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(
                            response=response,
                            logger_msg=logger_msg,
                            is_validation=is_validation,
                        )
                        if is_handle_error_required
                        else response
                    )
        except ForescoutEyeFocusPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read Timeout error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    f"Ensure that the {PLATFORM_NAME} platform is reachable "
                    "and responsive."
                ),
            )
            raise ForescoutEyeFocusPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the proxy "
                "configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy configuration "
                    "provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution="Verify the proxy configuration provided.",
            )
            raise ForescoutEyeFocusPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    "platform. Verify the Base URL provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    f"Ensure that the {PLATFORM_NAME} Base URL is correct and "
                    "the server is reachable."
                ),
            )
            raise ForescoutEyeFocusPluginException(err_msg)
        except requests.exceptions.RequestException as error:
            err_msg = f"Request error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing an API call to "
                    f"{PLATFORM_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the configuration parameters provided are "
                    "correct."
                ),
            )
            raise ForescoutEyeFocusPluginException(err_msg)
        except Exception as error:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing an API call to "
                    f"{PLATFORM_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the configuration parameters provided are "
                    "correct."
                ),
            )
            raise ForescoutEyeFocusPluginException(err_msg)

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Parse a JSON API response into a dict.

        Raises:
            ForescoutEyeFocusPluginException: When the body is not valid JSON.
        """
        try:
            return response.json()
        except ValueError as error:
            err_msg = (
                f"Invalid JSON response received from {PLATFORM_NAME} while "
                f"{logger_msg}."
            )
            if is_validation:
                err_msg = (
                    f"Invalid JSON response received from {PLATFORM_NAME}. "
                    "Verify the Base URL provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=f"API response: {response.text}",
                resolution=(
                    "Verify the Base URL points at a Forescout REM API "
                    "instance."
                ),
            )
            raise ForescoutEyeFocusPluginException(err_msg)

    def handle_error(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool,
    ) -> Dict:
        """Map HTTP status codes to parsed responses or plugin exceptions."""
        status_code = response.status_code
        validation_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, Bad Request",
            401: (
                "Received exit code 401, Unauthorized access. "
                "Verify the API Token provided in the configuration "
                "parameters."
            ),
            403: (
                "Received exit code 403, Forbidden. Verify "
                "that the API Token has permission to access the REM "
                "Asset Search API."
            ),
            404: (
                "Received exit code 404, Resource not found. "
                "Verify the Base URL provided in the configuration parameters."
            ),
        }
        resolution_dict = {
            400: (
                "Verify the Base URL and the configuration"
                " parameters provided in the "
                "configuration parameters."
            ),
            401: (
                "Verify the API Token provided in the configuration "
                "parameters. It may be invalid or expired."
            ),
            403: (
                "Verify that the API Token has permission to access the REM "
                "Asset Search API."
            ),
            404: (
                "Verify the Base URL provided in the configuration parameters."
            ),
        }

        def _log_and_raise(err_msg: str, resolution: str = None):
            if is_validation:
                self.logger.error(
                    message=f"{self.log_prefix}: {validation_msg}{err_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
            else:
                err_msg = f"{err_msg} while {logger_msg}."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
            raise ForescoutEyeFocusPluginException(err_msg)

        if status_code in [200, 201, 202]:
            return self.parse_response(
                response=response,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            _log_and_raise(
                error_dict[status_code], resolution_dict[status_code]
            )
        elif 400 <= status_code < 500:
            _log_and_raise(
                f"Received exit code {status_code}, HTTP Client Error"
            )
        elif 500 <= status_code < 600:
            _log_and_raise(
                f"Received exit code {status_code}, HTTP Server Error"
            )
        else:
            _log_and_raise(f"Received exit code {status_code}, HTTP Error")

    # ------------------------------------------------------------------ #
    # Windowed asset fetch (the ONLY reliable pagination for this API)
    # ------------------------------------------------------------------ #
    @staticmethod
    def format_risk_score(value: Union[int, float]) -> str:
        """Format a risk score for the query string.

        The API expects the bounds as strings and rejects non-numeric input
        with HTTP 400. Integral values are sent without a decimal part
        (``3.0`` -> ``"3"``) to match the documented examples.
        """
        score = float(value)
        return str(int(score)) if score.is_integer() else repr(score)

    def _build_search_params(
        self,
        from_dt: datetime,
        to_dt: datetime,
        risk_score_min: Optional[float] = None,
        risk_score_max: Optional[float] = None,
        order_by: str = ORDER_BY_FIELD,
    ) -> Dict:
        """Build the REM Asset Search query params for a single window.

        The datetime window, ordering and - when the Advanced Filters are
        enabled - the risk-score bounds are sent to the API. Category
        filtering stays client-side because the API exposes no documented
        category parameter.
        """
        params = {
            "from_date_time_iso_utc": self.format_datetime(from_dt),
            "to_date_time_iso_utc": self.format_datetime(to_dt),
            "order_by": order_by,
            "sort_order": SORT_ORDER,
        }
        if risk_score_min is not None:
            params[RISK_SCORE_MIN_PARAM] = self.format_risk_score(
                risk_score_min
            )
        if risk_score_max is not None:
            params[RISK_SCORE_MAX_PARAM] = self.format_risk_score(
                risk_score_max
            )
        return params

    def _search(
        self,
        ctx: "_SearchContext",
        from_dt: datetime,
        to_dt: datetime,
        score_min_tenths: Optional[int] = None,
        score_max_tenths: Optional[int] = None,
        order_by: str = ORDER_BY_FIELD,
    ) -> Tuple[List[Dict], Optional[int]]:
        """Run one REM Asset Search call and return ``(entities, total_hits)``.

        Score bounds are supplied in tenths of a risk point (or ``None`` to
        omit the bound entirely).

        A window that collapses to zero length *once rendered* is skipped: the
        API answers HTTP 400 when ``from`` equals ``to``, and the wire format
        only carries milliseconds, so two instants less than 1 ms apart are
        indistinguishable to it even though they differ as datetimes.
        """
        if from_dt >= to_dt or self.format_datetime(
            from_dt
        ) == self.format_datetime(to_dt):
            return [], 0

        params = self._build_search_params(
            from_dt=from_dt,
            to_dt=to_dt,
            risk_score_min=(
                None
                if score_min_tenths is None
                else score_min_tenths / RISK_SCORE_TENTHS_PER_POINT
            ),
            risk_score_max=(
                None
                if score_max_tenths is None
                else score_max_tenths / RISK_SCORE_TENTHS_PER_POINT
            ),
            order_by=order_by,
        )
        response = (
            self.api_helper(
                logger_msg=ctx.logger_msg,
                url=f"{ctx.base_url}{REM_ASSET_SEARCH_ENDPOINT}",
                method="GET",
                params=params,
                headers=self._build_headers(ctx.api_token),
                verify=ctx.verify,
                proxies=ctx.proxies,
            )
            or {}
        )
        return (response.get("entities") or []), response.get("total_hits")

    @staticmethod
    def _is_complete(entities: List[Dict], total_hits: Optional[int]) -> bool:
        """True when a response returned everything the API matched."""
        return total_hits is None or len(entities) >= total_hits

    @staticmethod
    def _to_tenths(value: Optional[float], default: int) -> int:
        """Convert a risk score to integer tenths, clamped to the 0-10 scale."""
        if value is None:
            return default
        return max(
            RISK_SCORE_TENTHS_MIN,
            min(
                RISK_SCORE_TENTHS_MAX,
                int(round(float(value) * RISK_SCORE_TENTHS_PER_POINT)),
            ),
        )

    def fetch_asset_window(
        self,
        base_url: str,
        api_token: str,
        from_dt: datetime,
        to_dt: datetime,
        verify: bool = True,
        proxies: Dict = None,
        logger_msg: str = "fetching REM assets",
        risk_score_min: Optional[float] = None,
        risk_score_max: Optional[float] = None,
    ) -> List[Dict]:
        """Fetch ALL asset entities matching ``[from_dt, to_dt)`` (and the
        configured risk bounds), de-duplicated by asset id.

        The REM Asset Search API caps every response at ``RESPONSE_HARD_CAP``
        entities and ignores ``limit``/``offset``/``page``, so a capped window
        has to be broken into smaller queries. This is done on TWO dimensions,
        score first:

        1. **risk_score bands** - the primary axis. Assets are stamped in
           ``last_seen`` bursts (over a thousand can share a 20-second span),
           which no datetime split can separate, but their risk scores still
           spread across the 0-10 scale.
        2. **datetime sub-windows** - the fallback, used only once a band has
           narrowed to a single score value and is *still* capped.

        The window is first queried as-is. That call doubles as the only way to
        observe assets whose ``risk_score`` is exactly 0, because the API
        silently excludes them as soon as either bound is sent; its results are
        merged with the banded results below.

        Returns:
            list[dict]: De-duplicated raw entities for the window. Complete
            unless a single score value inside the smallest supported
            sub-window is itself over the cap, which is logged explicitly.
        """
        if from_dt >= to_dt:
            return []

        ctx = _SearchContext(
            base_url=base_url,
            api_token=api_token,
            verify=verify,
            proxies=proxies,
            logger_msg=logger_msg,
        )
        lo = self._to_tenths(risk_score_min, RISK_SCORE_TENTHS_MIN)
        hi = self._to_tenths(risk_score_max, RISK_SCORE_TENTHS_MAX)

        # Pass 1: the window as configured. Cheap, and the only pass that can
        # surface risk_score == 0 assets when no bound is configured - hence
        # the risk_score ordering, which puts them at the top of the (possibly
        # capped) page instead of leaving them to chance.
        entities, total_hits = self._search(
            ctx,
            from_dt,
            to_dt,
            None if risk_score_min is None else lo,
            None if risk_score_max is None else hi,
            order_by=ZERO_SCORE_PROBE_ORDER_BY,
        )
        if self._is_complete(entities, total_hits):
            return entities

        # Pass 2: capped -> walk the score bands and merge.
        self.logger.debug(
            f"{self.log_prefix}: Window "
            f"[{self.format_datetime(from_dt)} - "
            f"{self.format_datetime(to_dt)}] returned {len(entities)} of "
            f"{total_hits} asset(s); paginating by risk score over "
            f"[{lo / RISK_SCORE_TENTHS_PER_POINT} - "
            f"{hi / RISK_SCORE_TENTHS_PER_POINT}]."
        )
        by_id = {e["id"]: e for e in entities if e.get("id")}
        for entity in self._fetch_score_band(ctx, from_dt, to_dt, lo, hi, 0):
            if entity.get("id"):
                by_id[entity["id"]] = entity
        return list(by_id.values())

    def _fetch_score_band(
        self,
        ctx: "_SearchContext",
        from_dt: datetime,
        to_dt: datetime,
        lo_tenths: int,
        hi_tenths: int,
        depth: int,
    ) -> List[Dict]:
        """Fetch one inclusive risk-score band, subdividing it while capped.

        Bands are half-open in integer tenths so that adjacent bands never
        overlap, even though the API's bounds are inclusive on both ends.
        """
        if lo_tenths > hi_tenths:
            return []

        entities, total_hits = self._search(
            ctx, from_dt, to_dt, lo_tenths, hi_tenths
        )
        if self._is_complete(entities, total_hits):
            return entities

        # Still capped. Narrow the score band first - it is orthogonal to the
        # last_seen bursts that make datetime splitting ineffective.
        span = hi_tenths - lo_tenths + 1
        if span > 1 and depth < MAX_SCORE_SPLIT_DEPTH:
            target = max(1.0, RESPONSE_HARD_CAP * WINDOW_FILL_TARGET)
            parts = min(span, max(2, math.ceil(total_hits / target)))
            step = math.ceil(span / parts)
            aggregated: List[Dict] = []
            band_start = lo_tenths
            while band_start <= hi_tenths:
                band_end = min(band_start + step - 1, hi_tenths)
                aggregated.extend(
                    self._fetch_score_band(
                        ctx, from_dt, to_dt, band_start, band_end, depth + 1
                    )
                )
                band_start = band_end + 1
            return aggregated

        # A single score value that still overflows: fall back to splitting
        # the datetime window for this one band.
        return self._split_band_by_time(
            ctx, from_dt, to_dt, lo_tenths, hi_tenths, entities, total_hits, 0
        )

    def _split_band_by_time(
        self,
        ctx: "_SearchContext",
        from_dt: datetime,
        to_dt: datetime,
        lo_tenths: int,
        hi_tenths: int,
        entities: List[Dict],
        total_hits: int,
        depth: int,
    ) -> List[Dict]:
        """Split a capped, already-minimal score band by datetime.

        ``entities`` / ``total_hits`` are the result of the call that found
        this band capped, so no request is repeated.
        """
        duration = to_dt - from_dt
        if (
            duration.total_seconds() <= MIN_WINDOW_SECONDS
            or depth >= MAX_BISECT_DEPTH
        ):
            self.logger.info(
                f"{self.log_prefix}: Risk score "
                f"{lo_tenths / RISK_SCORE_TENTHS_PER_POINT} within the "
                "smallest supported window "
                f"[{self.format_datetime(from_dt)} - "
                f"{self.format_datetime(to_dt)}] still reports {total_hits} "
                f"matching asset(s) but the API caps responses at "
                f"{RESPONSE_HARD_CAP}. Returning the {len(entities)} "
                "asset(s) available; the remainder for this single score "
                "value in this narrow time-slice cannot be paged and may be "
                "omitted."
            )
            return entities

        target = max(1.0, RESPONSE_HARD_CAP * WINDOW_FILL_TARGET)
        parts = max(2, math.ceil(total_hits / target))
        # Never let the step round below the API's millisecond resolution -
        # a zero-length sub-window is rejected with HTTP 400 and, because the
        # loop advances by `step`, would never terminate.
        step = max(duration / parts, MIN_WINDOW_STEP)
        aggregated: List[Dict] = []
        window_start = from_dt
        while window_start < to_dt:
            window_end = min(window_start + step, to_dt)
            if window_end <= window_start:
                break
            sub_entities, sub_hits = self._search(
                ctx, window_start, window_end, lo_tenths, hi_tenths
            )
            if self._is_complete(sub_entities, sub_hits):
                aggregated.extend(sub_entities)
            else:
                aggregated.extend(
                    self._split_band_by_time(
                        ctx,
                        window_start,
                        window_end,
                        lo_tenths,
                        hi_tenths,
                        sub_entities,
                        sub_hits,
                        depth + 1,
                    )
                )
            window_start = window_end
        return aggregated

    def validate_connectivity(
        self,
        base_url: str,
        api_token: str,
        verify: bool = True,
        proxies: Dict = None,
        risk_score_min: Optional[float] = None,
        risk_score_max: Optional[float] = None,
    ) -> None:
        """Make a single lightweight authenticated call to confirm the Base URL
        and API Token.

        The configured advanced filters are included so that a bound the API
        rejects surfaces as a validation error at save time instead of at the
        first pull. Raises ForescoutEyeFocusPluginException on failure.
        """
        now = datetime.now(timezone.utc)
        url = f"{base_url}{REM_ASSET_SEARCH_ENDPOINT}"
        headers = self._build_headers(api_token)
        params = self._build_search_params(
            from_dt=now - timedelta(hours=1),
            to_dt=now,
            risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )
        self.api_helper(
            logger_msg="validating configuration parameters",
            url=url,
            method="GET",
            params=params,
            headers=headers,
            verify=verify,
            proxies=proxies,
            is_validation=True,
        )
