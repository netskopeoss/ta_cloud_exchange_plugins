"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

CRE Kolide plugin helper module.
"""

import time
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Union

import requests
from netskope.common.utils import add_user_agent
from requests.models import Response

from .constants import (
    BASE_URL,
    DATETIME_FORMAT,
    DEFAULT_WAIT_TIME,
    DEVICE_GROUP_MEMBERSHIP_ENDPOINT,
    DEVICE_GROUP_MEMBERSHIPS_ENDPOINT,
    KOLIDE_API_VERSION,
    KOLIDE_API_VERSION_HEADER,
    KOLIDE_SSF_POLL_TOKEN_HEADER,
    MAX_API_CALLS,
    MAX_RETRY_AFTER,
    MODULE_NAME,
    NO_MORE_RETRIES_ERROR_MSG,
    PAGE_SIZE,
    PLATFORM_NAME,
    RETRY_ERROR_MSG,
    SSF_STREAM_BY_ID_ENDPOINT,
    SSF_STREAM_EVENTS_ENDPOINT,
    SSF_STREAMS_ENDPOINT,
)
from .exceptions import (
    KolidePluginException,
    SSFStreamNotFoundError,
)


class KolidePluginHelper:
    """Helper class for the Kolide CRE ZTRE plugin.

    Provides authentication, request execution with retry logic,
    pagination, and convenience wrappers for Kolide API operations.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        ssl_validation,
        proxy,
    ):
        """Initialize KolidePluginHelper.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix string for all log messages.
            plugin_name (str): Human-readable plugin name.
            plugin_version (str): Plugin version string.
            ssl_validation: SSL certificate verification flag or path.
            proxy: Proxy configuration dictionary.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.verify = ssl_validation
        self.proxies = proxy

    def _add_user_agent(
        self, headers: Union[Dict, None] = None
    ) -> Dict:
        """Add a User-Agent header to outgoing requests.

        If the headers dict already contains a ``User-Agent`` key the
        method returns it unchanged.  Otherwise the Netskope CE base
        agent string is fetched via :func:`add_user_agent` and the
        plugin's own identity is appended in the standard
        ``{ce_agent}-{module}-{plugin}-v{version}`` format.

        Args:
            headers (Dict | None): Existing headers dictionary, or
                ``None`` to start from an empty dict.

        Returns:
            Dict: Headers dictionary with ``User-Agent`` set.
        """
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

    def get_auth_headers(self, api_token: str) -> Dict:
        """Build the standard Kolide authentication headers.

        Args:
            api_token (str): Kolide API bearer token.

        Returns:
            Dict: Headers dict containing ``Authorization``,
                ``x-kolide-api-version``, ``Content-Type``, and
                ``Accept`` fields.
        """
        return {
            "Authorization": f"Bearer {api_token}",
            KOLIDE_API_VERSION_HEADER: KOLIDE_API_VERSION,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def get_configuration_parameters(
        self, configuration: Dict
    ) -> Tuple[str]:
        """Extract plugin configuration parameters.

        Args:
            configuration (Dict): Plugin configuration dictionary as
                provided by the Netskope CE framework.

        Returns:
            Tuple[str]: A one-tuple ``(api_token,)``.
        """
        api_token = configuration.get("api_token")
        return (api_token,)

    # ------------------------------------------------------------------
    # Field helpers
    # ------------------------------------------------------------------

    def _extract_field_from_event(
        self, key, event, default=None, transformation=None
    ):
        """Resolve a dot-notation key path against a nested dict and
        optionally apply a named transformation method.

        Args:
            key (str): Dot-separated path, e.g. ``"foo.bar.baz"``.
            event (dict): Source dictionary to traverse.
            default: Value to return when any segment is missing.
            transformation (str | None): Name of an instance method to
                call on the resolved value before returning it.

        Returns:
            The resolved (and optionally transformed) value, or
            *default* if any segment is absent.
        """
        parts = key.split(".")
        val = event
        for part in parts:
            if not isinstance(val, dict):
                return default
            val = val.get(part)
            if val is None:
                return default
        if transformation and val is not None:
            transform_fn = getattr(self, transformation)
            return transform_fn(val)
        return val if val is not None else default

    def _parse_datetime(self, value):
        """Parse an ISO 8601 datetime string into a datetime object.

        Args:
            value (str): Datetime string, e.g. ``"2026-06-22T07:45:00Z"``.

        Returns:
            datetime | None: Parsed datetime, or None on failure.
        """
        if not value:
            return None
        try:
            return datetime.strptime(value, DATETIME_FORMAT)
        except (ValueError, TypeError):
            return None

    def add_field(self, fields_dict, field_name, value):
        """Conditionally add a field to a record dictionary.

        Empty collections are stored as ``None``.  Numeric zero is
        stored as-is.  All other falsy values are omitted.

        Args:
            fields_dict (dict): Target record dictionary.
            field_name (str): Key to insert.
            value: Value to store.
        """
        if isinstance(value, (dict, list)) and not value:
            fields_dict[field_name] = None
        elif isinstance(value, (int, float)):
            fields_dict[field_name] = value
        elif value:
            fields_dict[field_name] = value

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str = "GET",
        params=None,
        data: Dict = None,
        headers: Dict = None,
        json: Dict = None,
        is_validation: bool = False,
        is_handle_error_required: bool = True,
    ):
        """Execute an HTTP request against the Kolide API.

        Automatically injects the User-Agent header, retries on HTTP
        429 (rate limit) and 5xx (server error) responses up to
        ``MAX_API_CALLS`` times, and delegates error handling to
        :meth:`handle_error` when requested.

        Args:
            logger_msg (str): Short description of the operation, used
                in log lines and exception messages.
            url (str): Full request URL.
            method (str): HTTP method (default ``"GET"``).
            params: Query-string parameters dict (optional).
            data (Dict): Form-encoded body (optional).
            headers (Dict): Request headers dict (optional).
            json (Dict): JSON-serialisable request body (optional).
            is_validation (bool): When ``True`` the retry loop is
                bypassed for 429/5xx so that validation fails fast.
            is_handle_error_required (bool): When ``True`` the raw
                :class:`Response` is passed through
                :meth:`handle_error` before being returned.

        Returns:
            Dict | Response: Parsed response dict when
                ``is_handle_error_required`` is ``True``, otherwise
                the raw :class:`requests.models.Response`.

        Raises:
            KolidePluginException: On any error condition including
                connection failures, timeouts, proxy errors, HTTP
                errors, and exhausted retries.
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
            for retry_count in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=self.verify,
                    proxies=self.proxies,
                    json=json,
                )
                status_code = response.status_code
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: Received API Response for "
                        f"{logger_msg}. Status Code={status_code}."
                    ),
                )
                # Handle rate-limit (429) and server errors (5xx)
                if not is_validation and (
                    status_code == 429
                    or 500 <= status_code <= 600
                ):
                    api_err_msg = str(response.text)
                    if retry_count == MAX_API_CALLS - 1:
                        err_msg = NO_MORE_RETRIES_ERROR_MSG.format(
                            status_code=status_code,
                            logger_msg=logger_msg,
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg}"
                            )
                        )
                        raise KolidePluginException(err_msg)
                    if status_code == 429:
                        error_reason = "API rate limit exceeded"
                    else:
                        error_reason = "HTTP server error occurred"
                    retry_after = self._get_retry_after(
                        response.headers
                    )
                    err_msg = RETRY_ERROR_MSG.format(
                        status_code=status_code,
                        error_reason=error_reason,
                        logger_msg=logger_msg,
                        wait_time=retry_after,
                        retry_remaining=(
                            MAX_API_CALLS - 1 - retry_count
                        ),
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=api_err_msg,
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
        except KolidePluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = (
                f"Read Timeout error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = "Read Timeout error occurred."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {error}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    f"Please check if the {PLATFORM_NAME} API server"
                    " is reachable."
                ),
            )
            raise KolidePluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify"
                " the proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy"
                    " configuration provided."
                )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {error}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Please check if the proxy configuration provided"
                    " is correct and the proxy server is reachable."
                ),
            )
            raise KolidePluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME}"
                f" platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with"
                    f" {PLATFORM_NAME} platform. Proxy server or"
                    f" {PLATFORM_NAME} server is not reachable."
                )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {error}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    f"Please check if the {PLATFORM_NAME} API server"
                    " is reachable."
                ),
            )
            raise KolidePluginException(err_msg)
        except requests.HTTPError as error:
            err_msg = (
                f"HTTP error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify configuration"
                    " parameters provided."
                )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {error}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Please verify the configuration parameters"
                    " provided."
                ),
            )
            raise KolidePluginException(err_msg)
        except Exception as error:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    "Unexpected error while performing API call to"
                    f" {PLATFORM_NAME}."
                )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {error}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Please verify the configuration parameters"
                    " provided."
                ),
            )
            raise KolidePluginException(err_msg)

    def _get_retry_after(self, headers) -> int:
        """Determine how long to wait before the next retry attempt.

        Reads the ``Retry-After`` or ``retry-after`` response header
        and clamps the value to ``MAX_RETRY_AFTER`` seconds to prevent
        unbounded waits.

        Args:
            headers: Response headers mapping.

        Returns:
            int: Number of seconds to wait, between 0 and
                ``MAX_RETRY_AFTER``.
        """
        val = headers.get("Retry-After") or headers.get(
            "retry-after"
        )
        wait = int(val) if val else DEFAULT_WAIT_TIME
        return min(wait, MAX_RETRY_AFTER)

    def parse_response(
        self,
        response: Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Parse the JSON body of a successful API response.

        Args:
            response (Response): The :class:`requests.models.Response`
                object to parse.
            logger_msg (str): Operation description for log messages.
            is_validation (bool): Passed through to error context.

        Returns:
            Dict: Deserialised JSON body.

        Raises:
            KolidePluginException: If the response body is not valid
                JSON or any other parsing error occurs.
        """
        try:
            return response.json()
        except ValueError as error:
            err_msg = (
                f"Invalid JSON response received while {logger_msg}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {error}"
                ),
                details=f"API response: {response.text}",
            )
            raise KolidePluginException(err_msg)
        except Exception as error:
            err_msg = (
                "Unexpected error occurred while parsing response"
                f" for {logger_msg}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {error}"
                ),
                details=f"API response: {response.text}",
            )
            raise KolidePluginException(err_msg)

    def handle_error(
        self,
        response: Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Interpret an HTTP response and raise on non-success codes.

        Maps HTTP status codes to actionable error and resolution
        messages.  Returns the parsed JSON body for 200/201/202, an
        empty dict for 204, and raises :class:`KolidePluginException`
        for all other codes.

        Args:
            response (Response): The :class:`requests.models.Response`
                to inspect.
            logger_msg (str): Operation description for log messages.
            is_validation (bool): When ``True`` uses
                validation-specific error wording that references
                "Verify the API Token".

        Returns:
            Dict: Parsed response body (200/201/202) or ``{}`` (204).

        Raises:
            KolidePluginException: For any non-2xx status code.
        """
        status_code = response.status_code
        validation_msg = "Validation error occurred, "

        error_dict = {
            400: "Received exit code 400, Bad Request",
            401: "Received exit code 401, Unauthorized access",
            403: "Received exit code 403, Forbidden",
            404: "Received exit code 404, Resource not found",
        }
        resolution_dict = {
            400: (
                "Ensure configuration or action parameters are"
                " valid."
            ),
            401: (
                "Ensure the API Token provided is valid and has"
                " not expired."
            ),
            403: (
                "Ensure the API Token has sufficient permissions"
                " for the requested operation."
            ),
            404: (
                "Ensure the Kolide resource being accessed exists."
            ),
        }

        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request, "
                    "Verify the API Token and configuration"
                    " parameters are valid."
                ),
                401: (
                    "Received exit code 401, Unauthorized, "
                    "Verify the API Token provided in the"
                    " configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, "
                    "Verify the API Token has sufficient"
                    " permissions to access the Kolide API."
                ),
                404: (
                    "Received exit code 404, Resource not found, "
                    "Verify the Kolide resource you are trying to"
                    " access exists."
                ),
            }

        def _log_error_message(resolution: str = None):
            """Log the error and raise KolidePluginException."""
            nonlocal err_msg
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {log_err_msg}"
                    ),
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise KolidePluginException(err_msg)
            else:
                err_msg = (
                    err_msg + " while " + logger_msg + "."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg}"
                    ),
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise KolidePluginException(err_msg)

        if status_code in (200, 201, 202):
            return self.parse_response(
                response=response,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            resolution_msg = resolution_dict.get(status_code)
            _log_error_message(resolution=resolution_msg)
        elif 400 <= status_code < 500:
            err_msg = "HTTP Client Error"
            _log_error_message()
        elif 500 <= status_code < 600:
            err_msg = "HTTP Server Error"
            _log_error_message()
        else:
            err_msg = "HTTP Error"
            _log_error_message()

    # ------------------------------------------------------------------
    # Pagination helper
    # ------------------------------------------------------------------

    def fetch_paginated_list(
        self,
        endpoint_url: str,
        headers: Dict,
        logger_msg: str,
        item_label: str = "item(s)",
        params: Optional[Dict] = None,
    ) -> List:
        """Retrieve all items from a cursor-paginated Kolide endpoint.

        Iterates through pages by following ``pagination.next_cursor``
        until the cursor is empty or absent, collecting all ``data``
        items across pages.

        Args:
            endpoint_url (str): Full URL of the list endpoint.
            headers (Dict): Authentication and version headers.
            logger_msg (str): Operation description for log messages.
            item_label (str): Human-readable name of the items being
                fetched (e.g. ``"open issues"`` or ``"device groups"``),
                used in the per-page debug log.
            params (Dict | None): Additional query parameters to merge
                into every request (optional).

        Returns:
            List: Flat list of all items returned across all pages.
        """
        all_items: List = []
        cursor: Optional[str] = None
        page = 1

        while True:
            page_params: Dict = {"per_page": PAGE_SIZE}
            if cursor is not None:
                page_params["cursor"] = cursor
            if params:
                page_params.update(params)

            response = self.api_helper(
                logger_msg=logger_msg,
                url=endpoint_url,
                method="GET",
                params=page_params,
                headers=headers,
            )

            items = response.get("data", [])
            all_items.extend(items)
            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched"
                f" {len(items)} {item_label} in page {page}. Total"
                f" {item_label} fetched: {len(all_items)}."
            )

            next_cursor = response.get(
                "pagination", {}
            ).get("next_cursor")
            if not next_cursor:
                break
            cursor = next_cursor
            page += 1

        return all_items

    # ------------------------------------------------------------------
    # Device-group helpers
    # ------------------------------------------------------------------

    def add_devices_to_group(
        self,
        group_id: str,
        device_ids: List[str],
        headers: Dict,
        group_name: str = "",
        batch_number: Optional[int] = None,
    ) -> Set[str]:
        """Add one or more devices to a Kolide device group.

        The API responds with one ``{"device_id", "group_id"}`` entry
        per device it actually added; a device that was not added (e.g.
        it does not exist) is omitted from the response. The set of
        added device IDs is returned so the caller can attribute the
        devices that were not added back to their originating actions.

        Args:
            group_id (str): Kolide device group ID.
            device_ids (List[str]): List of device IDs to add.
            headers (Dict): Authentication and version headers.
            group_name (str): Display name of the group, used in logs.
            batch_number (Optional[int]): 1-based batch number, included
                in log messages when the caller sends devices in
                batches.

        Returns:
            Set[str]: Device IDs (as strings) the API confirmed were
                added to the group.
        """
        url = DEVICE_GROUP_MEMBERSHIPS_ENDPOINT.format(
            base_url=BASE_URL, group_id=group_id
        )
        label = group_name or group_id
        batch_suffix = (
            f" in batch {batch_number}"
            if batch_number is not None
            else ""
        )
        logger_msg = (
            f"adding {len(device_ids)} device(s){batch_suffix} to"
            f" group '{label}'"
        )
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers=headers,
            json={"device_ids": device_ids},
        )
        if isinstance(response, list):
            entries = response
        elif isinstance(response, dict):
            entries = response.get("data", []) or []
        else:
            entries = []
        added_ids = {
            str(entry.get("device_id"))
            for entry in entries
            if isinstance(entry, dict)
            and entry.get("device_id") is not None
        }
        self.logger.info(
            message=(
                f"{self.log_prefix}: Successfully added {len(added_ids)}"
                f" out of {len(device_ids)} device(s){batch_suffix} to"
                f" group '{label}'"
            )
        )
        return added_ids

    def remove_device_from_group(
        self,
        group_id: str,
        device_id: str,
        headers: Dict,
        group_name: str = "",
    ) -> bool:
        """Remove a single device from a Kolide device group.

        The API responds with a ``{"device_id", "group_id"}`` body
        naming the device it removed, so the return value reports whether
        this device was removed. A device that is not a member of the
        group is reported by the API as a 404 and raised like any other
        error (handled per-device by the caller) rather than treated as a
        special no-op.

        Args:
            group_id (str): Kolide device group ID.
            device_id (str): ID of the device to remove.
            headers (Dict): Authentication and version headers.
            group_name (str): Display name of the group, used in logs.

        Returns:
            bool: True when the response confirms this device was
                removed from the group.
        """
        url = DEVICE_GROUP_MEMBERSHIP_ENDPOINT.format(
            base_url=BASE_URL,
            group_id=group_id,
            device_id=device_id,
        )
        label = group_name or group_id
        logger_msg = (
            f"removing device with ID '{device_id}' from group '{label}'"
        )
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="DELETE",
            headers=headers,
        )
        removed = (
            isinstance(response, dict)
            and str(response.get("device_id")) == str(device_id)
        )
        if removed:
            self.logger.info(
                f"{self.log_prefix}: Successfully removed device"
                f" '{device_id}' from group '{label}'."
            )
        return removed

    # ------------------------------------------------------------------
    # SSF (Shared Signals Framework) stream helpers
    # ------------------------------------------------------------------

    def get_ssf_poll_headers(
        self, api_token: str, poll_bearer_token: str
    ) -> Dict:
        """Build headers for SSF stream poll and acknowledge requests.

        Args:
            api_token (str): Kolide API bearer token.
            poll_bearer_token (str): Stream-specific poll bearer token.

        Returns:
            Dict: Headers dict with both auth tokens set.
        """
        headers = self.get_auth_headers(api_token)
        headers[KOLIDE_SSF_POLL_TOKEN_HEADER] = poll_bearer_token
        return headers

    def create_ssf_stream(
        self,
        api_token: str,
        stream_name: str,
        event_subscriptions: List[str],
    ) -> Tuple[str, str]:
        """Create a Kolide SSF poll-delivery stream (standard SSF format).

        This is the single point responsible for obtaining a stream ID
        and poll bearer token.  Swap this method if the token-acquisition
        mechanism changes (e.g. accepting a pre-configured token from
        plugin configuration instead).

        Uses the standard SSF request body (top-level ``delivery`` object
        with a method URN and ``events_requested``).  RFC 8936 is the
        poll-delivery method; no ``endpoint_url`` is required.

        Args:
            api_token (str): Kolide API bearer token.
            stream_name (str): Human-readable stream name shown in
                the Kolide UI.
            event_subscriptions (List[str]): CAEP event-type URIs to
                subscribe to.

        Returns:
            Tuple[str, str]: ``(stream_id, poll_bearer_token)``.
        """
        url = SSF_STREAMS_ENDPOINT.format(base_url=BASE_URL)
        body = {
            "name": stream_name,
            "delivery": {
                "method": "urn:ietf:rfc:8936",
            },
            "events_requested": event_subscriptions,
        }
        logger_msg = "creating SSF poll-delivery stream"
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers=self.get_auth_headers(api_token),
            json=body,
        )
        # Both standard and legacy formats return "stream_id" — the UUID
        # used in the events endpoint URL.  "id" is a separate short
        # numeric identifier and must NOT be used for polling.
        stream_id = str(response.get("stream_id", ""))
        poll_bearer_token = response.get("poll_bearer_token")
        if not stream_id:
            err_msg = (
                f"Error occurred while {logger_msg}. No stream ID"
                " found in API response."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise KolidePluginException(err_msg)
        if not poll_bearer_token:
            err_msg = (
                f"Error occurred while {logger_msg}. No Poll Bearer"
                " token found in the API response."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise KolidePluginException(err_msg)
        return stream_id, poll_bearer_token

    def delete_ssf_stream(
        self,
        api_token: str,
        stream_id: str,
    ) -> None:
        """Delete a Kolide SSF stream by its ID (best-effort).

        Used by the poll-error recovery path to remove a stale stream
        before a replacement is created. A 404 (stream already gone) is
        treated as success; any other non-2xx status - or a request
        error - is logged but never raised, because the caller proceeds
        to create a fresh stream regardless and must not be blocked by a
        failed clean-up of the old one.

        Args:
            api_token (str): Kolide API bearer token.
            stream_id (str): ID of the SSF stream to delete.

        Returns:
            None
        """
        url = SSF_STREAM_BY_ID_ENDPOINT.format(
            base_url=BASE_URL, stream_id=stream_id
        )
        logger_msg = f"deleting SSF stream '{stream_id}'"
        try:
            response = self.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="DELETE",
                headers=self.get_auth_headers(api_token),
                is_handle_error_required=False,
            )
            status_code = response.status_code
            if status_code in (200, 202, 204, 404):
                self.logger.info(
                    f"{self.log_prefix}: Deleted SSF stream"
                    f" '{stream_id}' (status {status_code})."
                )
            else:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Received status"
                        f" {status_code} while {logger_msg}."
                        " Continuing with new stream creation."
                    ),
                    details=f"API response: {response.text}",
                )
        except Exception as error:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error while {logger_msg}."
                    " Continuing with new stream creation."
                    f" Error: {error}"
                ),
                details=traceback.format_exc(),
            )

    def poll_ssf_events(
        self,
        stream_id: str,
        api_token: str,
        poll_bearer_token: str,
    ) -> Dict[str, str]:
        """Poll the SSF stream for pending Security Event Tokens.

        Distinguishes a genuinely missing stream (HTTP 404) from every
        other failure: a 404 raises :class:`SSFStreamNotFoundError` so
        the caller can recreate the stream, whereas transient problems
        (429/5xx/network) surface as a generic
        :class:`KolidePluginException` via :meth:`handle_error` and must
        NOT trigger a recreate.

        Args:
            stream_id (str): SSF stream ID.
            api_token (str): Kolide API bearer token.
            poll_bearer_token (str): Stream-specific poll bearer token.

        Returns:
            Dict[str, str]: Mapping of ``jti`` -> raw JWT string for
                each pending event.

        Raises:
            SSFStreamNotFoundError: If the stream returns HTTP 404.
            KolidePluginException: On any other non-2xx status or error.
        """
        url = SSF_STREAM_EVENTS_ENDPOINT.format(
            base_url=BASE_URL, stream_id=stream_id
        )
        logger_msg = "polling SSF stream events"
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="GET",
            headers=self.get_ssf_poll_headers(
                api_token, poll_bearer_token
            ),
            is_handle_error_required=False,
        )
        if response.status_code == 404:
            err_msg = (
                f"Received exit code 404, Resource not found."
                f" SSF stream '{stream_id}' was not found while"
                " polling for compliance events."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=(
                    "The stream was likely deleted on Kolide; it will"
                    " be recreated automatically."
                ),
            )
            raise SSFStreamNotFoundError(err_msg)
        parsed = self.handle_error(
            response=response, logger_msg=logger_msg
        )
        return parsed.get("sets", {})

    def acknowledge_ssf_events(
        self,
        stream_id: str,
        api_token: str,
        poll_bearer_token: str,
        jtis: List[str],
    ) -> None:
        """Acknowledge SSF events so they are not re-delivered.

        Args:
            stream_id (str): SSF stream ID.
            api_token (str): Kolide API bearer token.
            poll_bearer_token (str): Stream-specific poll bearer token.
            jtis (List[str]): JWT IDs to acknowledge.
        """
        if not jtis:
            return
        url = SSF_STREAM_EVENTS_ENDPOINT.format(
            base_url=BASE_URL, stream_id=stream_id
        )
        self.api_helper(
            logger_msg=(
                f"acknowledging {len(jtis)} SSF event(s)"
            ),
            url=url,
            method="POST",
            headers=self.get_ssf_poll_headers(
                api_token, poll_bearer_token
            ),
            json={"ack": list(jtis)},
        )
