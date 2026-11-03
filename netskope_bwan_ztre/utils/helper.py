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

CRE Netskope Borderless WAN plugin helper module.
"""

import ipaddress
import json
import re
import time
import traceback
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

import requests

from netskope.common.utils import add_user_agent

from .constants import (
    ADD_TO_ADDRESS_GROUP,
    APPLIED_IPS_OF_FAILED_RECORDS,
    DATETIME_PARSE_FORMATS,
    DEFAULT_WAIT_TIME,
    ERROR_CODE_INTERNAL,
    ERROR_CODE_UNAVAILABLE,
    FIELD_TYPE_BOOLEAN,
    FIELD_TYPE_IPV4,
    FIELD_TYPE_NUMBER,
    MAX_ADDRESS_OBJECTS_PER_GROUP,
    MAX_API_CALLS,
    MAX_HOST_LENGTH,
    MAX_PAGES,
    MAX_PORT,
    MAX_RETRY_AFTER_IN_SECS,
    MIN_PORT,
    MODULE_NAME,
    OUTCOME_ADDED,
    OUTCOME_ALREADY_EXISTS,
    OUTCOME_EXISTS_ON_TENANT,
    OUTCOME_FAILED,
    OUTCOME_LIMIT_EXCEEDED,
    OUTCOME_NOT_FOUND,
    OUTCOME_REMOVED,
    PAGE_SIZE,
    PLATFORM_NAME,
    PROTOCOL_PORT_PARAMS,
    REGEX_HOSTNAME_LABEL,
    RESOLUTION_401,
    RESOLUTION_403,
    RESOLUTION_403_VALIDATION,
    RESOLUTION_404,
    RESOLUTION_BASE_URL,
    RESOLUTION_CONFIG_TOKEN_401,
    RESOLUTION_CONFIG_TOKEN_PERMISSION,
    RESOLUTION_GENERIC,
    RESOLUTION_HTTP,
    RESOLUTION_PROXY,
    USER_EMAIL_KEY,
    USER_ID_PATH,
)


# Returned when a field cannot be resolved because the lookup it needs was
# unavailable, as opposed to the platform having no value. The caller
# leaves the field out of the record entirely, so Cloud Exchange keeps
# whatever it already holds instead of having it cleared.
FIELD_UNAVAILABLE = object()


class NetskopeBwanPluginException(Exception):
    """Netskope Borderless WAN plugin exception class."""

    pass


class NetskopeBwanFatalAPIException(NetskopeBwanPluginException):
    """Exception for failures that further similar API calls would repeat.

    Raised when retries are exhausted on HTTP 429 or HTTP 5xx, when
    Retry-After is too long, or on HTTP 401 or HTTP 403. The per IP
    loops of the plugin stop calling the API for the remaining IPs of an
    Address Group when they receive this exception.
    """

    def __init__(
        self, message: str, reason: str, resolution: Optional[str] = None
    ):
        """Initialize the exception.

        Args:
            message (str): Error message.
            reason (str): Short cause of the failure, e.g. 'received
                exit code 401, Unauthorized'.
            resolution (str, optional): Resolution for the cause. None
                when the user cannot fix the cause (HTTP 429 / 5xx).
        """
        super().__init__(message)
        self.reason = reason
        self.resolution = resolution


class NetskopeBwanPluginHelper(object):
    """Netskope Borderless WAN plugin helper class.

    Provides API request handling (retries, error handling, response
    parsing), cursor-based pagination and action summary builders.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """Netskope Borderless WAN plugin helper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): Log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        # User ID to user mapping, filled by the plugin before an
        # entity batch is mapped and read by the 'user_email' and
        # 'user_email' transformation.
        self.user_cache: Dict[str, Dict] = {}
        # True when the user listing could not be read for this batch, so
        # a miss in the cache means "not looked up" rather than "no such
        # user". The user fields are then left out of the record.
        self.user_lookup_failed: bool = False

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers of any request.

        Args:
            headers (Dict, optional): Headers needed to pass to the
                Third Party Platform.

        Returns:
            Dict: Dictionary containing the User-Agent.
        """
        if headers and "User-Agent" in headers:
            return headers

        headers = add_user_agent(header=headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def get_headers(self, api_token: str) -> Dict:
        """Build the request headers for the Netskope Borderless WAN API.

        The Auth Token is a password field, hence it is used exactly as
        provided and is never stripped or logged.

        Args:
            api_token (str): Netskope Borderless WAN tenant API token.

        Returns:
            Dict: Request headers.
        """
        return {
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _get_retry_after(self, headers: Dict) -> int:
        """Get the wait time in seconds from the Retry-After header.

        Args:
            headers (Dict): Response headers.

        Returns:
            int: Wait time in seconds. DEFAULT_WAIT_TIME when the header
                is missing, not numeric or negative.
        """
        try:
            retry_after = int(float((headers or {}).get("Retry-After")))
        except (TypeError, ValueError, OverflowError):
            return DEFAULT_WAIT_TIME
        if retry_after < 0:
            return DEFAULT_WAIT_TIME
        return retry_after

    def _log_and_raise(
        self,
        err_msg: str,
        resolution: Optional[str],
        details: Optional[str] = None,
        fatal_reason: Optional[str] = None,
        fatal_resolution: Optional[str] = None,
    ):
        """Log an error and raise the plugin exception.

        Args:
            err_msg (str): Error message (without log prefix).
            resolution (str, optional): Resolution for the error. None
                when the user cannot fix the error; the log is then
                written without a resolution.
            details (str, optional): Details for the error log.
            fatal_reason (str, optional): When provided, a
                NetskopeBwanFatalAPIException with this reason is raised.
            fatal_resolution (str, optional): Resolution of the cause
                carried by the fatal exception. Defaults to resolution.

        Raises:
            NetskopeBwanPluginException: Always.
        """
        log_kwargs = {"message": f"{self.log_prefix}: {err_msg}"}
        if details:
            log_kwargs["details"] = details
        if resolution:
            log_kwargs["resolution"] = resolution
        self.logger.error(**log_kwargs)
        if fatal_reason:
            raise NetskopeBwanFatalAPIException(
                err_msg, fatal_reason, fatal_resolution or resolution
            )
        raise NetskopeBwanPluginException(err_msg)

    def _handle_retry(
        self,
        response: requests.models.Response,
        logger_msg: str,
        retry_counter: int,
    ) -> int:
        """Handle a retryable (429 or 5xx) response.

        Args:
            response (requests.models.Response): Response object.
            logger_msg (str): Logger message for the operation.
            retry_counter (int): Current attempt index (0 based).

        Returns:
            int: Number of seconds to wait before the next attempt.

        Raises:
            NetskopeBwanPluginException: When retries are exhausted or
                Retry-After is greater than MAX_RETRY_AFTER_IN_SECS.
        """
        status_code = response.status_code
        api_details = f"API response: {response.text}"
        is_rate_limit = status_code == 429
        if retry_counter == MAX_API_CALLS - 1:
            if is_rate_limit:
                err_msg = (
                    f"Error occurred while {logger_msg}. Received exit "
                    "code 429, API rate limit exceeded. Max retries "
                    "exceeded."
                )
                reason = (
                    "received exit code 429, API rate limit exceeded, after "
                    "max retries"
                )
            else:
                err_msg = (
                    f"Error occurred while {logger_msg}. Received exit "
                    f"code {status_code}, HTTP server error. Max retries "
                    "exceeded."
                )
                reason = (
                    f"received exit code {status_code}, HTTP server error, "
                    "after max retries"
                )
            # API side failure the user cannot fix, hence no resolution.
            self._log_and_raise(err_msg, None, api_details, reason)

        if is_rate_limit:
            retry_after = self._get_retry_after(response.headers)
            if retry_after > MAX_RETRY_AFTER_IN_SECS:
                err_msg = (
                    f"Error occurred while {logger_msg}. Received exit "
                    "code 429 with Retry-After greater than "
                    f"{MAX_RETRY_AFTER_IN_SECS} seconds."
                )
                self._log_and_raise(
                    err_msg,
                    None,
                    api_details,
                    "received exit code 429 with Retry-After greater than "
                    f"{MAX_RETRY_AFTER_IN_SECS} seconds",
                )
            reason = "API rate limit exceeded"
        else:
            retry_after = DEFAULT_WAIT_TIME
            reason = "HTTP server error occurred"

        self.logger.info(
            message=(
                f"{self.log_prefix}: Received exit code {status_code}, "
                f"{reason} while {logger_msg}. Retrying after "
                f"{retry_after} second(s). "
                f"{MAX_API_CALLS - 1 - retry_counter} retries remaining."
            ),
            details=api_details,
        )
        return retry_after

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        verify: bool = True,
        proxies: Optional[Dict] = None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        resolution: Optional[str] = None,
        is_config_token: bool = False,
        is_write: bool = False,
    ) -> Union[Dict, requests.models.Response]:
        """Perform an API request on the Netskope Borderless WAN platform.

        Retries HTTP 429 and HTTP 5xx responses (not for validation
        calls) and converts every request error into the plugin
        exception after logging it with a resolution.

        Args:
            logger_msg (str): Logger message for the operation.
            url (str): URL of the endpoint.
            method (str): HTTP method of the endpoint.
            params (Dict, optional): Query parameters.
            json_data (Dict, optional): JSON payload.
            headers (Dict, optional): Request headers.
            verify (bool, optional): Verify the SSL certificate.
            proxies (Dict, optional): Proxies for the request.
            is_handle_error_required (bool, optional): Whether the status
                code should be handled by handle_error. Defaults to True.
            is_validation (bool, optional): Whether the call is made from
                validation. Validation calls are never retried.
            resolution (str, optional): Operation specific resolution
                used for non-specific failures.
            is_config_token (bool, optional): Whether 'headers' carry
                the optional 'API Token' from the configuration
                parameters (instead of the Tenant Auth Token). Used to
                report HTTP 401 and HTTP 403 for that token.
            is_write (bool, optional): Whether the call changes an object
                on the platform. An HTTP 5xx carrying a known Netskope
                Borderless WAN error code is then returned to the caller
                without a retry, since neither code is transient.

        Returns:
            Union[Dict, requests.models.Response]: Parsed JSON response
                when is_handle_error_required is True, else the raw
                response object with a 'bwan_had_server_error' attribute
                that is True when an HTTP 5xx was received (and retried)
                before the final response, a 'bwan_error_code' attribute
                carrying the error code of the final response, and a
                'bwan_is_config_token' attribute.

        Raises:
            NetskopeBwanPluginException: When the API call fails.
        """
        headers = self._add_user_agent(headers)
        # Whether an HTTP 5xx was received before the final response. A
        # 5xx may be returned after the server already applied a
        # mutation, hence it is attached to the returned raw response.
        had_server_error = False
        try:
            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}. "
                f"Endpoint: {method} {url}"
            )
            if params:
                debug_log_msg += f", params: {params}"
            self.logger.debug(debug_log_msg)

            for retry_counter in range(MAX_API_CALLS):
                response = self._send_request(
                    logger_msg, url, method, params, json_data, headers,
                    verify, proxies,
                )
                status_code = response.status_code
                response.bwan_is_config_token = is_config_token
                if (
                    status_code == 429 or 500 <= status_code <= 599
                ) and not is_validation:
                    if status_code != 429:
                        had_server_error = True
                    if (
                        is_write
                        and not is_handle_error_required
                        and 500 <= status_code <= 599
                    ):
                        error_code = self.get_error_code(response)
                        if error_code in (
                            ERROR_CODE_UNAVAILABLE,
                            ERROR_CODE_INTERNAL,
                        ):
                            self._log_write_server_error(
                                logger_msg, response, error_code
                            )
                            response.bwan_had_server_error = had_server_error
                            response.bwan_error_code = error_code
                            return response
                    retry_after = self._handle_retry(
                        response, logger_msg, retry_counter
                    )
                    time.sleep(retry_after)
                    continue
                if not is_handle_error_required:
                    response.bwan_had_server_error = had_server_error
                    response.bwan_error_code = self.get_error_code(response)
                    return response
                return self.handle_error(
                    response, logger_msg, is_validation, resolution
                )
        except NetskopeBwanPluginException:
            raise
        except requests.exceptions.ReadTimeout:
            err_msg = (
                f"Error occurred while {logger_msg}. Read timeout error "
                "occurred."
            )
            self._log_and_raise(err_msg, None, traceback.format_exc())
        except requests.exceptions.ProxyError:
            err_msg = (
                f"Error occurred while {logger_msg}. Proxy error occurred."
            )
            self._log_and_raise(
                err_msg, RESOLUTION_PROXY, traceback.format_exc()
            )
        except requests.exceptions.ConnectionError:
            err_msg = (
                f"Error occurred while {logger_msg}. Unable to establish "
                f"connection with {PLATFORM_NAME}."
            )
            self._log_and_raise(
                err_msg, RESOLUTION_BASE_URL, traceback.format_exc()
            )
        except requests.HTTPError:
            err_msg = (
                f"Error occurred while {logger_msg}. HTTP error occurred."
            )
            self._log_and_raise(
                err_msg, RESOLUTION_HTTP, traceback.format_exc()
            )
        except Exception as exp:
            raise self.handle_unexpected_error(logger_msg, exp)

    def _send_request(
        self,
        logger_msg: str,
        url: str,
        method: str,
        params: Optional[Dict],
        json_data: Optional[Dict],
        headers: Dict,
        verify: bool,
        proxies: Optional[Dict],
    ) -> requests.models.Response:
        """Send one HTTP request and log its status code.

        Args:
            logger_msg (str): Logger message for the operation.
            url (str): URL of the endpoint.
            method (str): HTTP method of the endpoint.
            params (Dict, optional): Query parameters.
            json_data (Dict, optional): JSON payload.
            headers (Dict): Request headers.
            verify (bool): Verify the SSL certificate.
            proxies (Dict, optional): Proxies for the request.

        Returns:
            requests.models.Response: Response of the request.
        """
        response = requests.request(
            url=url,
            method=method,
            params=params,
            json=json_data,
            headers=headers,
            verify=verify,
            proxies=proxies,
        )
        self.logger.debug(
            f"{self.log_prefix}: Received API Response for "
            f"{logger_msg}. Status Code={response.status_code}."
        )
        return response

    def handle_unexpected_error(
        self,
        logger_msg: str,
        exp: Exception,
    ) -> NetskopeBwanPluginException:
        """Log an unexpected error with traceback (no resolution).

        Must be called from within an except block so that the
        traceback of the caught exception is logged. Unexpected errors
        are not fixable by the user, hence no resolution is logged.

        Args:
            logger_msg (str): Logger message for the operation.
            exp (Exception): Caught exception.

        Returns:
            NetskopeBwanPluginException: Exception for the caller to raise.
        """
        err_msg = f"Error occurred while {logger_msg}. Error: {exp}"
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=traceback.format_exc(),
        )
        return NetskopeBwanPluginException(err_msg)

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Parse the JSON body of the response.

        Args:
            response (requests.models.Response): Response object.
            logger_msg (str): Logger message for the operation.
            is_validation (bool, optional): Whether the call is made from
                validation.

        Returns:
            Dict: Response JSON.

        Raises:
            NetskopeBwanPluginException: When the response is not a
                valid JSON.
        """
        try:
            return response.json()
        except json.JSONDecodeError:
            err_msg = (
                "Error occurred while parsing the JSON response for "
                f"{logger_msg}."
            )
            self._log_and_raise(
                err_msg, RESOLUTION_BASE_URL, f"API response: {response.text}"
            )
        except Exception as exp:
            raise self.handle_unexpected_error(
                f"parsing the JSON response for {logger_msg}", exp
            )

    def _get_error_resolution(
        self,
        status_code: int,
        is_validation: bool,
        resolution: Optional[str],
        is_config_token: bool = False,
    ) -> Optional[str]:
        """Get the resolution for an unsuccessful status code.

        Args:
            status_code (int): Response status code.
            is_validation (bool): Whether the call is made from
                validation.
            resolution (str, optional): Operation specific resolution.
            is_config_token (bool, optional): Whether the request used
                the 'API Token' from the configuration parameters.

        Returns:
            Optional[str]: Resolution for the error log, None when the
                user cannot fix the error.
        """
        if is_config_token and status_code == 401:
            return RESOLUTION_CONFIG_TOKEN_401
        if is_config_token and status_code == 403:
            # An operation that names its own resolution knows which
            # permission is missing; the generic one only guesses.
            return resolution or RESOLUTION_CONFIG_TOKEN_PERMISSION
        if status_code == 401:
            return RESOLUTION_401
        if status_code == 403:
            return resolution or (
                RESOLUTION_403_VALIDATION if is_validation
                else RESOLUTION_403
            )
        if status_code == 404:
            if is_validation:
                return RESOLUTION_BASE_URL
            return resolution or RESOLUTION_404
        if status_code == 429 or 500 <= status_code <= 599:
            # API side failure the user cannot fix.
            return None
        return resolution or RESOLUTION_GENERIC

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
        resolution: Optional[str] = None,
    ) -> Dict:
        """Handle the different HTTP response codes.

        Args:
            resp (requests.models.Response): Response object returned
                from the API call.
            logger_msg (str): Logger message for the operation.
            is_validation (bool, optional): Whether the call is made from
                validation.
            resolution (str, optional): Operation specific resolution.

        Returns:
            Dict: Response JSON for 200/201, empty dict for 204.

        Raises:
            NetskopeBwanFatalAPIException: For HTTP 401 and HTTP 403.
            NetskopeBwanPluginException: For any other status code.
        """
        status_code = resp.status_code
        if status_code in [200, 201]:
            return self.parse_response(
                response=resp,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        if status_code == 204:
            return {}

        error_dict = {
            400: "Received exit code 400, Bad Request.",
            401: "Received exit code 401, Unauthorized.",
            403: "Received exit code 403, Forbidden.",
            404: "Received exit code 404, Resource not found.",
            409: "Received exit code 409, Conflict.",
            429: "Received exit code 429, API rate limit exceeded.",
        }
        if status_code in error_dict:
            status_msg = error_dict[status_code]
        elif 500 <= status_code <= 599:
            status_msg = (
                f"Received exit code {status_code}, HTTP server error."
            )
        else:
            status_msg = f"Received exit code {status_code}, HTTP error."

        is_config_token = getattr(resp, "bwan_is_config_token", False)
        if is_config_token is True and status_code == 401:
            status_msg += (
                " The 'API Token' provided in the configuration parameters"
                " is not valid."
            )
        elif is_config_token is True and status_code == 403:
            status_msg += (
                " The 'API Token' provided in the configuration parameters"
                " does not have the required permissions."
            )
        else:
            is_config_token = False
        err_msg = f"Error occurred while {logger_msg}. {status_msg}"
        error_resolution = self._get_error_resolution(
            status_code, is_validation, resolution, is_config_token
        )
        # Every further call would fail the same way for 401 and 403.
        fatal_reason = {
            401: "received exit code 401, Unauthorized",
            403: "received exit code 403, Forbidden",
        }.get(status_code)
        fatal_resolution = error_resolution
        if fatal_reason and not is_config_token:
            fatal_resolution = {401: RESOLUTION_401, 403: RESOLUTION_403}[
                status_code
            ]
        self._log_and_raise(
            err_msg,
            error_resolution,
            f"API response: {resp.text}",
            fatal_reason,
            fatal_resolution,
        )

    def get_json_body(self, response: requests.models.Response) -> Dict:
        """Get the JSON body of a response without raising.

        Used for mutation calls whose successful (2xx) response may have
        an empty or non-JSON body.

        Args:
            response (requests.models.Response): Response object.

        Returns:
            Dict: Parsed JSON body, or an empty dict when the body is
                empty, not a valid JSON or not a JSON object.
        """
        try:
            body = response.json()
        except Exception:
            return {}
        return body if isinstance(body, dict) else {}

    def _get_next_cursor(
        self,
        response: Dict,
        seen_cursors: Set[str],
        page: int,
        logger_msg: str,
    ) -> Optional[str]:
        """Get the cursor of the next page, applying the loop guards.

        Partial data is never returned, since the lists drive decisions
        (e.g. whether an IP is already in an Address Group).

        Args:
            response (Dict): Parsed response of the current page.
            seen_cursors (Set[str]): Cursors already requested.
            page (int): Current page number.
            logger_msg (str): Logger message for the operation.

        Returns:
            Optional[str]: Next cursor, or None when there is no next
                page.

        Raises:
            NetskopeBwanPluginException: When 'has_next' is true but the
                next cursor is missing or repeated, or when MAX_PAGES
                pages were already fetched.
        """
        page_info = response.get("page_info")
        if not isinstance(page_info, dict) or not page_info.get("has_next"):
            return None
        next_cursor = page_info.get("end_cursor")
        if not next_cursor or next_cursor in seen_cursors:
            reason = "a new page cursor was not received in the API response"
        elif page >= MAX_PAGES:
            reason = f"the maximum page limit of {MAX_PAGES} was reached"
        else:
            return next_cursor
        err_msg = (
            f"Error occurred while {logger_msg}. Pagination stopped at "
            f"page {page} as {reason}."
        )
        # API behaviour the user cannot fix, hence no resolution.
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=f"API response page_info: {page_info}",
        )
        raise NetskopeBwanPluginException(err_msg)

    def fetch_paginated_data(
        self,
        logger_msg: str,
        url: str,
        headers: Dict,
        verify: bool = True,
        proxies: Optional[Dict] = None,
        required_keys: Sequence[str] = ("id",),
        is_validation: bool = False,
        resolution: Optional[str] = None,
        entity_label: str = "record",
        is_config_token: bool = False,
        extra_params: Optional[Dict] = None,
    ) -> List[Dict]:
        """Fetch every page of a cursor-paginated list endpoint.

        Requests pages with 'first' and 'after' query parameters and
        follows 'page_info.end_cursor' while 'page_info.has_next' is
        true. Raises instead of returning partial data when the next
        cursor is empty or was already seen (cursor cycle), or when
        MAX_PAGES pages were fetched.

        Args:
            logger_msg (str): Logger message for the operation.
            url (str): URL of the list endpoint.
            headers (Dict): Request headers.
            verify (bool, optional): Verify the SSL certificate.
            proxies (Dict, optional): Proxies for the request.
            required_keys (Sequence[str], optional): Keys every item must
                have (with a truthy value) to be collected.
            is_validation (bool, optional): Whether the call is made from
                validation.
            resolution (str, optional): Operation specific resolution.
            is_config_token (bool, optional): Whether 'headers' carry
                the 'API Token' from the configuration parameters.
            entity_label (str, optional): Item type used in the per-page
                log, e.g. 'Address Group'.
            extra_params (Dict, optional): Additional query parameters
                sent with every page, e.g. 'sort' and 'filter'.

        Returns:
            List[Dict]: Collected items from every page.

        Raises:
            NetskopeBwanPluginException: When a page could not be fetched
                or the pagination could not be completed.
        """
        all_items = []
        cursor = None
        seen_cursors: Set[str] = set()
        page = 1
        while True:
            params = {"first": PAGE_SIZE}
            params.update(extra_params or {})
            if cursor:
                params["after"] = cursor
                seen_cursors.add(cursor)
            response = self.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                params=params,
                headers=headers,
                verify=verify,
                proxies=proxies,
                is_validation=is_validation,
                resolution=resolution,
                is_config_token=is_config_token,
            )
            if not isinstance(response, dict):
                response = {}
            data = response.get("data")
            page_items = [
                item
                for item in (data if isinstance(data, list) else [])
                if isinstance(item, dict)
                and all(item.get(key) for key in required_keys)
            ]
            all_items.extend(page_items)
            # Page progress is API-level tracing, hence debug. The total
            # count is logged at debug level by the caller.
            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched "
                f"{len(page_items)} {entity_label}(s) in page {page}. "
                f"Total {entity_label}(s) fetched: {len(all_items)}."
            )
            cursor = self._get_next_cursor(
                response, seen_cursors, page, logger_msg
            )
            if not cursor:
                break
            page += 1
        return all_items

    def build_bucket_summary(
        self,
        action_value: str,
        group_name: str,
        outcomes: Dict[str, List[str]],
        applied_ips_of_failed_records: Optional[List[str]] = None,
    ) -> Tuple[str, str]:
        """Build the per Address Group summary log for an action.

        Args:
            action_value (str): Action value being executed.
            group_name (str): Name of the target Address Group.
            outcomes (Dict[str, List[str]]): IPs per outcome key.
            applied_ips_of_failed_records (List[str], optional): IPs that
                were added or removed for records that are marked as
                failed, so that an admin can clean them up.

        Returns:
            Tuple[str, str]: Summary message (without log prefix) and
                JSON serialized details.
        """
        failed = outcomes.get(OUTCOME_FAILED, [])
        if action_value == ADD_TO_ADDRESS_GROUP:
            success = outcomes.get(OUTCOME_ADDED, [])
            skipped = outcomes.get(OUTCOME_ALREADY_EXISTS, [])
            message = (
                f"Successfully added {len(success)} IP(s) to Address "
                f"Group '{group_name}'."
            )
            if skipped:
                message += (
                    f" {len(skipped)} IP(s) already exist in the Address "
                    "Group."
                )
            on_tenant = outcomes.get(OUTCOME_EXISTS_ON_TENANT, [])
            if on_tenant:
                message += (
                    f" {len(on_tenant)} IP(s) were not added as they "
                    "already exist as Address Objects on the tenant."
                )
            limit_exceeded = outcomes.get(OUTCOME_LIMIT_EXCEEDED, [])
            if limit_exceeded:
                message += (
                    f" {len(limit_exceeded)} IP(s) were not added as the "
                    "Address Group reached its limit of "
                    f"{MAX_ADDRESS_OBJECTS_PER_GROUP} IP(s)."
                )
            if failed:
                message += f" Failed to add {len(failed)} IP(s)."
            details = {
                OUTCOME_ADDED: success,
                OUTCOME_ALREADY_EXISTS: skipped,
                OUTCOME_EXISTS_ON_TENANT: on_tenant,
                OUTCOME_LIMIT_EXCEEDED: limit_exceeded,
                OUTCOME_FAILED: failed,
            }
        else:
            success = outcomes.get(OUTCOME_REMOVED, [])
            skipped = outcomes.get(OUTCOME_NOT_FOUND, [])
            message = (
                f"Successfully removed {len(success)} IP(s) from Address "
                f"Group '{group_name}'."
            )
            if skipped:
                message += (
                    f" {len(skipped)} IP(s) do not exist in the Address "
                    "Group, hence skipped."
                )
            if failed:
                message += f" Failed to remove {len(failed)} IP(s)."
            details = {
                OUTCOME_REMOVED: success,
                OUTCOME_NOT_FOUND: skipped,
                OUTCOME_FAILED: failed,
            }
        applied = list(applied_ips_of_failed_records or [])
        if applied:
            message += (
                f" {len(applied)} IP(s) were applied for record(s) marked "
                "as failed."
            )
        details[APPLIED_IPS_OF_FAILED_RECORDS] = applied
        return message, json.dumps(details)

    # ------------------------------------------------------------------ #
    # Entity field extraction (2.0.0)
    # ------------------------------------------------------------------ #
    def _extract_field_from_event(
        self,
        key: str,
        event: Dict,
        default=None,
        transformation: Optional[str] = None,
    ):
        """Get a value from an API record using a dot separated path.

        Traversal stops and the default is returned as soon as a segment
        is missing or an intermediate value is not a dictionary, so a
        record without the 'device_config_raw' leaves is handled without
        a lookup error.

        Args:
            key (str): Dot separated path, e.g.
                'device_config_raw.dcfg_overlay.ovlay_ipv4'.
            event (Dict): API record.
            default (optional): Value returned when the path is absent.
            transformation (str, optional): Name of the transformation to
                apply to the extracted value.

        Returns:
            Extracted value, or the default when the path is absent.
        """
        value = event
        for segment in key.split("."):
            if not isinstance(value, dict) or segment not in value:
                value = None
                break
            value = value[segment]
        # The transformation runs even when the path is absent, so that a
        # LIST field yields an empty list rather than nothing at all. A
        # field that is left out of the record is never '$set' by Cloud
        # Exchange, which would keep the previous value forever.
        if transformation == "labels":
            return self.normalize_labels(value)
        if transformation == "gateway_tags":
            return self.extract_gateway_tag_names(value)
        if transformation == "datetime":
            return self.normalize_datetime(value, key)
        if transformation == "user_email":
            return self.resolve_user_field(value, USER_EMAIL_KEY)
        return default if value is None else value

    def collect_user_ids(self, records: List[Dict]) -> Set[str]:
        """Get the user IDs the records of a batch point at.

        Args:
            records (List[Dict]): Client or Gateway records of the
                batch.

        Returns:
            Set[str]: Distinct user IDs, empty when no record of the
                batch is assigned to a user.
        """
        user_ids = set()
        for record in records:
            if not isinstance(record, dict):
                continue
            user_id = self._extract_field_from_event(
                key=USER_ID_PATH, event=record
            )
            if isinstance(user_id, str) and user_id.strip():
                user_ids.add(user_id.strip())
        return user_ids

    def resolve_user_field(self, user_id, key: str) -> Optional[str]:
        """Get one field of the user a record is assigned to.

        The cache is filled before the batch is mapped. A user ID that
        the platform does not resolve is held in the cache with an empty
        value, hence a record without a user, a record assigned to a
        deleted user and a user without that field alike yield no value
        and clear whatever Cloud Exchange holds.

        Args:
            user_id: Value of the user ID leaf of the record.
            key (str): Key of the user to return, the email or the name.

        Returns:
            Optional[str]: The value, or None when there is none.
        """
        if not isinstance(user_id, str) or not user_id.strip():
            return None
        user = self.user_cache.get(user_id.strip())
        if user is None and self.user_lookup_failed:
            # The record names a user but the listing was unavailable,
            # hence nothing is known about it. Leaving the field out
            # keeps the value Cloud Exchange already holds.
            return FIELD_UNAVAILABLE
        if not isinstance(user, dict):
            return None
        value = user.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    def add_field(self, fields: Dict, field_name: str, value):
        """Add a field to the record, always emitting the key.

        Cloud Exchange only '$set's the keys a record carries, hence a
        field left out keeps whatever is already stored. A Client that
        loses its last label omits the 'labels' key entirely, so the key
        has to be emitted with an empty list for the stored labels to be
        cleared. The same holds for a 'device_config_raw' leaf that
        disappears: the field is emitted as None, which clears it.

        An empty string is emitted as None so that an empty leaf and an
        absent one are stored alike. A field whose value is present but
        unusable never reaches here; the caller leaves it out, so Cloud
        Exchange keeps the value it already has.

        Args:
            fields (Dict): Record being built (updated in place).
            field_name (str): Name of the entity field.
            value: Extracted value.
        """
        if isinstance(value, str) and not value.strip():
            fields[field_name] = None
            return
        fields[field_name] = value

    def coerce_field_value(
        self, value, field_type: Optional[str], field_name: str
    ):
        """Coerce an extracted value to the declared entity field type.

        Cloud Exchange raises a ValueError for a non-bool value in a
        BOOLEAN field, and that error is caught only around the whole
        batch, so it drops every remaining record and every remaining
        mapped entity of the run. The provider has already advanced the
        entity checkpoint by then, hence those records are never
        re-delivered. A value that cannot be coerced is therefore dropped
        here, with a debug log, rather than passed through.

        Args:
            value: Extracted value.
            field_type (str, optional): Declared type of the field, or
                None when the field needs no coercion.
            field_name (str): Name of the entity field, for the log.

        Returns:
            The coerced value, or None when it cannot be coerced.
            extract_entity_fields tells the two apart by looking at the
            value it passed in: None back from a value that was present
            means the field is left out, so that Cloud Exchange keeps
            whatever it already holds.
        """
        if value is None or not field_type:
            return value
        if isinstance(value, str) and not value.strip():
            # An empty leaf is an absent value, not a malformed one, hence
            # it is dropped the way add_field drops an empty string.
            return None
        if field_type == FIELD_TYPE_BOOLEAN:
            coerced = self._coerce_boolean(value)
        elif field_type == FIELD_TYPE_NUMBER:
            coerced = self._coerce_number(value)
        elif field_type == FIELD_TYPE_IPV4:
            coerced = self._coerce_ipv4(value)
        else:
            return value
        if coerced is None:
            self.logger.debug(
                f"{self.log_prefix}: The value '{value}' of the "
                f"'{field_name}' field received from {PLATFORM_NAME} is "
                f"not a valid {field_type}, hence the field was skipped "
                "for this record."
            )
        return coerced

    def _coerce_boolean(self, value) -> Optional[bool]:
        """Coerce a value to a bool.

        The boolean leaves of 'device_config_raw' come from a device
        configuration blob, where a boolean can arrive as a string or as
        0/1 rather than as a JSON boolean.

        Args:
            value: Extracted value.

        Returns:
            Optional[bool]: The boolean, or None when the value is not a
                recognised spelling of one.
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        if isinstance(value, str):
            cleaned = value.strip().lower()
            if cleaned in ("true", "yes", "1"):
                return True
            if cleaned in ("false", "no", "0"):
                return False
        return None

    def _coerce_number(self, value) -> Optional[int]:
        """Coerce a value to an int.

        A bool is rejected rather than read as 0 or 1, because it is
        never a meaningful identifier.

        Args:
            value: Extracted value.

        Returns:
            Optional[int]: The integer, or None when the value is not
                one.
        """
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value) if value.is_integer() else None
        if isinstance(value, str):
            cleaned = value.strip()
            try:
                return int(cleaned)
            except ValueError:
                return None
        return None

    def _coerce_ipv4(self, value) -> Optional[str]:
        """Coerce a value to a plain IPv4 address.

        The overlay address is a single host address. A '/32' suffix is
        accepted and dropped; any wider range, an IPv6 address or an
        unparsable value is not an address of this field and is
        rejected.

        Args:
            value: Extracted value.

        Returns:
            Optional[str]: The IPv4 address, or None when the value is
                not one.
        """
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return None
        cleaned = str(value).strip()
        if not cleaned:
            return None
        try:
            interface = ipaddress.ip_interface(cleaned)
        except ValueError:
            return None
        if interface.version != 4 or interface.network.prefixlen != 32:
            return None
        return str(interface.ip)

    def extract_entity_fields(
        self, record: Dict, field_mapping: Dict
    ) -> Dict:
        """Build one entity record from an API record.

        'device_config_raw' is never stored: only the allow listed leaves
        named in the field mapping are read from it.

        Args:
            record (Dict): API record.
            field_mapping (Dict): Entity field mapping from constants.

        Returns:
            Dict: Entity record holding only the mapped fields.
        """
        extracted = {}
        for field_name, mapping in field_mapping.items():
            raw = self._extract_field_from_event(
                key=mapping.get("key"),
                event=record,
                default=mapping.get("default"),
                transformation=mapping.get("transformation"),
            )
            if raw is FIELD_UNAVAILABLE:
                # The lookup the field needs was unavailable. The field
                # is left out so that Cloud Exchange keeps its value,
                # rather than being cleared by a null.
                continue
            value = self.coerce_field_value(
                raw, mapping.get("type"), field_name
            )
            absent = self._is_absent(raw)
            if value is None and not absent:
                # The value was present but could not be used, hence the
                # field is left out and Cloud Exchange keeps whatever it
                # already holds. Only an absent value clears the stored
                # one.
                continue
            if absent and mapping.get("required"):
                # Never clear a required field, which Cloud Exchange
                # matches records on. The test is on the extracted
                # value, not on the coerced one: an empty string is an
                # absent value but does not become None until add_field.
                continue
            self.add_field(extracted, field_name, value)
        return extracted

    def _is_absent(self, value) -> bool:
        """Get whether an extracted value means 'no value on the platform'.

        An absent path and an empty leaf are the same state, and both
        clear the stored value in Cloud Exchange.

        Args:
            value: Value returned by _extract_field_from_event.

        Returns:
            bool: True when the platform reported no value.
        """
        if value is None:
            return True
        return isinstance(value, str) and not value.strip()

    # ------------------------------------------------------------------ #
    # Netskope Borderless WAN error codes (2.0.0)
    # ------------------------------------------------------------------ #
    def get_error_code(self, response: requests.models.Response) -> str:
        """Get the 'error_code' carried in the response body.

        The body of an unknown path is plain text rather than a JSON,
        hence the body is parsed without raising.

        Args:
            response (requests.models.Response): Response object.

        Returns:
            str: Error code, or an empty string when the body carries
                none.
        """
        body = self.get_json_body(response)
        error_code = body.get("error_code")
        return error_code if isinstance(error_code, str) else ""

    def is_write_applied(self, response: requests.models.Response) -> bool:
        """Get whether an HTTP 500 means the write was applied anyway.

        Netskope Borderless WAN returns two different HTTP 500 responses
        with opposite meanings. A slow one carrying
        'connect_err_unavailable' means the write was applied in full and
        only the response timed out, so the caller re-reads the object
        and compares instead of retrying. A fast one carrying
        'connect_err_internal' means the write was rejected.

        Args:
            response (requests.models.Response): Response object.

        Returns:
            bool: True when the write was most likely applied.
        """
        if not 500 <= response.status_code <= 599:
            return False
        return self.get_error_code(response) == ERROR_CODE_UNAVAILABLE

    # ------------------------------------------------------------------ #
    # Value normalisation (2.0.0)
    # ------------------------------------------------------------------ #
    def normalize_values(self, value) -> List[str]:
        """Normalize a Source or Static action parameter into a list.

        A Static field is a comma separated string, a Source field
        resolves to a string or to a list, and a parameter declared with
        'allowMultipleSource' adds one entry per mapped field, nested one
        level deeper wherever a mapped field's record value is itself a
        list. Every shape is flattened, each value is trimmed, empty
        values are dropped and duplicates are collapsed while the
        original order is kept.

        Args:
            value: Action parameter value.

        Returns:
            List[str]: Cleaned values in their original order.
        """
        candidates = []
        if isinstance(value, (list, tuple, set)):
            for item in value:
                if isinstance(item, (list, tuple, set)):
                    for nested in item:
                        if nested is not None:
                            candidates.extend(str(nested).split(","))
                elif item is not None:
                    candidates.extend(str(item).split(","))
        else:
            candidates = str(value if value is not None else "").split(",")
        cleaned, seen = [], set()
        for candidate in candidates:
            stripped = candidate.strip()
            if stripped and stripped not in seen:
                seen.add(stripped)
                cleaned.append(stripped)
        return cleaned

    def normalize_labels(self, value) -> List[str]:
        """Normalize a label array read from the API.

        A Gateway returns 'labels: []' when it has none while a Client
        omits the key entirely, so an absent key and an empty list are
        the same state. Netskope Borderless WAN stores labels verbatim,
        hence untrimmed, empty and duplicate labels can come back and are
        cleaned here too.

        Args:
            value: Value of the 'labels' key.

        Returns:
            List[str]: Cleaned labels.
        """
        if value is None:
            return []
        if not isinstance(value, list):
            value = [value]
        cleaned, seen = [], set()
        for label in value:
            if label is None:
                continue
            stripped = str(label).strip()
            if stripped and stripped not in seen:
                seen.add(stripped)
                cleaned.append(stripped)
        return cleaned

    def normalize_datetime(self, value, key: str = ""):
        """Parse an API timestamp into a timezone aware datetime object.

        A field declared as 'EntityFieldType.DATETIME' is stored verbatim
        by Cloud Exchange, hence an ISO string would reach MongoDB as a
        string and the date conditions of a business rule would never
        match it. The value is therefore parsed here, in fetch_records,
        as the best practices require.

        A value that cannot be parsed is dropped rather than raised on,
        so that one malformed timestamp does not cost the whole record.

        Args:
            value: Value of the timestamp leaf.
            key (str, optional): Dot separated path of the leaf, used
                only in the debug log of an unparsable value.

        Returns:
            Optional[datetime]: Timezone aware datetime object, or None
                when the value is empty or cannot be parsed.
        """
        if isinstance(value, datetime):
            return self._as_utc(value)
        if not isinstance(value, str) or not value.strip():
            return None
        raw = value.strip()
        # 'fromisoformat' rejects the trailing 'Z' before Python 3.11.
        candidate = f"{raw[:-1]}+00:00" if raw.endswith("Z") else raw
        try:
            return self._as_utc(datetime.fromisoformat(candidate))
        except ValueError:
            pass
        for date_format in DATETIME_PARSE_FORMATS:
            try:
                return self._as_utc(datetime.strptime(raw, date_format))
            except ValueError:
                continue
        leaf = f" of '{key}'" if key else ""
        self.logger.debug(
            f"{self.log_prefix}: Could not parse the timestamp "
            f"'{raw}'{leaf} received from {PLATFORM_NAME} into a "
            "datetime object, hence the field was skipped for this "
            "record."
        )
        return None

    def _as_utc(self, value: datetime) -> datetime:
        """Attach UTC to a naive datetime object.

        Netskope Borderless WAN returns every timestamp in UTC, and a
        format ending in a literal 'Z' parses as naive, hence the
        timezone is attached here so that every DATETIME field reaches
        Cloud Exchange as the same, comparable kind.

        Args:
            value (datetime): Parsed datetime object.

        Returns:
            datetime: Timezone aware datetime object.
        """
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def extract_gateway_tag_names(self, value) -> List[str]:
        """Flatten the tag names from a Gateway's 'dcfg_tags' blob.

        'dcfg_tags' is a list of tag groups, each carrying an
        'inftag_name' and a list of 'inftag_values' of
        {'inftag_id', 'inftag_value'}. Only the 'inftag_value' (the tag
        name) is surfaced on the entity; the group and the identifiers
        are an API detail. The names are cleaned and de-duplicated the
        same way labels are.

        Args:
            value: Value of the 'device_config_raw.dcfg_tags' leaf.

        Returns:
            List[str]: Cleaned tag names across every group.
        """
        names = []
        if isinstance(value, list):
            for group in value:
                if not isinstance(group, dict):
                    continue
                entries = group.get("inftag_values")
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if isinstance(entry, dict):
                        names.append(entry.get("inftag_value"))
        return self.normalize_labels(names)

    def has_source_field(self, value) -> bool:
        """Get whether a Source field is mapped to an action parameter.

        A parameter declared with 'allowMultipleSource' can mix Static
        values and Source fields, hence any entry naming a record field
        makes the whole parameter Source bound and defers its validation
        to the action execution.

        Cloud Exchange treats a value as a variable only when it starts
        with '$', so a Static value that merely contains one, such as a
        Custom Application named 'Sales$App', is not a Source field.

        Args:
            value: Action parameter value.

        Returns:
            bool: True when at least one entry is a Source field.
        """
        if isinstance(value, str):
            return value.strip().startswith("$")
        if isinstance(value, (list, tuple, set)):
            return any(self.has_source_field(item) for item in value)
        return False

    # ------------------------------------------------------------------ #
    # Host and port validation (2.0.0)
    # ------------------------------------------------------------------ #
    def is_valid_host(self, host: str) -> bool:
        """Get whether a host value can be sent to a Custom Application.

        A host is valid when it is an IPv4 address, an IPv4 CIDR range, a
        hostname or a domain. A wildcard is allowed only as the leftmost
        label of a host having at least three labels, e.g.
        '*.example.com'. Netskope Borderless WAN itself validates
        nothing and stores whatever it receives, so every check here
        mirrors the BWAN Tenant UI's own rules instead, to keep plugin
        and UI behaviour in sync.

        Args:
            host (str): Host value.

        Returns:
            bool: True when the host is valid.
        """
        if not host or len(host) > MAX_HOST_LENGTH:
            return False
        try:
            ipaddress.IPv4Interface(host)
            return True
        except ValueError:
            pass
        labels = host.split(".")
        if labels[0] == "*":
            if len(labels) < 3:
                return False
            labels = labels[1:]
        if len(labels) < 2:
            return False
        if not all(
            re.match(REGEX_HOSTNAME_LABEL, label) for label in labels
        ):
            return False
        # A real TLD is never all digits (RFC 3696 SS2), so this also
        # catches values IPv4Interface rejected and the per-label regex
        # alone would not, such as '10.0.0.1-20' or '10.0.0.256' - each
        # piece matches the hostname label pattern on its own, but no
        # genuine hostname or domain ends in a purely numeric label.
        return not re.fullmatch(r"[0-9-]+", labels[-1])

    def parse_hosts(self, value) -> Tuple[List[str], List[str]]:
        """Parse the Host action parameter into valid and invalid values.

        Args:
            value: Host action parameter value.

        Returns:
            Tuple[List[str], List[str]]: Valid hosts in order, and the
                invalid values.
        """
        valid, invalid = [], []
        for host in self.normalize_values(value):
            if self.is_valid_host(host):
                valid.append(host)
            else:
                invalid.append(host)
        return valid, invalid

    def parse_port_ranges(self, value) -> Tuple[List[Dict], List[str]]:
        """Parse a port parameter into the 'port_range' array.

        A bare port becomes a range whose start and end are equal and a
        hyphenated range becomes one object. An empty parameter returns
        an empty list, which the caller turns into an omitted
        'port_range' key rather than a full range: an omitted range does
        not match an explicit one in the grouping of Netskope Borderless
        WAN, so substituting a default would silently create duplicate
        definitions.

        Args:
            value: Port action parameter value.

        Returns:
            Tuple[List[Dict], List[str]]: Port ranges as
                {'start': int, 'end': int}, and the invalid values.
        """
        ranges, invalid = [], []
        for entry in self.normalize_values(value):
            parts = entry.split("-")
            if len(parts) > 2:
                invalid.append(entry)
                continue
            try:
                start = int(parts[0].strip())
                end = int(parts[-1].strip()) if len(parts) == 2 else start
            except ValueError:
                invalid.append(entry)
                continue
            if not (MIN_PORT <= start <= MAX_PORT):
                invalid.append(entry)
                continue
            if not (MIN_PORT <= end <= MAX_PORT) or end < start:
                invalid.append(entry)
                continue
            ranges.append({"start": start, "end": end})
        return ranges, invalid

    # ------------------------------------------------------------------ #
    # Custom Application traffic definitions (2.0.0)
    # ------------------------------------------------------------------ #
    def canonical_ports(self, definition: Dict) -> Tuple:
        """Get the order insensitive form of a definition's port range.

        Netskope Borderless WAN treats the order of 'port_range' as
        significant and stores two orderings of the same ranges as two
        definitions. Two orderings describe the same constraint, hence
        the plugin canonicalises before comparing and matches regardless
        of order. An absent 'port_range' and an empty one collapse to the
        same empty form.

        Args:
            definition (Dict): Traffic definition.

        Returns:
            Tuple: Sorted (start, end) pairs.
        """
        ranges = definition.get("port_range") or []
        pairs = []
        for entry in ranges:
            if isinstance(entry, dict):
                pairs.append((entry.get("start"), entry.get("end")))
        return tuple(sorted(pairs))

    def definition_matches(self, existing: Dict, wanted: Dict) -> bool:
        """Get whether hosts may be appended to an existing definition.

        All three definition fields must match. The checks are ordered
        cheapest first, so most candidates are rejected on a single
        boolean comparison.

        Args:
            existing (Dict): Definition stored on the Custom Application.
            wanted (Dict): Definition the action is configured for.

        Returns:
            bool: True when the definitions describe the same traffic.
        """
        if bool(existing.get("web_access", False)) != bool(
            wanted.get("web_access", False)
        ):
            return False
        if existing.get("protocol") != wanted.get("protocol"):
            return False
        return self.canonical_ports(existing) == self.canonical_ports(wanted)

    def get_definitions(self, custom_app: Dict) -> List[Dict]:
        """Get the traffic definitions of a Custom Application.

        Emptying the last host of the last definition sets
        'definitions_v2' to null rather than to an empty array, hence
        both are read as an empty list.

        Args:
            custom_app (Dict): Custom Application record.

        Returns:
            List[Dict]: Traffic definitions.
        """
        definitions = custom_app.get("definitions_v2") or []
        return [
            definition
            for definition in definitions
            if isinstance(definition, dict)
        ]

    def count_slots(self, definitions: List[Dict]) -> int:
        """Count the host slots used by a Custom Application.

        Capacity is counted in slots, one host inside one definition,
        because the legacy 'definitions' array the server generates holds
        one entry per host per definition and that is what drives the
        stored document toward the size ceiling. Selecting two protocols
        therefore halves the effective host capacity.

        Args:
            definitions (List[Dict]): Traffic definitions of a member.

        Returns:
            int: Number of host slots used.
        """
        return sum(
            len(definition.get("hosts") or []) for definition in definitions
        )

    def build_definition(
        self, protocol: str, web_access: bool, port_ranges: List[Dict]
    ) -> Dict:
        """Build the traffic definition the action is configured for.

        An empty port range omits the 'port_range' key entirely, which is
        a valid and distinct state rather than a gap needing a default.

        Args:
            protocol (str): Protocol value, e.g. 'tcp'.
            web_access (bool): Whether the definition matches web traffic.
            port_ranges (List[Dict]): Port ranges, possibly empty.

        Returns:
            Dict: Traffic definition without any host.
        """
        definition = {"protocol": protocol, "web_access": web_access}
        if port_ranges and protocol in PROTOCOL_PORT_PARAMS:
            definition["port_range"] = port_ranges
        return definition

    def get_member_number(self, name: str, base_name: str) -> Optional[int]:
        """Get the roll-over number a Custom Application name carries.

        The base application counts as member 1 and a sibling is named
        '<base name> <number>'. Any other name does not belong to the
        group.

        Args:
            name (str): Name of the Custom Application.
            base_name (str): Name of the base Custom Application.

        Returns:
            Optional[int]: Member number, or None when the name is not
                part of the group.
        """
        name = str(name if name is not None else "").strip()
        if name == base_name:
            return 1
        prefix = f"{base_name} "
        if not name.startswith(prefix):
            return None
        suffix = name[len(prefix):]
        if not suffix.isdigit():
            return None
        number = int(suffix)
        return number if number > 1 else None

    def _log_write_server_error(
        self,
        logger_msg: str,
        response: requests.models.Response,
        error_code: str,
    ):
        """Log an HTTP 5xx on a write that is not retried.

        Netskope Borderless WAN returns two HTTP 500 responses with
        opposite meanings and neither is transient, hence the request is
        not retried and the caller decides the outcome by re-reading the
        object.

        Args:
            logger_msg (str): Logger message for the operation.
            response (requests.models.Response): Response object.
            error_code (str): Error code carried in the response body.
        """
        if error_code == ERROR_CODE_UNAVAILABLE:
            reason = (
                "the request timed out on the server while "
                f"{logger_msg}, hence verifying whether the change was "
                "applied"
            )
        else:
            reason = (
                f"the server rejected the request while {logger_msg}, "
                "hence it is not retried"
            )
        self.logger.info(
            message=(
                f"{self.log_prefix}: Received exit code "
                f"{response.status_code} with error code '{error_code}', "
                f"{reason}."
            ),
            details=f"API response: {response.text}",
        )
