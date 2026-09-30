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

import json
import time
import traceback
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

import requests

from netskope.common.utils import add_user_agent

from .constants import (
    ADD_TO_ADDRESS_GROUP,
    APPLIED_IPS_OF_FAILED_RECORDS,
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MAX_ADDRESS_OBJECTS_PER_GROUP,
    MAX_PAGES,
    MAX_RETRY_AFTER_IN_SECS,
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
)


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

        Returns:
            Union[Dict, requests.models.Response]: Parsed JSON response
                when is_handle_error_required is True, else the raw
                response object with a 'bwan_had_server_error' attribute
                that is True when an HTTP 5xx was received (and retried)
                before the final response, and a 'bwan_is_config_token'
                attribute.

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
                    retry_after = self._handle_retry(
                        response, logger_msg, retry_counter
                    )
                    time.sleep(retry_after)
                    continue
                if not is_handle_error_required:
                    response.bwan_had_server_error = had_server_error
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
            return RESOLUTION_CONFIG_TOKEN_PERMISSION
        if status_code == 401:
            return RESOLUTION_401
        if status_code == 403:
            if is_validation:
                return RESOLUTION_403_VALIDATION
            return resolution or RESOLUTION_403
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
