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

CRE HPE Mist Plugin helper module.
"""

import hashlib
import time
import traceback
from json import JSONDecodeError
from typing import Dict, List, Optional, Tuple, Union

import requests
from netskope.common.utils import add_user_agent

from .constants import (
    DEFAULT_FETCH_ACCESS_POINTS,
    DEFAULT_FETCH_LABELS,
    DEFAULT_LABEL_OPERATION,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_WAIT_TIME,
    FETCH_ACCESS_POINTS_YES,
    FETCH_LABELS_YES,
    MAX_API_CALLS,
    MAX_RETRY_AFTER,
    MIST_HOURLY_RATE_LIMIT,
    NAC_CONFIG_FIELDS,
    NAC_DELETE_DEVICE_ENDPOINT,
    NAC_DEVICE_STRING_FIELDS,
    NAC_DEVICE_UUID_FIELD,
    NAC_DEVICES_ENDPOINT,
    NAC_ETHER_TYPE_CHOICES,
    NAC_ETHER_TYPE_FIELD,
    NAC_LABELS_FIELD,
    NAC_MAC_ADDRESSES_FIELD,
    NAC_PLATFORM_NAME,
    NAC_STORAGE_CONFIG_HASH_KEY,
    NAC_STORAGE_TOKEN_KEY,
    NAC_TOKEN_ENDPOINT,
    NO_MORE_RETRIES_ERROR_MSG,
    ORG_INVENTORY_SEARCH_ENDPOINT,
    ORG_SITES_ENDPOINT,
    PAGE_SIZE,
    PLATFORM_NAME,
    RETRY_ABORTED_ERROR_MSG,
    RETRY_ERROR_MSG,
    SITE_DEVICES_ENDPOINT,
    SITE_WXTAG_ENDPOINT,
    SITE_WXTAGS_ENDPOINT,
    USER_AGENT_MODULE_SEGMENT,
    USER_AGENT_VENDOR_SEGMENT,
    WXTAG_MATCH_TYPE,
)
from .exceptions import HPEMistAccessAssurancePluginException


class HPEMistAccessAssurancePluginHelper(object):
    """HPEMistAccessAssurancePluginHelper class.

    Wraps all outbound HTTP interaction with the HPE Mist API:
    Token Authentication header generation, the shared retrying API
    request helper, response/error parsing, site/device/label
    pagination, live choice-dropdown builders for actions, and the
    action API calls themselves.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        ssl_validation: bool,
        proxy: Dict,
        configuration: Dict,
    ):
        """Initialize the HPE Mist plugin helper.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
            ssl_validation (bool): SSL certificate validation flag.
            proxy (Dict): Proxy configuration dictionary.
            configuration (Dict): Plugin configuration dictionary.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.verify = ssl_validation
        self.proxies = proxy
        self.configuration = configuration

    # ------------------------------------------------------------------ #
    # User-Agent
    # ------------------------------------------------------------------ #
    def _add_user_agent(self, headers: Optional[Dict] = None) -> Dict:
        """Add the Netskope CE User-Agent to outbound request headers.

        Format: netskope-ce-v<ce_version>-cre-
        hpe-mist-access-assurance-v<plugin_version>

        Args:
            headers (Optional[Dict]): Existing headers dictionary.

        Returns:
            Dict: Headers dictionary with the User-Agent added, unless
            one is already present.
        """
        if headers and "User-Agent" in headers:
            return headers
        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            USER_AGENT_MODULE_SEGMENT,
            USER_AGENT_VENDOR_SEGMENT,
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    # ------------------------------------------------------------------ #
    # Core API call with retries
    # ------------------------------------------------------------------ #
    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        json_data: Optional[Union[Dict, List]] = None,
        headers: Optional[Dict] = None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        regenerate_auth_token: bool = True,
        is_nac: bool = False,
        storage: Optional[Dict] = None,
        config_params: Optional[Dict] = None,
    ) -> Union[Dict, requests.models.Response]:
        """Make an API call to the HPE Mist or NAC API with retries.

        Serves both the Mist API and the Juniper NAC / EDR API - the
        two differ only in how a 401 re-authenticates and in some
        platform-specific strings, selected by is_nac. Retries on HTTP
        429 and 5xx responses (skipped entirely during validation): the
        wait uses the response's 'Retry-After' header when present,
        otherwise a flat DEFAULT_WAIT_TIME (60 seconds each attempt)
        for both the NAC and Mist APIs; if the computed wait exceeds
        MAX_RETRY_AFTER (300 seconds) the loop is aborted and the
        error is raised. On HTTP 401 (outside validation), when
        regenerate_auth_token is True, the auth token is refreshed and
        the SAME request is retried exactly once with
        regenerate_auth_token=False - for the NAC API whenever storage
        and config_params are supplied (see _reauthenticate_on_401());
        the Mist API never qualifies for this retry.

        Args:
            logger_msg (str): Logger message describing the request.
            url (str): API endpoint.
            method (str): HTTP method. Defaults to "GET".
            params (Optional[Dict]): Query parameters.
            data (Optional[Dict]): Form-encoded request body.
            json_data (Optional[Union[Dict, List]]): JSON request body
                (the NAC add-devices endpoint takes a JSON array).
            headers (Optional[Dict]): Request headers.
            is_handle_error_required (bool): Whether to parse/raise on
                the final response, or return the raw Response object
                as-is. Defaults to True.
            is_validation (bool): Whether this call originates from
                validate(). Defaults to False.
            regenerate_auth_token (bool): Whether a 401 may trigger a
                token refresh and single retry. Defaults to True.
            is_nac (bool): Whether this call targets the NAC / EDR API
                instead of the Mist API. Defaults to False.
            storage (Optional[Dict]): Plugin storage dictionary, used
                on a NAC 401 to read/write the cached access token.
            config_params (Optional[Dict]): Extracted configuration
                parameters, used on a NAC 401 to get a new token.

        Returns:
            Union[Dict, requests.models.Response]: Parsed JSON
            response, or the raw Response object when
            is_handle_error_required is False.

        Raises:
            HPEMistAccessAssurancePluginException: On any unrecoverable error.
        """
        try:
            params = params or {}
            headers = self._add_user_agent(headers or {})

            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}. "
                f"Endpoint: {method} {url}"
            )
            if params:
                debug_log_msg += f", params: {params}."
            # The request body is never logged - for a token call it
            # would carry the NAC client secret, and for every other
            # call it may carry device/label data best kept out of
            # CE's logs regardless.
            self.logger.debug(debug_log_msg)

            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    json=json_data,
                    headers=headers,
                    verify=self.verify,
                    proxies=self.proxies,
                    timeout=DEFAULT_REQUEST_TIMEOUT,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )

                new_auth_header = self._reauthenticate_on_401(
                    response,
                    logger_msg,
                    is_nac=is_nac,
                    is_validation=is_validation,
                    regenerate_auth_token=regenerate_auth_token,
                    storage=storage,
                    config_params=config_params,
                )
                if new_auth_header is not None:
                    headers.update(new_auth_header)
                    return self.api_helper(
                        logger_msg=logger_msg,
                        url=url,
                        method=method,
                        params=params,
                        data=data,
                        json_data=json_data,
                        headers=headers,
                        is_handle_error_required=is_handle_error_required,
                        is_validation=is_validation,
                        regenerate_auth_token=False,
                        is_nac=is_nac,
                        storage=storage,
                        config_params=config_params,
                    )

                if (
                    status_code == 429 or 500 <= status_code < 600
                ) and not is_validation:
                    self._wait_before_retry(
                        response, logger_msg, retry_counter, is_nac
                    )
                    continue

                return (
                    self.handle_error(
                        response,
                        logger_msg,
                        is_validation=is_validation,
                        is_nac=is_nac,
                    )
                    if is_handle_error_required
                    else response
                )
        except HPEMistAccessAssurancePluginException:
            raise
        except Exception as error:
            self._raise_request_exception(
                error,
                logger_msg,
                is_nac=is_nac,
                is_validation=is_validation,
            )

    def _reauthenticate_on_401(
        self,
        response: requests.models.Response,
        logger_msg: str,
        *,
        is_nac: bool,
        is_validation: bool,
        regenerate_auth_token: bool,
        storage: Optional[Dict],
        config_params: Optional[Dict],
    ) -> Optional[Dict]:
        """Return refreshed auth headers when a 401 warrants one retry.

        A 401 triggers a single token-refresh-and-retry only outside
        validation and when regenerate_auth_token is True, and only
        for the NAC API, which needs both storage and config_params
        (to fetch and cache a new token). Any case that does not
        qualify returns None, so the caller falls through to normal
        error handling.

        Args:
            response (requests.models.Response): The received response.
            logger_msg (str): Logger message describing the request.
            is_nac (bool): Whether this is a NAC API call.
            is_validation (bool): Whether the call is from validate().
            regenerate_auth_token (bool): Whether a refresh is allowed.
            storage (Optional[Dict]): Plugin storage (NAC only).
            config_params (Optional[Dict]): Config params (NAC only).

        Returns:
            Optional[Dict]: New Authorization header to merge and retry
            with, or None when no re-authentication should happen.
        """
        if (
            response.status_code != 401
            or is_validation
            or not regenerate_auth_token
        ):
            return None
        if is_nac:
            if storage is None or not config_params:
                return None
            self.logger.debug(
                f"{self.log_prefix}: Received exit code 401 while "
                f"{logger_msg}. Regenerating NAC API access token and "
                "retrying the request."
            )
            access_token = self.get_nac_access_token(
                storage=storage,
                config_params=config_params,
                force_regenerate=True,
            )
            return self.get_nac_auth_header(access_token)
        return None

    def _wait_before_retry(
        self,
        response: requests.models.Response,
        logger_msg: str,
        retry_counter: int,
        is_nac: bool,
    ) -> None:
        """Sleep before the next retry on a 429/5xx, or raise.

        The wait is the response's 'Retry-After' header when present,
        otherwise a flat DEFAULT_WAIT_TIME for both the NAC and Mist
        APIs. A wait above MAX_RETRY_AFTER, or exhausting the retry
        budget, raises instead of sleeping. The rate-limit resolution
        text is chosen by is_nac.

        Args:
            response (requests.models.Response): The 429/5xx response.
            logger_msg (str): Logger message describing the request.
            retry_counter (int): Current zero-based retry attempt.
            is_nac (bool): Whether this is a NAC API call.

        Raises:
            HPEMistAccessAssurancePluginException: When the wait exceeds
                MAX_RETRY_AFTER or the retry budget is exhausted.
        """
        status_code = response.status_code
        # Both the NAC and Mist APIs use a flat wait (DEFAULT_WAIT_TIME
        # every attempt). A 'Retry-After' header, when present,
        # overrides it.
        fallback_wait = DEFAULT_WAIT_TIME
        retry_after_header = response.headers.get("Retry-After")
        if retry_after_header is not None:
            try:
                wait_time = int(float(retry_after_header))
            except (TypeError, ValueError):
                wait_time = fallback_wait
        else:
            wait_time = fallback_wait

        rate_limit_resolution = (
            (
                "Ensure that the HPE Mist NAC API is reachable and "
                "not rate limiting requests. The next action run "
                "will try again."
            )
            if is_nac
            else (
                "Ensure that API usage stays within HPE Mist's "
                f"documented limit of {MIST_HOURLY_RATE_LIMIT} calls "
                "per hour. If this limit was exceeded, the next "
                "scheduled pull will retry automatically once the "
                "hourly quota resets."
            )
        )

        if wait_time > MAX_RETRY_AFTER:
            err_msg = RETRY_ABORTED_ERROR_MSG.format(
                status_code=status_code,
                logger_msg=logger_msg,
                wait_time=wait_time,
                max_wait=MAX_RETRY_AFTER,
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=rate_limit_resolution,
            )
            raise HPEMistAccessAssurancePluginException(err_msg)

        if retry_counter == MAX_API_CALLS - 1:
            err_msg = NO_MORE_RETRIES_ERROR_MSG.format(
                status_code=status_code,
                logger_msg=logger_msg,
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=rate_limit_resolution,
            )
            raise HPEMistAccessAssurancePluginException(err_msg)

        error_reason = (
            "API rate limit exceeded"
            if status_code == 429
            else "HTTP server error occurred"
        )
        err_msg = RETRY_ERROR_MSG.format(
            status_code=status_code,
            error_reason=error_reason,
            logger_msg=logger_msg,
            wait_time=wait_time,
            retry_remaining=MAX_API_CALLS - 1 - retry_counter,
        )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=f"API response: {response.text}",
        )
        time.sleep(wait_time)

    def _raise_request_exception(
        self,
        error: Exception,
        logger_msg: str,
        *,
        is_nac: bool,
        is_validation: bool,
    ) -> None:
        """Log a request-layer exception and raise a plugin exception.

        Builds the message and resolution for the specific requests
        exception type, choosing Mist- or NAC-flavoured wording by
        is_nac and the shorter validation-time wording by is_validation
        (the latter only ever applies to Mist calls, which are the only
        ones made with is_validation=True).

        Args:
            error (Exception): The caught request-layer exception.
            logger_msg (str): Logger message describing the request.
            is_nac (bool): Whether this is a NAC API call.
            is_validation (bool): Whether the call is from validate().

        Raises:
            HPEMistAccessAssurancePluginException: Always.
        """
        platform_name = NAC_PLATFORM_NAME if is_nac else PLATFORM_NAME
        if isinstance(error, requests.exceptions.ReadTimeout):
            err_msg = f"Error occurred, read timeout while {logger_msg}."
            if is_validation:
                err_msg = "Error occurred, read timeout."
            resolution = (
                f"Ensure that the {platform_name} API is reachable and "
                "responsive."
                if is_nac
                else (
                    f"Ensure that the {platform_name} platform is "
                    "reachable and responsive."
                )
            )
        elif isinstance(error, requests.exceptions.ProxyError):
            err_msg = f"Error occurred, proxy error while {logger_msg}."
            if is_validation:
                err_msg = "Error occurred, proxy error."
            resolution = (
                "Ensure that the NAC API Base URL provided in the "
                "configuration parameters is correct and reachable."
                if is_nac
                else (
                    "Ensure that the Base URL provided in the "
                    "configuration parameters is correct and reachable."
                )
            )
        elif isinstance(error, requests.exceptions.ConnectionError):
            if is_nac:
                err_msg = (
                    "Error occurred, unable to establish connection "
                    f"with the {platform_name} API while {logger_msg}."
                )
                resolution = (
                    "Ensure that the NAC API Base URL is correct, the "
                    "proxy configuration provided is correct, and the "
                    "server is reachable."
                )
            else:
                err_msg = (
                    "Error occurred, unable to establish connection "
                    f"with {platform_name} platform while {logger_msg}."
                )
                if is_validation:
                    err_msg = (
                        "Error occurred, unable to establish connection "
                        f"with {platform_name} platform."
                    )
                resolution = (
                    f"Ensure that the {platform_name} Base URL is "
                    "correct, the proxy configuration provided is "
                    "correct, and the server is reachable."
                )
        elif isinstance(error, requests.HTTPError):
            err_msg = f"Error occurred, HTTP error while {logger_msg}."
            if is_validation:
                err_msg = "Error occurred, HTTP error."
            resolution = (
                "Ensure that the NAC API configuration parameters "
                "provided are correct."
                if is_nac
                else (
                    "Ensure that the configuration parameters provided "
                    "are correct."
                )
            )
        else:
            err_msg = f"Error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Error occurred while performing an API call to "
                    f"{platform_name}."
                )
            resolution = (
                "Ensure that the NAC API configuration parameters "
                "provided are correct."
                if is_nac
                else (
                    "Ensure that the configuration parameters provided "
                    "are correct."
                )
            )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg} Error: {error}",
            details=traceback.format_exc(),
            resolution=resolution,
        )
        raise HPEMistAccessAssurancePluginException(err_msg)

    # ------------------------------------------------------------------ #
    # Response / error parsing
    # ------------------------------------------------------------------ #
    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Parse a JSON API response into a dict.

        Args:
            response (requests.models.Response): Response object.
            logger_msg (str): Logger message describing the request.
            is_validation (bool): Whether this call originates from
                validate(). Defaults to False.

        Returns:
            Dict: Parsed JSON response.

        Raises:
            HPEMistAccessAssurancePluginException: When the body is not valid
                JSON, or any other parsing error occurs.
        """
        try:
            return response.json()
        except JSONDecodeError as err:
            err_msg = (
                "Error occurred, invalid JSON response received "
                f"from API while {logger_msg}. Error: {str(err)}"
            )
            if is_validation:
                err_msg = (
                    "Error occurred, invalid JSON response received "
                    "from API."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=(
                    "Ensure that the Base URL provided in the "
                    "configuration parameters is correct."
                ),
            )
            raise HPEMistAccessAssurancePluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Error occurred while parsing the JSON response "
                f"while {logger_msg}. Error: {exp}"
            )
            if is_validation:
                err_msg = (
                    "Error occurred while parsing the JSON response."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=(
                    "Ensure that the Base URL provided in the "
                    "configuration parameters is correct."
                ),
            )
            raise HPEMistAccessAssurancePluginException(err_msg)

    @staticmethod
    def _extract_api_error_detail(
        response: requests.models.Response,
    ) -> Optional[str]:
        """Best-effort extraction of a vendor error message from the
        response body.

        HPE Mist's exact error response schema is not confirmed
        by the source specification, so this checks a handful of
        common field names ('detail', 'message', 'error',
        'error_message', 'reason') used across REST APIs generally,
        rather than assuming one specific shape. Returns None (not an
        error) when the body isn't JSON or none of those keys are
        present with a non-empty string value — callers fall back to
        the generic status-code message in that case.

        Args:
            response (requests.models.Response): Response object.

        Returns:
            Optional[str]: The vendor's own error text, if found.
        """
        try:
            body = response.json()
        except (ValueError, JSONDecodeError):
            return None
        if not isinstance(body, dict):
            return None
        for key in (
            "detail",
            "message",
            "error_message",
            "error",
            "reason",
        ):
            value = body.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _get_auth_failure_resolution(self, is_nac: bool = False) -> str:
        """Build a 401 resolution message naming the fields that
        actually matter for the failed call, instead of a generic
        "check your credentials".

        Args:
            is_nac (bool): Whether the failed call went to the NAC /
                EDR API instead of the Mist API. The NAC API has its
                own credentials, so the Mist API Token field is
                not what the user needs to check. Defaults to False.

        Returns:
            str: Resolution text naming the relevant credential
            field(s) for the Mist API Token, or for the NAC API.
        """
        if is_nac:
            return (
                "Ensure that the Client ID and Client Secret provided "
                "in the configuration parameters for the NAC API are "
                "correct."
            )
        return (
            "Ensure the API Token provided in configuration "
            "parameters is correct."
        )

    def handle_error(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
        is_nac: bool = False,
    ) -> Dict:
        """Map an HTTP status code to a parsed response or exception.

        Args:
            response (requests.models.Response): Response object.
            logger_msg (str): Logger message describing the request.
            is_validation (bool): Whether this call originates from
                validate(). Defaults to False.
            is_nac (bool): Whether the call went to the NAC / EDR API
                instead of the Mist API. Only changes the 401 and 404
                resolution text, so every Mist call site keeps
                behaving exactly as before. Defaults to False.

        Returns:
            Dict: Parsed JSON response for 200/201/202, or an empty
            dict for 204.

        Raises:
            HPEMistAccessAssurancePluginException: For all other status codes.
        """
        status_code = response.status_code
        error_dict = {
            400: "received exit code 400, Bad Request",
            401: "received exit code 401, Unauthorized access",
            403: "received exit code 403, Forbidden",
            404: "received exit code 404, Resource not found",
        }
        resolution_dict = {
            400: (
                "Ensure that the request parameters and "
                "configuration provided are correct."
            ),
            403: (
                "Ensure that the configured identity has permission "
                "to perform this operation on the HPE Mist "
                "platform."
            ),
            404: (
                "Ensure that the Base URL, Organization ID, Site "
                "ID(s), and other identifiers provided are correct."
            ),
        }
        if is_nac:
            resolution_dict[404] = (
                "Ensure that the NAC API Base URL, Mist Org ID and "
                "Netskope Account ID provided in the configuration "
                "parameters are correct."
            )

        if status_code in (200, 201, 202):
            return self.parse_response(
                response=response,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            resolution = (
                self._get_auth_failure_resolution(is_nac=is_nac)
                if status_code == 401
                else resolution_dict.get(status_code)
            )
            api_error_detail = self._extract_api_error_detail(response)
            base_msg = error_dict[status_code]
            if api_error_detail:
                base_msg = f"{base_msg} ({api_error_detail})"
            if is_validation:
                err_msg = f"Error occurred, {base_msg}."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise HPEMistAccessAssurancePluginException(err_msg)
            err_msg = f"Error occurred, {base_msg} while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=resolution,
            )
            raise HPEMistAccessAssurancePluginException(err_msg)
        else:
            error_label = (
                "HTTP Server Error"
                if 500 <= status_code <= 600
                else "HTTP Error"
            )
            err_msg = (
                f"Error occurred, received exit code {status_code}, "
                f"{error_label} while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=(
                    "Ensure that the Base URL, credentials, and "
                    "request parameters provided are correct."
                ),
            )
            raise HPEMistAccessAssurancePluginException(err_msg)

    # ------------------------------------------------------------------ #
    # Authentication
    # ------------------------------------------------------------------ #
    def get_token_auth_header(self, api_key: str) -> Dict[str, str]:
        """Build a Token Authentication header.

        Note: HPE Mist expects the literal word "Token", not
        "Bearer", as the authorization scheme.

        Args:
            api_key (str): Mist API token.

        Returns:
            Dict[str, str]: {"Authorization": "Token <api_key>"}.
        """
        return {"Authorization": f"Token {api_key}"}

    def get_auth_header(
        self, configuration: Dict, is_validation: bool = False
    ) -> Dict[str, str]:
        """Build the Authorization header for the Mist API.

        Token Authentication is the only supported method; called only
        when 'Fetch Access Points' is 'Yes', so the API Token is
        expected to be present.

        Args:
            configuration (Dict): Plugin configuration dictionary.
            is_validation (bool): Whether this call originates from
                validate(). Defaults to False.

        Returns:
            Dict[str, str]: Authorization header dictionary.
        """
        return self.get_token_auth_header(configuration.get("api_key"))

    # ------------------------------------------------------------------ #
    # Configuration extraction
    # ------------------------------------------------------------------ #
    def get_config_params(self, configuration: Dict) -> Dict:
        """Extract and normalize configuration parameters.

        Non-secret text fields are stripped (base_url additionally
        has trailing slashes removed); password/secret fields
        (password, api_key, nac_client_secret) are returned
        unmodified.

        Args:
            configuration (Dict): Plugin configuration dictionary.

        Returns:
            Dict: Dictionary with keys "base_url", "org_id",
            "fetch_access_points", "site_name", "fetch_labels",
            "nac_base_url", "nac_client_id", "nac_mist_org_id",
            "nac_netskope_account_id", "api_key", "nac_client_secret".
        """
        site_name_raw = configuration.get("site_name")
        return {
            "base_url": (
                (configuration.get("base_url") or "")
                .strip()
                .rstrip("/")
            ),
            "org_id": (configuration.get("org_id") or "").strip(),
            "fetch_access_points": (
                (configuration.get("fetch_access_points") or "").strip()
            ),
            "site_name": (
                site_name_raw.strip()
                if isinstance(site_name_raw, str)
                else site_name_raw
            ),
            "fetch_labels": (
                (configuration.get("fetch_labels") or "").strip()
            ),
            # NAC / EDR API connection fields. A different service from
            # the Mist API above, with its own base URL and credentials.
            "nac_base_url": (
                (configuration.get("nac_base_url") or "")
                .strip()
                .rstrip("/")
            ),
            "nac_client_id": (
                (configuration.get("nac_client_id") or "").strip()
            ),
            "nac_mist_org_id": (
                (configuration.get("nac_mist_org_id") or "").strip()
            ),
            "nac_netskope_account_id": (
                (
                    configuration.get("nac_netskope_account_id") or ""
                ).strip()
            ),
            # Secrets - never stripped.
            "api_key": configuration.get("api_key"),
            "nac_client_secret": configuration.get("nac_client_secret"),
        }

    @staticmethod
    def _to_boolean(value) -> bool:
        """Convert a boolean-ish value, handling string "true"/"false"
        literally instead of via bool()'s any-non-empty-string-is-True
        rule (which would otherwise turn the string "false" into True).

        Args:
            value: Raw value read from the device payload.

        Returns:
            bool: True/False for a string "true"/"false"
            (case-insensitive), else bool(value) for every other type.
        """
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered == "true":
                return True
            if lowered == "false":
                return False
        return bool(value)

    @staticmethod
    def is_label_fetch_enabled(configuration: Dict) -> bool:
        """Return True when Fetch Labels is "Yes"."""
        value = configuration.get("fetch_labels")
        if isinstance(value, str):
            value = value.strip()
        return (value or DEFAULT_FETCH_LABELS) == FETCH_LABELS_YES

    @staticmethod
    def is_fetch_access_points_enabled(configuration: Dict) -> bool:
        """Return True when 'Fetch Access Points' is 'Yes'.

        A missing/unset value defaults to DEFAULT_FETCH_ACCESS_POINTS
        ('No'), i.e. disabled — matching the manifest field's own
        default.

        Args:
            configuration (Dict): Plugin configuration dictionary.

        Returns:
            bool: Whether the Device (Access Point) pull is enabled.
        """
        fetch_access_points = (configuration or {}).get(
            "fetch_access_points", DEFAULT_FETCH_ACCESS_POINTS
        )
        if isinstance(fetch_access_points, str):
            fetch_access_points = fetch_access_points.strip()
        return (
            fetch_access_points or DEFAULT_FETCH_ACCESS_POINTS
        ) == FETCH_ACCESS_POINTS_YES

    # ------------------------------------------------------------------ #
    # Site discovery / device / label pagination
    # ------------------------------------------------------------------ #
    @staticmethod
    def _extract_records(response: Union[Dict, List]) -> List[Dict]:
        """Normalize a Mist list-endpoint response into a list of dicts.

        Mist list endpoints are expected to return either a bare JSON
        array or an object carrying the array under a "results" key;
        both shapes are tolerated here.
        """
        if isinstance(response, list):
            return response
        if isinstance(response, dict):
            results = response.get("results")
            if isinstance(results, list):
                return results
        return []

    def _fetch_inventory_records(
        self,
        base_url: str,
        org_id: str,
        headers: Dict,
        is_validation: bool = False,
    ) -> List[Dict]:
        """Paginate GET orgs/{org_id}/inventory/search and return
        every raw record.

        Sole caller is fetch_device_status_map() (per-device status,
        used by the pull) - kept as its own pagination pass in case a
        second caller needs a different projection of these records
        again in the future.

        Args:
            base_url (str): API base URL.
            org_id (str): Organization ID.
            headers (Dict): Request headers (including auth).
            is_validation (bool): Whether this call originates from
                validate(). Defaults to False.

        Returns:
            List[Dict]: Every raw inventory record across all pages.
        """
        all_records: List[Dict] = []
        page = 1
        total = 0
        url = ORG_INVENTORY_SEARCH_ENDPOINT.format(
            base_url=base_url, org_id=org_id
        )
        while True:
            params = {"page": page, "limit": PAGE_SIZE}
            response = self.api_helper(
                logger_msg=(
                    f"fetching device connectivity status for page "
                    f"{page} from organization '{org_id}'"
                ),
                url=url,
                method="GET",
                params=params,
                headers=headers,
                is_validation=is_validation,
            )
            records = [
                record
                for record in self._extract_records(response)
                if isinstance(record, dict)
            ]
            all_records.extend(records)
            count = len(records)
            total += count
            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched {count} "
                f"record(s) in page {page} while fetching device "
                f"connectivity status from organization '{org_id}'. "
                f"Total records fetched: {total}."
            )
            if count < PAGE_SIZE:
                break
            page += 1
        return all_records

    def fetch_device_status_map(
        self,
        base_url: str,
        org_id: str,
        headers: Dict,
        is_validation: bool = False,
    ) -> Dict[str, str]:
        """Build a mac -> connectivity status map for an organization.

        The devices endpoint (GET /sites/{site_id}/devices) never
        returns a 'status' field (e.g. 'connected') — inventory/search
        is the only source for it. Keyed by MAC address rather than
        device id, since inventory/search records do not carry the
        device's own 'id' field. Always spans the whole organization,
        independent of Site Name scoping - Status is looked up by MAC
        after the site-scoped device pull, not filtered up front.

        Args:
            base_url (str): API base URL.
            org_id (str): Organization ID.
            headers (Dict): Request headers (including auth).
            is_validation (bool): Whether this call originates from
                validate(). Defaults to False.

        Returns:
            Dict[str, str]: mac -> status. A MAC missing or duplicated
            across records is not expected; the last record seen for a
            MAC wins if it somehow is.
        """
        records = self._fetch_inventory_records(
            base_url, org_id, headers, is_validation
        )
        return {
            record["mac"]: record["status"]
            for record in records
            if record.get("mac") and record.get("status")
        }

    def fetch_org_sites(
        self,
        base_url: str,
        org_id: str,
        headers: Dict,
        is_validation: bool = False,
    ) -> List[Dict]:
        """Paginate GET orgs/{org_id}/sites and return every raw Site.

        [TDD ASSUMPTION] The endpoint's pagination parameter names are
        not confirmed by the source specification (the documented
        example response is a bare array); the same page/limit shape
        already confirmed for the 'devices' and 'inventory/search'
        endpoints is assumed here too, stopping when a page returns
        fewer than PAGE_SIZE rows.

        This is the source of truth for resolving the configured
        'Site Names' to site_id (see build_site_name_map()) and for
        the full "every Site under the Organization" set used when no
        Site Name is configured.

        Args:
            base_url (str): API base URL.
            org_id (str): Organization ID.
            headers (Dict): Request headers (including auth).
            is_validation (bool): Whether this call originates from
                validate(). Defaults to False.

        Returns:
            List[Dict]: Every raw Site record across all pages.
        """
        all_sites: List[Dict] = []
        page = 1
        total = 0
        url = ORG_SITES_ENDPOINT.format(base_url=base_url, org_id=org_id)
        while True:
            params = {"page": page, "limit": PAGE_SIZE}
            response = self.api_helper(
                logger_msg=(
                    f"fetching Sites page {page} for organization "
                    f"'{org_id}'"
                ),
                url=url,
                method="GET",
                params=params,
                headers=headers,
                is_validation=is_validation,
            )
            sites = [
                site
                for site in self._extract_records(response)
                if isinstance(site, dict)
            ]
            all_sites.extend(sites)
            count = len(sites)
            total += count
            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched {count} "
                f"Site(s) in page {page} for organization '{org_id}'. "
                f"Total Sites fetched: {total}."
            )
            if count < PAGE_SIZE:
                break
            page += 1
        return all_sites

    @staticmethod
    def build_site_name_map(sites: List[Dict]) -> Dict[str, List[str]]:
        """Build a Site Name -> [site_id, ...] map from raw Sites.

        Mist does not guarantee unique Site names within an
        Organization; when more than one Site shares a configured
        name, ALL of them are matched (pull-scoping is a filter over a
        set of Sites, not a single-target selection like the Label
        dropdown), rather than arbitrarily picking one and silently
        skipping data from the other(s).

        Args:
            sites (List[Dict]): Raw Site records from fetch_org_sites().

        Returns:
            Dict[str, List[str]]: Site name -> list of site_id values
            sharing that name.
        """
        name_map: Dict[str, List[str]] = {}
        for site in sites or []:
            if not isinstance(site, dict):
                continue
            name = site.get("name")
            site_id = site.get("id")
            if name and site_id:
                name_map.setdefault(name, []).append(site_id)
        return name_map

    def fetch_devices_for_site(
        self, site_id: str, base_url: str, headers: Dict
    ) -> List[Dict]:
        """Fetch all device records for a single site.

        Paginates GET sites/{site_id}/devices with page (incrementing
        from 1) and limit=PAGE_SIZE, stopping when a page returns
        fewer than PAGE_SIZE records.

        Args:
            site_id (str): Mist site ID.
            base_url (str): API base URL.
            headers (Dict): Request headers (including auth).

        Returns:
            List[Dict]: Raw device records for the site.
        """
        devices: List[Dict] = []
        page = 1
        total = 0
        url = SITE_DEVICES_ENDPOINT.format(
            base_url=base_url, site_id=site_id
        )
        while True:
            params = {"page": page, "limit": PAGE_SIZE}
            response = self.api_helper(
                logger_msg=(
                    f"fetching devices page {page} for site "
                    f"'{site_id}'"
                ),
                url=url,
                method="GET",
                params=params,
                headers=headers,
            )
            records = self._extract_records(response)
            devices.extend(records)
            count = len(records)
            total += count
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched {count} "
                f"record(s) in page {page} for site '{site_id}'. "
                f"Total records fetched: {total}."
            )
            if count < PAGE_SIZE:
                break
            page += 1
        return devices

    def fetch_wxtags_for_site(
        self, site_id: str, base_url: str, headers: Dict
    ) -> List[Dict]:
        """Fetch all WX Tags (labels) defined on a single site.

        Paginates GET sites/{site_id}/wxtags with page (incrementing
        from 1) and limit=PAGE_SIZE, stopping when a page returns
        fewer than PAGE_SIZE records - confirmed to support the same
        page/limit contract as the other list endpoints.

        Args:
            site_id (str): Mist site ID.
            base_url (str): API base URL.
            headers (Dict): Request headers (including auth).

        Returns:
            List[Dict]: Raw WX Tag objects for the site.
        """
        wxtags: List[Dict] = []
        page = 1
        total = 0
        url = SITE_WXTAGS_ENDPOINT.format(
            base_url=base_url, site_id=site_id
        )
        while True:
            params = {"page": page, "limit": PAGE_SIZE}
            response = self.api_helper(
                logger_msg=(
                    f"fetching WX tags page {page} for site "
                    f"'{site_id}'"
                ),
                url=url,
                method="GET",
                params=params,
                headers=headers,
            )
            records = self._extract_records(response)
            wxtags.extend(records)
            count = len(records)
            total += count
            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched {count} "
                f"WX Tag(s) in page {page} for site '{site_id}'. "
                f"Total WX Tags fetched: {total}."
            )
            if count < PAGE_SIZE:
                break
            page += 1
        return wxtags

    @staticmethod
    def build_label_map(wxtags: List[Dict]) -> Dict[str, List[str]]:
        """Build a device_id -> [tag name, ...] map from raw WX Tags.

        Every tag's "values" array (a list of device IDs) is scanned
        for membership; a tag can apply to multiple devices and a
        device can carry multiple tags.

        Args:
            wxtags (List[Dict]): Raw WX Tag objects.

        Returns:
            Dict[str, List[str]]: device_id -> list of tag names.
        """
        label_map: Dict[str, List[str]] = {}
        for tag in wxtags or []:
            if not isinstance(tag, dict):
                continue
            name = tag.get("name")
            values = tag.get("values") or []
            if not name:
                continue
            for device_id in values:
                label_map.setdefault(device_id, []).append(name)
        return label_map

    @staticmethod
    def match_wxtag(
        wxtags: List[Dict], name: str, operation: str
    ) -> Tuple[Optional[Dict], bool]:
        """Locate a WX Tag by name + match + op within an already-
        fetched list of a Site's WX Tags.

        Takes a pre-fetched `wxtags` list rather than fetching one
        itself, so a caller processing several labels (or several
        device batches for one label) on the same Site can fetch that
        Site's WX Tags once per execute_actions() run and reuse the
        same list for every lookup, instead of re-fetching before
        every single create/update call. Only WX Tags whose "match" is
        WXTAG_MATCH_TYPE ("ap_id") are ever candidates - this plugin
        only ever creates that match type, so a same-named WX Tag of a
        different match type (e.g. Mist's built-in client-tag types)
        does not count as a conflict, only as "not found". Mist does
        not guarantee a Site's WX Tag names are unique, so more than
        one "ap_id"-match WX Tag can share `name`; an exact match on
        `operation` (the tag's own "op" field) is preferred, and only
        when NONE of the same-named "ap_id" candidates match
        `operation` is that reported back as a conflict.

        Args:
            wxtags (List[Dict]): WX Tags already fetched for the
                target Site (see fetch_wxtags_for_site()).
            name (str): WX Tag name to look for.
            operation (str): The "op" value ("in"/"not_in") that must
                match for an existing WX Tag to be considered "found".

        Returns:
            Tuple[Optional[Dict], bool]: (tag, op_conflict). `tag` is
            the raw WX Tag dict when name + match + op all agree, else
            None. `op_conflict` is True when a Site has an "ap_id"-
            match WX Tag whose name agrees but whose "op" does not -
            the caller should treat that as a hard failure rather than
            creating a duplicate same-named WX Tag or modifying the
            wrong one.
        """
        candidates = [
            tag
            for tag in wxtags
            if isinstance(tag, dict)
            and tag.get("name") == name
            and tag.get("match") == WXTAG_MATCH_TYPE
        ]
        for tag in candidates:
            if tag.get("op") == operation:
                return tag, False
        return (None, True) if candidates else (None, False)

    # ------------------------------------------------------------------ #
    # Action API calls
    # ------------------------------------------------------------------ #
    def create_label(
        self,
        site_id: str,
        name: str,
        headers: Dict,
        base_url: str,
        device_ids: Optional[List[str]] = None,
        operation: str = DEFAULT_LABEL_OPERATION,
    ) -> Dict:
        """Create a new WX Tag (label) on a site.

        Args:
            site_id (str): Mist site ID.
            name (str): Label name.
            headers (Dict): Request headers (including auth).
            base_url (str): API base URL.
            device_ids (Optional[List[str]]): Device ids to populate
                the tag's 'values' array with at creation time.
                Defaults to an empty list (no devices assigned yet)
                when not provided.
            operation (str): The tag's "op" value ("in"/"not_in").
                Defaults to DEFAULT_LABEL_OPERATION.

        Returns:
            Dict: Parsed API response.
        """
        url = SITE_WXTAGS_ENDPOINT.format(
            base_url=base_url, site_id=site_id
        )
        body = {
            "name": name,
            "type": "match",
            "match": WXTAG_MATCH_TYPE,
            "op": operation,
            "values": device_ids or [],
        }
        return self.api_helper(
            logger_msg=(
                f"creating label '{name}' for site '{site_id}'"
            ),
            url=url,
            method="POST",
            json_data=body,
            headers=headers,
        )

    def update_wxtag_values(
        self,
        site_id: str,
        wxtag_id: str,
        name: str,
        values: List[str],
        headers: Dict,
        base_url: str,
    ) -> Dict:
        """Replace an existing WX Tag's device membership list.

        [ASSUMPTION] Mist's PUT endpoint for WX Tags is not confirmed
        to merge partial bodies, so only 'values' is sent rather than
        the tag's full schema (name/type/match/op unchanged). This is
        a full replacement of the array, not an add/remove delta -
        callers are responsible for computing the complete merged
        list first.

        Args:
            site_id (str): Mist site ID.
            wxtag_id (str): WX Tag ID to update.
            name (str): Label name, used only for the logger message
                (the API call itself addresses the tag by wxtag_id).
            values (List[str]): The complete new list of member device
                ids.
            headers (Dict): Request headers (including auth).
            base_url (str): API base URL.

        Returns:
            Dict: Parsed API response.
        """
        url = SITE_WXTAG_ENDPOINT.format(
            base_url=base_url, site_id=site_id, wxtag_id=wxtag_id
        )
        return self.api_helper(
            logger_msg=(
                f"updating device membership for label '{name}' "
                f"on site '{site_id}'"
            ),
            url=url,
            method="PUT",
            json_data={"values": values},
            headers=headers,
        )

    # ------------------------------------------------------------------ #
    # Action parameter normalization
    # ------------------------------------------------------------------ #
    # Pure data-shaping helpers, no API calls of their own. Shared by
    # the Add/Update NAC Devices action (all six) and the Add/Remove
    # Label action (_resolve_label_param_values() and the two helpers
    # it calls, for the "Label Name" MultiSource param).
    @staticmethod
    def _resolve_mac_addresses(value) -> List[str]:
        """Normalize the 'MAC Address' param into a list of strings.

        A scalar string is wrapped in a single-item list, and a
        comma-separated string is split on commas with each part
        stripped and empty parts dropped. A value that already is a
        list keeps its order and is NOT comma-split, since the
        framework already split it into items. Duplicates are
        deliberately NOT removed (see _collect_nac_device_objects()'s
        docstring - a value here is not guaranteed unique and the NAC
        API takes duplicates as-is).

        Args:
            value: Raw 'mac_addresses' param value.

        Returns:
            List[str]: Cleaned MAC addresses, or [] when there is
            nothing to send.
        """
        if not value:
            return []
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if "," in stripped:
                return [
                    item.strip()
                    for item in stripped.split(",")
                    if item.strip()
                ]
            return [stripped]
        if isinstance(value, (list, tuple, set)):
            return [
                str(item).strip()
                for item in value
                if item is not None and str(item).strip()
            ]
        stripped = str(value).strip()
        return [stripped] if stripped else []

    @staticmethod
    def _is_multi_source_nested_label(value) -> bool:
        """Return True when a label-like value holds list items of its
        own.

        Shared by the NAC "Labels" param and the Add/Remove Label
        action's "Label Name" param - both are MultiSource-eligible
        text fields with the same comma-or-MultiSource shape. A
        MultiSource-bound value can arrive as a list whose items are
        themselves lists, one per bound source field.

        Args:
            value: Raw 'labels' or 'name' param value.

        Returns:
            bool: True when the value is a list holding lists.
        """
        return isinstance(value, (list, tuple, set)) and any(
            isinstance(item, (list, tuple, set)) for item in value
        )

    @staticmethod
    def _flatten_multi_source_label_values(value) -> List[str]:
        """Flatten a MultiSource label-like value one level deep.

        Shared by the NAC "Labels" param and the Add/Remove Label
        action's "Label Name" param. Every value is turned into a
        stripped string, empty values and None are dropped, and
        duplicates are removed while the original order is kept.

        Args:
            value: A list holding strings and/or lists of strings.

        Returns:
            List[str]: Flattened, cleaned, de-duplicated label values.
        """
        flattened: List[str] = []
        for item in value:
            if isinstance(item, (list, tuple, set)):
                for nested in item:
                    if nested is None:
                        continue
                    nested_value = str(nested).strip()
                    if nested_value:
                        flattened.append(nested_value)
            else:
                if item is None:
                    continue
                item_value = str(item).strip()
                if item_value:
                    flattened.append(item_value)
        return list(dict.fromkeys(flattened))

    def _resolve_label_param_values(self, value) -> List[str]:
        """Normalize a label-like param into a list of label values.

        Shared by the NAC "Labels" param and the Add/Remove Label
        action's "Label Name" param. A bare string is comma-split; a
        string that is already inside a list is not, since the
        framework produced that list. Nested lists from a MultiSource
        binding are flattened one level.

        Args:
            value: Raw 'labels' or 'name' param value.

        Returns:
            List[str]: Cleaned label values, or [] when there is
            nothing to send.
        """
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            if self._is_multi_source_nested_label(value):
                return self._flatten_multi_source_label_values(value)
            return [
                str(item).strip()
                for item in value
                if item is not None and str(item).strip()
            ]
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if "," in stripped:
                return [
                    label.strip()
                    for label in stripped.split(",")
                    if label.strip()
                ]
            return [stripped]
        if not value:
            return []
        stripped = str(value).strip()
        return [stripped] if stripped else []

    @staticmethod
    def _resolve_string_param(value) -> str:
        """Normalize a single-value device string param.

        The framework can hand a single-source value back as a
        one-item list, the same way _validate_parameters() (on the
        plugin class) already assumes, so the first item is used in
        that case.

        Args:
            value: Raw param value.

        Returns:
            str: The stripped value, or "" when there is none.
        """
        if isinstance(value, list):
            for item in value:
                if item is None:
                    continue
                item_value = str(item).strip()
                if item_value:
                    return item_value
            return ""
        if value is None:
            return ""
        return str(value).strip()

    def _build_device_object(self, params: Dict) -> Optional[Dict]:
        """Build one NAC device object from an action's parameters.

        'Netskope Device UUID' is Source Field only (see
        _validate_parameters(source_only=True) in main.py), so exactly
        one value is expected per record - resolved with
        _resolve_string_param(), same as every other single-value
        field here. 'MAC Address' is the one field that legitimately
        accepts a comma-separated Static list (or a Source Field
        bound to a list-type value) since the NAC API takes it as a
        list on a single device object - resolved with
        _resolve_mac_addresses(). A field whose value is empty has its
        key left out of the object entirely - no key is ever sent as
        null or "". Both Netskope Device UUID and MAC Address(es) are
        required; a record missing either is skipped (only their
        emptiness is checked, not their format). Every other field is
        optional.

        Args:
            params (Dict): This action's parameters.

        Returns:
            Optional[Dict]: The device object, or None when the
            Netskope Device UUID or MAC Address(es) is empty (the
            caller marks that action failed and makes no API call for
            it).
        """
        device_uuid = self._resolve_string_param(
            params.get(NAC_DEVICE_UUID_FIELD)
        )
        mac_addresses = self._resolve_mac_addresses(
            params.get(NAC_MAC_ADDRESSES_FIELD)
        )
        if not device_uuid or not mac_addresses:
            return None
        device: Dict = {
            NAC_DEVICE_UUID_FIELD: device_uuid,
            NAC_MAC_ADDRESSES_FIELD: mac_addresses,
        }
        for key in NAC_DEVICE_STRING_FIELDS:
            value = self._resolve_string_param(params.get(key))
            if value:
                device[key] = value
        labels = self._resolve_label_param_values(
            params.get(NAC_LABELS_FIELD)
        )
        if labels:
            device[NAC_LABELS_FIELD] = labels
        ether_type = self._resolve_string_param(
            params.get(NAC_ETHER_TYPE_FIELD)
        )
        # Optional: sent only when it is one of the accepted values; a
        # blank or unexpected value is omitted so NAC applies its own
        # 'wireless' default.
        if ether_type in NAC_ETHER_TYPE_CHOICES:
            device[NAC_ETHER_TYPE_FIELD] = ether_type
        return device

    # ------------------------------------------------------------------ #
    # NAC (Juniper NAC / EDR API)
    # ------------------------------------------------------------------ #
    # Everything below talks to the NAC / EDR API, which is a different
    # service from the Mist API above: different host, different
    # credentials, and its own client-credentials token flow. These
    # calls reuse api_helper() with is_nac=True (passing storage and
    # config_params); its 401 branch then mints a fresh NAC token
    # (see _reauthenticate_on_401()).
    @staticmethod
    def get_nac_config_hash(config_params: Dict) -> str:
        """Build the sha256 cache key for the NAC access token.

        The five NAC configuration values are concatenated with NO
        delimiter, in NAC_CONFIG_FIELDS order (Base URL, Client ID,
        Client Secret, Mist Org ID, Netskope Account ID), and hashed.
        A cached token is only reused when the stored hash matches, so
        changing any NAC credential invalidates the cached token.

        Args:
            config_params (Dict): Extracted configuration parameters.

        Returns:
            str: Hex sha256 digest of the five NAC values.
        """
        joined = "".join(
            str(config_params.get(key) or "")
            for key, _ in NAC_CONFIG_FIELDS
        )
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

    def generate_nac_access_token(self, config_params: Dict) -> str:
        """Get a new access token from the NAC API token endpoint.

        Args:
            config_params (Dict): Extracted configuration parameters.

        Returns:
            str: The new access token.

        Raises:
            HPEMistAccessAssurancePluginException: When the token
                endpoint fails or does not return an access_token.
        """
        logger_msg = "generating the NAC API access token"
        url = NAC_TOKEN_ENDPOINT.format(
            base_url=config_params["nac_base_url"],
            org_id=config_params["nac_mist_org_id"],
            account_id=config_params["nac_netskope_account_id"],
        )
        body = {
            "grant_type": "client_credentials",
            "client_id": config_params["nac_client_id"],
            "client_secret": config_params["nac_client_secret"],
        }
        # regenerate_auth_token=False is required here: a 401 on the
        # token call itself must not try to get another token.
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            json_data=body,
            headers={"Content-Type": "application/json"},
            is_handle_error_required=False,
            regenerate_auth_token=False,
            is_nac=True,
        )
        err_msg = (
            "Error occurred, unable to get the NAC API access "
            "token; 'access_token' key not found in the "
            f"response received while {logger_msg}."
        )
        err_resolution = (
            "Ensure that the Client ID and Client Secret provided in "
            "the configuration parameters for the NAC API are correct."
        )
        if response.status_code in (200, 201):
            resp_json = self.parse_response(response, logger_msg)
            access_token = resp_json.get("access_token")
            if not access_token:
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                    resolution=err_resolution,
                )
                raise HPEMistAccessAssurancePluginException(err_msg)
            return access_token
        elif response.status_code == 204:
            # A 204 has no response body at all, so it cannot hold an
            # access token. Report it the same way as a missing token
            # instead of letting it fall through with no clear reason.
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=err_resolution,
            )
            raise HPEMistAccessAssurancePluginException(err_msg)
        return self.handle_error(response, logger_msg, is_nac=True)

    def get_nac_access_token(
        self,
        storage: Dict,
        config_params: Dict,
        force_regenerate: bool = False,
    ) -> str:
        """Return a NAC access token, from the cache when possible.

        The token is cached in storage next to a hash of the five NAC
        configuration values. The cached token is reused only when it
        is present AND the stored hash still matches, so a credential
        change always gets a new token. The token's 'expires_in' is
        never read and no expiry time is stored - a stale token shows
        up as a 401, which api_helper()'s NAC re-auth branch
        (_reauthenticate_on_401()) handles by calling this method again
        with force_regenerate=True.

        Args:
            storage (Dict): Plugin storage dictionary.
            config_params (Dict): Extracted configuration parameters.
            force_regenerate (bool): Skip the cache and get a new
                token. Defaults to False.

        Returns:
            str: A NAC API access token.

        Raises:
            HPEMistAccessAssurancePluginException: When a new token cannot be
                obtained.
        """
        config_hash = self.get_nac_config_hash(config_params)
        cached_token = storage.get(NAC_STORAGE_TOKEN_KEY)
        if (
            not force_regenerate
            and cached_token
            and storage.get(NAC_STORAGE_CONFIG_HASH_KEY) == config_hash
        ):
            self.logger.debug(
                f"{self.log_prefix}: Using the NAC API access token "
                "saved from an earlier run."
            )
            return cached_token
        access_token = self.generate_nac_access_token(config_params)
        storage.update(
            {
                NAC_STORAGE_TOKEN_KEY: access_token,
                NAC_STORAGE_CONFIG_HASH_KEY: config_hash,
            }
        )
        return access_token

    @staticmethod
    def get_nac_auth_header(access_token: str) -> Dict[str, str]:
        """Build the NAC API Authorization header.

        Args:
            access_token (str): NAC API access token.

        Returns:
            Dict[str, str]: {"Authorization": "Bearer <token>"}.
        """
        return {"Authorization": f"Bearer {access_token}"}

    def push_nac_devices(
        self,
        devices: List[Dict],
        config_params: Dict,
        storage: Dict,
        headers: Dict,
    ) -> Dict:
        """Send a batch of device objects to the NAC API.

        The endpoint is an upsert - a device that already exists is
        updated by the same POST. The request body is a JSON array of
        device objects. Callers are responsible for chunking the full
        list into batches of at most NAC_DEVICE_BATCH_SIZE before
        calling this method once per batch.

        Args:
            devices (List[Dict]): Device objects in this batch.
            config_params (Dict): Extracted configuration parameters.
            storage (Dict): Plugin storage dictionary.
            headers (Dict): Request headers (including auth).

        Returns:
            Dict: Parsed API response, with the 'processed',
            'updated', 'failed' counts and the 'errors' list.
        """
        url = NAC_DEVICES_ENDPOINT.format(
            base_url=config_params["nac_base_url"],
            org_id=config_params["nac_mist_org_id"],
            account_id=config_params["nac_netskope_account_id"],
        )
        return self.api_helper(
            logger_msg=f"adding {len(devices)} device(s) to NAC",
            url=url,
            method="POST",
            json_data=devices,
            headers=headers,
            storage=storage,
            config_params=config_params,
            is_nac=True,
        )

    def delete_nac_device(
        self,
        netskope_device_uuid: str,
        config_params: Dict,
        storage: Dict,
        headers: Dict,
    ) -> None:
        """Delete one device from the NAC API by its Netskope UUID.

        A successful delete is an HTTP 200 with NO response body, so
        this call must NOT go through handle_error()/parse_response()
        on success - parse_response() would raise on the empty body
        and a working delete would be reported as a failure. The call
        is therefore made with is_handle_error_required=False and the
        raw status code is checked here: any 2xx is a success, and
        anything else is passed to handle_error() to raise.

        Args:
            netskope_device_uuid (str): UUID of the device to delete.
            config_params (Dict): Extracted configuration parameters.
            storage (Dict): Plugin storage dictionary.
            headers (Dict): Request headers (including auth).

        Raises:
            HPEMistAccessAssurancePluginException: When the delete did not
                return a 2xx status code.
        """
        logger_msg = (
            f"deleting device '{netskope_device_uuid}' from NAC"
        )
        url = NAC_DELETE_DEVICE_ENDPOINT.format(
            base_url=config_params["nac_base_url"],
            org_id=config_params["nac_mist_org_id"],
            account_id=config_params["nac_netskope_account_id"],
            uuid=netskope_device_uuid,
        )
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="DELETE",
            headers=headers,
            storage=storage,
            config_params=config_params,
            is_handle_error_required=False,
            is_nac=True,
        )
        if 200 <= response.status_code < 300:
            return
        self.handle_error(response, logger_msg, is_nac=True)
