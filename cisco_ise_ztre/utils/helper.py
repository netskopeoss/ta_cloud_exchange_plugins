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

CRE Cisco ISE Plugin helper module.
"""

import base64
import json
import requests
import time
import traceback
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Dict, Optional, Tuple, Union

from netskope.common.utils import add_user_agent

from .constants import (
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_WAIT_TIME,
    ERS_PASSWORD_KEY,
    ERS_USERNAME_KEY,
    ISE_HOST_KEY,
    MAX_API_CALLS,
    MAX_WAIT_TIME,
    MODULE_NAME,
    PLATFORM_NAME,
    PXGRID_ACCOUNT_CREATE_ENDPOINT,
    PXGRID_ACCOUNT_ACTIVATE_ENDPOINT,
    PXGRID_ACCESS_SECRET_ENDPOINT,
    PXGRID_CONTROL_HEADERS,
    PXGRID_NODE_NAME_KEY,
    PXGRID_PASSWORD_KEY,
    PXGRID_PORT,
    PXGRID_PROVIDER_NODE_KEY,
    PXGRID_REST_BASE_URL_KEY,
    PXGRID_SECRET_KEY,
    PXGRID_SERVICE_LOOKUP_ENDPOINT,
    PXGRID_SERVICE_NAME,
    PXGRID_STATE_DISABLED,
    PXGRID_STATE_ENABLED,
    PXGRID_STATE_PENDING,
)


class CiscoISEPluginException(Exception):
    """Cisco ISE plugin custom exception class."""

    pass


class CiscoISEPluginHelper(object):
    """CiscoISEPluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """Cisco ISE Plugin Helper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): Log prefix string.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers for Cisco ISE requests.

        Args:
            headers (Dict): Dictionary containing headers for any request.

        Returns:
            Dict: Dictionary after adding User-Agent.
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

    def strip_cidr_suffix(self, host_ip: Optional[str]) -> Optional[str]:
        """Strip a trailing '/32' CIDR suffix from an IP address.

        Only '/32' is stripped, since that's the only prefix length
        that denotes a single host - the bare IP address and the
        '/32' form mean exactly the same thing. Any other prefix
        length (e.g. '/31', '/24') describes an actual subnet, not a
        single host, and is left untouched rather than silently
        collapsed to its network address.

        Args:
            host_ip (Optional[str]): IP address, optionally with a CIDR
                suffix, e.g. '10.50.2.120/32'.

        Returns:
            Optional[str]: Bare IP address if 'host_ip' ended with
                '/32' (e.g. '10.50.2.120'), otherwise 'host_ip'
                unchanged.
        """
        if not host_ip or not isinstance(host_ip, str):
            return host_ip
        if host_ip.endswith("/32"):
            return host_ip.split("/")[0]
        return host_ip

    def _get_retry_after(self, response: requests.models.Response) -> int:
        """Compute how long to wait before retrying a 429/5xx response.

        Reads the 'Retry-After' header when present - it can be either
        a plain integer number of seconds or an HTTP-date - and falls
        back to DEFAULT_WAIT_TIME when the header is absent or could
        not be parsed. The result is always clamped to MAX_WAIT_TIME
        seconds so a misbehaving/huge header value can never stall a
        run for an unreasonable amount of time.

        Args:
            response (requests.models.Response): Response object.

        Returns:
            int: Number of seconds to wait before retrying.
        """
        retry_after = response.headers.get("Retry-After")
        wait_time = DEFAULT_WAIT_TIME
        if retry_after:
            try:
                wait_time = int(float(retry_after))
            except (TypeError, ValueError):
                try:
                    retry_date = parsedate_to_datetime(retry_after)
                    if retry_date.tzinfo is None:
                        retry_date = retry_date.replace(
                            tzinfo=timezone.utc
                        )
                    wait_time = int(
                        (
                            retry_date - datetime.now(timezone.utc)
                        ).total_seconds()
                    )
                except (TypeError, ValueError, OverflowError):
                    wait_time = DEFAULT_WAIT_TIME
        if wait_time < 0:
            wait_time = DEFAULT_WAIT_TIME
        return min(wait_time, MAX_WAIT_TIME)

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data=None,
        headers: Optional[Dict] = None,
        json=None,
        verify=True,
        proxies=None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        auth: Optional[Tuple] = None,
        timeout: int = DEFAULT_REQUEST_TIMEOUT,
    ):
        """API helper to perform API request on Cisco ISE platform
        and capture all possible errors for requests.

        Args:
            logger_msg (str): Logger message describing the operation.
            url (str): API endpoint URL.
            method (str): HTTP method. Defaults to "GET".
            params (Dict, optional): Query parameters. Defaults to None.
            data: Request body data. Defaults to None.
            headers (Dict, optional): Request headers. Defaults to None.
            json: JSON payload. Defaults to None.
            verify (bool, optional): SSL verification. Defaults to True.
            proxies (Dict, optional): Proxy configuration. Defaults to None.
            is_handle_error_required (bool, optional): Whether to handle
                HTTP error codes. Defaults to True.
            is_validation (bool, optional): Whether this is a validation
                call. Defaults to False.
            auth (Tuple, optional): Basic auth tuple (user, pass).
                Defaults to None.
            timeout (int, optional): Request timeout in seconds, covering
                both connect and read. Defaults to DEFAULT_REQUEST_TIMEOUT.

        Returns:
            dict or Response: Parsed response dict or raw Response object.

        Raises:
            CiscoISEPluginException: On any API or network error.
        """
        try:
            headers = self._add_user_agent(headers)

            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}. "
                f"Endpoint: {method} {url}"
            )
            if params:
                debug_log_msg += f", params: {params}."

            self.logger.debug(debug_log_msg)

            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                    json=json,
                    auth=auth,
                    timeout=timeout,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )

                if (
                    status_code == 429
                    or 500 <= status_code <= 600
                ) and not is_validation:
                    api_err_msg = str(response.text)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}, "
                            "API rate limit exceeded or server error while "
                            f"{logger_msg}. Max retries exceeded hence "
                            f"returning status code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise CiscoISEPluginException(err_msg)
                    if status_code == 429:
                        log_err_msg = "API rate limit exceeded"
                    else:
                        log_err_msg = "HTTP server error occurred"
                    retry_after = self._get_retry_after(response)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code "
                            f"{status_code}, "
                            f"{log_err_msg} while {logger_msg}. "
                            f"Retrying after {retry_after} seconds. "
                            f"{MAX_API_CALLS - 1 - retry_counter} "
                            "retries remaining."
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(
                            response, logger_msg, is_validation
                        )
                        if is_handle_error_required
                        else response
                    )
        except CiscoISEPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = (
                f"Read Timeout error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    "Read Timeout error occurred. Verify the "
                    "'ISE Host' provided in the configuration parameters."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise CiscoISEPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the "
                "proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy "
                    "configuration provided."
                )
            resolution = (
                "Ensure that the proxy configuration provided is correct."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                resolution=resolution,
                details=traceback.format_exc(),
            )
            raise CiscoISEPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            resolution = (
                "Connection error occurred. Ensure that the proxy server "
                f"or {PLATFORM_NAME} server is reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    f"platform. Proxy server or {PLATFORM_NAME} server "
                    "is not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                resolution=resolution,
                details=traceback.format_exc(),
            )
            raise CiscoISEPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify the "
                    "configuration parameters provided."
                )
            resolution = (
                "Ensure that the configuration parameters provided "
                "are correct."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                resolution=resolution,
                details=traceback.format_exc(),
            )
            raise CiscoISEPluginException(err_msg)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing API call "
                    f"to {PLATFORM_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise CiscoISEPluginException(err_msg)

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ):
        """Parse Response will return JSON from response object.

        Args:
            response (Response): Response object.
            logger_msg (str): Logger message.
            is_validation (bool): Whether this is a validation call.

        Returns:
            Any: Parsed JSON response.

        Raises:
            CiscoISEPluginException: On JSON decode error.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received from API while "
                f"{logger_msg}. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify the ISE Host provided in the configuration "
                    "parameters. Check logs for more details."
                )
            raise CiscoISEPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing JSON response "
                f"while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred. Verify the ISE "
                    "Host provided in the configuration parameters. "
                    "Check logs for more details."
                )
            raise CiscoISEPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ):
        """Handle the different HTTP response codes.

        Args:
            resp (requests.models.Response): Response object.
            logger_msg (str): Logger message.
            is_validation (bool): Whether this is a validation call.

        Returns:
            dict: Response JSON for 200/201/204.

        Raises:
            CiscoISEPluginException: For non-2xx status codes.
        """
        status_code = resp.status_code
        validation_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, Bad Request",
            401: "Received exit code 401, Unauthorized access",
            403: "Received exit code 403, Forbidden",
            404: "Received exit code 404, Resource not found",
        }
        resolution_dict = {
            400: (
                "Ensure that the ISE Host provided in the "
                "configuration parameter is correct."
            ),
            401: (
                "Ensure that the ERS Username and Password provided "
                "in the configuration parameters are correct and the "
                "account is in the ERS-Admin or ERS-Operator group."
            ),
            403: (
                "Ensure that the ERS user account has the required "
                "ERS-Admin or ERS-Operator group membership."
            ),
            404: (
                "Ensure that the ISE Host provided in the "
                "configuration parameter is correct and the "
                "ERS API is enabled on the ISE node."
            ),
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request. "
                    "Verify the ISE Host provided in the "
                    "configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized. "
                    "Verify the ERS Username and Password provided "
                    "in the configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden. "
                    "Verify the ERS user has ERS-Admin or "
                    "ERS-Operator group membership."
                ),
                404: (
                    "Received exit code 404, Resource not found. "
                    "Verify the ISE Host provided in the "
                    "configuration parameters."
                ),
            }

        if status_code in [200, 201]:
            return self.parse_response(
                response=resp,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            resolution = resolution_dict.get(status_code)
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    resolution=resolution,
                    details=f"API response: {resp.text}",
                )
                raise CiscoISEPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                    details=f"API response: {resp.text}",
                )
                raise CiscoISEPluginException(err_msg)
        else:
            err_msg = (
                "HTTP Server Error"
                if 500 <= status_code <= 600
                else "HTTP Error"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{validation_msg + err_msg} while {logger_msg}."
                ),
                details=f"API response: {resp.text}",
            )
            raise CiscoISEPluginException(err_msg)

    def get_config_params(self, configuration: Dict) -> Tuple:
        """Extract configuration parameters needed to fetch records.

        The pxGrid node name isn't included: it's derived from the
        plugin configuration's name (see
        CiscoISEPlugin._get_pxgrid_node_name), not read from
        configuration.

        Args:
            configuration (Dict): Configuration parameter dictionary.

        Returns:
            Tuple: Tuple of (ise_host, ers_username, ers_password).
        """
        return (
            configuration.get(ISE_HOST_KEY, "").strip().strip("/"),
            configuration.get(ERS_USERNAME_KEY, "").strip(),
            configuration.get(ERS_PASSWORD_KEY),
        )

    def get_ers_auth_header(
        self, username: str, password: str
    ) -> Dict:
        """Build HTTP Basic Auth header for ERS API.

        Args:
            username (str): ERS API username.
            password (str): ERS API password.

        Returns:
            Dict: Authorization header dict.
        """
        auth_string = base64.b64encode(
            f"{username}:{password}".encode()
        ).decode()
        return {"Authorization": f"Basic {auth_string}"}

    def get_pxgrid_auth_header(
        self, node_name: str, secret: str
    ) -> Dict:
        """Build HTTP Basic Auth header for pxGrid data plane calls.

        Args:
            node_name (str): pxGrid client node name.
            secret (str): pxGrid peer secret.

        Returns:
            Dict: Authorization header dict.
        """
        auth_string = base64.b64encode(
            f"{node_name}:{secret}".encode()
        ).decode()
        return {"Authorization": f"Basic {auth_string}"}

    def _get_pxgrid_control_auth(
        self, node_name: str, password: str
    ) -> Tuple:
        """Return (node_name, password) tuple for pxGrid control auth.

        Args:
            node_name (str): pxGrid client node name.
            password (str): pxGrid control plane password.

        Returns:
            Tuple: (node_name, password) for requests auth= param.
        """
        return (node_name, password)

    def create_account(
        self,
        ise_host: str,
        configured_node_name: str,
        storage: dict,
        verify: bool = True,
        proxies: Optional[Dict] = None,
        is_validation: bool = False,
    ) -> Tuple[str, str]:
        """Register (or reuse) the plugin's pxGrid client account.

        Calls pxGrid AccountCreate. If the node is already registered
        (409) and storage has matching cached credentials, those are
        reused; otherwise this raises, since the plugin cannot recover
        the password of a node it did not register itself.

        Args:
            ise_host (str): ISE PAN base URL, including scheme (e.g.
                https://10.50.1.14).
            configured_node_name (str): Node name from plugin config.
            storage (dict): Mutable storage dict (self.storage or {}).
            verify (bool): SSL verification flag.
            proxies (Dict, optional): Proxy configuration.
            is_validation (bool): True when called from validate().

        Returns:
            Tuple[str, str]: (node_name, password).

        Raises:
            CiscoISEPluginException: On account creation failure.
        """
        node_name = configured_node_name
        account_create_url = PXGRID_ACCOUNT_CREATE_ENDPOINT.format(
            ise_host=ise_host, port=PXGRID_PORT
        )
        self.logger.debug(
            f"{self.log_prefix}: Starting pxGrid AccountCreate "
            f"for node '{node_name}'."
        )
        create_response = self.api_helper(
            logger_msg=(
                f"creating pxGrid account for node '{node_name}'"
            ),
            url=account_create_url,
            method="POST",
            headers=dict(PXGRID_CONTROL_HEADERS),
            json={"nodeName": node_name},
            verify=verify,
            proxies=proxies,
            is_handle_error_required=False,
            is_validation=is_validation,
        )
        create_status = create_response.status_code
        if create_status == 409:
            # Node already registered — must reuse stored credentials.
            # If storage has no credentials, we cannot proceed.
            stored_node = storage.get(PXGRID_NODE_NAME_KEY, "")
            stored_pass = storage.get(PXGRID_PASSWORD_KEY, "")
            if stored_node and stored_pass:
                self.logger.info(
                    f"{self.log_prefix}: pxGrid node '{node_name}' "
                    "already registered. Reusing stored credentials."
                )
                return stored_node, stored_pass
            err_msg = (
                f"pxGrid node '{node_name}' is already registered "
                "in Cisco ISE but no stored credentials were found. "
                "Please delete the existing pxGrid node from ISE "
                "Admin Console and retry, or ensure the plugin "
                "storage contains valid credentials."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {create_response.text}",
                resolution=(
                    "Delete the existing pxGrid client node with "
                    f"name '{node_name}' from the Cisco ISE Admin "
                    "Console, then re-validate the plugin."
                ),
            )
            raise CiscoISEPluginException(err_msg)
        elif create_status in [200, 201]:
            create_json = self.parse_response(
                create_response,
                logger_msg=(
                    f"creating pxGrid account for node '{node_name}'"
                ),
                is_validation=is_validation,
            )
            node_name = create_json.get("nodeName", node_name)
            password = create_json.get("password", "")
            if not password:
                err_msg = (
                    "pxGrid AccountCreate did not return a password. "
                    "Cannot proceed with bootstrap."
                )
                raise CiscoISEPluginException(err_msg)
            storage[PXGRID_NODE_NAME_KEY] = node_name
            storage[PXGRID_PASSWORD_KEY] = password
            self.logger.info(
                f"{self.log_prefix}: Successfully created pxGrid "
                f"account for node '{node_name}'."
            )
            return node_name, password
        else:
            # Unexpected status code from AccountCreate.
            self.handle_error(
                create_response,
                logger_msg=(
                    f"creating pxGrid account for node '{node_name}'"
                ),
                is_validation=is_validation,
            )
            err_msg = (
                f"Unexpected response from pxGrid AccountCreate for "
                f"node '{node_name}'."
            )
            raise CiscoISEPluginException(err_msg)

    def activate_account(
        self,
        ise_host: str,
        node_name: str,
        password: str,
        verify: bool = True,
        proxies: Optional[Dict] = None,
        is_validation: bool = False,
    ) -> str:
        """Call pxGrid AccountActivate once and return the account state.

        This is a single, non-blocking API call - it never sleeps or
        retries. Callers decide what to do with a non-ENABLED state:
        bootstrap_pxgrid() does one wait-and-recheck for validate(),
        while a scheduled fetch should skip pxGrid data for that run
        instead of blocking (see main.py's _fetch_pxgrid_records).

        Args:
            ise_host (str): ISE PAN base URL, including scheme (e.g.
                https://10.50.1.14).
            node_name (str): pxGrid client node name.
            password (str): pxGrid control plane password.
            verify (bool): SSL verification flag.
            proxies (Dict, optional): Proxy configuration.
            is_validation (bool): True when called from validate().

        Returns:
            str: 'accountState' from the response, e.g. 'ENABLED'.
        """
        account_activate_url = PXGRID_ACCOUNT_ACTIVATE_ENDPOINT.format(
            ise_host=ise_host, port=PXGRID_PORT
        )
        self.logger.debug(
            f"{self.log_prefix}: Checking pxGrid account status "
            f"for node '{node_name}'."
        )
        activate_response = self.api_helper(
            logger_msg=(
                f"checking pxGrid account status for node '{node_name}'"
            ),
            url=account_activate_url,
            method="POST",
            headers=dict(PXGRID_CONTROL_HEADERS),
            json={"description": "Netskope CRE Integration"},
            auth=self._get_pxgrid_control_auth(node_name, password),
            verify=verify,
            proxies=proxies,
            is_handle_error_required=True,
            is_validation=is_validation,
        )
        return activate_response.get("accountState", "")

    def discover_session_service(
        self,
        ise_host: str,
        node_name: str,
        password: str,
        storage: dict,
        verify: bool = True,
        proxies: Optional[Dict] = None,
        is_validation: bool = False,
    ) -> Tuple[str, str]:
        """Run ServiceLookup + AccessSecret and cache the results.

        One-time discovery: ServiceLookup's result never needs to be
        repeated once cached in storage - only AccessSecret does (see
        refresh_pxgrid_secret). ServiceLookup's 'restBaseUrl' is cached
        for logging only - getSessions is called directly against
        ise_host:PXGRID_PORT (see PXGRID_GET_SESSIONS_ENDPOINT), since
        restBaseUrl can point at an internal hostname that isn't
        reachable from the Cloud Exchange host. What ServiceLookup
        actually provides that's needed is the provider node name,
        required by AccessSecret.

        Args:
            ise_host (str): ISE PAN base URL, including scheme (e.g.
                https://10.50.1.14).
            node_name (str): pxGrid client node name.
            password (str): pxGrid control plane password.
            storage (dict): Mutable storage dict to cache results into.
            verify (bool): SSL verification flag.
            proxies (Dict, optional): Proxy configuration.
            is_validation (bool): True when called from validate().

        Returns:
            Tuple[str, str]: (rest_base_url, secret).

        Raises:
            CiscoISEPluginException: On discovery failure.
        """
        service_lookup_url = PXGRID_SERVICE_LOOKUP_ENDPOINT.format(
            ise_host=ise_host, port=PXGRID_PORT
        )
        self.logger.debug(
            f"{self.log_prefix}: Performing pxGrid ServiceLookup for "
            f"service '{PXGRID_SERVICE_NAME}'."
        )
        lookup_response = self.api_helper(
            logger_msg=(
                f"performing pxGrid ServiceLookup for "
                f"service '{PXGRID_SERVICE_NAME}'"
            ),
            url=service_lookup_url,
            method="POST",
            headers=dict(PXGRID_CONTROL_HEADERS),
            json={"name": PXGRID_SERVICE_NAME},
            auth=self._get_pxgrid_control_auth(node_name, password),
            verify=verify,
            proxies=proxies,
            is_handle_error_required=True,
            is_validation=is_validation,
        )
        services = lookup_response.get("services", [])
        if not services or not isinstance(services, list):
            err_msg = (
                "pxGrid ServiceLookup returned no services for "
                f"'{PXGRID_SERVICE_NAME}'. Ensure the Cisco ISE MnT "
                "node has the Session Directory service enabled."
            )
            raise CiscoISEPluginException(err_msg)

        service = services[0]
        provider_node_name = service.get("nodeName", "")
        rest_base_url = (
            service.get("properties", {}).get("restBaseUrl", "")
        )

        if not provider_node_name:
            err_msg = (
                "pxGrid ServiceLookup did not return a 'nodeName' for "
                "the session directory service."
            )
            raise CiscoISEPluginException(err_msg)

        storage[PXGRID_REST_BASE_URL_KEY] = rest_base_url
        storage[PXGRID_PROVIDER_NODE_KEY] = provider_node_name
        self.logger.info(
            f"{self.log_prefix}: pxGrid ServiceLookup found provider "
            f"node '{provider_node_name}'."
        )

        secret = self._get_access_secret(
            ise_host=ise_host,
            node_name=node_name,
            password=password,
            provider_node_name=provider_node_name,
            storage=storage,
            verify=verify,
            proxies=proxies,
            is_validation=is_validation,
        )

        return rest_base_url, secret

    def bootstrap_pxgrid(
        self,
        ise_host: str,
        configured_node_name: str,
        storage: dict,
        verify: bool = True,
        proxies: Optional[Dict] = None,
        is_validation: bool = False,
    ) -> Optional[Tuple[str, str, str]]:
        """Run the pxGrid bootstrap flow used by validate().

        A pxGrid client account requires manual Cisco ISE admin
        approval, which can take an arbitrary amount of time - this
        method never waits or retries for it. Whether this
        configuration already has a registered account (per storage,
        not the secret - see class docstring) only changes what a
        non-ENABLED result means, not whether AccountActivate is
        called:

        - No account yet: call AccountCreate, then AccountActivate.
          AccountActivate must be called even for an account created
          moments ago - Cisco ISE leaves a brand-new pxGrid client in
          an internal state that isn't yet visible to an ISE admin
          until AccountActivate is called at least once; that call is
          what actually transitions it into the state that shows up
          under Administration > pxGrid Services > Client Management
          awaiting approval. Skipping this call for a fresh account
          would leave it with nothing for an admin to ever approve. A
          fresh account coming back as anything other than ENABLED is
          the expected outcome, not a failure - reporting it as such
          would make the very first save of every pxGrid configuration
          fail; only an unexpected ENABLED result (e.g. ISE configured
          to auto-approve) proceeds straight to
          discover_session_service() instead of waiting for a second
          validate().
        - Account already exists: call AccountActivate. Only an
          ENABLED account proceeds to discover_session_service(); any
          other state raises immediately, with no wait - the caller
          must re-validate once ISE admin approval has happened.

        Args:
            ise_host (str): ISE PAN base URL, including scheme (e.g.
                https://10.50.1.14).
            configured_node_name (str): pxGrid node name, derived from
                the plugin configuration's own name.
            storage (dict): Mutable storage dict (self.storage or {}).
            verify (bool): SSL verification flag.
            proxies (Dict, optional): Proxy configuration.
            is_validation (bool): True when called from validate().

        Returns:
            Optional[Tuple[str, str, str]]: (rest_base_url, node_name,
                secret) once the account is confirmed ENABLED and
                session directory discovery has run, or None when a
                brand-new account was just created/activated and is
                still pending approval.

        Raises:
            CiscoISEPluginException: On bootstrap failure, or when an
                already-registered account isn't ENABLED.
        """
        node_name = storage.get(PXGRID_NODE_NAME_KEY, "")
        password = storage.get(PXGRID_PASSWORD_KEY, "")
        is_new_account = not node_name or not password

        if is_new_account:
            node_name, password = self.create_account(
                ise_host=ise_host,
                configured_node_name=configured_node_name,
                storage=storage,
                verify=verify,
                proxies=proxies,
                is_validation=is_validation,
            )

        account_state = self.activate_account(
            ise_host=ise_host,
            node_name=node_name,
            password=password,
            verify=verify,
            proxies=proxies,
            is_validation=is_validation,
        )

        if is_new_account and account_state != PXGRID_STATE_ENABLED:
            self.logger.info(
                f"{self.log_prefix}: pxGrid client account created for "
                f"node '{node_name}' (status: '{account_state}'). The "
                "pxGrid client requires admin approval, request your "
                "admin to approve the client to enable data pulling "
                "for live sessions."
            )
            return None

        if account_state == PXGRID_STATE_PENDING:
            err_msg = (
                "pxGrid node account is PENDING admin approval. "
                "Please approve the pxGrid client node "
                f"'{node_name}' in the Cisco ISE Admin Console "
                "(Administration > pxGrid Services > Client Management) "
                "and then re-validate the plugin configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Approve the pxGrid client node in the Cisco ISE Admin "
                    "Console under Administration > pxGrid Services > "
                    "Client Management, then retry."
                ),
            )
            raise CiscoISEPluginException(err_msg)
        elif account_state == PXGRID_STATE_DISABLED:
            err_msg = (
                f"pxGrid node '{node_name}' is DISABLED in Cisco ISE. "
                "Re-enable the pxGrid client node in the ISE Admin Console "
                "(Administration > pxGrid Services > Client Management) "
                "and re-validate the plugin configuration."
            )
            resolution = (
                "Enable the pxGrid client node in the Cisco ISE Admin "
                "Console and retry."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            raise CiscoISEPluginException(err_msg)
        elif account_state != PXGRID_STATE_ENABLED:
            err_msg = (
                f"pxGrid node '{node_name}' returned unexpected account "
                f"state: '{account_state}'. Expected 'ENABLED'."
            )
            raise CiscoISEPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: pxGrid account '{node_name}' is ENABLED."
        )

        rest_base_url, secret = self.discover_session_service(
            ise_host=ise_host,
            node_name=node_name,
            password=password,
            storage=storage,
            verify=verify,
            proxies=proxies,
            is_validation=is_validation,
        )

        return rest_base_url, node_name, secret

    def _get_access_secret(
        self,
        ise_host: str,
        node_name: str,
        password: str,
        provider_node_name: str,
        storage: dict,
        verify: bool = True,
        proxies: Optional[Dict] = None,
        is_validation: bool = False,
    ) -> str:
        """Call pxGrid AccessSecret to obtain peer secret.

        Args:
            ise_host (str): ISE PAN base URL, including scheme (e.g.
                https://10.50.1.14).
            node_name (str): pxGrid client node name.
            password (str): pxGrid control plane password.
            provider_node_name (str): Provider node name from ServiceLookup.
            storage (dict): Storage dict to update with new secret.
            verify (bool): SSL verification flag.
            proxies (Dict, optional): Proxy configuration.
            is_validation (bool): True when called from validate().

        Returns:
            str: Peer secret for data plane authentication.

        Raises:
            CiscoISEPluginException: If secret cannot be obtained.
        """
        access_secret_url = PXGRID_ACCESS_SECRET_ENDPOINT.format(
            ise_host=ise_host, port=PXGRID_PORT
        )
        self.logger.debug(
            f"{self.log_prefix}: Performing pxGrid AccessSecret "
            f"for provider node '{provider_node_name}'."
        )
        secret_response = self.api_helper(
            logger_msg=(
                "obtaining pxGrid access secret for provider node "
                f"'{provider_node_name}'"
            ),
            url=access_secret_url,
            method="POST",
            headers=dict(PXGRID_CONTROL_HEADERS),
            json={"peerNodeName": provider_node_name},
            auth=self._get_pxgrid_control_auth(node_name, password),
            verify=verify,
            proxies=proxies,
            is_handle_error_required=True,
            is_validation=is_validation,
        )
        secret = secret_response.get("secret", "")
        if not secret:
            err_msg = (
                "pxGrid AccessSecret did not return a secret. "
                "Cannot authenticate with the session directory service."
            )
            raise CiscoISEPluginException(err_msg)

        storage[PXGRID_SECRET_KEY] = secret
        self.logger.info(
            f"{self.log_prefix}: Successfully obtained pxGrid "
            "access secret."
        )
        return secret

    def refresh_pxgrid_secret(
        self,
        ise_host: str,
        storage: dict,
        verify: bool = True,
        proxies: Optional[Dict] = None,
    ) -> str:
        """Re-run AccessSecret (Step 4 only) to refresh the peer secret.

        Called when getSessions returns HTTP 401 to obtain a new secret
        without re-running the full bootstrap.

        Args:
            ise_host (str): ISE PAN base URL, including scheme (e.g.
                https://10.50.1.14).
            storage (dict): Storage dict with existing credentials.
            verify (bool): SSL verification flag.
            proxies (Dict, optional): Proxy configuration.

        Returns:
            str: Fresh peer secret.

        Raises:
            CiscoISEPluginException: If secret cannot be refreshed.
        """
        node_name = storage.get(PXGRID_NODE_NAME_KEY, "")
        password = storage.get(PXGRID_PASSWORD_KEY, "")
        provider_node_name = storage.get(PXGRID_PROVIDER_NODE_KEY, "")

        if not node_name or not password:
            err_msg = (
                "Cannot refresh pxGrid secret — node_name or password "
                "not found in storage. A full re-bootstrap is required."
            )
            raise CiscoISEPluginException(err_msg)

        if not provider_node_name:
            err_msg = (
                "Cannot refresh pxGrid secret — provider node name "
                "not found in storage. A full re-bootstrap is required."
            )
            raise CiscoISEPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Refreshing pxGrid secret after 401 "
            "response from session directory service."
        )
        return self._get_access_secret(
            ise_host=ise_host,
            node_name=node_name,
            password=password,
            provider_node_name=provider_node_name,
            storage=storage,
            verify=verify,
            proxies=proxies,
            is_validation=False,
        )
