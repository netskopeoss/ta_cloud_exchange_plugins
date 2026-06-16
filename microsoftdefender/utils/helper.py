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

CTE Microsoft Defender for Endpoint plugin helper.
"""

import hashlib
import ipaddress
import json
import time
import traceback
import re
import requests
from dateutil import parser
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
from packaging import version
from typing import Dict, List, Literal, Tuple, Union

from ..lib import msal
from netskope.common.api import __version__ as CE_VERSION
from netskope.common.utils import add_user_agent
from netskope.integrations.cte.models import IndicatorType, SeverityType

from .constants import (
    CHECK_TENANT_ID_ERROR,
    MODULE_NAME,
    PLUGIN_NAME,
    DEFAULT_SLEEP_TIME,
    MAX_API_CALLS,
    MAX_WAIT_TIME,
    MAXIMUM_CE_VERSION,
    NO_MORE_RETRIES_ERROR_MSG,
    RETRACTION,
    RETRY_ERROR_MSG,
    VALIDATION_ERROR_MSG
)


class MicrosoftDefenderPluginException(Exception):
    """Microsoft Defender for Endpoint plugin custom exception class."""

    pass


class MicrosoftDefenderPluginHelper:
    """Microsoft Defender for Endpoint plugin helper class."""

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """Microsoft Defender for Endpoint Plugin Helper initializer.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix string.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.resolution_support = version.parse(CE_VERSION) > version.parse(
            MAXIMUM_CE_VERSION
        )
        # Patch logger methods to handle resolution parameter compatibility
        self._patch_logger_methods()

    def _patch_logger_methods(self):
        """Monkey patch logger methods to handle \
            resolution parameter compatibility."""
        # Store original methods
        original_error = self.logger.error

        def patched_error(
            message=None, details=None, resolution=None, **kwargs
        ):
            """Patched error method that handles resolution compatibility."""
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self.resolution_support:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        # Replace logger methods with patched versions
        self.logger.error = patched_error

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers for third-party requests.

        Args:
            headers (Dict): Dictionary containing headers for any request.

        Returns:
            Dict: Dictionary after adding User-Agent.
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

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str = "GET",
        params: Dict = {},
        data=None,
        files=None,
        headers: Dict = {},
        json=None,
        verify: bool = True,
        proxies: Dict = {},
        configuration: Dict = None,
        storage: Dict = None,
        is_validation: bool = False,
        is_retraction: bool = False,
        is_handle_error_required: bool = True,
        regenerate_auth_token=True,
    ):
        """API helper to perform API request on the platform and captures
        all the possible errors for requests.

        Args:
            logger_msg (str): Logger message.
            url (str): API endpoint URL.
            method (str): HTTP method for the endpoint. Defaults to "GET".
            params (Dict): Request parameters dictionary. Defaults to {}.
            data: Data to be sent to API. Defaults to None.
            files: Files to be sent to API. Defaults to None.
            headers (Dict): Headers for the request. Defaults to {}.
            json: JSON payload for the request. Defaults to None.
            verify (bool): Verify SSL. Defaults to True.
            proxies (Dict): Proxies. Defaults to {}.
            configuration (Dict, optional): Configuration. Defaults to None.
            storage (Dict, optional): Storage. Defaults to None.
            is_validation (bool): Whether this request is from validate
                method. Defaults to False.
            is_retraction (bool, optional): Is this called from the retraction.
            is_handle_error_required (bool): Whether handling of the status
                code is required. Defaults to True.
            regenerate_auth_token (bool, optional): Is regenerating auth token
                required? Defaults to True.

        Returns:
            requests.models.Response: Response object.

        Raises:
            MicrosoftDefenderPluginException: If any error occurs.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

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
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    files=files,
                    headers=headers,
                    json=json,
                    verify=verify,
                    proxies=proxies,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API response for "
                    f"{logger_msg}. Status Code={status_code}."
                )
                if status_code == 401 and regenerate_auth_token:
                    (base_url, tenant_id, app_id, app_secret, *_) = (
                        self.get_configuration_parameters(configuration)
                    )

                    auth_header = self.generate_auth_token(
                        tenant_id=tenant_id,
                        app_id=app_id,
                        app_secret=app_secret,
                        base_url=base_url,
                        proxies=proxies,
                        is_validation=is_validation
                    )
                    storage.update(
                        {
                            "auth_header": auth_header,
                        }
                    )
                    headers.update(auth_header)
                    return self.api_helper(
                        url=url,
                        method=method,
                        params=params,
                        headers=headers,
                        json=json,
                        data=data,
                        verify=verify,
                        proxies=proxies,
                        storage=storage,
                        configuration=configuration,
                        is_handle_error_required=is_handle_error_required,
                        is_validation=is_validation,
                        is_retraction=is_retraction,
                        logger_msg=logger_msg,
                        regenerate_auth_token=False,
                    )
                elif not is_validation and (
                    status_code == 429 or status_code in range(500, 601)
                ):
                    api_err_msg = str(response.text)
                    if retry_count == MAX_API_CALLS - 1:
                        err_msg = NO_MORE_RETRIES_ERROR_MSG.format(
                            status_code=status_code,
                            logger_msg=logger_msg,
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}"
                        )
                        raise MicrosoftDefenderPluginException(err_msg)
                    if status_code == 429:
                        error_reason = "API rate limit exceeded"
                    else:
                        error_reason = "HTTP server error occurred"
                    retry_after = self._get_retry_after(
                        headers=response.headers
                    )
                    if retry_after is None:
                        self.logger.info(
                            f"{self.log_prefix}: No Retry-After value "
                            f"received from API hence plugin will "
                            f"retry after {DEFAULT_SLEEP_TIME} seconds."
                        )
                        time.sleep(DEFAULT_SLEEP_TIME)
                        continue
                    diff_retry_after = round(abs(retry_after), 2)
                    if diff_retry_after > MAX_WAIT_TIME:
                        err_msg = (
                            f"'Retry-After' value received from "
                            f"response headers while {logger_msg} "
                            f"is greater than {MAX_WAIT_TIME} "
                            f"seconds hence returning status code "
                            f"{status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}"
                        )
                        raise MicrosoftDefenderPluginException(err_msg)

                    err_msg = RETRY_ERROR_MSG.format(
                        status_code=status_code,
                        error_reason=error_reason,
                        logger_msg=logger_msg,
                        wait_time=retry_after,
                        retry_remaining=MAX_API_CALLS - 1 - retry_count,
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=api_err_msg,
                    )
                    time.sleep(diff_retry_after)
                else:
                    return (
                        self._handle_error(
                            response=response,
                            logger_msg=logger_msg,
                            is_validation=is_validation,
                        )
                        if is_handle_error_required
                        else response
                    )
        except MicrosoftDefenderPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read Timeout error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that Base URL provided in the "
                    "configuration parameter is correct."
                ),
            )
            raise MicrosoftDefenderPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg} when trying to "
                f"communicate with {PLUGIN_NAME} platform."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred when trying to communicate with "
                    f"{PLUGIN_NAME} platform."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the proxy configuration provided is "
                    "correct and the proxy server is reachable."
                ),
            )
            raise MicrosoftDefenderPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLUGIN_NAME} platform "
                f"while {logger_msg}. Proxy server or "
                f"{PLUGIN_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLUGIN_NAME} "
                    "platform. Proxy server or "
                    f"{PLUGIN_NAME} server is not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Base URL provided in "
                    "configuration parameter is correct."
                ),
            )
            raise MicrosoftDefenderPluginException(err_msg)
        except requests.HTTPError as error:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify configuration parameters "
                    "provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the provided configuration parameters "
                    "are correct."
                ),
            )
            raise MicrosoftDefenderPluginException(err_msg)
        except Exception as error:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    f"Unexpected error occurred while performing API call"
                    f" to {PLUGIN_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the provided configuration parameters "
                    "are correct."
                ),
            )
            raise MicrosoftDefenderPluginException(err_msg)

    def _handle_error(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Handle different HTTP response status codes.

        Args:
            response (requests.models.Response): Response object returned
                from API call.
            logger_msg (str): Logger message.
            is_validation (bool): Whether this is called from validate
                method. Defaults to False.

        Returns:
            Dict: Response JSON dictionary for successful responses.

        Raises:
            MicrosoftDefenderPluginException: If response indicates an error.
        """
        status_code = response.status_code
        validation_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, Bad Request. ",
            403: "Received exit code 403, Forbidden. ",
            401: "Received exit code 401, Unauthorized access. ",
            404: "Received exit code 404, Resource not found. ",
        }

        def _log_error_message(resolution: str = None):
            nonlocal err_msg
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise MicrosoftDefenderPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise MicrosoftDefenderPluginException(err_msg)

        if status_code in [200, 201, 202]:
            return self._parse_response(
                response=response,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            error_response = self._parse_response(
                response=response,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
            error_val = error_response.get("error", "")
            err_msg = error_dict[status_code]
            if isinstance(error_val, dict):
                err_message = error_val.get("message")
                if err_message:
                    err_msg = err_msg + err_message
                    resolution_msg = None
                else:
                    err_msg = err_msg + (
                        "Verify the configuration parameters provided. "
                        "Check logs for more details."
                    )
                    resolution_msg = None
            elif isinstance(error_val, str):
                text_response = response.text
                if "90002" in text_response:
                    err_msg = err_msg + (
                        "Invalid Tenant ID provided in "
                        "the configuration parameters."
                    )
                    resolution_msg = (
                        "Ensure that the Tenant ID provided in "
                        "the configuration parameters is correct."
                    )
                elif "700016" in text_response:
                    err_msg = err_msg + (
                        "Invalid Application ID provided in "
                        "the configuration parameters."
                    )
                    resolution_msg = (
                        "Ensure that the Application ID provided in "
                        "the configuration parameters is correct."
                    )
                elif "7000215" in text_response:
                    err_msg = err_msg + (
                        "Invalid Application Secret provided in "
                        "the configuration parameters."
                    )
                    resolution_msg = (
                        "Ensure that the Application Secret provided in "
                        "the configuration parameters is correct."
                    )
                else:
                    err_msg = err_msg + (
                        "Invalid Tenant ID, "
                        "Application ID, or Application Secret provided "
                        "in the configuration parameters."
                    )
                    resolution_msg = (
                        "Ensure that the Tenant ID, "
                        "Application ID, or Application Secret "
                        "provided in the configuration parameters is correct."
                    )
            _log_error_message(resolution=resolution_msg)
        elif status_code >= 400 and status_code < 500:
            err_msg = "HTTP Client Error"
            _log_error_message()
        elif status_code >= 500 and status_code < 600:
            err_msg = "HTTP Server Error"
            _log_error_message()
        else:
            err_msg = "HTTP Error"
            _log_error_message()

    def _parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Parse JSON from response object.

        Args:
            response (requests.models.Response): Response object.
            logger_msg (str): Logger message.
            is_validation (bool): Whether this is called from validate
                method. Defaults to False.

        Returns:
            Dict: Parsed response JSON.

        Raises:
            MicrosoftDefenderPluginException: If response cannot be parsed.
        """
        try:
            return response.json()
        except json.JSONDecodeError as error:
            err_msg = (
                f"Invalid JSON response received from API while"
                f" {logger_msg}. Error: {str(error)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify the Base URL provided in the configuration"
                    " parameters. Check logs for more details."
                )
            raise MicrosoftDefenderPluginException(err_msg)
        except Exception as error:
            err_msg = (
                f"Unexpected error occurred while parsing JSON response"
                f" while {logger_msg}. Error: {error}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred. Verify the Base"
                    " URL provided in the configuration parameters."
                    " Check logs for more details."
                )
            raise MicrosoftDefenderPluginException(err_msg)

    def generate_auth_token(
        self,
        tenant_id: str,
        app_id: str,
        app_secret: str,
        base_url: str,
        proxies: dict,
        is_validation: bool = False,
    ) -> Dict:
        """Get authorization token from Azure AD.

        Args:
            tenant_id (str): Azure AD Tenant ID.
            app_id (str): Azure AD Application ID.
            app_secret (str): Azure AD Application Secret.
            base_url (str): Microsoft Defender for Endpoint base URL.
            proxies (dict): Proxies.
            is_validation (bool): Whether this is called from validate
                method. Defaults to False.

        Returns:
            Dict: Authorization JSON containing access token.
        """
        if base_url == "https://api-gov.securitycenter.microsoft.us":
            authority = "https://login.microsoftonline.us/{0}".format(tenant_id)  # noqa
        else:
            authority = "https://login.microsoftonline.com/{0}".format(tenant_id)  # noqa
        scope = [f"{base_url}/.default"]

        try:
            self.logger.debug(
                f"{self.log_prefix}: Generating access token."
            )
            app = msal.ConfidentialClientApplication(
                app_id,
                authority=authority,
                client_credential=app_secret,
                proxies=proxies,
            )
            auth_json = app.acquire_token_for_client(scopes=scope)
            auth_token = auth_json.get("access_token")
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while generating "
                f"access token. Error: {err}"
            )
            resolution_msg = None
            if CHECK_TENANT_ID_ERROR in str(err):
                err_msg = (
                    "Invalid Tenant ID provided in "
                    "the configuration parameters."
                )
                resolution_msg = (
                    "Ensure that the Tenant ID provided in "
                    "the configuration parameters is correct."
                )

            if is_validation:
                err_msg = f"{VALIDATION_ERROR_MSG} {err_msg}"

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
                resolution=resolution_msg
            )
            raise MicrosoftDefenderPluginException(err_msg)

        if not auth_token:
            text_response = str(auth_json)
            if "90002" in text_response:
                err_msg = (
                    "Invalid Tenant ID provided in "
                    "the configuration parameters."
                )
                resolution_msg = (
                    "Ensure that the Tenant ID provided in "
                    "the configuration parameters is correct."
                )
            elif "700016" in text_response:
                err_msg = (
                    "Invalid Application ID provided in "
                    "the configuration parameters."
                )
                resolution_msg = (
                    "Ensure that the Application ID provided in "
                    "the configuration parameters is correct."
                )
            elif "7000215" in text_response:
                err_msg = (
                    "Invalid Application Secret provided in "
                    "the configuration parameters."
                )
                resolution_msg = (
                    "Ensure that the Application Secret provided in "
                    "the configuration parameters is correct."
                )
            else:
                err_msg = (
                    "Invalid Tenant ID, "
                    "Application ID, or Application Secret provided "
                    "in the configuration parameters."
                )
                resolution_msg = (
                    "Ensure that the Tenant ID, "
                    "Application ID, or Application Secret "
                    "provided in the configuration parameters is correct."
                )

            if is_validation:
                err_msg = f"{VALIDATION_ERROR_MSG} {err_msg}"

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(auth_json),
                resolution=resolution_msg
            )
            raise MicrosoftDefenderPluginException(err_msg)

        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {auth_token}",
        }

    def _get_retry_after(self, headers: Dict) -> int:
        """Get the Retry-After wait time from response headers.

        Args:
            headers (Dict): Response headers dict.

        Returns:
            int: Seconds to wait before retrying. Falls back to
                DEFAULT_SLEEP_TIME if the header is absent.
        """
        return int(headers.get("Retry-After", DEFAULT_SLEEP_TIME))

    def get_configuration_parameters(
        self, configuration: Dict
    ) -> Tuple[str, str, str, str, str, List, List, str, str, int, int]:
        """Get configuration parameters from the configuration dictionary.

        Args:
            configuration (Dict): Configuration parameters dictionary.

        Returns:
            Tuple: Tuple of (base_url, tenant_id, app_id, app_secret,
                source, threat_data_type, actions_to_be_pulled,
                generate_alert, is_pull_required, retraction_interval,
                initial_range).
        """
        return (
            configuration.get("base_url", "").strip(),
            configuration.get("tenantid", "").strip(),
            configuration.get("appid", "").strip(),
            configuration.get("appsecret", ""),
            configuration.get("source", "").strip(),
            configuration.get("threat_data_type", []),
            configuration.get("actions_to_be_pulled", []),
            configuration.get("generate_alert", "Both"),
            configuration.get("is_pull_required", "Yes"),
            configuration.get("retraction_interval"),
            configuration.get("initial_range", 7),
        )

    def hash_string(self, string: str) -> str:
        """Hash the string using SHA-256.

        Args:
            string (str): String to hash.

        Returns:
            str: Hex-encoded SHA-256 digest.
        """
        return hashlib.sha256(string.encode()).hexdigest()

    def determine_ip_version(
        self, ip_address_str: str
    ) -> Union[Literal["IpAddressV4", "IpAddressV6"], None]:
        """Determine whether an IP string is IPv4 or IPv6.

        Args:
            ip_address_str (str): IP address string to classify.

        Returns:
            Union[Literal["IpAddressV4", "IpAddressV6"], None]:
                "IpAddressV4" or "IpAddressV6", or None if the value
                is not a valid IP address.
        """
        try:
            ip_obj = ip_address(ip_address_str)
            if isinstance(ip_obj, IPv4Address):
                return "IpAddressV4"
            elif isinstance(ip_obj, IPv6Address):
                return "IpAddressV6"
        except Exception:
            return None

    def parse_date_time(self, date_str: str) -> datetime:
        """Convert datetime string to datetime object.

        Args:
            date_str (str): Datetime string

        Returns:
            datetime: Datetime object
        """
        try:
            date_time_obj = parser.parse(date_str)
            return date_time_obj
        except Exception:
            return datetime.now(timezone.utc)

    def ioc_type_severity_conversion(
        self, is_sharing: bool = False
    ) -> Tuple[Dict, Dict]:
        """Return IOC type and severity conversion dicts.

        When is_sharing is False (pull), maps MDE type/severity strings to
        internal IndicatorType/SeverityType enums. When is_sharing is True
        (push), maps the inverse direction.

        Args:
            is_sharing (bool): True for push (internal → MDE), False for
                pull (MDE → internal). Defaults to False.

        Returns:
            Tuple[Dict, Dict]: (type_conversion, severity_conversion).
        """
        type_conversion = {
            "Url": IndicatorType.URL,
            "DomainName": getattr(IndicatorType, "DOMAIN", IndicatorType.URL),
            "IpAddressV4": getattr(IndicatorType, "IPV4", IndicatorType.URL),
            "IpAddressV6": getattr(IndicatorType, "IPV6", IndicatorType.URL),
            "FileMd5": IndicatorType.MD5,
            "FileSha256": IndicatorType.SHA256,
        }
        severity_conversion = {
            "Low": SeverityType.LOW,
            "Medium": SeverityType.MEDIUM,
            "High": SeverityType.HIGH,
            "Informational": SeverityType.UNKNOWN,
        }

        if is_sharing:
            type_conversion = {
                IndicatorType.URL: "Url",
                IndicatorType.HOSTNAME: "DomainName",
                IndicatorType.FQDN: "DomainName",
                IndicatorType.DOMAIN: "DomainName",
                IndicatorType.IPV4: "IpAddress",
                IndicatorType.IPV6: "IpAddress",
                IndicatorType.MD5: "FileMd5",
                IndicatorType.SHA256: "FileSha256",
            }
            severity_conversion = {
                SeverityType.LOW: "Low",
                SeverityType.MEDIUM: "Medium",
                SeverityType.HIGH: "High",
                SeverityType.CRITICAL: "High",
                SeverityType.UNKNOWN: "Informational",
            }

        return type_conversion, severity_conversion

    def check_url_domain_ip(self, value):
        """Categorize a URL value as IpAddress, DomainName, or Url.

        Args:
            value (str): Indicator value to categorize.

        Returns:
            str: One of "IpAddress", "DomainName", or "Url".
        """
        regex_domain = (
            "^((?!-)[A-Za-z0-9-]"
            "{1,63}(?<!-)\\.)+"
            "[A-Za-z]{2,6}"
        )
        try:
            ipaddress.ip_address(value)
            return "IpAddress"
        except Exception:
            if re.search(regex_domain, value):
                return "DomainName"
            else:
                return "Url"
