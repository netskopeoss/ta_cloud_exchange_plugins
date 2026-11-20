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

CTE VMRay plugin helper module.
"""

import json
import time
import traceback
from typing import Any, Dict, Tuple, Union
from urllib.parse import urlparse

import requests
from netskope.common.utils import add_user_agent
from netskope.integrations.cte.models import IndicatorType

try:
    from netskope.integrations.cte.models.business_rule import SeverityType
except ImportError:
    from netskope.integrations.cte.models import SeverityType

from .constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    NO_MORE_RETRIES_ERROR_MSG,
    PLATFORM_NAME,
    RETRACTION,
    RETRY_ERROR_MSG,
)
from .exception import VMRayPluginException

# Maps IndicatorType to a short pull-stats key
IOC_TYPE_PULL_LABEL = {
    IndicatorType.DOMAIN: "domain",
    IndicatorType.FQDN: "fqdn",
    IndicatorType.URL: "url",
    IndicatorType.IPV4: "ipv4",
    IndicatorType.MD5: "md5",
    IndicatorType.SHA256: "sha256",
}

# IOC type mapping from VMRay type to CE IndicatorType.
# "ip"   is the key used by the VMRay API ip_address field handler.
# "ipv4" is the key returned by determine_ioc_type() for IPv4 values.
# Both map to IndicatorType.IPV4 so either source works correctly.
VMRAY_IOC_TYPE_MAP = {
    "domain": IndicatorType.DOMAIN,
    "fqdn": IndicatorType.FQDN,
    "ip": IndicatorType.IPV4,
    "ipv4": IndicatorType.IPV4,
    "ipv6": IndicatorType.IPV6,
    "url": IndicatorType.URL,
    "file_md5": IndicatorType.MD5,
    "file_sha256": IndicatorType.SHA256,
}

# numeric_severity (0-5) -> SeverityType enum
NUMERIC_SEVERITY_MAP = {
    0: SeverityType.UNKNOWN,
    1: SeverityType.LOW,
    2: SeverityType.LOW,
    3: SeverityType.MEDIUM,
    4: SeverityType.HIGH,
    5: SeverityType.CRITICAL,
}


class VMRayPluginHelper(object):
    """VMRayPluginHelper class.

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
        """VMRayPluginHelper initializer.

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

    def _add_user_agent(
        self, headers: Union[Dict, None] = None
    ) -> Dict:
        """Add User-Agent header for third-party requests.

        Args:
            headers (Dict, optional): Existing headers dict.

        Returns:
            Dict: Headers dict with User-Agent set.
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

    def _get_headers(self, api_token: str) -> Dict:
        """Build request headers with API key authorization.

        Args:
            api_token (str): VMRay API token.

        Returns:
            Dict: Headers with Authorization and Content-Type.
        """
        return {
            "Authorization": f"api_key {api_token}",
            "Content-Type": "application/json",
        }

    def build_url(self, endpoint: str, base_url: str) -> str:
        """Construct a full URL from base URL and endpoint path.

        Args:
            endpoint (str): API endpoint path.
            base_url (str): Base URL of the VMRay instance.

        Returns:
            str: Full URL string.
        """
        return f"{base_url.rstrip('/')}{endpoint}"

    def get_configuration_parameters(
        self, configuration: Dict
    ) -> Tuple[str, str, list, list, str, str]:
        """Extract all VMRay plugin configuration parameters.

        Args:
            configuration (Dict): Plugin configuration dict.

        Returns:
            Tuple: (base_url, api_token, sample_verdicts, ioc_types,
                    is_pull_required, enable_push_retraction)
        """
        base_url = (
            configuration.get("base_url", "").strip().rstrip("/")
        )
        api_token = configuration.get("api_token", "")
        sample_verdicts = configuration.get(
            "sample_verdicts", ["malicious", "suspicious"]
        )
        ioc_types = configuration.get(
            "ioc_types", ["domains", "ipv4", "urls", "md5", "sha256"]
        )
        is_pull_required = (
            configuration.get("is_pull_required", "Yes").strip()
        )
        enable_push_retraction = (
            configuration.get(
                "enable_push_retraction", "No"
            ).strip()
        )
        return (
            base_url,
            api_token,
            sample_verdicts,
            ioc_types,
            is_pull_required,
            enable_push_retraction,
        )

    def validate_url(self, url: str) -> bool:
        """Validate that a URL has a scheme and netloc.

        Args:
            url (str): URL string to validate.

        Returns:
            bool: True if valid URL; False otherwise.
        """
        parsed = urlparse(url)
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
        )

    def _get_retry_after(self, headers) -> int:
        """Return the retry wait time from Retry-After header or default.

        Args:
            headers: Response headers object.

        Returns:
            int: Seconds to wait before the next retry.
        """
        try:
            return int(headers.get("Retry-After", DEFAULT_WAIT_TIME))
        except (TypeError, ValueError):
            return DEFAULT_WAIT_TIME

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str = "GET",
        params: Dict = None,
        data=None,
        headers: Dict = None,
        json_data=None,
        proxy: Any = None,
        verify: Any = None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        is_retraction: bool = False,
    ):
        """Execute an HTTP request with retry and error handling.

        Args:
            logger_msg (str): Context message for log output.
            url (str): Full request URL.
            method (str): HTTP method. Defaults to "GET".
            params (Dict): Query parameters.
            data: Request body for non-JSON payloads.
            headers (Dict): Request headers.
            json_data: JSON payload.
            proxy: Proxy configuration.
            verify: SSL verification flag or path.
            is_handle_error_required (bool): Apply response error
                handling when True. Defaults to True.
            is_validation (bool): Tune error messages for validation
                flows. Defaults to False.
            is_retraction (bool): Append retraction tag to log prefix
                when True. Defaults to False.

        Returns:
            Union[dict, requests.Response]: Parsed JSON on success, or
                raw Response when is_handle_error_required is False.

        Raises:
            VMRayPluginException: On HTTP, connectivity, or unexpected
                errors after exhausting retries.
        """
        try:
            if is_retraction and RETRACTION not in self.log_prefix:
                self.log_prefix = (
                    self.log_prefix + f" {RETRACTION}"
                )
            if headers is None:
                headers = {}
            headers = self._add_user_agent(headers)

            self.logger.debug(
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" Endpoint: {method} {url}"
                f", params: {params}"
            )

            for retry_count in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=verify,
                    proxies=proxy,
                    json=json_data,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for"
                    f" {logger_msg}. Status Code={status_code}."
                )

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
                            ),
                            resolution=(
                                f"Ensure that the {PLATFORM_NAME} platform is"
                                " reachable and the API rate limit is not "
                                "exceeded."
                            ),
                        )
                        raise VMRayPluginException(err_msg)

                    if status_code == 429:
                        error_reason = "API rate limit exceeded"
                    else:
                        error_reason = "HTTP server error occurred"

                    retry_after = DEFAULT_WAIT_TIME
                    try:
                        retry_after = self._get_retry_after(
                            response.headers
                        )
                    except Exception:
                        pass

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
                        resolution=(
                            f"Ensure that the {PLATFORM_NAME} platform is"
                            " reachable."
                        ),
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
        except VMRayPluginException:
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
                    f"Ensure that the {PLATFORM_NAME} platform"
                    " server is reachable."
                ),
            )
            raise VMRayPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}."
                " Verify the proxy configuration provided."
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
                    "Ensure that the proxy configuration provided"
                    " is correct and the proxy server is reachable."
                ),
            )
            raise VMRayPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with"
                f" {PLATFORM_NAME} platform while {logger_msg}."
                f" Proxy server or {PLATFORM_NAME} server is not"
                " reachable."
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
                    f"Ensure that the {PLATFORM_NAME} platform"
                    " server is reachable."
                ),
            )
            raise VMRayPluginException(err_msg)
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
                    "Ensure that the configuration parameters"
                    " provided are correct."
                ),
            )
            raise VMRayPluginException(err_msg)
        except Exception as error:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    "Unexpected error while performing API call"
                    f" to {PLATFORM_NAME}."
                )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} Error: {error}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the configuration parameters"
                    " provided are correct."
                ),
            )
            raise VMRayPluginException(err_msg)

    def handle_push_error(
        self,
        response,
        indicator_value: str,
        logger_msg: str,
    ) -> bool:
        """Check a push/submit response and log an error if it failed.

        Args:
            response: Raw HTTP response from the submit call.
            indicator_value (str): Indicator value for log context.
            logger_msg (str): Context message for log output.

        Returns:
            bool: True if status is 200/201; False otherwise.
        """
        status_code = response.status_code
        if status_code not in [200, 201]:
            try:
                error_body = response.json()
                error_msg = error_body.get(
                    "error_msg", f"HTTP {status_code}"
                )
            except Exception:
                error_msg = f"HTTP {status_code}"
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Failed to push"
                    f" '{indicator_value}' to {PLATFORM_NAME}."
                    f" Error: {error_msg}"
                ),
                resolution=(
                    f"Verify that the indicator value is"
                    f" valid and supported by {PLATFORM_NAME}."
                ),
            )
            return False
        return True

    def handle_delete_response(
        self,
        response,
        submission_id: int,
        log_prefix: str,
    ) -> bool:
        """Check a delete response and log an error if it failed.

        Args:
            response: Raw HTTP response from the delete call.
            submission_id (int): Submission ID for log context.
            log_prefix (str): Log prefix to use in messages.

        Returns:
            bool: True if status is 200; False otherwise.
        """
        status_code = response.status_code
        if status_code != 200:
            self.logger.error(
                message=(
                    f"{log_prefix}: Failed to delete"
                    f" submission {submission_id}."
                    f" Status: {status_code}."
                ),
                details=f"API response: {response.text}",
                resolution=(
                    f"Ensure the API Token has delete"
                    f" permissions on the {PLATFORM_NAME}"
                    " platform."
                ),
            )
            return False
        return True

    def parse_response(
        self,
        response: requests.models.Response,
        is_validation: bool = False,
        logger_msg: str = None,
    ):
        """Parse JSON from a requests Response object.

        Args:
            response: HTTP response object.
            is_validation (bool): Tune error messages for validation.
            logger_msg (str): Context for log messages.

        Returns:
            Any: Parsed JSON content.

        Raises:
            VMRayPluginException: If JSON parsing fails.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                f"Invalid JSON response received from API while"
                f" {logger_msg}. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=(
                    "Verify the Base URL provided in the"
                    " configuration parameters."
                ),
            )
            if is_validation:
                err_msg = (
                    "Verify Base URL provided in the configuration"
                    " parameters. Check logs for more details."
                )
            raise VMRayPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing JSON"
                f" response for {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution="Check logs for more details.",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred. Verify"
                    " Base URL in the configuration parameters."
                    " Check logs for more details."
                )
            raise VMRayPluginException(err_msg)

    def handle_error(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ):
        """Handle HTTP status codes and return parsed responses.

        Args:
            response: HTTP response object.
            logger_msg (str): Context for log messages.
            is_validation (bool): Tune messages for validation flows.

        Returns:
            dict: Parsed JSON for 2xx responses; empty dict for 204.

        Raises:
            VMRayPluginException: For 4xx/5xx errors.
        """
        status_code = response.status_code
        validation_msg = "Validation error occurred, "

        error_dict = {
            400: "Received exit code 400, HTTP client error",
            401: "Received exit code 401, Unauthorized access",
            403: "Received exit code 403, Forbidden",
            404: "Received exit code 404, Resource not found",
        }
        resolution_dict = {
            400: (
                "Verify the Base URL and API Token provided in"
                " the configuration parameters."
            ),
            401: (
                "Verify the API Token provided in the"
                " configuration parameters."
            ),
            403: (
                "Verify the permissions associated with the API"
                " Token provided in the configuration parameters."
            ),
            404: (
                "Verify the resource you are trying to access"
                " is valid."
            ),
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request. Verify"
                    " the Base URL and API Token provided in the"
                    " configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized. Verify"
                    " the API Token provided in the configuration"
                    " parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden. Verify the"
                    " permissions associated with the API Token."
                ),
                404: (
                    "Received exit code 404, Resource not found."
                    " Verify the Base URL provided in the"
                    " configuration parameters."
                ),
            }

        def _log_and_raise(resolution: str = None):
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
                raise VMRayPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg}"
                    ),
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise VMRayPluginException(err_msg)

        if status_code in [200, 201, 202]:
            return self.parse_response(
                response=response,
                is_validation=is_validation,
                logger_msg=logger_msg,
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            resolution_msg = resolution_dict.get(status_code)
            _log_and_raise(resolution=resolution_msg)
        elif 400 <= status_code < 500:
            err_msg = "HTTP Client Error"
            _log_and_raise()
        elif 500 <= status_code < 600:
            err_msg = "HTTP Server Error"
            _log_and_raise()
        else:
            err_msg = "HTTP Error"
            _log_and_raise()
