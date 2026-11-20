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

SentinelOne Singularity Data Lake CLS plugin helper.
"""

import json
import math
import time
import traceback
from typing import Any, Dict, Optional, Union

import requests
from netskope.common.utils import add_user_agent

from .constants import (
    HTTP_STATUS_REASONS,
    MAX_RETRIES,
    MAX_WAIT_TIME,
    RETRY_SLEEP_TIME,
    MODULE_NAME,
    PLATFORM_NAME,
)
from .exceptions import (
    SentinelOneSDLPayloadTooLargeError,
    SentinelOneSDLPluginException,
)
from .utilities import is_soft_time_limit

# Extra advice shown in validate() for each HTTP status.
VALIDATION_HINTS = {
    400: (
        "Make sure the key is a Log Access Write Key. Other key types need"
        " an S1-Scope header that this plugin does not send."
    ),
    401: "The Log Access Write Key is invalid.",
    403: "The Log Access Write Key does not have permission to write logs.",
    404: "Check the HEC Base URL in the configuration parameters.",
    413: "The test log was too large. This should not happen.",
    429: "The rate limit was reached. Try again in a few minutes.",
}

# What the user should do for each HTTP status.
RESOLUTIONS = {
    400: (
        "Use a Log Access Write Key. Generate it in Singularity Data Lake"
        " under API Keys > Log Access Key > Add Write Key."
    ),
    401: (
        "Check the Log Access Write Key in the configuration parameters, or"
        " generate a new one."
    ),
    403: (
        "Generate a new Log Access Write Key with write access and update"
        " the configuration."
    ),
    404: (
        "Use the HEC Base URL of your datacenter, for example"
        " https://ingest.us1.sentinelone.net, with no path."
    ),
    413: "Check the source data for logs with very large fields.",
    429: "Wait a few minutes and try again.",
}


class SentinelOneSDLPluginHelper:
    """Makes every HTTP call the plugin needs.

    Retries, status code handling and error logging live here, so they
    are written once.
    """

    def __init__(
        self,
        logger: Any,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """Store the logging and plugin details.

        Args:
            logger (Any): Cloud Exchange logger.
            log_prefix (str): Prefix put in front of every log message.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add the Cloud Exchange User-Agent to the request headers.

        Produces, for example:
        netskope-ce-7.0.0-cls-sentinelone-singularity-data-lake-1.0.0

        Args:
            headers (Dict): Headers for the request.

        Returns:
            Dict: Headers with a User-Agent added.
        """
        if headers and "User-Agent" in headers:
            return headers

        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    @staticmethod
    def _get_response_text(response: requests.models.Response) -> str:
        """Read the "text" field HEC puts in its JSON answers.

        HEC answers like {"text": "Missing S1-Scope header", "code": 5}.

        Args:
            response (Response): Response object.

        Returns:
            str: The "text" value, or an empty string.
        """
        try:
            body = response.json()
        except Exception as exp:
            if is_soft_time_limit(exp):
                raise
            return ""
        if isinstance(body, dict) and body.get("text"):
            return str(body["text"])
        return ""

    @staticmethod
    def _describe_status(status_code: int) -> str:
        """Describe an HTTP status in plain words.

        Args:
            status_code (int): HTTP status.

        Returns:
            str: For example "HTTP status 401 (Unauthorized)".
        """
        reason = HTTP_STATUS_REASONS.get(status_code)
        if not reason:
            reason = (
                "Server error"
                if 500 <= status_code < 600
                else "Client error"
            )
        return f"HTTP status {status_code} ({reason})"

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Any:
        """Read the JSON body of a response.

        Args:
            response (Response): Response object.
            logger_msg (str): What the plugin was doing.
            is_validation (bool): True when called from validate().

        Returns:
            Any: Parsed JSON body.

        Raises:
            SentinelOneSDLPluginException: If the body is not valid JSON.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                f"Could not read the response from {PLATFORM_NAME} while"
                f" {logger_msg}. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=(
                    "Check that the HEC Base URL points to a Singularity"
                    " Data Lake ingest host, for example"
                    " https://ingest.us1.sentinelone.net."
                ),
            )
            if is_validation:
                err_msg = (
                    f"Could not read the response from {PLATFORM_NAME}."
                    " Check the HEC Base URL in the configuration"
                    " parameters."
                )
            raise SentinelOneSDLPluginException(err_msg)
        except Exception as exp:
            # Celery raises SoftTimeLimitExceeded once, wherever the
            # task happens to be. Cloud Exchange needs that exact type
            # to reschedule the run; wrapping it means the worker is
            # killed at the hard limit and the logs in flight are lost.
            if is_soft_time_limit(exp):
                raise
            err_msg = (
                f"Unexpected error while reading the response from"
                f" {PLATFORM_NAME} while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
                resolution="Check the logs for the full error and retry.",
            )
            if is_validation:
                err_msg = (
                    f"Unexpected error while reading the response from"
                    f" {PLATFORM_NAME}. Check logs for more details."
                )
            raise SentinelOneSDLPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Any:
        """Turn an HTTP status code into a result or an exception.

        Args:
            resp (Response): Response object.
            logger_msg (str): What the plugin was doing.
            is_validation (bool): True when called from validate().

        Returns:
            Any: Parsed body for 200/201/202, {} for 204.

        Raises:
            SentinelOneSDLPayloadTooLargeError: On 413.
            SentinelOneSDLPluginException: On any other error status.
        """
        status_code = resp.status_code
        if status_code in (200, 201, 202):
            return self.parse_response(
                response=resp,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        if status_code == 204:
            return {}

        status = self._describe_status(status_code)
        hec_text = self._get_response_text(resp)
        said = f" It said: '{hec_text}'." if hec_text else ""
        if is_validation:
            hint = VALIDATION_HINTS.get(status_code)
            if not hint:
                hint = (
                    "Try again later."
                    if 500 <= status_code < 600
                    else "Check the configuration parameters."
                )
            err_msg = f"{PLATFORM_NAME} returned {status}. {hint}{said}"
        else:
            err_msg = (
                f"{PLATFORM_NAME} returned {status} while {logger_msg}."
                f"{said}"
            )

        if status_code == 413 and not is_validation:
            # push() splits the batch and sends it again. It logs what
            # happens, so nothing is logged here.
            raise SentinelOneSDLPayloadTooLargeError(err_msg, status_code)

        resolution = RESOLUTIONS.get(status_code)
        if not resolution:
            resolution = (
                f"Check the {PLATFORM_NAME} service status and try again."
                if 500 <= status_code < 600
                else "Check the configuration parameters and try again."
            )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=f"API response: {resp.text}",
            resolution=resolution,
        )
        if status_code == 413:
            raise SentinelOneSDLPayloadTooLargeError(err_msg, status_code)
        raise SentinelOneSDLPluginException(err_msg, status_code)

    def _get_retry_wait_time(
        self, response: requests.models.Response, logger_msg: str
    ) -> int:
        """Work out how long to wait before the next retry.

        What the server asks for comes first. Without a usable
        Retry-After the wait is a flat RETRY_SLEEP_TIME.

        A Retry-After above MAX_WAIT_TIME is not waited out. Holding a
        Celery worker that long risks the task's soft time limit, and
        retrying sooner than the server asked would most likely earn
        another rejection and use up an attempt. The push is handed
        back to Cloud Exchange instead.

        A Retry-After sent as an absolute epoch, which is not what the
        standard defines, is far above the limit and so lands in that
        same branch. That is safe: Cloud Exchange retries the push, and
        the error message names the value that caused it.

        Args:
            response (Response): Response object.
            logger_msg (str): What the plugin was doing, for logs.

        Returns:
            int: Seconds to wait.

        Raises:
            SentinelOneSDLPluginException: If the server asks for
                longer than MAX_WAIT_TIME.
        """
        retry_after = response.headers.get("Retry-After")
        if retry_after is None:
            return RETRY_SLEEP_TIME
        try:
            seconds = float(retry_after)
        except (TypeError, ValueError):
            # Retry-After can also be an HTTP date. It is not parsed.
            return RETRY_SLEEP_TIME
        if not math.isfinite(seconds) or seconds < 0:
            return RETRY_SLEEP_TIME
        if seconds > MAX_WAIT_TIME:
            err_msg = (
                f"{PLATFORM_NAME} asked to wait {int(seconds)} seconds"
                f" while {logger_msg}. That is longer than the"
                f" {MAX_WAIT_TIME} second limit, so the logs were not"
                " sent."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=(
                    "Cloud Exchange will retry this push. If it keeps"
                    f" happening, check the {PLATFORM_NAME} service"
                    " status and the volume being sent."
                ),
            )
            raise SentinelOneSDLPluginException(
                err_msg, response.status_code
            )
        return int(seconds)

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str,
        params: Optional[Dict] = None,
        data: Any = None,
        headers: Optional[Dict] = None,
        json_body: Any = None,
        verify: bool = True,
        proxies: Optional[Dict] = None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        show_data: bool = False,
    ) -> Any:
        """Make an API call. Retry on rate limits and server errors.

        Args:
            logger_msg (str): What the plugin is doing.
            url (str): Endpoint to call.
            method (str): HTTP method.
            params (Optional[Dict]): Query parameters.
            data (Any): Request body.
            headers (Optional[Dict]): Request headers.
            json_body (Any): JSON body, used instead of data.
            verify (bool): Verify the TLS certificate.
            proxies (Optional[Dict]): Proxy settings.
            is_handle_error_required (bool): Pass the response through
                handle_error() instead of returning it as it is.
            is_validation (bool): True when called from validate(). No
                retries, so the user is not kept waiting.
            show_data (bool): Write the request body to the debug log.
                Off by default so log data never ends up in the logs.

        Returns:
            Any: Parsed body, or the raw Response when
                is_handle_error_required is False.

        Raises:
            SentinelOneSDLPayloadTooLargeError: On 413.
            SentinelOneSDLPluginException: On any other failure.
        """
        try:
            headers = self._add_user_agent(headers)

            debug_msg = (
                f"API request for {logger_msg}. Endpoint: {method} {url}"
            )
            if params:
                debug_msg += f", API params: {params}"
            if data and show_data:
                debug_msg += f", API data: {data}"
            if json_body and show_data:
                debug_msg += f", API json body: {json_body}"
            self.logger.debug(f"{self.log_prefix}: {debug_msg}")

            for retry_counter in range(MAX_RETRIES):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    json=json_body,
                    verify=verify,
                    proxies=proxies,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API response for"
                    f" {logger_msg}. Status code: {status_code}."
                )

                is_retryable = status_code == 429 or (
                    500 <= status_code < 600
                )
                if is_retryable and not is_validation:
                    status = self._describe_status(status_code)
                    if retry_counter == MAX_RETRIES - 1:
                        err_msg = (
                            f"{PLATFORM_NAME} returned {status} while"
                            f" {logger_msg}. Gave up after"
                            f" {MAX_RETRIES} attempts."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"API response: {response.text}",
                            resolution=(
                                f"Check the {PLATFORM_NAME} service"
                                " status. Cloud Exchange will retry this"
                                " push."
                            ),
                        )
                        raise SentinelOneSDLPluginException(
                            err_msg, status_code
                        )

                    wait_time = self._get_retry_wait_time(
                        response, logger_msg
                    )
                    tries_left = MAX_RETRIES - 1 - retry_counter
                    seconds = "second" if wait_time == 1 else "seconds"
                    tries = "try" if tries_left == 1 else "tries"
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {PLATFORM_NAME} returned"
                            f" {status} while {logger_msg}. Trying again"
                            f" in {wait_time} {seconds}. {tries_left}"
                            f" {tries} left."
                        ),
                        details=f"API response: {response.text}",
                    )
                    time.sleep(wait_time)
                    continue

                return (
                    self.handle_error(response, logger_msg, is_validation)
                    if is_handle_error_required
                    else response
                )

            # Not reached while MAX_RETRIES is at least 1: the last
            # attempt always returns or raises. Kept so this method never
            # returns None.
            raise SentinelOneSDLPluginException(
                f"No request was made while {logger_msg}."
            )
        except SentinelOneSDLPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Request timed out while {logger_msg}."
            if is_validation:
                err_msg = (
                    f"Request to {PLATFORM_NAME} timed out. Check the HEC"
                    " Base URL in the configuration parameters."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    f"Check the network connection to {PLATFORM_NAME}"
                    " and try again."
                ),
            )
            raise SentinelOneSDLPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error while {logger_msg}. Check the proxy"
                " settings."
            )
            if is_validation:
                err_msg = "Proxy error occurred. Check the proxy settings."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution="Check the proxy settings in Cloud Exchange.",
            )
            raise SentinelOneSDLPluginException(err_msg)
        except requests.exceptions.SSLError as error:
            # SSLError is a kind of ConnectionError. It gets its own
            # message so a certificate problem is not reported as "cannot
            # reach the host".
            err_msg = (
                f"The TLS certificate check failed while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    f"The TLS certificate of {PLATFORM_NAME} could not be"
                    " verified."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "If a proxy inspects TLS traffic, add its CA"
                    " certificate to Cloud Exchange. Otherwise check the"
                    " HEC Base URL."
                ),
            )
            raise SentinelOneSDLPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Could not connect to {PLATFORM_NAME} while"
                f" {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    f"Cloud Exchange cannot reach {PLATFORM_NAME}. Check"
                    " the HEC Base URL, network, proxy and firewall."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Check the HEC Base URL, and make sure Cloud Exchange"
                    f" can reach {PLATFORM_NAME} through the network,"
                    " proxy and firewall."
                ),
            )
            raise SentinelOneSDLPluginException(err_msg)
        except requests.HTTPError as error:
            err_msg = f"HTTP error while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Check the configuration"
                    " parameters."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution="Check the configuration parameters.",
            )
            raise SentinelOneSDLPluginException(err_msg)
        except Exception as exp:
            # Celery raises SoftTimeLimitExceeded once, wherever the
            # task happens to be. Cloud Exchange needs that exact type
            # to reschedule the run; wrapping it means the worker is
            # killed at the hard limit and the logs in flight are lost.
            if is_soft_time_limit(exp):
                raise
            err_msg = f"Unexpected error while {logger_msg}."
            if is_validation:
                err_msg = (
                    f"Unexpected error while calling {PLATFORM_NAME}."
                    " Check logs for more details."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
                resolution="Check the logs for the full error and retry.",
            )
            raise SentinelOneSDLPluginException(err_msg)
