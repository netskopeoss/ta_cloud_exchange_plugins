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

CrowdStrike Next-Gen SIEM Helper.
"""

import json
import time
import traceback
from enum import Enum
from typing import Dict, Union

import requests
from netskope.common.utils import add_user_agent

from .constant import (
    DEFAULT_WAIT_TIME,
    MAX_RETRY_AFTER_IN_MIN,
    MAX_RETRY_COUNT,
    MAX_WAIT_TIME,
    MODULE_NAME,
    PLATFORM_NAME,
)
from .exception import CrowdStrikeNGSIEMException


class DataTypes(Enum):
    """Data Type Class."""

    ALERT = "alerts"
    EVENT = "events"


class CrowdStrikeNGSIEMPluginHelper:
    """CrowdStrike Next-Gen SIEM Helper Class."""

    def __init__(
        self,
        logger,
        log_prefix,
        plugin_name,
        plugin_version,
    ):
        """Initialize CrowdStrike Next-Gen SIEM Client Class.

        Args:
            logger (Logger): Logger object.
            log_prefix (str): Logger prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers for third-party requests.
        Args:
            headers (Dict): Dictionary containing headers for any request.
        Returns:
            Dict: Dictionary after adding User-Agent.
        """
        if headers and "User-Agent" in headers:
            return headers

        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}/{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg,
        is_validation: bool = False,
    ):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.
            logger_msg (str): Logger message.
            is_validation (bool): Is validation required.
        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received "
                f"from API while {logger_msg}. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify API URL and API Token provided in "
                    "the configuration parameters. Check logs for more"
                    " details."
                )
            raise CrowdStrikeNGSIEMException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing "
                f"json response for {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, Verify "
                    "API URL and API Token provided in the"
                    " configuration parameters. Check logs for more details."
                )
            raise CrowdStrikeNGSIEMException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object
            returned from API call.
            logger_msg: logger message.
            is_validation : API call from validation method or not
        Returns:
            dict: Returns the dictionary of response JSON
            when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        status_code = resp.status_code
        validation_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, HTTP client error",
            403: "Received exit code 403, Forbidden",
            401: "Received exit code 401, Unauthorized access",
            404: "Received exit code 404, Resource not found",
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request, Verify the "
                    " API URL and API Token provided in the"
                    " configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, Verify "
                    "API Token provided in the "
                    "configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, Verify API scopes "
                    " provided to Token."
                ),
                404: (
                    "Received exit code 404, Resource not found, Verify "
                    "API URL provided in the configuration parameters."
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
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise CrowdStrikeNGSIEMException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise CrowdStrikeNGSIEMException(err_msg)

        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{validation_msg+err_msg} while {logger_msg}."
                ),
                details=f"API response: {resp.text}",
            )
            raise CrowdStrikeNGSIEMException(err_msg)

    def api_helper(
        self,
        logger_msg: str,
        url,
        method,
        params=None,
        data=None,
        headers=None,
        json=None,
        verify=True,
        proxies=None,
        is_handle_error_required=True,
        is_validation=False,
        show_data=True,
    ):
        """API helper to perform API request on ThirdParty platform
         and captures all the possible errors for requests.

        Args:
            logger_msg (str): Logger message.
            url (str): API Endpoint.
            method (str): Method for the endpoint.
            params (Dict, optional): Request parameters dictionary.
            Defaults to None.
            data (Any,optional): Data to be sent to API. Defaults to None.
            headers (Dict, optional): Headers for the request. Defaults to {}.
            json (optional): Json payload for request. Defaults to None.
            verify (bool, optional): Verify SSL. Defaults to True.
            proxies (Dict, optional): Proxies. Defaults to None.
            is_handle_error_required (bool, optional): Does the API helper
            should handle the status codes. Defaults to True.
            is_validation (bool, optional): Does this request coming from
            validate method?. Defaults to False.
            show_data (bool): Does the API helper show the data.
            Defaults to True.

        Returns:
            dict: Response dictionary.
        """
        try:
            headers = self._add_user_agent(headers)

            debug_msg = f"API request for {logger_msg}. Endpoint: {url}"
            if params:
                debug_msg += f", API params: {params}"
            if data and show_data:
                debug_msg += f", API data: {data}"
            if json and show_data:
                debug_msg += f", API json body: {json}"
            self.logger.debug(f"{self.log_prefix}: {debug_msg}")

            for retry_counter in range(MAX_RETRY_COUNT):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                    json=json,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API response for "
                    f"{logger_msg}. Status Code={status_code}."
                )

                if (
                    (status_code >= 500 and status_code <= 600)
                    or status_code == 429
                    and not is_validation
                ):
                    if retry_counter == MAX_RETRY_COUNT - 1:
                        err_msg = (
                            f"Received exit code {status_code}, while"
                            f" {logger_msg}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            f" code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=str(response.text),
                        )
                        raise CrowdStrikeNGSIEMException(err_msg)
                    retry_after = response.headers.get("Retry-After")
                    if retry_after is None:
                        self.logger.info(
                            "{}: No Retry-After value received from "
                            "API, hence plugin will retry after 60 "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                MAX_RETRY_COUNT - 1 - retry_counter,
                            )
                        )
                        time.sleep(DEFAULT_WAIT_TIME)
                        continue
                    retry_after = int(retry_after)
                    diff_retry_after = abs(retry_after - time.time())
                    if diff_retry_after > MAX_WAIT_TIME:
                        err_msg = (
                            "'Retry-After' value received from "
                            f"response headers while {logger_msg} is greater "
                            f" than {MAX_RETRY_AFTER_IN_MIN} minutes hence "
                            f"returning status code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}"
                        )
                        raise CrowdStrikeNGSIEMException(err_msg)

                    log_msg = (
                        f"{self.log_prefix}: Received response code "
                        f"{status_code}, "
                    )
                    if status_code == 429:
                        log_msg += (
                            f"API Rate Limit Exceeded while {logger_msg}."
                        )
                    else:
                        log_msg += (
                            f"HTTP server error occurred while {logger_msg}."
                        )
                    log_msg += (
                        f" Retrying after {retry_after} seconds. "
                        f"{MAX_RETRY_COUNT - 1 - retry_counter} "
                        "retries remaining."
                    )
                    self.logger.error(
                        message=log_msg,
                        details=f"API response: {response.text}",
                    )
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )
        except CrowdStrikeNGSIEMException as exp:
            raise CrowdStrikeNGSIEMException(exp)
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Read Timeout error occurred. "
                    "Verify the 'API URL' provided in the "
                    "configuration parameters."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise CrowdStrikeNGSIEMException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the "
                "proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify "
                    "the proxy configuration provided."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise CrowdStrikeNGSIEMException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    f"platform. Proxy server or {PLATFORM_NAME} "
                    "server is not reachable."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise CrowdStrikeNGSIEMException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify "
                    "configuration parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise CrowdStrikeNGSIEMException(err_msg)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing "
                    f"API call to {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                raise CrowdStrikeNGSIEMException(err_msg)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise CrowdStrikeNGSIEMException(err_msg)
