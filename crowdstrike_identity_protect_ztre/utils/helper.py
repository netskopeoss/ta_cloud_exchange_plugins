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

CRE CrowdStrike plugin helper module.
"""

import time
import traceback
from typing import Dict, Tuple, Union

import requests
from netskope.common.utils import add_user_agent

from ..lib.falconpy import IdentityProtection
from .constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    PLATFORM_NAME,
)


class CrowdStrikeIdentityProtectException(Exception):
    """CrowdStrikeIdentityProtectException exception class."""

    pass


class CrowdStrikeIdentityProtectPluginHelper(object):
    """CrowdStrikePluginHelper Class.

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
        """CrowdStrikePluginHelper initializer.

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
        return user_agent

    def api_helper(
        self,
        falcon: IdentityProtection,
        query: str,
        variables: Dict,
        logger_msg: str,
        is_validation: bool = False,
        is_handle_error_required=True,
        show_query: bool = True,
        show_variables: bool = True,
    ) -> Dict:
        """API Call Helper method.

        Args:
            falcon (IdentityProtection): Falcon Object.
            query (str): Query String.
            variables (Dict): Query Variables.
        """
        try:
            debug_log_msg = f"{self.log_prefix}: API Request for {logger_msg}."
            if query and show_query:
                debug_log_msg += f" Query: {query}"
            if variables and show_variables:
                debug_log_msg += f", Variables: {variables}"

            self.logger.debug(debug_log_msg)
            for retry_counter in range(MAX_API_CALLS):
                response = falcon.api_preempt_proxy_post_graphql(
                    query=query, variables=variables
                )
                status_code = response.get("status_code")
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )
                if status_code == 429 or 500 <= status_code <= 600:
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}, While"
                            f" {logger_msg}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            f" code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"API response: {response}",
                        )
                        raise CrowdStrikeIdentityProtectException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, While"
                            " {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                status_code,
                                logger_msg,
                                DEFAULT_WAIT_TIME,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=f"API response: {response}",
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )

            return response
        except CrowdStrikeIdentityProtectException:
            raise
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the"
                " proxy configuration provided."
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
            raise CrowdStrikeIdentityProtectException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    f"platform. Proxy server or {PLATFORM_NAME}"
                    " server is not reachable."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise CrowdStrikeIdentityProtectException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify"
                    " configuration parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise CrowdStrikeIdentityProtectException(err_msg)
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
                raise CrowdStrikeIdentityProtectException(
                    f"{err_msg} Check logs for more details."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise CrowdStrikeIdentityProtectException(err_msg)

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
        status_code = resp.get("status_code")
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
                    " Base URL, Client ID and Client Secret provided in the"
                    " configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, Verify "
                    "Client ID and Client Secret provided in the "
                    "configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, Verify API scopes "
                    " provided to Client ID and Client Secret."
                ),
                404: (
                    "Received exit code 404, Resource not found, Verify "
                    "Base URL provided in the configuration parameters."
                ),
            }
        if status_code == 200:
            return resp.get("body", {})
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp}",
                )
                raise CrowdStrikeIdentityProtectException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp}",
                )
                raise CrowdStrikeIdentityProtectException(err_msg)
        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Received exit "
                        f"code {status_code}, {log_err_msg}"
                    ),
                    details=f"API response: {resp}",
                )
                raise CrowdStrikeIdentityProtectException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Received exit "
                        f"code {status_code}, {log_err_msg}"
                    ),
                    details=f"API response: {resp}",
                )
                raise CrowdStrikeIdentityProtectException(err_msg)

    def get_credentials(self, configuration: Dict) -> Tuple:
        """Get API Credentials.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            Tuple: Tuple containing Base URL, Client ID and Client Secret.
        """
        return (
            configuration.get("base_url", "").strip().strip("/"),
            configuration.get("client_id", "").strip(),
            configuration.get("client_secret"),
        )

    def get_falcon(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        proxy,
        ssl_validation,
        logger_msg,
    ) -> IdentityProtection:
        """Get Falcon Identity protection object to perform operations.

        Args:
            base_url (str): Base URL for CrowdStrike.
            client_id (str): Client ID.
            client_secret (str): Client Secret.

        Returns:
            IdentityProtection: IdentityProtection object.
        """
        try:
            return IdentityProtection(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
                proxy=proxy,
                ssl_verify=ssl_validation,
                user_agent=self._add_user_agent(),
            )
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while "
                    "creating Identity Protection client object"
                    f" for {logger_msg}."
                ),
                details=str(exp),
            )
            raise CrowdStrikeIdentityProtectException(exp)

    def normalize_risk_score(self, risk_score: int) -> int:
        """Normalize Risk score from CrowdStrike IP to Netskope Range.

        Args:
            risk_score (int): Risk score in range of CrowdStrike IP.

        Returns:
            int: Normalized risk score as per Netskope range.
        """
        return round(abs(1 - risk_score), 2) * 1000
