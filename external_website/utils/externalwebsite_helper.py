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

CTE External Website plugin helper module.
"""


import traceback
import time
from typing import Dict, Union

import requests
from netskope.common.utils import add_user_agent

from .externalwebsite_constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    PLUGIN_NAME
)


class ExternalWebsitePluginException(Exception):
    """ExternalWebsite plugin custom exception class."""

    pass


class ExternalWebsitePluginHelper(object):
    """ExternalWebsitePluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str
    ):
        """ExternalWebsitePluginHelper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers for third-party requests.

        Args:
            headers (Dict): Dictionary containing headers for any request.
        Returns:
            Dict: Dictionary after adding User-Agent.
        """
        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.replace(" ", "-").lower(),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def handle_error(self, response):
        status_code = response.status_code

        if status_code == 200:
            return response.text

        if status_code == 401:
            err_msg = "Received exit code 401, Authentication Error."
            self.logger.error(f"{self.log_prefix} {err_msg}.")
            raise ExternalWebsitePluginException(err_msg)
        elif status_code == 404:
            err_msg = "Received exit code 404, Resource Not Found."
            self.logger.error(f"{self.log_prefix} {err_msg}.")
            raise ExternalWebsitePluginException(err_msg)
        elif 400 <= status_code < 500:
            err_msg = f"Received exit code {status_code}, HTTP Client Error."
            self.logger.error(f"{self.log_prefix} {err_msg}.")
            raise ExternalWebsitePluginException(err_msg)
        elif 500 <= status_code < 600:
            err_msg = f"Received exit code {status_code}, HTTP Server Error."
            self.logger.error(f"{self.log_prefix} {err_msg}.")
            raise ExternalWebsitePluginException(err_msg)
        else:
            err_msg = f"Received exit code {status_code}, HTTP Error."
            self.logger.error(f"{self.log_prefix} {err_msg}.")
            raise ExternalWebsitePluginException(err_msg)

    def api_helper(
        self,
        url,
        method,
        params=None,
        data=None,
        headers=None,
        verify=True,
        proxies=None,
        logger_msg=str
    ):
        """API Helper perform API request to ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            request (request): Requests object.
            code is required?. Defaults to True.

        Returns:
            dict: Response dictionary.
        """
        try:
            debuglog_msg = (f"{self.log_prefix} : API Request for "
                            f"{logger_msg}. URL={url}.")
            if params:
                debuglog_msg += f", params={params}"
            if data:
                debuglog_msg += f", data={data}"

            self.logger.debug(debuglog_msg)

            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=self._add_user_agent(headers),
                    verify=verify,
                    proxies=proxies,
                )
                self.logger.debug(
                    f"{self.log_prefix} : Received API Response while "
                    f"{logger_msg} Method={method}, "
                    f"Status Code={response.status_code}."
                )
                if response.status_code >= 500 and response.status_code <= 600:
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            "Received exit code {}, HTTP Server Error."
                            " Max retries for rate limit "
                            "handler exceeded hence returning status"
                            " code {}.".format(
                                response.status_code,
                                response.status_code,
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=err_msg,
                        )
                        raise ExternalWebsitePluginException(err_msg)

                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, HTTP Server Error"
                            " occurred. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                DEFAULT_WAIT_TIME,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        )
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return self.handle_error(response)

        except requests.exceptions.ProxyError as error:
            err_msg = (
                "Proxy error occurred. Verify the provided "
                "proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise ExternalWebsitePluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = f"Unable to establish connection with {PLUGIN_NAME}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise ExternalWebsitePluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = "HTTP Error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ExternalWebsitePluginException(err_msg)
        except ExternalWebsitePluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting "
                f"to {self.plugin_name}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise ExternalWebsitePluginException(err_msg)
