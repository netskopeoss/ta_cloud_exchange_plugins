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
"""

"""CrowdStrike LogScale Client."""


import json
import time
import requests
from enum import Enum
import traceback
from .crowdstrike_logscale_helper import _add_user_agent
from .crowdstrike_logscale_exception import CrowdStrikeLogScaleException
from .crowdstrike_logscale_constant import MAX_RETRY_COUNT, PLATFORM_NAME


class DataTypes(Enum):
    """Data Type Class."""

    ALERT = "alerts"
    EVENT = "events"
    WEBTX = "webtx"


class CrowdStrikeLogScaleClient:
    """CrowdStrike LogScale Client Class."""

    def __init__(
        self, configuration, logger, log_prefix, plugin_name, verify_ssl, proxy
    ):
        """Initialize."""
        self.configuration = configuration
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.data_length = 0
        self.data_type = None
        self.verify_ssl = verify_ssl
        self.proxy = proxy

        if str(self.verify_ssl).lower() == "true":
            self.verify_ssl = True
        else:
            self.verify_ssl = False

    def chunks(self, lst):
        """Yield successive n-sized chunks from lst."""
        chunk_size = 500
        for i in range(0, len(lst), chunk_size):
            yield lst[i : i + chunk_size]

    def _post_data(self, payload, uid):
        """Post the given data to CrowdStrike LogScale workspace.

        :param body: The actual data being ingested
        :raises MaxRetriesExceededError: When data ingestion fails
        even after max. number of retries
        """
        uri = "{}/api/v1/ingest/hec".format(
            self.configuration.get("hostname", "").strip("/").strip()
        )

        headers = {
            "Authorization": f"Bearer {self.configuration.get('token')}",
            "Content-Type": "application/json",
        }
        headers = _add_user_agent(headers)
        self.logger.debug(
            f"{self.log_prefix}: [{self.data_type}] [{self.subtype}] "
            f"Initiating the ingestion of {len(payload)} logs in the batch of 500 to "
            f"CrowdStrike LogScale. UUID: {uid}."
        )

        count = 0
        if payload:
            start = time.time()
            for chunk in self.chunks(payload):
                chunk_size = len(chunk)
                payload_str = ""
                payload_list = [json.dumps({"event": single_event}) for single_event in chunk]
                payload_str = "\n".join(payload_list)
                batch_start = time.time()
                self.logger.debug(
                    f"{self.log_prefix}: [{self.data_type}] [{self.subtype}]"
                    f" Ingesting {chunk_size} log(s) to {self.plugin_name}. "
                    f"UUID: {uid}."
                )
                self._api_helper(
                    lambda: requests.post(
                        url=uri,
                        headers=headers,
                        data=payload_str,
                        proxies=self.proxy,
                    ),
                    (
                        f" [{self.data_type}] [{self.subtype}] ingesting data "
                        f"into {self.plugin_name} having UUID: {uid}."
                    ),
                )
                batch_end = time.time()
                count += chunk_size
                self.logger.debug(
                    "{}: [{}] [{}] Successfully pushed {} record(s) of size {} KB to {} "
                    "in current page. Total {} record(s) pushed so far "
                    "in the current Push cycle. Time taken to ingest {} "
                    "record(s): {} seconds. UUID: {}.".format(
                        self.log_prefix,
                        self.data_type,
                        self.subtype,
                        chunk_size,
                        round(len(json.dumps(chunk))/1024, 2),
                        PLATFORM_NAME,
                        count,
                        chunk_size,
                        round(batch_end - batch_start, 2),
                        uid,
                    )
                )

            end = time.time()
            log_msg = (
                "[{}] [{}] Successfully ingested {} log(s)"
                " to {} server. Time taken to ingest {} record(s) is {} seconds.".format(
                    self.data_type,
                    self.subtype,
                    count,
                    self.plugin_name,
                    count,
                    round(end - start, 2),
                )
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return
        else:
            err_msg = f"[{self.data_type}] [{self.subtype}] Received empty transformed data hence the record(s) were skipped. UUID: {uid}."
            self.logger.info(
                "{}: {}".format(self.log_prefix, err_msg),
            )
            return

    def handle_error(self, response, logger_msg):
        """Handle API Status code errors.

        Args:
            response (Requests response object): Response object of requests.
        """

        if response.status_code == 200:
            return response.json()
        elif response.status_code in [401, 403]:
            err_msg = (
                "Received exit code {} while {}. "
                "Verify CrowdStrike LogScale Host or "
                "Ingest Token provided in configuration parameters.".format(
                    response.status_code, logger_msg
                )
            )
        elif response.status_code >= 400 and response.status_code < 500:
            err_msg = (
                "Received exit code {}, HTTP Client error while {}.".format(
                    response.status_code, logger_msg
                )
            )
        elif response.status_code >= 500 and response.status_code < 600:
            err_msg = (
                "Received exit code {}. HTTP Server error while {}.".format(
                    response.status_code, logger_msg
                )
            )
        else:
            err_msg = "Received exit code {}, HTTP error while {}.".format(
                response.status_code, logger_msg
            )

        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}.",
            details=f"Received API response: {response.text}",
        )
        raise CrowdStrikeLogScaleException(err_msg)

    def push(self, data, data_type, subtype, uid):
        """Call method of post_data with appropriate parameters.

        :param data: The data to be ingested
        :param data_type: The type of the data being ingested (alerts/events)
        """
        # Setting a few properties of data being ingested
        self.data_length = len(data)
        self.data_type = data_type
        self.subtype = subtype
        self._post_data(data, uid)

    def _api_helper(self, request, logger_msg, is_handle_error_required=True):
        """Helper function for api call."""

        try:
            for retry_counter in range(MAX_RETRY_COUNT):
                response = request()
                debug_log = (
                    f"{self.log_prefix}: Received status "
                    f"code {response.status_code} while {logger_msg}."
                )
                if "ingesting data" in logger_msg:
                    debug_log += f" Response body: {response.text}"
                self.logger.debug(
                    debug_log
                )
                if response.status_code == 429 or (
                    response.status_code >= 500 and response.status_code < 600
                ):
                    if retry_counter == MAX_RETRY_COUNT - 1:
                        if response.status_code == 429:
                            err_msg = (
                                "Received response code {}, max retries limit "
                                "exceeded while {}. Hence exiting.".format(
                                    response.status_code,
                                    logger_msg,
                                )
                            )
                        else:
                            err_msg = (
                                "Received response code {}, while {}. "
                                "Hence exiting.".format(
                                    response.status_code,
                                    logger_msg,
                                )
                            )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"Received API response: {response.text}",
                        )
                        raise CrowdStrikeLogScaleException(err_msg)
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
                        time.sleep(60)
                        continue
                    retry_after = int(retry_after)
                    if retry_after > 300:
                        err_msg = (
                            "Received response code {}, 'Retry-After' value "
                            "received from response headers while {} is "
                            "greater than 5 minutes. Hence exiting.".format(
                                response.status_code,
                                logger_msg,
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"Received API response: {response.text}",
                        )
                        raise CrowdStrikeLogScaleException(err_msg)

                    if response.status_code == 429:
                        self.logger.error(
                            message=(
                                "{}: Received response code {}, max retries "
                                "limit exceeded while {}. Retrying after {} "
                                "seconds. {} retries remaining.".format(
                                    self.log_prefix,
                                    response.status_code,
                                    logger_msg,
                                    retry_after,
                                    MAX_RETRY_COUNT - 1 - retry_counter,
                                )
                            ),
                            details=f"Received API response: {response.text}",
                        )
                    else:
                        self.logger.error(
                            message=(
                                "{}: Received response code {}, while {}. "
                                "Retrying after {} "
                                "seconds. {} retries remaining.".format(
                                    self.log_prefix,
                                    response.status_code,
                                    logger_msg,
                                    retry_after,
                                    MAX_RETRY_COUNT - 1 - retry_counter,
                                )
                            ),
                            details=f"Received API response: {response.text}",
                        )
                    time.sleep(retry_after)

                else:
                    return (
                        self.handle_error(response, logger_msg)
                        if is_handle_error_required
                        else response
                    )
        except json.JSONDecodeError as err:
            err_msg = "Invalid JSON response received from API."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=f"Received API response {response.text}",
            )
            raise CrowdStrikeLogScaleException(err_msg)
        except requests.exceptions.ProxyError as exp:
            err_msg = (
                "ProxyError occurred while {}. "
                "Verify proxy configuration. Error: {}".format(logger_msg, exp)
            )
            toast_msg = "Invalid Proxy configuration."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise CrowdStrikeLogScaleException(toast_msg)
        except requests.exceptions.ConnectionError as exp:
            err_msg = (
                "Unable to establish connection with {} "
                "platform while {}.Proxy server or {} is not reachable or "
                "Invalid CrowdStrike LogScale Host provided. Error: {}".format(
                    PLATFORM_NAME, logger_msg, PLATFORM_NAME, exp
                )
            )
            toast_msg = (
                "Proxy server or {} is not reachable or "
                "Invalid CrowdStrike LogScale Host provided.".format(
                    PLATFORM_NAME
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise CrowdStrikeLogScaleException(toast_msg)
        except requests.exceptions.RequestException as exp:
            err_msg = (
                "Error occurred while requesting"
                " to {} server for {}. Error: {}".format(
                    PLATFORM_NAME, logger_msg, exp
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            toast_msg = "Request exception occurred."
            raise CrowdStrikeLogScaleException(toast_msg)
        except CrowdStrikeLogScaleException as err:
            raise err
        except Exception as exp:
            err_msg = (
                "Exception occurred while making API call to"
                " {} server while {}. Error: {}".format(
                    PLATFORM_NAME, logger_msg, exp
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise exp
