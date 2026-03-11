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

Microsoft Azure Sentinel Client.
"""

import base64
import datetime
import hashlib
import hmac
import json
import sys
import time
import traceback
from binascii import Error
from enum import Enum

import requests
from requests.exceptions import ReadTimeout
from netskope.common.utils import add_user_agent

from .sentinel_constants import (
    API_BASE_URL,
    CONTENT_TYPE,
    HTTP_METHOD,
    MAX_RETRIES,
    MODULE_NAME,
    PLUGIN_NAME,
    RESOURCE,
    RETRY_SLEEP_TIME,
    TARGET_SIZE_BYTES,
)
from .sentinel_exception import AzureSentinelException


class DataTypes(Enum):
    """Data Type Class."""

    ALERT = "alerts"
    EVENT = "events"
    WEBTX = "webtx"


class AzureSentinelClient:
    """Microsoft Azure Sentinel Client Class."""

    def __init__(
        self,
        configuration,
        logger,
        verify_ssl,
        proxy,
        log_prefix,
        plugin_name,
        plugin_version,
    ):
        """Initialize."""
        self.configuration = configuration
        self.logger = logger
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

        if str(self.verify_ssl).lower() == "true":
            self.verify_ssl = True
        else:
            self.verify_ssl = False

    def _build_signature(
        self,
        workspace_id,
        primary_key,
        date,
        content_length,
        is_validation=False,
    ):
        """Build the required authentication signature for Azure Sentinel.

        :param workspace_id: The ID of workspace to which the data is to be
        ingested
        :param primary_key: The primary key of workspace
        :param date: Date when the data is being ingested
        :param content_length: Number of records being ingested in a single
        POST call
        :return: The HMAC signature string
        """
        try:
            x_headers = "x-ms-date:" + date
            string_to_hash = (
                HTTP_METHOD
                + "\n"
                + str(content_length)
                + "\n"
                + CONTENT_TYPE
                + "\n"
                + x_headers
                + "\n"
                + RESOURCE
            )
            bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
            decoded_key = base64.b64decode(primary_key)
            encoded_hash = base64.b64encode(
                hmac.new(
                    decoded_key, bytes_to_hash, digestmod=hashlib.sha256
                ).digest()
            ).decode()
            authorization = "SharedKey {}:{}".format(
                workspace_id, encoded_hash
            )
            return authorization
        except Error as err:
            if is_validation:
                err_msg = (
                    "Invalid Primary Key provided in configuration parameter."
                )
            else:
                err_msg = (
                    "An error occurred while decoding primary key. "
                    "Primary key should be a valid base64 string."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {err}",
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)
        except Exception as err:
            err_msg = (
                "An unexpected error occurred while building "
                "authentication signature."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {err}",
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)

    def _add_user_agent(self, headers) -> str:
        """Add User-Agent in the headers of any request.

        Returns:
            str: String containing the User-Agent.
        """
        if headers and "User-Agent" in headers:
            return headers

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

    def parse_response(
        self, response: requests.models.Response, is_validation
    ):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = f"Invalid JSON response received from API. {str(err)}"
            if is_validation:
                err_msg = (
                    "Verify Azure Log Analytics Domain, Workspace ID and "
                    "Primary Key provided in "
                    "the configuration parameters."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            raise AzureSentinelException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. {exp}"
            )
            if is_validation:
                err_msg = (
                    "Verify Azure Log Analytics Domain, Workspace ID and "
                    "Primary Key provided in "
                    "the configuration parameters."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            raise AzureSentinelException(err_msg)

    def handle_error(
        self, resp: requests.models.Response, logger_msg, is_validation
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
        validation_msg = (
            " Verify the Azure Log Analytics Domain, Workspace ID and "
            "Primary Key provided in the "
            "configuration parameters."
        )
        error_dict = {
            400: "Bad Request",
            403: "Forbidden Error",
            401: "Unauthorized Error",
        }
        if status_code in [200, 201]:
            return
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            response = self.parse_response(resp, is_validation)
            if response and response.get("Message"):
                err_msg = error_dict[status_code] + ". " + response["Message"]
            else:
                err_msg = error_dict[status_code]
            if is_validation:
                err_msg = err_msg + "." + validation_msg
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"while {logger_msg}, {err_msg}"
                ),
                details=str(resp.text),
            )
            raise AzureSentinelException(err_msg)
        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            if is_validation:
                err_msg = err_msg + "." + validation_msg
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f" while {logger_msg}, {err_msg}"
                ),
                details=str(resp.text),
            )
            raise AzureSentinelException(err_msg)

    def api_helper(
        self,
        logger_msg: str,
        url,
        method,
        params=None,
        data=None,
        headers=None,
        verify=True,
        proxies=None,
        is_validation=False,
    ):
        """API Helper perform API request to ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            request (request): Requests object.
            code is required?. Defaults to True.
            is_validation : API call from validation method or not

        Returns:
            dict: Response dictionary.
        """
        try:
            display_headers = {
                k: v for k, v in headers.items() if k not in {"Authorization"}
            }
            debuglog_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}"
                f". URL={url}, Headers={display_headers}"
            )
            if params:
                debuglog_msg += f", params={params}"

            self.logger.debug(debuglog_msg)
            for retry_counter in range(MAX_RETRIES):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                    timeout=180,
                )
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response while "
                    f"{logger_msg}. Method={method}, "
                    f"Status Code={response.status_code}."
                )
                if not is_validation and (
                    response.status_code == 429
                    or (
                        response.status_code >= 500
                        and response.status_code <= 600
                    )
                ):
                    if retry_counter == MAX_RETRIES - 1:
                        err_msg = (
                            "Received exit code {}, while"
                            " {}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            " code {}.".format(
                                response.status_code,
                                logger_msg,
                                response.status_code,
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=str(response.text),
                        )
                        raise AzureSentinelException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, while {}. "
                            "Retrying after {} seconds. {} "
                            "retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                RETRY_SLEEP_TIME,
                                MAX_RETRIES - 1 - retry_counter,
                            )
                        ),
                        details=str(response.text),
                    )
                    time.sleep(RETRY_SLEEP_TIME)
                else:
                    return self.handle_error(
                        response, logger_msg, is_validation
                    )

        except ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. "
                "Verify the provided proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} "
                f"{error} while {logger_msg}.",
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection while {logger_msg}. "
                "Check the Azure Log Analytics Domain or Workspace "
                "ID provided in configuration parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} "
                    f"{error} while {logger_msg}."
                ),
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} "
                f"{err} while {logger_msg}.",
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)
        except AzureSentinelException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting "
                f"to {PLUGIN_NAME} while {logger_msg}. {str(exp)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)

    def create_payload(self, data, data_types):
        payload_size = sys.getsizeof(json.dumps(data))

        # If the payload size is within the limit, return it as a single chunk
        if payload_size <= TARGET_SIZE_BYTES or len(data) == 1:
            return [data]

        self.logger.debug(
            f"{self.log_prefix}: {data_types} - The size of the current data "
            "chunk exceeds the allowed payload limit "
            "hence data will be divided into further chunks "
            "before sharing. Current data chunk length: "
            f"{len(data)}. Current data chunk size in bytes: {payload_size}"
        )

        # Split the data into two parts
        mid = len(data) // 2
        part1 = self.create_payload(
            data[:mid], data_types
        )  # Recursively process the first half
        part2 = self.create_payload(
            data[mid:], data_types
        )  # Recursively process the second half
        return part1 + part2  # Combine the results from both halves

    def push(self, data, data_type, sub_type, logger_msg, base_url, is_validation=False):
        """Call method of post_data with appropriate parameters.

        :param data: The data to be ingested
        :param data_type: The type of the data being ingested (alerts/events)
        """
        total_count = 0
        log_type = self.configuration.get("alerts_log_type_name", "").strip()
        if data_type == DataTypes.WEBTX.value:
            log_type = self.configuration.get(
                "webtx_log_type_name", ""
            ).strip()
        elif data_type == DataTypes.EVENT.value:
            log_type = self.configuration.get(
                "events_log_type_name", ""
            ).strip()

        try:
            workspace_id = self.configuration.get("workspace_id", "").strip()
            shared_key = self.configuration.get("primary_key", "")
            result = []
            data_types = f"[{data_type}][{sub_type}]"
            result = self.create_payload(data, data_types)
            if not is_validation:
                self.logger.info(
                    f"{self.log_prefix}: {data_types} - "
                    f"Initializing the sharing of data in {len(result)} "
                    "chunk(s)."
                )
            rfc1123date = datetime.datetime.utcnow().strftime(
                "%a, %d %b %Y %H:%M:%S GMT"
            )

            uri = API_BASE_URL.format(workspace_id, base_url, RESOURCE)
            headers = {
                "Content-Type": CONTENT_TYPE,
                "Log-Type": log_type,
                "x-ms-date": rfc1123date,
            }
            headers = self._add_user_agent(headers)
            page = 0
            for result_data in result:
                json_data = json.dumps(result_data)
                current_chunk_size = sys.getsizeof(json_data)
                page += 1
                content_length = len(json_data)
                signature = self._build_signature(
                    workspace_id,
                    shared_key,
                    rfc1123date,
                    content_length,
                    is_validation,
                )

                headers["Authorization"] = signature
                msg = ""
                if not is_validation:
                    msg = (
                        f", sharing {data_types} for batch {page}, "
                        f"batch size: {current_chunk_size} and batch "
                        f"length: {len(result_data)}"
                    )
                self.api_helper(
                    logger_msg + msg,
                    uri,
                    "POST",
                    data=json_data,
                    headers=headers,
                    verify=self.verify_ssl,
                    proxies=self.proxy,
                    is_validation=is_validation,
                )
                total_count += len(result_data)
                if not is_validation:
                    log_msg = (
                        "{} - Successfully ingested {} {}(s) for"
                        " batch {} to {}. Total {}(s) shared till now: {}"
                    ).format(
                        data_types,
                        len(result_data),
                        data_type,
                        page,
                        PLUGIN_NAME,
                        data_type,
                        total_count,
                    )
                    self.logger.info(f"{self.log_prefix}: {log_msg}")

            if not is_validation:
                log_msg = "{} - Successfully ingested {} {}(s) to {}.".format(
                    data_types,
                    total_count,
                    data_type,
                    PLUGIN_NAME,
                )
                self.logger.info(f"{self.log_prefix}: {log_msg}")

        except AzureSentinelException as error:
            raise error
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while "
                f"requesting for {logger_msg}. "
                f"Failed to share {data_types} for "
                f"batch {page}, batch size: "
                f"{current_chunk_size} and batch "
                f"length: {len(result_data)}. "
                f"{str(exp)}"
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg}"),
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)
