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


import json
import time
import sys
import requests
import datetime
import hashlib
import hmac
import base64
import traceback
from netskope.common.utils import add_user_agent
from enum import Enum
from binascii import Error

from .sentinel_exception import AzureSentinelException
from .sentinel_constants import (
    HTTP_METHOD,
    CONTENT_TYPE,
    RESOURCE,
    API_BASE_URL,
    MAX_RETRIES,
    RETRY_SLEEP_TIME,
    MODULE_NAME,
    TARGET_SIZE_MB,
    BATCH_SIZE,
)
from .sentinel_helper import split_into_size


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

    def _build_signature(self, workspace_id, primary_key, date, content_length):
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
                hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
            ).decode()
            authorization = "SharedKey {}:{}".format(workspace_id, encoded_hash)
            return authorization
        except Error as err:
            err_msg = (
                "Found an invalid primary key. Primary key should be a valid "
                "base64 string. An error occurred while decoding primary key."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {err}",
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)
        except Exception as err:
            err_msg = "An error occurred while building authentication signature."
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

    def parse_response(self, response: requests.models.Response):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = f"Invalid JSON response received from API. Error: {str(err)}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            raise AzureSentinelException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            raise AzureSentinelException(err_msg)

    def handle_error(self, resp: requests.models.Response, logger_msg, is_validation):
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
        validation_msg = " Verify the Workspace ID and Primary Key provided in configuration parameters."
        error_dict = {
            400: "Bad Request",
            403: "Forbidden",
            401: "Unauthorized",
        }
        if status_code in [200, 201]:
            return
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            response = self.parse_response(response=resp)
            if response and "Message" in response:
                err_msg = error_dict[status_code] + ". " + response["Message"]
            else:
                err_msg = error_dict[status_code]
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                details=str(resp.text),
            )
            if is_validation:
                err_msg = err_msg + "." + validation_msg
            raise AzureSentinelException(err_msg)
        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                details=str(resp.text),
            )
            if is_validation:
                err_msg = err_msg + "." + validation_msg
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
            debuglog_msg = f"{self.log_prefix} : API Request for {logger_msg}. URL={url}, Headers={display_headers}"
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
                )
                self.logger.debug(
                    f"{self.log_prefix} : Received API Response while "
                    f"{logger_msg}. Method={method}, "
                    f"Status Code={response.status_code}."
                )
                if not is_validation and (
                    response.status_code == 429
                    or (response.status_code >= 500 and response.status_code <= 600)
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
                    return self.handle_error(response, logger_msg, is_validation)

        except requests.exceptions.ProxyError as error:
            err_msg = "Proxy error occurred. Verify the provided proxy configuration."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error} while {logger_msg}.",
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {self.plugin_name}. "
                "Check Workspace ID provided in configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error} while {logger_msg}.",
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)
        except requests.HTTPError as err:
            err_msg = "HTTP Error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err} while {logger_msg}.",
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)
        except AzureSentinelException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting "
                f"to {self.plugin_name}. Error: {str(exp)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise AzureSentinelException(err_msg)

    def push(self, data, data_type, sub_type, logger_msg, is_validation=False):
        """Call method of post_data with appropriate parameters.

        :param data: The data to be ingested
        :param data_type: The type of the data being ingested (alerts/events)
        """
        skipped_count = 0
        total_count = 0
        log_type = self.configuration.get("alerts_log_type_name").strip()
        if data_type == DataTypes.WEBTX.value:
            log_type = self.configuration.get("webtx_log_type_name").strip()
        elif data_type == DataTypes.EVENT.value:
            log_type = self.configuration.get("events_log_type_name").strip()

        try:
            workspace_id = self.configuration.get("workspace_id").strip()
            shared_key = self.configuration.get("primary_key")
            result = []

            size_in_bytes = sys.getsizeof(json.dumps(data))
            size_in_mb = size_in_bytes / (1024.0**2)  # Convert bytes to megabytes
            if size_in_mb > TARGET_SIZE_MB:
                for item in range(0, len(data), BATCH_SIZE):
                    current_part = data[item : item + BATCH_SIZE]
                    size_in_bytes = sys.getsizeof(json.dumps(current_part))
                    size_in_mb = size_in_bytes / (
                        1024.0**2
                    )  # Convert bytes to megabytes
                    if size_in_mb > TARGET_SIZE_MB:
                        chunk_data = split_into_size(current_part)
                        result.extend(chunk_data)
                    else:
                        result.append(current_part)
            else:
                result.append(data)

            rfc1123date = datetime.datetime.utcnow().strftime(
                "%a, %d %b %Y %H:%M:%S GMT"
            )

            uri = API_BASE_URL.format(workspace_id, RESOURCE)
            headers = {
                "Content-Type": CONTENT_TYPE,
                "Log-Type": log_type,
                "x-ms-date": rfc1123date,
            }
            headers = self._add_user_agent(headers)
            page = 0
            for result_data in result:
                page += 1
                content_length = len(json.dumps(result_data))
                signature = self._build_signature(
                    workspace_id, shared_key, rfc1123date, content_length
                )
                try:
                    headers["Authorization"] = signature
                    msg = ""
                    if not is_validation:
                        msg = f" for page {page}"
                    self.api_helper(
                        logger_msg + msg,
                        uri,
                        "POST",
                        data=json.dumps(result_data),
                        headers=headers,
                        verify=self.verify_ssl,
                        proxies=self.proxy,
                        is_validation=is_validation,
                    )
                except Exception:
                    skipped_count += len(result_data)
                    continue
                total_count += len(result_data)
                if not is_validation:
                    log_msg = "[{}]:[{}] Successfully ingested {} {}(s) for page {} to {}.".format(
                        data_type,
                        sub_type,
                        len(result_data),
                        data_type,
                        page,
                        self.plugin_name,
                    )
                    self.logger.info(f"{self.log_prefix}: {log_msg}")

            if not is_validation:
                log_msg = "[{}]:[{}] Successfully ingested {} {}(s) to {}.".format(
                    data_type,
                    sub_type,
                    total_count,
                    data_type,
                    self.plugin_name,
                )
                self.logger.info(f"{self.log_prefix}: {log_msg}")
            if not is_validation and skipped_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skipped_count} records due to some unexpected error occurred, check logs for more details."
                )

        except Error:
            raise
        except AzureSentinelException as error:
            raise error
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting "
                f"to {self.plugin_name}. Error: {str(exp)}"
            )
            raise AzureSentinelException(err_msg)
