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
import requests
import datetime
import hashlib
import hmac
import base64
from netskope.common.utils import add_user_agent
from enum import Enum
from binascii import Error

from .sentinel_exception import (
    MaxRetriesExceededError,
)
from .sentinel_constants import (
    HTTP_METHOD,
    CONTENT_TYPE,
    RESOURCE,
    API_BASE_URL,
    MAX_RETRIES,
    RETRY_SLEEP_TIME,
)


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
        plugin_version,
    ):
        """Initialize."""
        self.configuration = configuration
        self.logger = logger
        self.data_length = 0
        self.data_type = None
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.log_prefix = log_prefix
        self.plugin_version = plugin_version

        if str(self.verify_ssl).lower() == "true":
            self.verify_ssl = True
        else:
            self.verify_ssl = False

    def _build_signature(
        self, workspace_id, primary_key, date, content_length
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
            self.logger.error(
                "{}: Found an invalid primary key. Primary key should be a  "
                "valid base64 string.An error occurred while decoding "
                "primary key: {}".format(self.log_prefix, err)
            )
            raise
        except Exception as err:
            self.logger.error(
                "{}: An error occurred while building authentication "
                "signature: {}".format(self.log_prefix, err)
            )
            raise

    def _log_custom_error_message(self, status_code, response_body):
        """Log custom error message based on the status code.

        :param status_code: The response status code
        :param response_body: The response body
        """
        if status_code in [400, 404]:
            self.logger.error(
                "{}: HTTP client error occurred. Status code: {}. "
                "Response: {}".format(
                    self.log_prefix, status_code, response_body
                )
            )
        elif status_code == 403:
            self.logger.error(
                "{}: Invalid Authorization. Status code: {}. "
                "Response: {}".format(
                    self.log_prefix, status_code, response_body
                )
            )

    def _post_retry_process(self, status_code, retry_count, response_body):
        # If it has done enough retries or the API call is successful or there
        # is a client error,
        # don't retry.
        if status_code in [400, 403, 404]:
            # Exit with no error as these are client errors (except 500) and
            # won't be recovered even
            # after docker restart
            self._log_custom_error_message(status_code, response_body)
            raise requests.exceptions.HTTPError(
                status_code,
                "HTTP client error occurred or Invalid Authentication.",
            )

        if retry_count == MAX_RETRIES:
            """This means we have done enough retries."""

            # Even after retrying MAX_RETRIES times if it could not ingest
            # data into Sentinel,
            # raise a custom exception.
            self.logger.error(
                "{}: Could not ingest data after {} retries".format(
                    self.log_prefix, MAX_RETRIES
                )
            )
            raise MaxRetriesExceededError(
                "Could not ingest data after {} retries".format(MAX_RETRIES)
            )

    def _add_user_agent(self, headers) -> str:
        """Add User-Agent in the headers of any request.

        Returns:
            str: String containing the User-Agent.
        """
        headers = add_user_agent(headers)
        plugin_name = "microsoft_azure_sentinel"
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        new_user_agent = "{}-cls-{}-v{}".format(
            ce_added_agent, plugin_name, self.plugin_version
        )
        headers.update({"User-Agent": new_user_agent})
        return headers

    def _post_data(self, workspace_id, shared_key, body, log_type):
        """Post the given data to Azure Sentinel workspace.

        :param workspace_id: The Azure Sentinel Workspace in which the data is
        to be ingested
        :param shared_key: The primary key of the workspace
        :param body: The actual data being ingested
        :param log_type: The name of the log type in which the given data is
        to be ingested
        :raises MaxRetriesExceededError: When data ingestion fails even after
        max. number of retries
        """
        rfc1123date = datetime.datetime.utcnow().strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        content_length = len(body)
        signature = self._build_signature(
            workspace_id, shared_key, rfc1123date, content_length
        )
        uri = API_BASE_URL.format(workspace_id, RESOURCE)

        headers = {
            "content-type": CONTENT_TYPE,
            "Authorization": signature,
            "Log-Type": log_type,
            "x-ms-date": rfc1123date,
        }

        retry, retry_count = True, 1
        try:
            while retry_count <= MAX_RETRIES:
                response = requests.post(
                    uri,
                    data=body,
                    headers=self._add_user_agent(headers),
                    proxies=self.proxy,
                    verify=self.verify_ssl,
                )
                status_code = response.status_code
                response_body = response.text

                # Do not retry in case of client errors and successful
                # API call.
                retry = status_code == 429 or status_code >= 500

                if retry_count == MAX_RETRIES or not retry:
                    self._post_retry_process(
                        status_code, retry_count, response_body
                    )
                    return

                self.logger.error(
                    "{}: Could not ingest data into Azure Sentinel. Retrying "
                    "in {} seconds. Status Code: {}. Response: {}".format(
                        self.log_prefix,
                        RETRY_SLEEP_TIME,
                        status_code,
                        response_body,
                    )
                )
                time.sleep(RETRY_SLEEP_TIME)
                retry_count += 1

        except requests.exceptions.HTTPError as err:
            self.logger.error(
                "{}: HTTP error occurred: {}".format(self.log_prefix, err)
            )
            raise
        except requests.exceptions.ConnectionError as err:
            self.logger.error(
                "{}: Connection error occurred: {}".format(
                    self.log_prefix, err
                )
            )
            raise
        except requests.exceptions.Timeout as err:
            self.logger.error(
                "{}: Request timed out: {}".format(self.log_prefix, err)
            )
            raise
        except requests.exceptions.RequestException as err:
            self.logger.error(
                "{}: An error occurred while making REST API call to Microsoft"
                " Azure Sentinel: {}".format(self.log_prefix, err)
            )
            raise
        except MaxRetriesExceededError as err:
            raise err
        except Exception as err:
            self.logger.error(
                "{}: An error occurred while processing the API "
                "response: {}".format(self.log_prefix, err)
            )
            raise

    def push(self, data, data_type):
        """Call method of post_data with appropriate parameters.

        :param data: The data to be ingested
        :param data_type: The type of the data being ingested (alerts/events)
        """
        # Setting a few properties of data being ingested
        self.data_length = len(data)
        self.data_type = data_type

        log_type = self.configuration.get("alerts_log_type_name").strip()
        if data_type == DataTypes.WEBTX.value:
            log_type = self.configuration.get("webtx_log_type_name").strip()
        elif data_type == DataTypes.EVENT.value:
            log_type = self.configuration.get("events_log_type_name").strip()

        try:
            self._post_data(
                self.configuration.get("workspace_id").strip(),
                self.configuration.get("primary_key"),
                json.dumps(data),
                log_type,
            )
        except MaxRetriesExceededError as err:
            raise err
