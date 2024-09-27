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

MCAS CLient."""

import json
import threading
import time
import traceback

import requests

from .mcas_constants import (
    API_GET_URL,
    API_POST_URL,
    APPLICATION_ID,
    DATAFILE,
    ERROR_CODE,
    INGESTION_DATAFILE,
    MAX_RETRIES,
    OAUTH_URL,
    PLATFORM_NAME,
    RETRY_SLEEP_TIME,
)
from .mcas_exceptions import MaxRetriesExceededError, MCASPluginException
from .mcas_helper import add_mcas_user_agent, parse_response


class MCASClient:
    """MCAS CLient."""

    def __init__(
        self, configuration: dict, logger, *, verify_ssl, proxy, log_prefix
    ):
        """Initialize."""
        self.configuration = configuration
        self.log_prefix = log_prefix
        self.logger = logger
        self.data_length = 0
        self.data_type = None
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.datafile = DATAFILE

    def _log_custom_error_message(
        self, status_code, response_body, purpose_log
    ):
        """Log custom error message based on the status code.

        :param status_code: The response status code
        :param response_body: The response body
        """
        if status_code in [400, 404]:
            err_msg = "HTTP client error occurred."
            if (
                isinstance(response_body, dict)
                and response_body.get("errorMessageCode") == ERROR_CODE
            ):
                err_msg = (
                    f"{err_msg} Data Source not found on "
                    f"{PLATFORM_NAME}. Verify the Data Source provided in the"
                    " configuration parameters."
                )

        elif status_code == 403:
            err_msg = "Invalid Authorization."
        elif status_code == 401:
            err_msg = "Authentication failed due to invalid credentials."

        self.logger.error(
            message=(
                f"{self.log_prefix}: Error occurred while"
                f" {purpose_log} - {err_msg} Status code: {status_code}."
            ),
            details=f"Received API response: {response_body}",
        )
        return err_msg

    def _post_retry_process(
        self, req_type, status_code, retry_count, response_body, purpose_log=""
    ):
        # If it has done enough retries or the API call is successful or
        # there is a client error, don't retry.

        retry_log_message = {
            "get": "{}: Could not initiate the file upload after {} retries",
            "put": "{}: Could not upload the file after {} retries",
            "post": (
                "{}: Could not notify Microsoft Defender for Cloud Apps to"
                " start processing the data after {} retries"
            ),
        }

        error_log_message = {
            "get": (
                "{}: An error occurred while initiating file upload for {},"
                " status code: {}"
            ),
            "put": (
                "{}: An error occurred while uploading the file on {},"
                " status code: {}"
            ),
            "post": (
                "{}: An error occurred while notifying {} to start"
                " processing the uploaded data, status code: {}"
            ),
        }

        if status_code in [200, 201]:
            return
        err_msg = "HTTP client error occurred."
        if status_code in [400, 403, 404, 401]:
            # Exit with no error as these are client errors (except 500) and
            # won't be recovered even after docker restart
            err_msg = self._log_custom_error_message(
                status_code, response_body, purpose_log
            )
            raise MCASPluginException(err_msg)

        elif status_code == 413:
            err_msg = (
                "The request body is too large and exceeds the maximum"
                " permissible limit."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while"
                    f" {purpose_log}- {err_msg}  Status code: {status_code}."
                ),
                details=f"Received API response: {response_body}",
            )
            raise MCASPluginException(err_msg)

        elif not (
            status_code == 429 or status_code >= 500 and status_code < 600
        ):
            self.logger.error(
                message=(
                    error_log_message[req_type].format(
                        self.log_prefix, PLATFORM_NAME, status_code
                    )
                ),
                details=f"Received API response: {response_body}",
            )
            raise MCASPluginException(err_msg)

        if retry_count == MAX_RETRIES:
            """This means we have done enough retries."""

            # Even after retrying MAX_RETRIES times if it could not
            # ingest data into MCAS, raise a custom exception.

            self.logger.error(
                message=(
                    retry_log_message[req_type].format(
                        self.log_prefix, MAX_RETRIES
                    )
                ),
                details=f"Received API response: {response_body}",
            )
            raise MaxRetriesExceededError(
                retry_log_message[req_type].format(
                    self.log_prefix, MAX_RETRIES
                )
            )

    def _api_request(
        self,
        method,
        uri,
        purpose,
        params={},
        headers={},
        proxies={},
        data=None,
        files=None,
        is_from_validation=False,
    ):
        """Call the appropriate API call based on request type param.

        Args:
            method (str): request type ['get', 'put', 'post']
            uri (str): Url to do API call
            purpose (str): _description_
            params (dict, optional): params for API request. Defaults to {}.
            headers (dict, optional): headers for API request. Defaults to {}.
            proxies (dict, optional): proxies for API request. Defaults to {}.
            data (optional): data for API request. Defaults to None.
            files (optional): Files to send to API request. Defaults
                 to None.
            is_from_validation (bool, optional): _description_. Defaults to
                 False.
        """
        retry_log_message = {
            "init": (
                "{}: Could not initiate the file upload. Retrying in {}"
                " seconds. Status Code: {}."
            ),
            "upload": (
                "{}: Could not upload the log file to Microsoft Defender"
                " for Cloud Apps. Retrying in {} seconds. Status Code: {}."
            ),
            "finalize": (
                "{}: Could not notify Microsoft Defender for Cloud"
                " Apps to start processing the data. Retrying in {} seconds. "
                "Status Code: {}."
            ),
            "generate token": (
                "{}: Could not generate the token. Retrying in"
                " {} seconds. Status Code: {}."
            ),
        }

        api_purpose = {
            "init": "Initiating the file upload",
            "upload": "Performing file upload",
            "finalize": "Finalizing file upload",
            "generate token": "Generating the token",
        }

        retry, retry_count = True, 1
        try:
            purpose_log = api_purpose[purpose.lower()]
            display_headers = {
                k: v for k, v in headers.items() if k not in {"Authorization"}
            }
            debuglog_msg = (
                f"{self.log_prefix}: API Request for {purpose_log}"
                f" - Method={method},  URL={uri},  headers={display_headers}, "
            )
            if params:
                debuglog_msg += f"params={params}"
            if data and purpose.lower() != "generate token":
                debuglog_msg += f" data={data}"

            if purpose != "generate token":
                debuglog_msg += f", Ingestion_file={self.ingestion_file}"

            self.logger.debug(debuglog_msg)

            while retry_count <= MAX_RETRIES:
                response = requests.request(
                    url=uri,
                    method=method,
                    params=params,
                    data=data,
                    files=files,
                    headers=headers,
                    proxies=proxies,
                )
                status_code = response.status_code
                response_body = response.text
                if response.status_code in [400, 404]:
                    try:
                        response_body = parse_response(self, response)
                    except Exception:
                        pass

                debug_log = ""
                if purpose != "generate token":
                    debug_log += f", Ingestion_file={self.ingestion_file}"

                self.logger.debug(
                    f"{self.log_prefix} : Received API Response for"
                    f" {purpose_log} - Method={method}, Status Code"
                    f"={status_code}, {debug_log}."
                )

                if is_from_validation:
                    return response

                # Do not retry in case of client errors and successful
                # API call.
                retry = status_code == 429 or (
                    status_code >= 500 and status_code < 600
                )
                if retry_count == MAX_RETRIES or not retry:
                    self._post_retry_process(
                        req_type=method.lower(),
                        status_code=status_code,
                        retry_count=retry_count,
                        response_body=response_body,
                        purpose_log=purpose_log,
                    )
                    return response

                self.logger.error(
                    message=(
                        retry_log_message[purpose.lower()].format(
                            self.log_prefix,
                            RETRY_SLEEP_TIME,
                            status_code,
                        )
                    ),
                    details=f"Received API Response. {response_body}",
                )
                time.sleep(RETRY_SLEEP_TIME)
                retry_count += 1

        except requests.exceptions.ProxyError as exp:
            err_msg = (
                "ProxyError occurred while {}. "
                "Verify proxy configuration.".format(purpose_log)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(err_msg)
        except requests.exceptions.HTTPError as err:
            err_msg = f"HTTP error occurred while {purpose_log}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(err_msg)
        except requests.exceptions.ConnectionError as err:
            err_msg = f"Connection error occurred while {purpose_log}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(err_msg)
        except requests.exceptions.Timeout as err:
            err_msg = f"Request timed out while {purpose_log}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(err_msg)
        except requests.exceptions.RequestException as err:
            err_msg = (
                "An error occurred while making REST API call to"
                f" {purpose_log}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(err_msg)
        except MaxRetriesExceededError as err:
            raise err
        except MCASPluginException as err:
            raise err
        except Exception as err:
            toast_msg = "Unexcepted error occurred check logs."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: An error occurred while processing"
                    f" the API response: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(toast_msg)

    def validate_token(self):
        """To check whether the token is valid or not."""
        self.ingestion_file = self.datafile.format(threading.get_ident())

        params = {"filename": self.ingestion_file, "source": "GENERIC_CEF"}

        get_uri = API_GET_URL.format(
            self.configuration.get("portal_url", "").strip()
        )

        self._api_request(
            "get",
            get_uri,
            "init",
            params,
            self.get_headers(True),
            self.proxy,
        )

    def get_headers(self, is_from_validation=False):
        """
        Generates the headers for the API request.

        Args:
            is_from_validation (bool): A flag indicating whether the request
                                         is from a validation process.
                                         Defaults to False.

        Returns:
            dict: The headers to be used in the API request.
        """
        auth_method = self.configuration.get("auth_method")
        if auth_method and auth_method == "oauth":
            token = self.generate_token(is_from_validation)
            return add_mcas_user_agent({"Authorization": f"Bearer {token}"})
        else:
            token = self.configuration.get("token", "")
            return add_mcas_user_agent({"Authorization": f"Token {token}"})

    def generate_token(self, is_from_validation):
        """
        Generates a token for authentication.

        Parameters:
            is_from_validation (bool): A flag indicating whether the request
              is from a validation process.

        Returns:
            str: The generated token.
        """

        headers = add_mcas_user_agent(
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            }
        )
        tenant_id = self.configuration.get("tenant_id", "").strip()
        authBody = {
            "scope": f"{APPLICATION_ID}/.default",
            "client_id": self.configuration.get("client_id", "").strip(),
            "client_secret": self.configuration.get("client_secret", ""),
            "grant_type": "client_credentials",
        }
        try:
            response = self._api_request(
                "post",
                f"{OAUTH_URL}/{tenant_id}/oauth2/v2.0/token",
                "generate token",
                headers=headers,
                proxies=self.proxy,
                data=authBody,
                is_from_validation=is_from_validation,
            )
            if response.status_code == 200:
                resp = parse_response(self, response=response)
                return resp.get("access_token", "")
            else:
                if is_from_validation:
                    err_msg = (
                        "Verify Tenant ID, Client ID and Client Secret"
                        " provided in configuration parameters."
                    )
                else:
                    err_msg = (
                        "Error while generating token. Error:"
                        f" {response.text}."
                    )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                )
                raise MCASPluginException(err_msg)
        except MCASPluginException as err:
            raise err
        except Exception as e:
            raise e

    def _post_data(self, portal_url, body, data_source):
        """Post the given data to MCAS Platform.

        Args:
            portal_url (str): portal url to get the API url
            body (List): The actual data being ingested
            data_source (str): Name of data source, where records
                are to be ingested
        """
        self.ingestion_file = INGESTION_DATAFILE.format(
            threading.get_ident(), self.data_type, self.sub_type
        )
        # Step 1 : initiate the file upload
        headers = self.get_headers()

        params = {"filename": self.ingestion_file, "source": "GENERIC_CEF"}

        get_uri = API_GET_URL.format(portal_url)
        resp_get = self._api_request(
            "GET",
            get_uri,
            "init",
            params,
            headers,
            proxies=self.proxy,
        )

        self.logger.info(
            f"{self.log_prefix}: API Request Successful to Initiate the file"
            f" upload. Ingestion_file={self.ingestion_file}."
        )
        # Step 2 : Upload the file
        response_get = parse_response(self, response=resp_get)
        upload_url = response_get["url"]
        if upload_url:
            headers_put = {"x-ms-blob-type": "BlockBlob"}
            if self.configuration.get("transformData", True):
                put_data = str.encode("\n".join(x for x in body))
            else:
                put_data = str.encode("\n".join(json.dumps(x) for x in body))
            files = {"file": (self.ingestion_file, put_data)}
            self._api_request(
                "PUT",
                upload_url,
                "upload",
                headers=add_mcas_user_agent(headers_put),
                proxies=self.proxy,
                files=files,
            )
            self.logger.info(
                f"{self.log_prefix}: API Request Successful to Perform file"
                f" upload. Ingestion_file={self.ingestion_file}."
            )

            # Step 3 : Notify MCAS so that it can start processing the data
            post_uri = API_POST_URL.format(portal_url)
            body = {"uploadUrl": upload_url, "inputStreamName": data_source}
            self._api_request(
                "POST",
                post_uri,
                "finalize",
                data=body,
                headers=headers,
                proxies=self.proxy,
            )
            self.logger.info(
                f"{self.log_prefix}: API Request Successful to Finalize file"
                f" upload. Ingestion_file={self.ingestion_file}."
            )

            log_msg = "[{}] [{}] Successfully ingested {} {}(s) to {}.".format(
                self.data_type,
                self.sub_type,
                self.data_length,
                self.data_type,
                PLATFORM_NAME,
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
        else:
            log_msg = (
                f"{self.log_prefix}: Could not upload the log file to "
                f"{PLATFORM_NAME}. Hence, Ingestion of "
                f"{self.data_length} records will be skipped."
            )
            self.logger.error(log_msg)
            raise MCASPluginException(log_msg)

    def push(self, data, data_type, sub_type):
        """Call method of "post_data" with appropriate parameters.

        Args:
            data (List): The data to be ingested
            data_type (str): The type of the data being ingested
                 (alerts/events)
            sub_type (str): The subtype of the data being ingested
                (alerts/events)
        """
        # Setting a few properties of data being ingested
        self.data_length = len(data)
        self.data_type = data_type
        self.sub_type = sub_type

        self._post_data(
            self.configuration.get("portal_url", "").strip(),
            data,
            self.configuration.get("data_source", "").strip(),
        )
