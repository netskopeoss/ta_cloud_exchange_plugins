"""MCAS CLient."""
import time
import requests
import threading

from .mcas_constants import (
    API_GET_URL,
    API_POST_URL,
    MAX_RETRIES,
    RETRY_SLEEP_TIME,
    DATAFILE,
)
from .mcas_exceptions import (
    MaxRetriesExceededError,
)
from netskope.common.utils import add_user_agent


class MCASClient:
    """MCAS CLient."""

    def __init__(self, configuration: dict, logger, *, verify_ssl, proxy):
        """Initialize."""
        self.configuration = configuration
        self.logger = logger
        self.data_length = 0
        self.data_type = None
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.datafile = DATAFILE

    def _log_custom_error_message(self, status_code, response_body):
        """Log custom error message based on the status code.

        :param status_code: The response status code
        :param response_body: The response body
        """
        if status_code in [400, 404]:
            self.logger.error(
                "HTTP client error occurred. Status code: {}. Response: {}".format(
                    status_code, response_body
                )
            )
        elif status_code == 403:
            self.logger.error(
                "Invalid Authorization. Status code: {}. Response: {}".format(
                    status_code, response_body
                )
            )

    def _post_retry_process(
        self, req_type, status_code, retry_count, response_body
    ):
        # If it has done enough retries or the API call is successful or there is a client error,
        # don't retry.

        retry_log_message = {
            "get": "Could not initiate the file upload after {} retries",
            "put": "Could not upload the file after {} retries",
            "post": "Could not notify MCAS to start processing the data after {} retries",
        }

        error_log_message = {
            "get": "An error occurred while initiating file upload for MCAS, status code: {} response: {}",
            "put": "An error occurred while uploading the file on MCAS, status code: {} response: {}",
            "post": "An error occurred while notifying MCAS to start processing the uploaded data, "
            "status code: {} response: {}",
        }

        if status_code in [200, 201]:
            return

        if status_code in [400, 403, 404]:
            # Exit with no error as these are client errors (except 500) and won't be recovered even
            # after docker restart
            self._log_custom_error_message(status_code, response_body)
            raise Exception(
                f"HTTP client error occurred. Status code: {status_code}. Response: {response_body}"
            )

        elif not (status_code == 429 or status_code >= 500):
            self.logger.error(
                error_log_message[req_type].format(status_code, response_body)
            )
            raise Exception(
                f"HTTP client error occurred. Status code: {status_code}. Response: {response_body}"
            )

        if retry_count == MAX_RETRIES:
            """This means we have done enough retries."""

            # Even after retrying MAX_RETRIES times if it could not ingest data into MCAS,
            # raise a custom exception.

            self.logger.error(retry_log_message[req_type].format(MAX_RETRIES))
            raise MaxRetriesExceededError(
                retry_log_message[req_type].format(MAX_RETRIES)
            )

    def _api_request(
        self, req_type, uri, params={}, headers={}, proxies={}, data=None
    ):
        """Call the appropriate API call based on request type param.

        :param req_type: request type ['get', 'put', 'post']
        :param uri: Url to do API call
        :param params: params for API request
        :param headers: headers for API request
        :param proxies: proxies for API request
        :param data: data for API request
        :raises MaxRetriesExceededError: When data ingestion fails even after max. number of retries
        """
        retry_log_message = {
            "get": "Could not initiate the file upload. Retrying in {} seconds. Status Code: {}. Response: {}",
            "put": "Could not upload the log file to MCAS. Retrying in {} seconds. Status Code: {}. Response: {}",
            "post": "Could not notify MCAS to start processing the data. Retrying in {} seconds. "
            "Status Code: {}. Response: {}",
        }

        retry, retry_count = True, 1
        try:
            while retry_count <= MAX_RETRIES:
                if req_type == "get":
                    response = requests.get(
                        uri,
                        params=params,
                        headers=add_user_agent(headers),
                        proxies=proxies,
                        verify=self.verify_ssl,
                    )

                elif req_type == "put":
                    put_data = str.encode("\n".join(data))
                    file_name = self.datafile.format(threading.get_ident())
                    files = {"file": (file_name, put_data)}
                    response = requests.put(
                        uri,
                        files=files,
                        headers=add_user_agent(headers),
                        proxies=proxies,
                        verify=self.verify_ssl,
                    )

                elif req_type == "post":
                    response = requests.post(
                        uri,
                        data=data,
                        headers=add_user_agent(headers),
                        proxies=proxies,
                        verify=self.verify_ssl,
                    )

                status_code = response.status_code
                response_body = response.text
                # Do not retry in case of client errors and successful API call.
                retry = status_code == 429 or status_code >= 500
                if retry_count == MAX_RETRIES or not retry:
                    self._post_retry_process(
                        req_type, status_code, retry_count, response_body
                    )
                    return response

                self.logger.error(
                    retry_log_message[req_type].format(
                        RETRY_SLEEP_TIME, status_code, response_body
                    )
                )

                time.sleep(RETRY_SLEEP_TIME)
                retry_count += 1

        except requests.exceptions.HTTPError as err:
            self.logger.error("HTTP error occurred: {}".format(err))
            raise
        except requests.exceptions.ConnectionError as err:
            self.logger.error("Connection error occurred: {}".format(err))
            raise
        except requests.exceptions.Timeout as err:
            self.logger.error("Request timed out: {}".format(err))
            raise
        except requests.exceptions.RequestException as err:
            self.logger.error(
                "An error occurred while making REST API call to MCAS: {}".format(
                    err
                )
            )
            raise
        except MaxRetriesExceededError as err:
            raise err
        except Exception as err:
            self.logger.error(
                "An error occurred while processing the API response: {}".format(
                    err
                )
            )
            raise

    def validate_token(self):
        """To check whether the token is valid or not."""
        ingestion_file = self.datafile.format(threading.get_ident())
        headers = {
            "Authorization": f"Token {self.configuration.get('token').strip()}"
        }

        params = {"filename": ingestion_file, "source": "GENERIC_CEF"}

        get_uri = API_GET_URL.format(
            self.configuration.get("portal_url").strip()
        )
        try:
            self._api_request("get", get_uri, params, headers, self.proxy)
            return True
        except Exception:
            raise

    def _post_data(self, portal_url, api_token, body, data_source):
        """Post the given data to MCAS Platform.

        :param portal_url: portal url to get the API url
        :param api_token: api token to access the MCAS
        :param body: The actual data being ingested
        :param data_source: Name of data source, where records to be ingested
        :raises MaxRetriesExceededError: When data ingestion fails even after max. number of retries
        """
        ingestion_file = self.datafile.format(threading.get_ident())
        # Step 1 : initiate the file upload
        headers = {"Authorization": f"Token {api_token}"}

        params = {"filename": ingestion_file, "source": "GENERIC_CEF"}

        get_uri = API_GET_URL.format(portal_url)
        response_get = self._api_request(
            "get", get_uri, params, headers, self.proxy
        )

        # Step 2 : Upload the file
        response_get = response_get.json()
        upload_url = response_get["url"]
        headers_put = {"x-ms-blob-type": "BlockBlob"}
        self._api_request(
            "put",
            upload_url,
            headers=headers_put,
            proxies=self.proxy,
            data=body,
        )

        # Step 3 : Notify MCAS so that it can start processing the data
        post_uri = API_POST_URL.format(portal_url)
        body = {"uploadUrl": upload_url, "inputStreamName": data_source}
        self._api_request(
            "post",
            post_uri,
            data=body,
            headers=headers,
            proxies=self.proxy,
        )

    def push(self, data, data_type):
        """Call method of "post_data" with appropriate parameters.

        :param data: The data to be ingested
        :param data_type: The type of the data being ingested (alerts/events)
        """
        # Setting a few properties of data being ingested
        self.data_length = len(data)
        self.data_type = data_type

        self._post_data(
            self.configuration.get("portal_url").strip(),
            self.configuration.get("token").strip(),
            data,
            self.configuration.get("data_source").strip(),
        )
