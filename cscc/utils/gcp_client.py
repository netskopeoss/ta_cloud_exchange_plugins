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

"""Google Cloud SCC Plugin Client."""


import json
import time
import traceback
from google.auth.exceptions import TransportError, MalformedError
from google.oauth2 import service_account
from google.auth.transport import requests as gRequest
import requests
from .cscc_exceptions import (
    MaxRetriesExceededError,
    CSCCPluginException
)
from .cscc_constants import (
    GCP_SCOPE,
    GET_PROJECT_NUMBER_URL,
    GCP_URL
)

RETRY_COUNT = 2
RETRY_SLEEP_TIME = 60  # seconds


class GCPClient:
    """Handles GCP authentication and ingests data into Google CSCC."""

    def __init__(self, configuration, logger, log_prefix, plugin_name, proxy):
        """Initialize GCP instance with required parameters."""
        self.gcp_scope = GCP_SCOPE
        self.gcp_session = None
        self.configuration = configuration
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.proxy = proxy
        self.set_gcp_session()

    def set_gcp_session(self):
        """Set GCP authenticated session.

        :return session (object): GCP authenticated session object to make request
        """
        try:
            self.creds = service_account.Credentials.from_service_account_info(
                json.loads(self.configuration["key_file"])
            )
            scoped = self.creds.with_scopes(self.gcp_scope)
            self.gcp_session = gRequest.AuthorizedSession(scoped)
            self.gcp_session.proxies = self.proxy
        except MalformedError as err:
            err_msg = (
                f"Invalid Key File provided."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(err)}",
                details=str(traceback.format_exc()),
            )
            raise CSCCPluginException(err_msg)
        except Exception as err:
            err_msg = (
                f"Could not create authenticated session object."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}"
                    f" Error: {str(err)}"
                ),
                details=str(traceback.format_exc())
            )
            raise err

    def set_resource_name(self, headers):
        """Help to get project number by using project id from Google service account file.

        :return Project number: Project number of given Google service account
        """
        try:
            res = self.gcp_session.get(
                url=f"{GET_PROJECT_NUMBER_URL}/{self.creds.project_id}",
                headers=headers
            )
            response = self.parse_response(response=res)
            project_number = response.get("projectNumber")
            if project_number:
                return project_number
            else:
                err_msg = f"Invalid response. Error: {response}"
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(res.text),
                )
                raise CSCCPluginException(err_msg)

        except TransportError:
            err_msg = f"Found invalid proxy configurations. Error: {response}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise CSCCPluginException(err_msg)
        except Exception as e:
            err_msg = f"Error occurred while getting project number. Error: {e}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise CSCCPluginException(err_msg)

    def ingest(self, fid, finding, headers, data_type, subtype):
        """Ingest finding(s) on google CSCC.

        :param subtype: The subtype of data type being ingested
        :param data_type: The data type being ingested
        :param fid : Finding Id
        :param finding: finding data to ingest
        """
        param = {"findingId": fid}
        try:
            org_id = self.configuration.get("organization_id", None)
            src_id = self.configuration.get("source_id", None)
            gcp_post_url = "{}/{}/sources/{}/findings".format(
                GCP_URL, org_id, src_id
            )
            for retry_count in range(RETRY_COUNT):
                res = self.gcp_session.post(
                    gcp_post_url,
                    params=param,
                    json=finding,
                    headers=headers
                )

                if res.status_code == 200:
                    break

                elif res.status_code == 429 or res.status_code >= 500:
                    remaining_retries = RETRY_COUNT - retry_count - 1
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}] Could not ingest data "
                            f"to {self.plugin_name}. Retrying again in {RETRY_SLEEP_TIME} seconds."
                            f" {remaining_retries} retries remaining."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    time.sleep(RETRY_SLEEP_TIME)
                    continue
                else:
                    if res.status_code != 400:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: [{data_type}][{subtype}] Error occurred in ingestion, "
                                f"exiting from script. Status code: {res.status_code}. Error: {res.text}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                    else:
                        response = self.parse_response(response=res)
                        status_code = response.get("error", {}).get("code", "unknown")
                        message = response.get("error", {}).get("message", "unknown")
                        status = response.get("error", {}).get("status", "unknown")

                        if status in ["FAILED_PRECONDITION", "PERMISSION_DENIED"]:
                            raise Exception(f"Invalid Customer ID provided. {message}")
                        if status in ["INVALID_ARGUMENT"]:
                            raise Exception(f"Invalid Finding event provided. {message}")
                        raise Exception(
                            f"status_code: {status_code}, message: {message}, status: {status}"
                        )
            if retry_count + 1 >= RETRY_COUNT:
                raise MaxRetriesExceededError(
                    f"Could not ingest data after {RETRY_COUNT} retries"
                )
        except MaxRetriesExceededError as err:
            raise CSCCPluginException(err)
        except TransportError as err:
            err_msg = (
                "Found invalid proxy configurations for "
                f"{self.plugin_name} server while ingesting data. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise CSCCPluginException(err_msg)
        except requests.exceptions.HTTPError as err:
            err_msg = "HTTP Error occurred while ingesting data."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}.",
                details=str(traceback.format_exc()),
            )
            raise CSCCPluginException(err_msg)
        except requests.exceptions.ConnectionError as err:
            err_msg = (
                f"Unable to establish connection with {self.plugin_name} "
                "while ingesting data. "
                "Check Organization ID or Source ID provided in configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}.",
                details=str(traceback.format_exc()),
            )
            raise CSCCPluginException(err_msg)
        except requests.exceptions.Timeout as err:
            err_msg = "Request timed out while ingesting data."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}.",
                details=str(traceback.format_exc()),
            )
            raise CSCCPluginException(err_msg)
        except CSCCPluginException:
            raise
        except Exception as err:
            err_msg = (
                "Error occurred while requesting to "
                f"{self.plugin_name} server while ingesting data. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise CSCCPluginException(err_msg)

    def validate_credentials(self, headers):
        """Validate credentials by making a GET request to the GCP findings API.

        Parameters:
            headers (dict): Headers to be sent with the request.

        Returns:
            bool: True if the credentials are valid, False otherwise.

        Raises:
            CSCCPluginException: If any error occurs during the API request or response parsing.
        """
        try:
            org_id = self.configuration.get("organization_id", None)
            src_id = self.configuration.get("source_id", None)
            gcp_post_url = "{}/{}/sources/{}/findings".format(
                GCP_URL, org_id, src_id
            )
            gcp_source_url = "{}/{}/sources/{}".format(
                GCP_URL, org_id, src_id
            )

            source_res = self.gcp_session.get(
                url=gcp_source_url,
                headers=headers
            )

            if source_res.status_code != 200:
                raise Exception("Invalid Source ID provided.")

            res = self.gcp_session.get(
                url=gcp_post_url,
                params={"pageSize": 1},
                headers=headers
            )
            response = self.parse_response(response=res, is_validation=True)

            if res.status_code == 200 and "listFindingsResults" in response:
                return True
            elif res.status_code == 200 and "listFindingsResults" not in response:
                return False

            status_code = response.get("error", {}).get("code", "unknown")
            message = response.get("error", {}).get("message", "unknown")
            status = response.get("error", {}).get("status", "unknown")
            raise Exception(
                f"status_code: {status_code}, message: {message}, status: {status}"
            )
        except Exception as err:
            err_msg = (
                "Error occurred while requesting to "
                f"{self.plugin_name}. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            error_message = (
                "Verify provided configuration parameters "
                "are correct with required permissions."
            )
            raise CSCCPluginException(error_message)

    def parse_response(self, response: requests.models.Response, is_validation=False):
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
            if is_validation:
                err_msg = (
                    "Verify provided Key File or Organization ID "
                    "is correct with required permissions."
                )
            raise CSCCPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify provided Key File or Organization ID "
                    "is correct with required permissions."
                )
            raise CSCCPluginException(err_msg)
