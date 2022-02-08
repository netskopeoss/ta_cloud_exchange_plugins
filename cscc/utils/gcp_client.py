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

"""GCP Client."""


import time
from google.auth.exceptions import TransportError
from google.oauth2 import service_account
from google.auth.transport import requests
from .cscc_exceptions import (
    MaxRetriesExceededError,
)
from .cscc_constants import (
    GCP_SCOPE,
    GET_PROJECT_NUMBER_URL,
)

RETRY_COUNT = 2
RETRY_SLEEP_TIME = 60  # seconds


class GCPClient:
    """Handles GCP authentication and ingests data into Google CSCC."""

    def __init__(self, url, key_file, logger, proxy):
        """Initialize GCP instance with required parameters.

        :param url: url for making POST request on GCP API to ingest finding
        :param key_file: Google service account file name
        :param logger: Logger object for logging purpose
        """
        self.gcp_scope = GCP_SCOPE
        self.gcp_post_url = url
        self.key_file = key_file
        self.gcp_session = None
        self.logger = logger
        self.proxy = proxy

    def set_gcp_session(self):
        """Set GCP authenticated session.

        :return session (object): GCP authenticated session object to make request
        """
        try:
            creds = service_account.Credentials.from_service_account_info(
                self.key_file
            )
            scoped = creds.with_scopes(self.gcp_scope)
            self.gcp_session = requests.AuthorizedSession(scoped)
            self.gcp_session.proxies = self.proxy
        except Exception as err:
            self.logger.error(
                "Could not create authenticated session object. Error:{}".format(
                    err
                )
            )
            raise err

    def set_resource_name(self):
        """Help to get project number by using project id from Google service account file.

        :return Project number: Project number of given Google service account
        """
        try:
            credentials = (
                service_account.Credentials.from_service_account_info(
                    self.key_file, scopes=GCP_SCOPE
                )
            )
            self.set_gcp_session()
            res = self.gcp_session.get(
                "{}/{}".format(GET_PROJECT_NUMBER_URL, credentials.project_id)
            )
            res = res.json()
            project_number = res.get("projectNumber")
            if project_number:
                return project_number
            else:
                self.logger.error(
                    "Getting invalid response for project number. Error: {}".format(
                        res
                    )
                )
                raise Exception("Invalid project number in response.")

        except TransportError:
            self.logger.error("Found invalid proxy configurations.")
            raise
        except Exception as e:
            self.logger.error(
                "Error occurred while getting project number. Error:{}".format(
                    e
                )
            )
            raise

    def _check_for_retries(self, retry_count):
        if retry_count + 1 == RETRY_COUNT:
            raise MaxRetriesExceededError(
                "Could not ingest data after {} retries".format(RETRY_COUNT)
            )

    def ingest(self, fid, finding, data_type, subtype):
        """Ingest finding(s) on google CSCC.

        :param subtype: The subtype of data type being ingested
        :param data_type: The data type being ingested
        :param fid : Finding Id
        :param finding: finding data to ingest
        """
        param = {"findingId": fid}
        try:
            for retry_count in range(RETRY_COUNT):
                res = self.gcp_session.post(
                    self.gcp_post_url, params=param, json=finding
                )

                if res.status_code == 200:
                    break
                # elif res.status_code in [401, 403, 404]:
                elif res.status_code == 429 or res.status_code >= 500:
                    self._check_for_retries(retry_count)
                    self.logger.error(
                        "Could not ingest data to GCP. Retrying again in {} seconds".format(
                            RETRY_SLEEP_TIME
                        )
                    )
                    self.logger.error(
                        "[{}][{}]: Error occurred in ingestion. Error: "
                        "{}".format(data_type, subtype, res.text)
                    )
                    time.sleep(RETRY_SLEEP_TIME)
                else:
                    if res.status_code != 400:
                        self.logger.error(
                            "[{}][{}]: Error occurred in ingestion, exiting from script. Status code: {}."
                            " Error: {}".format(
                                data_type, subtype, res.status_code, res.text
                            )
                        )
                    else:
                        self.logger.error(
                            "[{}][{}]: Error occurred in ingestion, the record will be skipped. Status "
                            "code: {}. Error: {}".format(
                                data_type, subtype, res.status_code, res.text
                            )
                        )
                        break
        except MaxRetriesExceededError as err:
            raise err
        except TransportError:
            self.logger.error("Found invalid proxy configurations.")
            raise
        except Exception as err:
            self.logger.error(
                "Could not ingest data on GCP. Ingestion "
                "of the record will be skipped. Error:{}".format(err)
            )
            raise err
