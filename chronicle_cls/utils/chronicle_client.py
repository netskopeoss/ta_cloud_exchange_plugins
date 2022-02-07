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

"""Chronicle CLient."""


import requests
import json
from netskope.common.utils import add_user_agent


class ChronicleClient:
    """Chronicle Client."""

    def __init__(self, configuration: dict, logger):
        """Initialize."""
        self.configuration = configuration
        self.logger = logger

    def _api_request(self, transformed_data):
        """Call the API for data Ingestion.

        :transformed_data : The transformed data to be ingested.
        """
        try:
            base_url = self.configuration["base_url"]
            url = f"{base_url.strip().strip('/')}/v1/udmevents"
            data = {"events": transformed_data}
            payload = json.dumps(data)
            headers = {"Content-Type": "application/json"}
            response = requests.request(
                "POST",
                url,
                params={"key": self.configuration["api_key"].strip()},
                headers=add_user_agent(headers),
                data=payload,
            )
            status_code = response.status_code
            response_body = response.text
            if status_code >= 500:
                raise Exception(
                    "Server Error : Status Code: {}. Response: {}".format(
                        status_code, response_body
                    )
                )
            elif status_code == 429:
                raise Exception(
                    f"Either out of resource quota or reaching rate limiting."
                    f" Status Code: {status_code}. Response: {response_body}"
                )

            elif status_code in [400, 404]:
                raise Exception(
                    "Client specified an invalid argument . Status code: {}. Response: {}".format(
                        status_code, response_body
                    )
                )
            elif status_code == 499:
                raise Exception(
                    "Request Cancelled by the client :  Status code: {}. Response: {}".format(
                        status_code, response_body
                    )
                )
            elif status_code == 403:
                raise Exception(
                    "Invalid Authorization. Status code: {}. Response: {}".format(
                        status_code, response_body
                    )
                )

        except requests.exceptions.HTTPError as err:
            self.logger.error(
                "Chronicle: HTTP error occurred: {}.".format(err)
            )
            raise
        except requests.exceptions.ConnectionError as err:
            self.logger.error(
                "Chronicle: Connection error occurred: {}.".format(err)
            )
            raise
        except requests.exceptions.Timeout as err:
            self.logger.error("Chronicle: Request timed out: {}.".format(err))
            raise
        except requests.exceptions.RequestException as err:
            self.logger.error(
                f"Chronicle: An error occurred while making REST API call to"
                f" Chronicle: {err}."
            )
            raise
        except Exception as err:
            self.logger.error(
                f"Chronicle: An error occurred while processing the "
                f"API response: {err}."
            )
            raise
