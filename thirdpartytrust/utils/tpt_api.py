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

"""Contains helper classes for BitSight API calls.."""
from typing import List
import requests

BITSIGHT_API_URL = "https://api.thirdpartytrust.com/api/v3/netskope"


class BaseAPIClient:
    """
    Base BitSight API methods
    """

    def __init__(self, token: str, proxy, ssl_validation: bool, base_url: str):
        """Initialize variables.

        Args:
            token (str): Authentication token.
            base_url (str): Base URL where we are going to do the requests.
            It can be different depending on the environment we are executing
            the requests.
        """

        assert token, "Invalid Token."
        assert base_url, "Invalid BitSight API url."

        if proxy is None:
            proxy = {}

        self._base_url = base_url
        self._token = "Token " + token.strip()
        self.proxy = proxy
        self.ssl_validation = ssl_validation

    def _get_response(self, endpoint: str):
        """Get request response.

        Args:
            endpoint (str): Endpoint we are requesting

        Returns:
            str: Response of requested url
        """
        assert type(endpoint) == str

        headers = {"Authorization": self._token}
        url = f"{self._base_url}/{endpoint}"
        response = requests.get(
            url,
            headers=headers,
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        response.raise_for_status()
        return response

    def _get(self, endpoint: str) -> dict:
        """Get request in JSON.

        Args:
            endpoint (str): endpoint we are requesting

        Returns:
            dict: Returns the response or an empty {}
        """
        assert type(endpoint) == str

        response = self._get_response(endpoint=endpoint)
        if response.content == b"":
            return {}

        return response.json()


class BitSightAPIClient(BaseAPIClient):
    """BitSightAPIClient Class."""

    def __init__(
        self,
        token: str,
        proxy=None,
        ssl_validation=True,
        base_url=BITSIGHT_API_URL,
    ):
        """Initialize Variables.

        Args:
            token (str): _description_
            proxy (dict, optional): Proxy. Defaults to None.
            ssl_validation (bool, optional): SSL Validation is required. Defaults to True.
            base_url (dict, optional): Base URL. Defaults to BITSIGHT_API_URL.
        """
        if proxy is None:
            proxy = {}

        super().__init__(
            token=token,
            proxy=proxy,
            ssl_validation=ssl_validation,
            base_url=base_url,
        )

    def get_destination_data_config(self, data_type, data_subtype=""):
        """Gets the destination url where the data should be uploaded.

        Args:
            data_type (_type_): Data type
            data_subtype (str, optional): Data Subtype. Defaults to "".
        """
        endpoint = f"cloudexchange/data_destination_url/{data_type}?data_subtype={data_subtype}"

        return self._get(endpoint=endpoint)


class BitSightDataSender:
    """BitSight Data Sender Class."""

    def __init__(self, bitsight_token: str, proxy: dict, ssl_validation: bool):
        """Initialize variables.

        Args:
            bitsight_token (str): API Token for Bitsight.
            proxy (dict): Proxy dictionary.
            ssl_validation (bool): SSL Validation. True for SSL validation else False
        """
        self.ssl_validation = ssl_validation
        self.proxy = proxy
        self.bitsight_token = bitsight_token

    def send_data(self, data: List, data_type: str, data_subtype=""):
        """Send Data.

        Args:
            data (List): Data
            data_type (str): Data type
            data_subtype (str, optional): Data subtype. Defaults to "".
        """
        bitsight_client = BitSightAPIClient(
            self.bitsight_token, self.proxy, self.ssl_validation
        )
        upload_url = bitsight_client.get_destination_data_config(
            data_type, data_subtype
        )
        response = requests.put(
            upload_url,
            data=data,
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        response.raise_for_status()
