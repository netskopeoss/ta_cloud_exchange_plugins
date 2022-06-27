"""
TODO: Copyright (c) 2022 ThirdPartyTrust
"""


import requests

TPT_API_URL = 'https://api.thirdpartytrust.com/api/v3/netskope'


class BaseAPIClient:
    """
    Base TPT API methods
    """

    def __init__(self, token, proxy, ssl_validation, base_url):
        """

        :param token: Authentication token.
        :param base_url: Base URL where we are going to do the requests. It can be different
                         depending on the environment we are executing the requests
        """

        assert token, "Invalid Token."
        assert base_url, "Invalid TPT API url."

        if proxy is None:
            proxy = {}

        self._base_url = base_url
        self._token = "Token " + token.strip()
        self.proxy = proxy
        self.ssl_validation = ssl_validation

    def _get_response(self, endpoint):
        """
        Get request response

        :param endpoint: endpoint we are requesting
        """
        assert type(endpoint) == str

        headers = {'Authorization': self._token}
        url = f'{self._base_url}/{endpoint}'
        response = requests.get(url, headers=headers, proxies=self.proxy, verify=self.ssl_validation)
        response.raise_for_status()

        return response

    def _get(self, endpoint):
        """
        Get request in JSON

        :param endpoint: endpoint we are requesting

        Returns the response or an empty {}
        """
        assert type(endpoint) == str

        response = self._get_response(endpoint=endpoint)
        if response.content == b'':
            return {}

        return response.json()


class ThirdPartyTrustAPIClient(BaseAPIClient):

    def __init__(self, token, proxy=None, ssl_validation=True, base_url=TPT_API_URL):
        if proxy is None:
            proxy = {}

        super().__init__(token=token, proxy=proxy, ssl_validation=ssl_validation, base_url=base_url)

    def get_destination_data_config(self, data_type, data_subtype=""):
        """
        Gets the destination url where the data should be uploaded.

        :param data_type: Data type
        :param data_subtype: Data subtype
        """
        endpoint = f'cloudexchange/data_destination_url/{data_type}?data_subtype={data_subtype}'

        return self._get(endpoint=endpoint)


class ThirdPartyTrustDataSender:

    def __init__(self, tpt_token, proxy, ssl_validation):
        self.ssl_validation = ssl_validation
        self.proxy = proxy
        self.tpt_token = tpt_token

    def send_data(self, data, data_type, data_subtype=""):
        tpt_client = ThirdPartyTrustAPIClient(self.tpt_token, self.proxy, self.ssl_validation)
        upload_url = tpt_client.get_destination_data_config(data_type, data_subtype)
        response = requests.put(upload_url, data=data, proxies=self.proxy, verify=self.ssl_validation)
        response.raise_for_status()
