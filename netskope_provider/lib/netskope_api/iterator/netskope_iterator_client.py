import sys
import os
import time

import requests as request

sys.path.insert(0, os.path.abspath(os.path.join(__file__, "../api", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(__file__, "../api", "..", "..", "..")))
from netskope_api.iterator.operation import Operation
from requests.auth import AuthBase
from netskope_api.iterator.const import Const

import logging


logger = logging.getLogger()


class AuthToken(AuthBase):
    """Netskope-API-Token Auth for header token."""

    def __init__(self, token):
        """Initialize the object."""
        self.token = token

    def __call__(self, req):
        """Set Netskope-Api-Token in request"""
        req.headers["Netskope-Api-Token"] = "{}".format(self.token)
        return req


class NetskopeIteratorClient:
    """Iterator client for netskope event downloads"""

    #Flag to track the iterator has the valid token or not.
    valid_token = 0
    _error_counter = 0

    # Total number of consecutive invalid token API call
    MAX_INVALID_TOKEN_API_CALL = 10

    #WAIT for 30 seconds upon every invalid token configuration.
    TOKEN_ERROR_WAIT_TIME = 30
    DAY_IN_SECONDS = 86400

    def __init__(self,params):
        """
        :param params:
        """

        configs = {
            "base_url": "https://{}".format(params.get(Const.NSKP_TENANT_HOSTNAME)),
            "iterator_name": params.get(Const.NSKP_ITERATOR_NAME),
            "eventtype" : params.get(Const.NSKP_EVENT_TYPE),
            "alerttype": params.get(Const.NSKP_ALERT_TYPE)
        }
        self.token = params.get(Const.NSKP_TOKEN)
        self.user_agent = params.get(Const.NSKP_USER_AGENT)

        if not self.user_agent:
            self.user_agent = "DataExport-Iterator-{}".format(params.get(Const.NSKP_TENANT_HOSTNAME))

        # Accept gzip-encoded response from the server.
        headers = {
            "User-Agent": self.user_agent,
            "Accept-Encoding": "gzip"
        }

        self.configs = configs
        self.session = request.Session()
        self.session.headers.update(headers)
        self.session.proxies = params.get(Const.NSKP_PROXIES)
        self.session.auth = AuthToken(self.token)


    # Construct the url as per the operation.
    def build_url(self, op):
        """

        :param op : Operation to be invoked:
        :return The Iterator API to be called:
        """
        base_url = self.configs.get("base_url")
        event_type = self.configs.get("eventtype")
        alert_type = self.configs.get("alerttype")
        iterator_name = self.configs.get("iterator_name")

        if alert_type and event_type == Const.EVENT_TYPE_ALERT:
            # If the query is to download the alerts specific to the alert_type
            url = "{}/api/v2/events/dataexport/alerts/{}?index={}&operation={}".format(base_url,alert_type,iterator_name,op)
        else:
            url = "{}/api/v2/events/dataexport/events/{}?index={}&operation={}".format(base_url,event_type,iterator_name,op)
        return url


    # Download the response based on the operation.
    def get(self, operation):
        """
        :param operation: Operation to be invoked
        :return Response objects for the operation.
        """
        op = self.validate_and_return_operation(operation)
        url = self.build_url(op)

        # If the token configure is invalid then return ERROR.
        if self.valid_token != 0:
            # Reset the token flag validation after a DAY of wait time.
            # Upon the invalid token failures the client could able to associate the endpoint to the respective token.
            # After the reconfiguration the client should seemlessly able to pull the events without restart of their process.
            time_period = time.time() - self.valid_token
            if time_period > self.DAY_IN_SECONDS:
                self.valid_token = 0
            else:
                raise ValueError("Invalid API token {}  configured to access the endpoint {}".format(self.token, url))

        res = self.session.get(url=url, timeout=120)
        self.honor_rate_limiting(res.headers)
        self.validate_status_code(res)
        return res

    def validate_status_code(self, res):
        """
        Validate the status code of the response
        """
        if res.status_code in [403, 401]:
            if self._error_counter >= self.MAX_INVALID_TOKEN_API_CALL:
                self.valid_token = time.time()
            self._error_counter = self._error_counter + 1
            time.sleep(self.TOKEN_ERROR_WAIT_TIME)

        # If the response status code is 200 then reset the invalid token counter.
        if res.status_code == 200:
            self._error_counter = 0
            self.valid_token = 0

    def honor_rate_limiting(self, headers):
        """
        Identify the response headers carrying the rate limiting value.
        If the rate limit remaining for this endpoint is 0 then wait for the rate limit reset time before sending the response to the client.
        """
        try:
            if Const.RATELIMIT_REMAINING in headers:
                remaining = headers[Const.RATELIMIT_REMAINING]
                if int(remaining) <= 0:
                    logging.warning("Rate limiting reached for the endpoint config {} ".format(self.configs))
                    if Const.RATELIMIT_RESET in headers:
                        time.sleep(int(headers[Const.RATELIMIT_RESET]))
                    else:
                        # if the RESET value does not exist in the header then
                        # sleep for default 1 second as the rate limit remaining is 0
                        time.sleep(10)
        except ValueError as ve:
            logging.error("Value error when honoring the rate limiting wait time {} {}".format(headers,str(ve)))


    def validate_and_return_operation(self, op):
        """
        Raise an exception if the iterator operation is not valid.
        The operation can be: next, head, tail, resend, or a timestamp value.
        """
        if op in (Operation.OP_HEAD, Operation.OP_TAIL, Operation.OP_NEXT, Operation.OP_RESEND):
            return op.value

        try:
            return int(op)
        except Exception as e:
            raise ValueError("Invalid iterator operation: {}".format(op))

        if ts < 0:
            raise ValueError("Invalid iterator operation as timestamp: {}".format(op))
