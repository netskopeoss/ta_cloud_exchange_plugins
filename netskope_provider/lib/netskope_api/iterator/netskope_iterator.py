import sys
import os

from requests.exceptions import RequestException
import requests as request

sys.path.insert(0, os.path.abspath(os.path.join(__file__, "../api", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(__file__, "../api", "..", "..", "..")))
from netskope_api.iterator.netskope_iterator_client import NetskopeIteratorClient
from netskope_api.iterator.operation import Operation
from netskope_api.iterator.const import Const

import logging
import re

from requests.packages.urllib3.util.retry import Retry

logger = logging.getLogger()


class NetskopeIterator:
    """Iterator client for netskope event downloads"""

    #Create the iteartor client with the parameters

    #:param params:
    #    HOSTNAME : Ex Netskope.com
    #    ITERATOR_NAME : application_splunk_iterator ( This could be any unique meaningful name )
    #    EVENT_TYPE : Event types [alert / application / network / page / connection / audit / incident / infrastructure]
    def __init__(self,params):
        self.validate_params(params)
        self.client = NetskopeIteratorClient(params)


    def validate_params(self , params):
        """
        Validate all the input parameters.
        :param params:
        :return:
        """
        if params.get(Const.NSKP_TOKEN,None) is None:
            raise ValueError("API Token must be a valid string value")
        elif params.get(Const.NSKP_TENANT_HOSTNAME,None) is None:
            raise ValueError("Tenant Hostname must be a valid string value")
        elif params.get(Const.NSKP_ITERATOR_NAME,None) is None:
            raise ValueError("Iterator Name must be a valid string value")
        elif params.get(Const.NSKP_EVENT_TYPE,None) is None:
            raise ValueError("Iterator EventType must be a valid string value")


    def next(self):
        """
        Return the next chunk of data
        :return Response Object
        """
        return self.client.get(Operation.OP_NEXT)

    def head(self):
        """
        Returns the first chunk of data that is persent in the Netskope System
        :return Response Object
        """
        return self.client.get(Operation.OP_HEAD)

    def tail(self):
        """
        Returns the first chunk of data that is present in the Netskope System
        :return:
        """
        return self.client.get(Operation.OP_TAIL)

    def resend(self):
        """
        Returns the previous chunk of data that is sent recently.
        :return:
        """
        return self.client.get(Operation.OP_RESEND)

    def download(self,timestamp):
        """

        # Timestamp must be a valid integer, it was already validated.
        # To start at this timestamp, set the iterator's to the previous
        # timestamp, as if it had finished sending that previous data.

        :param timestamp:
        :return:
        """
        return self.client.get(timestamp)
