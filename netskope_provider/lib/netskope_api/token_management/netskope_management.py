import os
import sys

from netskope_api.token_management.netskope_management_client import NetskopeTokenManagemenClient

sys.path.insert(0, os.path.abspath(os.path.join(__file__, "../api", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(__file__, "../api", "..", "..", "..")))
from netskope_api.iterator.const import Const


class NetskopeTokenManagement:
    """TokenManagement client for netskope to provide authentication to access web transactions"""

    def __init__(self, params):
        self.validate_params(params)
        self.client = NetskopeTokenManagemenClient(params)

    def validate_params(self, params):
        """
        Validate all the input parameters.
        :param params:
        :return:
        """
        if params.get(Const.NSKP_TOKEN, None) is None:
            raise ValueError("API Token must be a valid string value")
        elif params.get(Const.NSKP_TENANT_HOSTNAME, None) is None:
            raise ValueError("Tenant Hostname must be a valid string value")

    def get(self):
        """
        Return the subscription credentials
        :return Response Object
        """
        return self.client.get()

    # Func to be called only to override 403 error.
    # Subscription key and path are already present for the customer, use regenerate=true parameter.
    # Note: Regenerating subscription key and path will invalidate the existing credentials.
    def regenerate_and_get(self):
        """
        Return the subscription credentials after regenerating subscription key and path.
        :return Response Object
        """
        return self.client.regenerate_and_get()
