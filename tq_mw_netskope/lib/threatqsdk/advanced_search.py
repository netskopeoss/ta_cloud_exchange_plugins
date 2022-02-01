# coding=utf-8
# --------------------------------------------------------------------------------------------------
# ThreatQuotient Proprietary and Confidential
# Copyright ©2020 ThreatQuotient, Inc. All rights reserved.
#
# NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc.
# The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.
#
# Dissemination of this information or reproduction of this material is strictly forbidden unless
# prior written permission is obtained from ThreatQuotient, Inc.
# --------------------------------------------------------------------------------------------------

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from .indicator import Indicator


class AdvancedSearch(object):
    """ Perform an advanced search

    :param Threatq tq: Threatq connection object
    :param dict query_params: Query parameters
    """

    def __init__(self, tq, query_params):
        self.tq = tq
        self.query_params = query_params

    def execute(self):
        """
        Executes the advanced search, returning a generator
        """

        offset = 0
        total = -1
        while total == -1 or offset < total:
            params = {'limit': 1000, 'offset': offset}
            resp = self.tq.post('/api/search/advanced', params=params, data=self.query_params)
            search_results = resp.get('data', [])
            offset += len(search_results)

            if search_results:
                total = resp['total']
                for i in search_results:
                    ind = Indicator(self.tq)
                    ind.value = i['value']
                    ind.iid = i['id']
                    ind.typename = i['type']['id']
                    ind.statusname = i['status']['id']

                    yield ind
