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


class Feed(object):
    """ Interact with Incoming Feeds

    :param Threatq tq: Threatq connection object
    """

    def __init__(self, tq):
        self.tq = tq
        self.id = None
        self.name = None
        self.namespace = None
        self.custom_fields = {}
        self.frequency = None
        self.category_id = None
        self.category = {}
        self.indicator_status_id = None
        self.tlp_id = None
        self.gate_oauth2_client_id = None
        self.last_import_at = None
        self.last_import_count = None
        self.is_active = None
        self.created_at = None
        self.updated_at = None

    def _parse_response(self, data):
        """ Parse API response for feed object

        :param dict d: dict of feed object from API
        """
        data_items = data.iteritems if hasattr(data, 'iteritems') else data.items  # generator for either Py 2 or 3
        for k, v in data_items():
            if k == 'is_active':
                if v == '' or v == 'False':
                    setattr(self, k, False)
                else:
                    setattr(self, k, True)
            else:
                setattr(self, k, v)

    def by_id(self, feed_id):
        """ Retrieve settings for a specific feed (by id)

        :param int feed_id: Feed ID
        """
        try:
            resp = self.tq.get('/api/connectors/{}'.format(feed_id))
            data = resp.get('data')
        except Exception:
            raise ValueError('Connector Does Not Exist')

        self._parse_response(data)

    def by_name(self, name):
        """ Retrieve settings for a specific feed (by name)

        :param int name: Feed Name
        """
        resp = self.tq.get('/api/connectors', params={'name': name})
        data = resp.get('data')
        if not data:
            raise ValueError('Connector Does Not Exist')

        self._parse_response(data[0])

    def from_dict(self, d):
        """ Parse JSON feed object from API

        :param dict d: Feed dict from API response
        """

        self._parse_response(d)

    def enable(self):
        """ Enable a feed """
        if not self.id:
            raise ValueError('Must specify Feed.id')

        try:
            resp = self.tq.put('/api/connectors/{}'.format(self.id), data={'is_active': True})
            data = resp.get('data')
        except Exception:
            raise ValueError('Connector Does Not Exist')

        self._parse_response(data)

    def disable(self):
        """ Disable a feed """
        if not self.id:
            raise ValueError('Must specify Feed.id')

        try:
            resp = self.tq.put('/api/connectors/{}'.format(self.id), data={'is_active': False})
            data = resp.get('data')
        except Exception:
            raise ValueError('Connector Does Not Exist')

        self._parse_response(data)
