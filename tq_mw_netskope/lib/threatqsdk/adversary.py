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

from . import exceptions
from .source import make_source_list
from .tqobject import ThreatQuotientObject


class Adversary(ThreatQuotientObject):
    """ Represents an Adversary in the ThreatQ system """

    def __init__(self, tq):
        self.tq = tq

        self.name = None
        self.description = None
        self.published_at = None
        self.aid = None

    @staticmethod
    def _get_base_endpoint_name():
        return 'adversaries'

    def _id(self):
        return self.aid

    def _set_id(self, value):
        self.aid = value

    def fill_from_api_response(self, api_response):
        self.aid = api_response['id']
        self.name = api_response['name']
        self.description = None

    def _to_dict(self):
        raise NotImplementedError("Adversary uploads don't serialize well")

    def _adversary_url(self, aid):
        """ Get a link to the adversary suitable for presentation to an
        end user

        :param aid: Adversary ID
        :type aid: int
        """
        base = self.tq.threatq_host + '/adversaries/'
        return base + str(aid) + '/details'

    def upload(self, sources=None):
        """ Upload ourself to threatq """
        if self.name is None:
            raise ValueError("Cannot upload without a name")

        sources = make_source_list(sources)
        data = {
            'name': self.name
        }

        if self.published_at:
            data['published_at'] = self.validate_date(self.published_at)

        if sources is not None and len(sources) > 0:
            data['sources'] = [x.to_dict() for x in sources]
        post_res = self.tq.post('/api/adversaries', data=data)
        self._set_id(post_res['data']['id'])

        if self.description is not None:
            ep = self._get_api_endpoint() + '/description'
            self.tq.post(ep, data={
                'value': self.description
            })

        return self._id()

    def get_related_indicators(self):
        """ Get the indicators related to this Adversary

        .. deprecated:: 1.01
            Use :py:meth:`threatqsdk.tqobject.get_related_objects` instead
        """
        # imported here to prevent circular deps
        from threatqsdk.indicator import Indicator
        return self.get_related_objects(Indicator)

    def url(self):
        """ Get a link to the adversary suitable for presentation to an
        end user

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the indicator has yet to be created
        """
        if not self.aid:
            raise exceptions.NotCreatedError(object=self)

        return self._adversary_url(self.aid)

    def search(self, name):
        """ Search for an Adversary by name (exact)

        :param str name: adversary name

        :returns: Adversary
       """
        p = {'name': name}
        results = self.tq.get('/api/adversaries', params=p).get('data')
        if results:
            result = results[0]
            self.fill_from_api_response(result)
            try:
                self.description = self.tq.get(self._get_api_endpoint() + '/description').get('data')
            except Exception:
                self.description = ''
        else:
            raise ValueError('Adversary not found: {}'.format(name))


def get_adversary(tq, aid):
    a = Adversary(tq)
    a.aid = aid

    basic_data = tq.get(a._get_api_endpoint())['data']
    try:
        description = tq.get(a._get_api_endpoint() + '/description')['data']
    except Exception:
        description = ''

    a.name = basic_data['name']
    a.description = description
    a.published_at = basic_data['published_at']

    return a
