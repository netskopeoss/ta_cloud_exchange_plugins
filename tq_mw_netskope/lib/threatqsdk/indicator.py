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

import datetime
import warnings

from . import exceptions
from .source import make_source_list
from .tqobject import ThreatQuotientObject


class Indicator(ThreatQuotientObject):
    """
    Represents an IOC

    :param tq: API connection to use
    :type tq: :py:class:`~threatqsdk.Threatq`
    """
    classes = {
        'IP Address': 'network',
        'URL': 'network',
        'FQDN': 'network',
        'MD5': 'host',
        'SHA-1': 'host',
        'SHA-256': 'host',
        'SHA-384': 'host',
        'SHA-512': 'host',
        'Email Address': 'network',
        'Filename': 'host',
        'Fuzzy Hash': 'host',
        'Mutex': 'host',
        'Registry Key': 'host',
        'User-agent': 'network',
        'CIDR Block': 'network',
        'Email Subject': 'network'
    }

    def __init__(self, tq):

        if not tq:
            raise ValueError("Must provide a Threatq instance")

        self.tq = tq
        self.iid = None
        self.statusname = None
        self.typename = None
        self.value = None
        self.published_at = None
        self.description = None

    def set_status(self, statusname):
        """ Set the status of this indicator.
        This action is not automatically mirrored to ThreatQuotient

        :param str statusname: Human-readable status name
        """
        self.statusname = statusname

    def set_type(self, typename):
        """ Set the type of this indicator.
        This action is not automatically mirrored to ThreatQuotient

        :param str typename: Human-readable type name
        """
        self.typename = typename

    def set_class(self, itype):
        """ Set the class of this indicator.
        This action is not automatically mirrored to ThreatQuotient

        :param str itype: Indicator type to derive the class from
        """
        if itype not in self.classes:
            raise ValueError(str(itype) + ' is not a valid indicator type')

        self.classname = self.classes[itype]

    def set_value(self, value):
        """ Set the value of this indicator.
        This action is not automatically mirrored to ThreatQuotient
        """
        self.value = value

    def set_published_at(self, published_at):
        """ Set published_at for this indicator.
        This action is not automatically mirrored to ThreatQuotient

        :param datetime_object published_at: datetime object
        """
        self.published_at = datetime.datetime.strftime(
            published_at, "%Y-%m-%d %H:%M:%S")

    def set_description(self, description):
        """ Set the description of this indicator.
        This action is not automatically mirrored to ThreatQuotient

        :param str description: Indicator Description
        """

        self.description = description

    @staticmethod
    def _get_base_endpoint_name():
        return 'indicators'

    def _id(self):
        if not self.iid:
            raise exceptions.NotCreatedError(
                'Indicator has not been created',
                object=self
            )
        return self.iid

    def _set_id(self, value):
        self.iid = value

    def _to_dict(self, **kwargs):
        # Ensure value is set
        if not self.value:
            raise ValueError("Cannot upload without a value")
        # Ensure typename is set
        if not self.typename:
            raise ValueError("Cannot upload without a typename")
        # Ensure statusname is set
        if not self.statusname:
            raise ValueError("Cannot upload without a statusname")

        data = {
            'type': self.typename,
            'status': self.statusname,
            'value': self.value,
        }

        if self.published_at:
            data['published_at'] = self.validate_date(self.published_at)

        if self.description:
            data['description'] = self.description

        if hasattr(self, 'classname'):
            data['class'] = self.classname

        if 'normalize' in kwargs and kwargs['normalize']:
            data['normalize'] = 'Y'
        return [data]

    def _indicator_url(self, iid):
        """ Get a link to the indicator suitable for presentation to an
        end user

        :param int iid: Indicator ID
        """

        base = self.tq.threatq_host + '/indicators/'

        return base + str(iid) + '/details'

    def fill_from_api_response(self, api_response):
        """ Fill ourselves in based on an API response """
        self.iid = api_response['id']
        self.value = api_response['value']
        type_id = api_response['type_id']
        self.typename = self.tq.gettypename(type_id)
        status_id = api_response['status_id']
        self.statusname = self.tq.getstatusname(status_id)

    def upload(self, normalize=True, sources=None, published=None):
        """ Upload this indicator to ThreatQuotient using the consume endpoint.
        Always creates a new indicator

        :param bool normalize: True if ThreatQ should normalize the indicator
                value

        :param sources: Converted to a list of sources as defined by
                :py:func:`~threatqsdk.source.make_source_list`

        :raises: :py:class:`~threatqsdk.exceptions.UploadFailedError` if
                the API does not give us an indicator ID back.

        :returns: Our indicator ID
        """
        data = self._to_dict()
        if normalize:
            data[0]['normalize'] = 'Y'

        sources = make_source_list(sources)
        s = None
        if sources is not None and len(sources) > 0:
            msg = 'Ability to add Sources during upload will be removed in a future release'
            warnings.warn(msg, DeprecationWarning)
            source_list = [x.to_dict() for x in sources]
            s = source_list[0]
            for d in data:
                d['sources'] = source_list

        if s and 'published_at' in s:
            data[0]['published_at'] = s['published_at']
        if published:
            data[0]['published_at'] = published

        result = self.tq.post(
            '/api/indicators/consume/new', data=data).get('data')
        if not result or 'id' not in result[0]:
            raise exceptions.UploadFailedError(result)

        self._set_id(result[0]['id'])
        return self._id()

    def relate_indicator(self, ind):
        """ Relate an indicator to ourselves

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                either indicator has yet to be created
        :raises: :py:class:`~threatqsdk.exceptions.ActionFailedError` if
                The relation is not added successfully

        .. deprecated:: 1.00
            Use :py:meth:`threatqsdk.tqobject.ThreatQuotientObject.relate_object` instead.
        """
        return self.relate_object(ind)

    def get_related_indicators(self):
        """ Get the IDs indicators that are related to this one

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                either indicator has yet to be created

        .. deprecated:: 1.01
            Use :py:meth:`~threatqsdk.tqobject.ThreatQuotientObject.get_related_objects` instead
        """
        from threatqsdk.indicator import Indicator
        return self.get_related_objects(Indicator)

    def get_related_adversaries(self):
        """ Get the adversaries that are related to this indicator

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                either indicator has yet to be created

        :returns: list of :py:class:`~threatqsdk.adversary.Adversary`

        .. deprecated:: 1.01
            Use :py:meth:`~threatqsdk.tqobject.ThreatQuotientObject.get_related_objects` instead
        """
        # prevent circular imports
        from threatqsdk.adversary import Adversary
        return self.get_related_objects(Adversary)

    def url(self):
        """ Get a link to the indicator suitable for presentation to an
        end user

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the indicator has yet to be created
        """
        if not self.iid:
            raise exceptions.NotCreatedError(object=self)

        return self._indicator_url(self.iid)
