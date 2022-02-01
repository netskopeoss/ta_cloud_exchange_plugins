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


class Signature(ThreatQuotientObject):
    """
    Represents an IOC

    :param tq: API connection to use
    :type tq: :py:class:`~threatqsdk.Threatq`
    """

    def __init__(self, tq):

        if not tq:
            raise ValueError("Must provide a Threatq instance")

        self.tq = tq
        self.sid = None
        self.typeid = None

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
        self.type_id = self.tq.getsigparseridbyname(typename)

    def set_value(self, value):
        """ Set the value of this indicator.
        This action is not automatically mirrored to ThreatQuotient
        """
        self.text = value

    @staticmethod
    def _get_base_endpoint_name():
        return 'signatures'

    def _id(self):
        if not self.sid:
            raise exceptions.NotCreatedError(
                'Signature has not been created',
                object=self
            )
        return self.sid

    def _set_id(self, value):
        self.sid = value

    def _to_dict(self, **kwargs):
        # Ensure value is set
        if not self.text:
            raise ValueError("Cannot upload without a text")
        # Ensure typename is set
        if not self.type_id:
            raise ValueError("Cannot upload without a type_id")
        data = {
            'type_id': self.type_id,
            'text': self.text,
        }

        return data

    def _signature_url(self, sid):
        """ Get a link to the signature suitable for presentation to an
        end user

        :param int sid: Signature ID
        """

        base = self.tq.threatq_host + '/signatures/'

        return base + str(sid) + '/details'

    def fill_from_api_response(self, api_response):
        """ Fill ourselves in based on an API response """
        self.sid = api_response['id']
        self.value = api_response['value']

    def upload(self, normalize=True, sources=None, published=None):
        """ Upload this indicator to ThreatQuotient.
        Always creates a new indicator

        :param bool normalize: True if ThreatQ should normalize the indicator
                value

        :param sources: Converted to a list of sources as defined by
                :py:func:`~threatqsdk.source.make_source_list`

        :raises: :py:class:`~threatqsdk.exceptions.UploadFailedError` if
                the API does not give us an indicator ID back.

        :returns: Our indicator ID
        """

        if not self.statusname:
            raise ValueError("Must provide a Status")

        endpoint = '/api/' + self.__class__._get_base_endpoint_name() + '/import'
        data = self._to_dict()

        result = self.tq.post(endpoint, data).get('data')
        if not result or 'hash' not in result[0]:
            raise exceptions.UploadFailedError(result)

        result = result[0]

        sources = make_source_list(sources)
        if sources is not None and len(sources) > 0:
            source_list = [x.to_dict() for x in sources]
            for d in data:
                result['sources'] = source_list

        result['status'] = self.statusname

        endpoint = '/api/' + self.__class__._get_base_endpoint_name() + '/consume'
        result = self.tq.post(endpoint, [result]).get('data')
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
        """ Get a link to the signature suitable for presentation to an
        end user

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the indicator has yet to be created
        """
        if not self.sid:
            raise exceptions.NotCreatedError(object=self)

        return self._signature_url(self.sid)
