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

from .source import make_source_list
from .tqobject import ThreatQuotientObject


class BulkSignature(ThreatQuotientObject):

    def __init__(self, tq):
        if not tq:
            raise ValueError("Must provide Threatq object")

        self.tq = tq

        self.value = None
        self.name = None
        self.type_id = None
        self.status = None
        self.description = None
        self.published_at = ''
        self.hash = None
        self.attributes = []
        self.indicators = []
        self.events = []
        self.adversaries = []

    def set_value(self, value):
        """ Set the value of this signature.
        This action is not automatically mirrored to ThreatQuotient
        """
        self.value = value

    def set_name(self, name):
        """ Set the name of this signature.
        This action is not automatically mirrored to ThreatQuotient
        """
        self.name = name

    def set_type(self, typename):
        """ Set the type of this signature.
        This action is not automatically mirrored to ThreatQuotient

        :param str typename: Human-readable type name
        """
        self.type_id = self.tq.getsigparseridbyname(typename)

    def set_status(self, statusname):
        """ Set the status of this signature.
        This action is not automatically mirrored to ThreatQuotient

        :param str statusname: Human-readable status name
        """
        self.status = statusname

    def set_published_at(self, published_at):
        """ Set published_at for this signature.
        This action is not automatically mirrored to ThreatQuotient

        :param datetime_object published_at: datetime object
        """
        self.published_at = datetime.datetime.strftime(
            published_at, "%Y-%m-%d %H:%M:%S")

    def set_description(self, description):
        """ Set the description of this signature.
        This action is not automatically mirrored to ThreatQuotient

        :param str description: Signature Description
        """

        self.description = description

    def relate_indicator(self, value, itype):
        """ Relate the indicator with signature.

        :param str value: Indicator value
        :param str itype: Indicator type (string)
        """
        self.indicators.append({'value': value, 'type': itype})

    def add_attribute(self, name, value, source=None):
        """ Add an attribute key/value pair
        This action is not automatically mirrored to ThreatQuotient

        :param str name: attribute name/key
        :param str value: attribute value
        :param str/list source: attribute source
        """
        if source:
            sources = [x.to_dict() for x in make_source_list(source)]
            self.attributes.append({'name': name, 'value': value, 'sources': [{'name': sources}]})
        else:
            self.attributes.append({'name': name, 'value': value})

    def relate_event(self, eid):
        """ Relate to an event

        :param int eid: Event id
        """
        self.events.append({'id': eid})

    def relate_adversary(self, aid):
        """ Relate to an adversary

        :param int aid: Adversary id
        """
        self.adversaries.append({'id': aid})

    def to_dict(self):
        # Ensure value is set
        if not self.value:
            raise ValueError("Cannot upload without a value")
        # Ensure typename is set
        if not self.type_id:
            raise ValueError("Cannot upload without a type")
        # Ensure statusname is set
        if not self.status:
            raise ValueError("Cannot upload without a statusname")
        if self.published_at:
            self.published_at = self.validate_date(self.published_at)

        res = {}

        res['status'] = self.status
        res['value'] = self.value
        res['name'] = self.name
        res['type_id'] = self.type_id
        res['published_at'] = self.published_at
        res['description'] = self.description
        if self.hash:
            res['hash'] = self.hash
        res['attributes'] = self.attributes
        res['indicators'] = self.indicators
        res['events'] = self.events
        res['adversaries'] = self.adversaries

        return res

    @staticmethod
    def _get_base_endpoint_name():
        pass

    def _id(self):
        pass

    def _set_id(self, value):
        pass

    def _to_dict(self, **kwargs):
        pass

    def fill_from_api_response(self, api_response):
        pass
