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
import json

from .source import make_source_list
from .tqobject import ThreatQuotientObject


class BulkIndicator(ThreatQuotientObject):

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
            raise ValueError("Must provide Threatq object")

        self.tq = tq

        self.value = None
        self.status = None
        self.attributes = []
        self.typename = None
        self.indicators = []
        self.events = []
        self.adversaries = []
        self.published_at = ""
        self.last_detected_at = ""
        self.normalize = True
        self.description = None

    def set_status(self, statusname):
        """ Set the status of this indicator.
        This action is not automatically mirrored to ThreatQuotient

        :param str statusname: Human-readable status name
        """
        self.status = statusname

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

    def set_last_detected_at(self, last_detected_at):
        """ Set last_detected_at for this indicator.
        This action is not automatically mirrored to ThreatQuotient

        :param datetime_object last_detected_at: datetime object
        """
        self.last_detected_at = datetime.datetime.strftime(
            last_detected_at, "%Y-%m-%d %H:%M:%S")

    def set_normalize(self, normalize):
        """ Set normalize for this indicator.
        This action is not automatically mirrored to ThreatQuotient

        :param bool normalize: boolean for normalization
        """

        if not isinstance(normalize, bool):
            raise ValueError('Normalize value must be of type boolean')

        self.normalize = normalize

    def set_description(self, description):
        """ Set the description of this indicator.
        This action is not automatically mirrored to ThreatQuotient

        :param str description: Indicator Description
        """

        self.description = description

    def add_attribute(self, name, value, source=None):
        """ Add an attribute key/value pair
        This action is not automatically mirrored to ThreatQuotient

        :param str name: attribute name/key
        :param str value: attribute value
        :param str/list source: attribute source
        """
        if source:
            sources = [x.to_dict() for x in make_source_list(source)]
            self.attributes.append({'name': name, 'value': value, 'sources': sources})
        else:
            self.attributes.append({'name': name, 'value': value})

    def to_dict(self):
        # Ensure value is set
        if not self.value:
            raise ValueError("Cannot upload without a value")
        # Ensure typename is set
        if not self.typename:
            raise ValueError("Cannot upload without a typename")
        # Ensure statusname is set
        if not self.status:
            raise ValueError("Cannot upload without a statusname")
        if self.published_at:
            self.published_at = self.validate_date(self.published_at)
        if self.last_detected_at:
            self.last_detected_at = self.validate_date(self.last_detected_at)

        res = {}

        res['status'] = {'id': self.tq.getstatusidbyname(self.status)}
        res['value'] = self.value
        res['attributes'] = self.attributes
        res['type'] = {'name': self.typename}
        res['class'] = self.classes.get(self.typename)
        if self.normalize:
            res['normalize'] = 'Y'
        else:
            res['normalize'] = 'N'
        res['indicators'] = self.indicators
        res['events'] = self.events
        res['adversaries'] = self.adversaries
        res['published_at'] = self.published_at
        res['last_detected_at'] = self.last_detected_at

        if self.description:
            res['description'] = self.description

        return res

    def relate_indicator(self, value, itype):
        """ Relate the values of two indicators.
        """
        self.indicators.append({'value': value, 'type': itype})

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

    def __str__(self):
        res = {}

        res['status'] = {'id': self.tq.getstatusidbyname(self.status)}
        res['value'] = self.value
        res['attributes'] = self.attributes
        res['type'] = {'name': self.typename}
        res['class'] = self.classes.get(self.typename)

        return json.dumps(res)

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
