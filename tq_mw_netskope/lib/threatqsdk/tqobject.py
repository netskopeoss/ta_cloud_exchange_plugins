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

from abc import abstractmethod
import datetime
import warnings

try:
    from abc import ABC
except ImportError:  # Python 2
    from abc import ABCMeta

    class ABC(object):
        __metaclass__ = ABCMeta

    del ABCMeta

from .source import make_source_list
from .exceptions import ActionFailedError


class ThreatQuotientObject(ABC):
    """ Abstract base class for all ThreatQuotient objects """

    def __init__(self, tq):
        self.tq = tq

    @abstractmethod
    def _get_base_endpoint_name():
        """ Get the name of the endpoint """

    def _get_api_endpoint(self):
        base_endpoint = self.__class__._get_base_endpoint_name()
        return "/api/" + base_endpoint + "/" + str(self._id())

    @abstractmethod
    def _id(self):
        """ Get the ID of this object within its namespace """
        pass

    @abstractmethod
    def _set_id(self, value):
        """ Set the ID value """
        pass

    @abstractmethod
    def fill_from_api_response(self, api_response):
        """ Fill ourselves in based on an API response """
        pass

    @abstractmethod
    def _to_dict(self, **kwargs):
        """ Serialize this object to a representation suitable for
        upload to threatquotient
        """
        pass

    def add_comment(self, value):

        data = {"value": value}

        res = self.tq.post(
            self._get_api_endpoint() + "/comments?with=sources", data=data
        )

        if not res or "data" not in res:
            raise ActionFailedError(res)

    def get_comments(self):
        p = {"with": "sources"}
        res = self.tq.get(self._get_api_endpoint() + "/comments", params=p)
        comments = res.get("data")
        return comments

    def add_attribute(
        self, key, value, sources=None, modify=False, published_at=None
    ):
        """ Add an attribute to this object

        :param str key: Attribute name
        :param str value: Attribute value. If of type `~list`, all values
                will be added to to the object with the same key
        :param sources: Converted to a list of sources as defined by
                :py:func:`~threatqsdk.source.make_source_list`

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the indicator has yet to be created
        :raises: :py:class:`~threatqsdk.exceptions.ActionFailedError` if
                The attribute is not added successfully

        :returns: The unique ID of the added attribute, or a list of attribute
                IDs if values was a list.
        """

        # Only throw error if None type or is an empty string
        if value is None or (isinstance(value, str) and value.strip() == ""):
            raise ValueError("Must supply an attribute value.")

        res_data = None

        values = value
        values_list = type(values) == list
        if not values_list:
            values = [value]

        sources = make_source_list(sources)
        source_data = []
        if sources is not None:
            source_data = [x.to_dict() for x in sources]

        attribute_ids = []
        for v in values:
            data = {
                "name": key,
                "value": v,
                "published_at": self.validate_date(published_at),
            }
            if len(source_data) > 0:
                data["sources"] = source_data

            found = False
            if modify:
                attrs = self.get_attributes()
                for v in values:
                    for a in attrs:
                        if a["attribute"]["name"] == key:
                            if a["value"] == v:
                                continue

                            url = (
                                self._get_api_endpoint()
                                + "/attributes/"
                                + str(a["id"])
                            )
                            new = {"name": key, "value": v}
                            if len(source_data) > 0:
                                new["sources"] = source_data
                            res = self.tq.put(url, new)
                            res_data = [res["data"]]
                            found = True

                    # FIXME Won't work right with multiple attributes

            if not found:
                res = self.tq.post(
                    self._get_api_endpoint() + "/attributes", data=data
                )

                if not res or "data" not in res:
                    raise ActionFailedError(res)

                res_data = res["data"]
                if len(res_data) == 0 or "attribute_id" not in res_data[0]:
                    raise ActionFailedError(res)
                attribute_ids.append(res_data[0]["attribute_id"])

        if values_list:
            return attribute_ids
        else:
            if not res_data:
                return

            return res_data[0]["attribute_id"]

    def get_attributes(self):
        """ Get attributes associated with this object

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the object has yet to be created
        """

        endpoint = self._get_api_endpoint() + "/attributes"
        results = self.tq.get(endpoint, withp="attribute")
        if "data" not in results:
            return {}

        return results["data"]
        # tr = {}
        # for attribute in results['data']:
        #    tr[attribute['attribute']['name']] = attribute['value']
        # return tr

    def _get_api_suffix(self, obj_type):
        return obj_type._get_base_endpoint_name()

    def relate_object(self, obj):
        """ Relate this object to another in the system

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                either object has not been created
        """
        suffix = self._get_api_suffix(obj.__class__)
        endpoint = self._get_api_endpoint() + "/" + suffix
        obj_id = obj._id()
        results = self.tq.post(endpoint, data={"id": obj_id})

        results = results.get("data")
        if not results or "pivot" not in results[0]:
            raise ActionFailedError("Relate indicators")

    def get_related_objects(self, obj_type):
        """ Get the objects related to this one of type ``obj_type``

        Note: adversary to adversary relations currently return an empty
        list, until the API adds an endpoint for that

        :param obj_type: Object type to get. Should be a subclass of
            :py:class:`~threatqsdk.tqobject.ThreatQuotientObject`.

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the object has yet to be created

        :returns: A list of objects of type ``obj_type``
        """
        suffix = self._get_api_suffix(obj_type)
        if obj_type == self.__class__ and suffix == "adversaries":
            return []
        endpoint = self._get_api_endpoint() + "/" + suffix
        results = self.tq.get(endpoint)
        if "data" not in results:
            return []

        tr = []
        for obj in results["data"]:
            inst = obj_type(self.tq)
            inst.fill_from_api_response(obj)
            tr.append(inst)
        return tr

    def validate_date(self, ds):
        """ Validate a date string is: %Y-%m-%d %H:%M:%S. Print warning if not in correct format.

        :param string ds: Date string

        :returns: string ds
        """
        error_message = " is not in %Y-%m-%d %H:%M:%S format"
        if ds:
            try:
                datetime.datetime.strptime(ds, "%Y-%m-%d %H:%M:%S")
            except Exception:
                warnings.warn(ds + error_message)

        return ds
