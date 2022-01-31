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

from functools import partial


class Operation(object):
    """ Represents an Adversary in the ThreatQ system """
    def __init__(self, tq, name, oid=None, actions=None, enabled=None):

        if not tq:
            raise ValueError("Must pass TQ object.")

        if not name:
            raise ValueError("Must pass Operation name.")

        self.tq = tq
        self.name = name
        self.actions = actions
        if enabled is not None:
            self.enabled = bool(enabled)
        self.oid = oid

        if self.oid is None:
            r = tq.get('/api/plugins?with=action.objectType')
            plugins = r.get('data')
            for p in plugins:
                if p['name'] == name:
                    self.oid = p['id']
                    self.actions = p['action']
                    self.enabled = bool(p['enabled'])

        if self.oid is None:
            raise ValueError("No plugin found.")

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<{} operation at {}>".format(self.name, hex(id(self)))

    @classmethod
    def from_dict(cls, tq, obj):
        '''
        This will crete an operation from a dictionary, rather than by
        selecting a name.

        The key difference is that this will not make a call to the API
        '''
        try:
            name = obj['name']
            oid = obj['id']
            actions = obj['action']
            enabled = obj['enabled']
        except KeyError as e:
            raise KeyError(str(e))
        return cls(tq, name, oid=oid, actions=actions, enabled=enabled)

    @classmethod
    def list_from_tq(cls, tq, active_only=True):
        '''
        This will create and return a list of Operation objects from the
        associated Tq instance

        :param threatqsdk.Threatq tq: TQ Connection instance
        :param bool active_only: Determines whether to include only active
            operations
        :returns: List of Operation Objects
        '''
        if not tq:
            raise ValueError("Must pass TQ object.")

        resp = tq.get("/api/plugins?with=action.objectType")
        if "total" not in resp:
            raise ValueError("Unknown Error occurred while fetching Operations")
        if resp["total"] == 0:
            return []

        ops = []
        for op in resp["data"]:
            if (
                not active_only or
                (active_only and bool(op['enabled']))
            ):
                ops.append(cls.from_dict(tq, op))

        return ops

    def get_valid_object_types(self):
        '''
        This will retrieve all object types that actions associated with this
        Operation can act on.

        :returns: List of type ids
        '''
        retList = set()

        for action in self.actions:
            for object_type in action["object_type"]:
                retList.add(object_type["object_type_id"])

        return list(retList)

    def get_actions_for_type(self, type_id):
        '''
        This returns a list of actionable calls for actions of this operation.
        '''
        retList = []
        for action in self.actions:
            for object_type in action['object_type']:
                if object_type['object_type_id'] == type_id:
                    retList.append(partial(
                        self.execute,
                        action=action['name'],
                        itype=object_type['object_type'],
                        opname=self.name
                    ))
        return retList

    def execute(self, action, iid, itype, **kwargs):

        data = {'action': action, 'id': iid, 'type': itype}
        r = self.tq.post('/api/plugins/%i/execute' % self.oid, data=data)

        if 'data' not in r:
            return None

        data = r.get('data').get('data')

        return data
