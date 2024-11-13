# -*- coding: utf-8 -*-

"""This module provides classes for security policy provisioning.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
import re
from dataclasses import dataclass
from typing import List

from .exceptions import IllumioException
from .util import (
    JsonObject,
    Reference,
    MutableObject,
    ImmutableObject,
    HREF_REGEX
)
from .policyobjects import LabelSet


@dataclass
class FirewallSetting(MutableObject):
    allow_dhcp_client: bool = None
    log_dropped_multicast: bool = None
    log_dropped_broadcast: bool = None
    allow_traceroute: bool = None
    allow_ipv6: bool = None
    ipv6_mode: str = None
    network_detection_mode: str = None
    ike_authentication_type: str = None
    static_policy_scopes: List[LabelSet] = None
    firewall_coexistence: List[LabelSet] = None
    containers_inherit_host_policy_scopes: List[LabelSet] = None
    blocked_connection_reject_scopes: List[LabelSet] = None
    loopback_interfaces_in_policy_scopes: List[LabelSet] = None


@dataclass
class PolicyChangeset(JsonObject):
    label_groups: List[Reference] = None
    services: List[Reference] = None
    rule_sets: List[Reference] = None
    ip_lists: List[Reference] = None
    virtual_services: List[Reference] = None
    firewall_settings: List[Reference] = None
    enforcement_boundaries: List[Reference] = None
    secure_connect_gateways: List[Reference] = None
    virtual_servers: List[Reference] = None

    @staticmethod
    def build(hrefs: List[str]):
        changeset = PolicyChangeset()
        for href in hrefs:
            match = re.match(HREF_REGEX, href)
            if match:
                object_type = match.group('type')
                arr = getattr(changeset, object_type) or []
                arr.append(Reference(href=href))
                setattr(changeset, object_type, arr)
            else:
                raise IllumioException('Invalid HREF in policy provision changeset: {}'.format(href))
        return changeset


@dataclass
class PolicyObjectCounts(JsonObject):
    label_groups: int = None
    services: int = None
    rule_sets: int = None
    ip_lists: int = None
    virtual_services: int = None
    firewall_settings: int = None
    enforcement_boundaries: int = None
    secure_connect_gateways: int = None
    virtual_servers: int = None


@dataclass
class PolicyVersion(ImmutableObject):
    commit_message: str = None
    version: int = None
    workloads_affected: int = None
    object_counts: PolicyObjectCounts = None


__all__ = [
    'FirewallSetting',
    'PolicyVersion',
    'PolicyObjectCounts',
    'PolicyChangeset'
]
