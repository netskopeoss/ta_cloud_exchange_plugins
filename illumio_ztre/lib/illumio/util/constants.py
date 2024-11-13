# -*- coding: utf-8 -*-

"""This module provides constant values and enumerations used by the PCE REST API.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
import re
from enum import Enum, EnumMeta

#: Active policy version path literal.
ACTIVE = 'active'

#: Draft policy version path literal.
DRAFT = 'draft'

#: Used in rules and enforcement boundaries to denote that all
#: workloads should be affected.
AMS = 'ams'

#: Used in resolve_labels_as block in rule creation to denote that
#: workloads matching the rule scope should be affected.
RESOLVE_AS_WORKLOADS = 'workloads'

#: Used in resolve_labels_as block in rule creation to denote that
#: virtual services matching the rule scope should be affected.
RESOLVE_AS_VIRTUAL_SERVICES = 'virtual_services'

#: Name of the default global IP list.
ANY_IP_LIST_NAME = 'Any (0.0.0.0/0 and ::/0)'

#: Name of the default global Service.
ALL_SERVICES_NAME = 'All Services'

#: Max port number.
PORT_MAX = 65535

#: Max value for the ICMP header Code field.
#: See https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes
ICMP_CODE_MAX = 15

#: Max value for the ICMP header Type field.
#: See https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types
ICMP_TYPE_MAX = 255

FQDN_REGEX = re.compile('(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)')
HREF_REGEX = re.compile('^\/orgs\/\d+\/(?:sec_policy\/(?:active|draft)\/)?(?P<type>[a-zA-Z_]+)\/(?P<uid>[a-zA-Z0-9-]+)$')

#: Upper limit on the number of objects that can be sent to PCE bulk change
#: endpoints in a single request.
BULK_CHANGE_LIMIT = 1000

PCE_APIS = {}


class IllumioEnumMeta(EnumMeta):
    """Metaclass to provide a common contains check for enumerations."""

    def __contains__(cls, value):
        if value is None:
            return False
        if type(value) is str:
            value = value.lower()
        if isinstance(type(value), IllumioEnumMeta):
            value = value.value
        return value in cls._value2member_map_


class LinkState(str, Enum, metaclass=IllumioEnumMeta):
    """Network interface link state enumeration."""
    UP = 'up'
    DOWN = 'down'
    UNKNOWN = 'unknown'


class EnforcementMode(str, Enum, metaclass=IllumioEnumMeta):
    """Workload enforcement mode enumeration."""
    IDLE = 'idle'
    VISIBILITY_ONLY = 'visibility_only'
    FULL = 'full'
    SELECTIVE = 'selective'


class VisibilityLevel(str, Enum, metaclass=IllumioEnumMeta):
    """Workload visibility level enumeration."""
    FLOW_FULL_DETAIL = 'flow_full_detail'
    FLOW_SUMMARY = 'flow_summary'
    FLOW_DROPS = 'flow_drops'
    FLOW_OFF = 'flow_off'
    ENHANCED_DATA_COLLECTION = 'enhanced_data_collection'


class PolicyDecision(str, Enum, metaclass=IllumioEnumMeta):
    """Traffic flow policy decision enumeration."""
    ALLOWED = 'allowed'
    BLOCKED = 'blocked'
    POTENTIALLY_BLOCKED = 'potentially_blocked'
    UNKNOWN = 'unknown'


class Transmission(str, Enum, metaclass=IllumioEnumMeta):
    """Traffic flow transmission enumeration."""
    BROADCAST = 'broadcast'
    MULTICAST = 'multicast'
    UNICAST = 'unicast'


class FlowDirection(str, Enum, metaclass=IllumioEnumMeta):
    """Traffic flow direction enumeration."""
    INBOUND = 'inbound'
    OUTBOUND = 'outbound'


class TrafficState(str, Enum, metaclass=IllumioEnumMeta):
    """Traffic flow state enumeration."""
    ACTIVE = 'active'
    CLOSED = 'closed'
    TIMED_OUT = 'timed out'
    SNAPSHOT = 'snapshot'
    NEW = 'new'
    UNKNOWN = 'unknown'
    INCOMPLETE = 'incomplete'


class ApplyTo(str, Enum, metaclass=IllumioEnumMeta):
    """Virtual service apply to value enumeration."""
    HOST_ONLY = 'host_only'
    INTERNAL_BRIDGE_NETWORK = 'internal_bridge_network'


class VENType(str, Enum, metaclass=IllumioEnumMeta):
    """VEN type enumeration."""
    SERVER = 'server'
    ENDPOINT = 'endpoint'
    CONTAINERIZED = 'containerized'


class ChangeType(str, Enum, metaclass=IllumioEnumMeta):
    """Resource event change type enumeration."""
    CREATE = 'create'
    UPDATE = 'update'
    DELETE = 'delete'


class EventSeverity(str, Enum, metaclass=IllumioEnumMeta):
    """Event severity enumeration."""
    EMERGENCY = 'emerg'
    ALERT = 'alert'
    CRITICAL = 'crit'
    ERROR = 'err'
    WARNING = 'warning'
    NOTICE = 'notice'
    INFO = 'info'
    DEBUG = 'debug'


class EventStatus(str, Enum, metaclass=IllumioEnumMeta):
    """Event status enumeration."""
    SUCCESS = 'success'
    FAILURE = 'failure'


__all__ = [
    'ACTIVE',
    'DRAFT',
    'AMS',
    'RESOLVE_AS_WORKLOADS',
    'RESOLVE_AS_VIRTUAL_SERVICES',
    'ANY_IP_LIST_NAME',
    'ALL_SERVICES_NAME',
    'PORT_MAX',
    'ICMP_CODE_MAX',
    'ICMP_TYPE_MAX',
    'FQDN_REGEX',
    'HREF_REGEX',
    'BULK_CHANGE_LIMIT',
    'PCE_APIS',
    'EnforcementMode',
    'LinkState',
    'EnforcementMode',
    'VisibilityLevel',
    'PolicyDecision',
    'Transmission',
    'FlowDirection',
    'TrafficState',
    'ApplyTo',
    'VENType',
    'ChangeType',
    'EventSeverity',
    'EventStatus',
]
