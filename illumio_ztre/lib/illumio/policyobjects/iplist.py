# -*- coding: utf-8 -*-

"""This module provides classes related to IP list policy objects.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import List

from illumio import IllumioException
from illumio.util import JsonObject, MutableObject, pce_api


@dataclass
class IPRange(JsonObject):
    """Represents a range of one or more IP addresses in an IP list.

    Args:
        from_ip (str, optional): IP address at the start of the range. Can be a
            single IP or CIDR range, e.g. "10.0.0.0/8".
        to_ip (str, optional): IP address at the end of the range. If provided,
            ``from_ip`` must be a single IP address
        exclusion (bool, optional): if True, this range represents an exclusion
            rather than an inclusion in the IP list object.
        description (str, optional): optional description.

    Raises:
        IllumioException: if an invalid IP range is given.
    """
    from_ip: str = None
    to_ip: str = None
    exclusion: bool = None
    description: str = None

    def _validate(self):
        try:
            from_net = ip_network(self.from_ip)
            if self.to_ip:
                to_ip = ip_address(self.to_ip)
                if from_net.prefixlen < 32:
                    raise "Can't specify CIDR block and to_ip in same range"
                if to_ip <= from_net.network_address:
                    raise "to_ip address must be greater than from_ip address"
        except Exception as e:
            raise IllumioException("Invalid IP range: {}".format(e))
        return super()._validate()


@dataclass
class FQDN(JsonObject):
    """Represents a fully-qualified domain name associated with an IP list.

    Args:
        fqdn (str, optional): fully-qualified domain name.
        description (str, optional): optional description.
    """
    fqdn: str = None
    description: str = None


@dataclass
@pce_api('ip_lists', is_sec_policy=True)
class IPList(MutableObject):
    """Represents an IP list in the PCE.

    IP lists are list of IP addresses, subnets, CIDR blocks, and/or FQDNs.
    They can be used in conjunction with other security policy objects to
    allow or deny traffic from these defined ranges.

    See https://docs.illumio.com/core/21.5/Content/Guides/security-policy/security-policy-objects/ip-lists.htm

    Usage:
        >>> from illumio import PolicyComputeEngine, IPList, IPRange
        >>> pce = PolicyComputeEngine('my.pce.com')
        >>> pce.set_credentials('api_key_username', 'api_key_secret')
        >>> ip_list = IPList(
        ...     name='IPL-INTERNAL',
        ...     ip_ranges=IPRange(
        ...         from_ip='192.168.0.0/16'
        ...     )
        ... )
        >>> ip_list = pce.ip_lists.create(ip_list)
        >>> ip_list
        IPList(
            href='/orgs/1/sec_policy/draft/ip_lists/22',
            name='IPL-INTERNAL',
            ip_ranges=IPRange(
                from_ip='192.168.0.0/16'
            ),
            ...
        )
    """
    ip_ranges: List[IPRange] = None
    fqdns: List[FQDN] = None


__all__ = [
    'IPRange',
    'FQDN',
    'IPList',
]
