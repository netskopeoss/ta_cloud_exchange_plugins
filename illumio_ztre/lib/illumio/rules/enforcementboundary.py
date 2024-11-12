# -*- coding: utf-8 -*-

"""This module is a stub for enforcement boundary objects.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass

from illumio.util import pce_api

from .rule import BaseRule


@dataclass
@pce_api('enforcement_boundaries', is_sec_policy=True)
class EnforcementBoundary(BaseRule):
    """Represents an enforcement boundary in the PCE.

    Enforcement boundaries establish deny rules for workloads within their scope
    communicating on its defined services.

    Workloads in selective enforcement mode that fall within an enforcement
    boundary will have policy rules apply to them as if they were in full
    enforcement.

    Rules allowing traffic that would otherwise be denied by an enforcement
    boundary will override the boundary's deny rule.

    See https://docs.illumio.com/core/21.5/Content/Guides/security-policy/policy-enforcement/enforcement-boundaries.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> any_ip_list = pce.get_default_ip_list()
        >>> enforcement_boundary = illumio.EnforcementBoundary.build(
        ...     name='EB-BLOCK-RDP',
        ...     providers=[AMS],  # the special 'ams' literal denotes all workloads
        ...     consumers=[any_ip_list.href],
        ...     ingress_services=[
        ...         {'port': 3389, 'proto': 'tcp'},
        ...         {'port': 3389, 'proto': 'udp'},
        ...     ]
        ... )
        >>> enforcement_boundary = pce.enforcement_boundaries.create(enforcement_boundary)
        >>> enforcement_boundary
        EnforcementBoundary(
            href='/orgs/1/sec_policy/draft/enforcement_boundary/8',
            name='EB-BLOCK-RDP',
            providers=[
                Actor(
                    actors='ams',
                    ...
                )
            ],
            consumers=[
                Actor(
                    ip_list=Reference(
                        href='/orgs/1/sec_policy/active/ip_lists/1'
                    ),
                    ...
                )
            ],
            ingress_services=[
                ServicePort(port=3389, proto=6),
                ServicePort(port=3389, proto=17)
            ],
            ...
        )
    """
    name: str = None


__all__ = [
    'EnforcementBoundary',
]
