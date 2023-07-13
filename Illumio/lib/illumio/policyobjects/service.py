# -*- coding: utf-8 -*-

"""This module provides classes related to services and service ports.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List, Union

from illumio import IllumioException
from illumio.util import (
    JsonObject,
    MutableObject,
    ICMP_CODE_MAX,
    ICMP_TYPE_MAX,
    PORT_MAX,
    pce_api,
    convert_protocol,
    validate_int
)


@dataclass
class BaseService(JsonObject):
    port: int = None
    proto: Union[str, int] = None

    def __post_init__(self):
        if type(self.proto) is str:
            self.proto = int(self.proto) if self.proto.isnumeric() else convert_protocol(self.proto)
        super().__post_init__()

    def _validate(self):
        if self.port:
            validate_int(self.port, maximum=PORT_MAX)
        super()._validate()


@dataclass
class ServicePort(BaseService):
    """Represents a port, port range, Windows service, or traffic flow service."""
    to_port: int = None
    icmp_type: int = None
    icmp_code: int = None
    service_name: str = None
    process_name: str = None
    windows_service_name: str = None
    user_name: str = None

    def _validate(self):
        if self.to_port:
            validate_int(self.to_port, maximum=PORT_MAX)
            if self.to_port <= self.port:
                raise IllumioException("Invalid port range: to_port must be higher than port")
        if self.icmp_type:
            validate_int(self.icmp_type, maximum=ICMP_TYPE_MAX)
        if self.icmp_code:
            validate_int(self.icmp_code, maximum=ICMP_CODE_MAX)
        super()._validate()


@dataclass
@pce_api('services', is_sec_policy=True)
class Service(MutableObject):
    """Represents a service in the PCE.

    A service can be port-based or process-based (Windows services).

    Each service contains one or more objects defining the port, protocol, and/or
    process name used by an application running on a workload.

    Service objects are used to write rules or enforcement boundaries to allow
    or deny traffic on its defined ports and processes for workloads in the network.

    See https://docs.illumio.com/core/21.5/Content/Guides/security-policy/security-policy-objects/services.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> service = illumio.Service(
        ...     name='S-HTTP',
        ...     service_ports=[
        ...         illumio.ServicePort(port=80, proto='tcp'),
        ...         illumio.ServicePort(port=443, proto='tcp')
        ...     ]
        ... )
        >>> service = pce.services.create(service)
        >>> service
        Service(
            href='/orgs/1/sec_policy/draft/services/15',
            name='S-HTTP',
            service_ports=[
                ServicePort(
                    port=80,
                    proto=6,
                    ...
                ),
                ...
            ],
            ...
        )
    """
    process_name: str = None
    service_ports: List[ServicePort] = None
    windows_services: List[ServicePort] = None
    windows_egress_services: List[ServicePort] = None


__all__ = [
    'BaseService',
    'ServicePort',
    'Service',
]
