# -*- coding: utf-8 -*-

"""This module provides classes related to virtual services.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio import IllumioException
from illumio.util import (
    IllumioObject,
    Reference,
    MutableObject,
    ApplyTo,
    PORT_MAX,
    pce_api,
    validate_int
)

from .service import BaseService, ServicePort


@dataclass
class ServiceAddress(BaseService):
    """Defines a Service Address record for use in a Virtual Service address pool.

    A ServiceAddress can be defined with either an IP address or FQDN.

    If an IP is provided, one of a port number or network object HREF
    must be provided as well.

    If an FQDN is given it's sufficient by itself, but description or
    port values can optionally be provided.
    """
    ip: str = None
    fqdn: str = None
    network: Reference = None
    description: str = None


@dataclass
@pce_api('virtual_services', is_sec_policy=True)
class VirtualService(MutableObject):
    """Represents a virtual service object in the PCE.

    Virtual services provide an abstraction for a service that can be bound to
    one or more workloads. This can be useful when a workload is running multiple
    services, or multiple instances of the same service for different apps.

    See https://docs.illumio.com/core/21.5/Content/Guides/security-policy/security-policy-objects/virtual-services.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> role_label = pce.labels.create({'key': 'role', 'value': 'R-Tomcat'})
        >>> app_label = pce.labels.create({'key': 'app', 'value': 'A-App'})
        >>> env_label = pce.labels.create({'key': 'env', 'value': 'E-Dev'})
        >>> loc_label = pce.labels.create({'key': 'loc', 'value': 'L-NYC'})
        >>> tomcat_svc = pce.services.create(illumio.Service(
        ...     name='S-Tomcat',
        ...     service_ports=[
        ...         {
        ...             'port': 80,
        ...             'proto': illumio.convert_protocol('tcp')
        ...         },
        ...         {
        ...             'port': 443,
        ...             'proto': illumio.convert_protocol('tcp')
        ...         }
        ...     ]
        ... )
        >>> virtual_service = illumio.VirtualService(
        ...     name='VS-Tomcat',
        ...     apply_to=illumio.ApplyTo.HOST_ONLY,
        ...     service=tomcat_svc,
        ...     labels=[role_label, app_label, env_label, loc_label]
        ... )
        >>> virtual_service = pce.virtual_services.create(virtual_service)
        >>> virtual_service
        VirtualService(
        {
            "href": "/orgs/1/sec_policy/draft/virtual_services/14d7ff69-2fa4-458b-a299-e3f11ffa9b01",
            "created_at": "2021-10-05T12:34:56.789Z",
            "updated_at": "2021-10-05T12:34:56.789Z",
            "deleted_at": null,
            "created_by": {
                "href": "/users/1"
            },
            "updated_by": {
                "href": "/users/1"
            },
            "deleted_by": null,
            "update_type": "create",
            "name": "VS-INTERNAL",
            "description": null,
            "pce_fqdn": null,
            "service_ports": [
                {
                    "port": 1234,
                    "proto": 6
                },
                {
                    "port": 80,
                    "proto": 17,
                    "to_port": 443
                }
            ],
            "service_addresses": [
                {
                    "ip": "1.1.1.1",
                    "port": 101
                },
                {
                    "description": "test description",
                    "fqdn": "*.illumio.com"
                }
            ],
            "labels": [
                {
                    "href": "/orgs/1/labels/1",
                    "key": "role",
                    "value": "R-WEB"
                },
                {
                    "href": "/orgs/1/labels/2",
                    "key": "app",
                    "value": "A-HRM"
                },
                {
                    "href": "/orgs/1/labels/3",
                    "key": "env",
                    "value": "E-STAGE"
                },
                {
                    "href": "/orgs/1/labels/4",
                    "key": "loc",
                    "value": "L-TOR"
                }
            ],
            "ip_overrides": [
                "1.2.3.4"
            ],
            "apply_to": "host_only",
            "caps": [
                "write",
                "provision",
                "delete"
            ]
        }
        )

    Raises:
        IllumioException: if an invalid apply_to value is provided.
    """
    apply_to: str = None
    pce_fqdn: str = None
    service: Reference = None
    service_ports: List[ServicePort] = None
    service_addresses: List[ServiceAddress] = None
    ip_overrides: List[str] = None
    labels: List[Reference] = None

    def _validate(self):
        if self.apply_to and self.apply_to not in ApplyTo:
            raise IllumioException("Invalid 'apply_to' value: {}".format(self.apply_to))
        super()._validate()


@dataclass
class PortOverride(BaseService):
    """Represents a service binding port override.

    The ``proto`` field can be provided as a string, e.g. 'tcp', and it will be
    converted to its IANA integer equivalent.

    Args:
        port (int, optional): virtual service port to override. If the port is
            part of a range in the service, this must be the starting port in
            the range.
        proto (Union[str, int], optional): IANA protocol name or number for the
            service protocol.
        new_port (int, optional): override port or starting port of an override
            range.
        new_to_port (int, optional): ending port in an override range.

    Raises:
        IllumioException: if an invalid port value or port range is given.
    """
    new_port: int = None
    new_to_port: int = None

    def _validate(self):
        if self.new_port:
            validate_int(self.new_port, maximum=PORT_MAX)
        if self.new_to_port:
            validate_int(self.new_to_port, maximum=PORT_MAX)
            if self.new_to_port <= self.new_port:
                raise IllumioException("Invalid port range: new_to_port must be higher than new_port")
        super()._validate()


@dataclass
@pce_api('service_bindings')
class ServiceBinding(IllumioObject):
    """Represents a service binding between a virtual service and a workload.

    The ``/service_bindings`` POST method accepts a list of bindings and returns
    a list containing either the binding HREF (if the workload was successfully
    bound to the virtual service) or an error token and message.

    **NOTE:** Service bindings can only be created using an active virtual service.

    See https://docs.illumio.com/core/21.5/Content/Guides/security-policy/security-policy-objects/virtual-services.htm#BindaVirtualServicetoaWorkload

    Usage:
        >>> import illumio
        >>> workload = pce.workloads.create(illumio.Workload(
        ...     name='haproxy0.company.com',
        ...     hostname='haproxy0.company.com',
        ...     public_ip='10.0.14.201'
        ... ))
        >>> virtual_service = pce.virtual_services.create(illumio.VirtualService(
        ...     name='VS-HAProxy',
        ...     apply_to=illumio.ApplyTo.HOST_ONLY,
        ...     service_ports=[{'port': 443, 'proto': convert_protocol('tcp')}]
        ... ))
        >>> policy_version = pce.provision_policy_changes(
        ...     change_description="Create HAProxy virtual service",
        ...     hrefs=[virtual_service.href]
        ... )
        >>> virtual_service.href = convert_draft_href_to_active(virtual_service.href)
        >>> service_binding = illumio.ServiceBinding(
        ...     virtual_service=virtual_service,
        ...     workload=workload,
        ...     port_overrides=[illumio.PortOverride(port=443, new_port=8443, proto='tcp')]
        ... )
        >>> bindings = pce.service_bindings.create([service_binding])
        {
            'service_bindings': [
                ServiceBinding(href='/orgs/1/service_bindings/bc98cf25-8f24-4989-853c-578fa14108cf')
            ],
            'errors': []
        }
    """
    virtual_service: Reference = None
    workload: Reference = None
    port_overrides: List[PortOverride] = None


__all__ = [
    'ServiceAddress',
    'VirtualService',
    'PortOverride',
    'ServiceBinding',
]
