# -*- coding: utf-8 -*-

"""This module provides classes related to policy rules.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List, Union

from illumio.util import (
    JsonObject,
    Reference,
    MutableObject,
    pce_api,
    RESOLVE_AS_WORKLOADS
)
from illumio.policyobjects import Service, ServicePort

from .actor import Actor


@dataclass
class BaseRule(Reference):
    ingress_services: List[Union[Service, ServicePort]] = None
    providers: List[Actor] = None
    consumers: List[Actor] = None

    @classmethod
    def build(cls, providers: List[Union[str, Reference, dict]], consumers: List[Union[str, Reference, dict]],
            ingress_services: List[Union[JsonObject, dict, str]], **kwargs) -> 'BaseRule':
        services = []
        for service in ingress_services:
            if isinstance(service, JsonObject):
                services.append(service)
            elif type(service) is str:
                services.append(Service(href=service))
            else:
                service_type = Service if 'href' in service else ServicePort
                services.append(service_type.from_json(service))
        return cls(
            providers=[Actor.from_reference(provider) for provider in providers],
            consumers=[Actor.from_reference(consumer) for consumer in consumers],
            ingress_services=services,
            **kwargs
        )

    def _decode_complex_types(self):
        decoded_ingress_services = []
        if self.ingress_services:
            for service in self.ingress_services:
                service_type = Service if 'href' in service else ServicePort
                decoded_ingress_services.append(service_type.from_json(service))
        self.ingress_services = decoded_ingress_services
        super()._decode_complex_types()


@dataclass
class LabelResolutionBlock(JsonObject):
    providers: List[str] = None
    consumers: List[str] = None


@dataclass
@pce_api('rules', endpoint='/sec_rules')
class Rule(BaseRule, MutableObject):
    """Represents a security rule in the PCE.

    Each security rule defines one or more services on which traffic will be
    allowed from the defined providers to the defined consumers.

    Providers and consumers can be defined using static (workload HREF) or
    dynamic (label, IP list) references. By default, providers and consumers
    are resolved as workloads.

    See https://docs.illumio.com/core/21.5/Content/Guides/security-policy/create-security-policy/rules.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> any_ip_list = pce.get_default_ip_list()
        >>> role_label = pce.labels.create({'key': 'role', 'value': 'R-Web'})
        >>> app_label = pce.labels.create({'key': 'app', 'value': 'A-App'})
        >>> env_label = pce.labels.create({'key': 'env', 'value': 'E-Prod'})
        >>> loc_label = pce.labels.create({'key': 'loc', 'value': 'L-AWS'})
        >>> ruleset = illumio.RuleSet(
        ...     name='RS-LAB-ALLOWLIST',
        ...     scopes=[
        ...         illumio.LabelSet(
        ...             labels=[app_label, env_label, loc_label]
        ...         )
        ...     ]
        ... )
        >>> ruleset = pce.rule_sets.create(ruleset)
        >>> rule = illumio.Rule.build(
        ...     providers=[role_label],
        ...     consumers=[any_ip_list],
        ...     ingress_services=[
        ...         {'port': 80, 'proto': 'tcp'},
        ...         {'port': 443, 'proto': 'tcp'}
        ...     ],
        ...     unscoped_consumers=True  # creates an extra-scope rule
        ... )
        >>> rule = pce.rules.create(rule, parent=ruleset)
        >>> rule
        Rule(
            href='/orgs/1/sec_policy/rule_sets/19/rules/sec_rules/34',
            enabled=True,
            providers=[
                Actor(
                    label=Reference(
                        href='/orgs/1/labels/21'
                    ),
                    ...
                )
            ],
            consumers=[
                Actor(
                    ip_list=Reference(
                        href='/orgs/1/sec_policy/draft/ip_lists/1'
                    ),
                    ...
                )
            ],
            ingress_services=[
                ServicePort(port=80, proto=6, ...),
                ServicePort(port=443, proto=6, ...)
            ],
            resolve_labels_as=LabelResolutionBlock(
                providers=['workloads'],
                consumers=['workloads']
            ),
            unscoped_consumers=True,
            ...
        )
    """
    enabled: bool = None
    resolve_labels_as: LabelResolutionBlock = None
    sec_connect: bool = None
    stateless: bool = None
    machine_auth: bool = None
    consuming_security_principals: List[Reference] = None
    unscoped_consumers: bool = None
    network_type: str = None

    @classmethod
    def build(cls, providers: List[Union[str, Reference, dict]], consumers: List[Union[str, Reference, dict]],
            ingress_services: List[Union[JsonObject, dict, str]],
            resolve_providers_as: List[str]=None, resolve_consumers_as: List[str]=None, enabled=True, **kwargs) -> 'Rule':
        resolve_labels_as = LabelResolutionBlock(
            providers=resolve_providers_as or [RESOLVE_AS_WORKLOADS],
            consumers=resolve_consumers_as or [RESOLVE_AS_WORKLOADS]
        )
        return super().build(providers, consumers, ingress_services, resolve_labels_as=resolve_labels_as, enabled=enabled, **kwargs)


__all__ = [
    'BaseRule',
    'Rule',
    'LabelResolutionBlock',
]
