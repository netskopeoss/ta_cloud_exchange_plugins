# -*- coding: utf-8 -*-

"""This module provides classes related to Virtual Enfocement Node objects.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass, field
from typing import List

from illumio import IllumioException, NotificationEvent
from illumio.infrastructure import ContainerCluster
from illumio.util import (
    JsonObject,
    Reference,
    MutableObject,
    LinkState,
    VENType,
    VisibilityLevel,
    pce_api,
)


@dataclass
class Interface(Reference):
    name: str = None
    link_state: str = None
    address: str = None
    cidr_block: int = None
    default_gateway_address: str = None
    network: Reference = None
    network_detection_mode: str = None
    friendly_name: str = None
    loopback: bool = None

    def _validate(self):
        if self.link_state and not self.link_state in LinkState:
            raise IllumioException("Invalid link_state: {}".format(self.link_state))
        super()._validate()


@dataclass
class AgentConfig(JsonObject):
    mode: str = None
    log_traffic: bool = None
    security_policy_update_mode: str = None
    visibility_level: str = None

    def _validate(self):
        if self.visibility_level and not self.visibility_level in VisibilityLevel:
            raise IllumioException("Invalid visibility_level: {}".format(self.visibility_level))
        super()._validate()


@dataclass
class SecureConnect(JsonObject):
    matching_issuer_name: str = None


@dataclass
class AgentHealthErrors(JsonObject):
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class AgentHealth(JsonObject):
    type: str = None
    severity: str = None
    audit_event: str = None


@dataclass
class AgentStatus(JsonObject):
    status: str = None
    uid: str = None
    instance_id: str = None
    last_heartbeat_on: str = None
    uptime_seconds: int = None
    agent_version: str = None
    managed_since: str = None
    fw_config_current: bool = None
    firewall_rule_count: int = None
    security_policy_refresh_at: str = None
    security_policy_applied_at: str = None
    security_policy_received_at: str = None
    agent_health_errors: AgentHealthErrors = None
    agent_health: List[AgentHealth] = None
    security_policy_sync_state: str = None


@dataclass
class VENAgent(MutableObject):
    config: AgentConfig = None
    secure_connect: SecureConnect = None
    status: AgentStatus = None
    unpair_allowed: bool = None
    active_pce_fqdn: str = None
    target_pce_fqdn: str = None
    type: str = None


@dataclass
class SecureConnect(JsonObject):
    matching_issuer_name: str = None


@dataclass
class VENCondition(JsonObject):
    first_reported_timestamp: str = None
    latest_event: NotificationEvent = None


@dataclass
@pce_api("vens")
class VEN(MutableObject):
    """Represents a Virtual Enforcement Node object in the PCE.

    The VEN object represents the agent on a workload that has been paired with
    the PCE.

    **NOTE:** VENs are read-only via the PCE API.

    See https://docs.illumio.com/core/21.5/Content/Guides/rest-api/workloads/ven-operations.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> vens = pce.vens.get()
        >>> vens
        [
            VEN(
                href="/orgs/1/vens/5fe88f13-d22c-427e-be47-b9c3369e1e32",
                hostname="web01.lab.company.com",
                status="active",
                os_id="centos-x86_64-8.0",
                os_detail="5.18.11-200.fc36.x86_64 #1 SMP PREEMPT_DYNAMIC Tue Jul 12 22:52:35 UTC 2022 (CentOS Linux release 8.5.2111)",
                os_platform="linux",
                version="21.2.5-8017",
                activation_type="pairing_key",
                labels=[
                    Reference(href="/orgs/1/labels/14"),
                    ...
                ],
                interfaces=[
                    Interface(
                        href="/orgs/1/workloads/5fe88f13-d22c-427e-be47-b9c3369e1e32/interfaces/eth0",
                        name="eth0",
                        address="10.88.0.3",
                        cidr_block=16,
                        default_gateway_address="10.88.0.1",
                        network=Reference(
                            href="/orgs/1/networks/40995e57-5e83-4fc5-9492-5b0e6df32a68"
                        ),
                        network_detection_mode="single_private_brn",
                        loopback=False,
                    ),
                    ...
                ],
                workloads=[
                    Reference(href="/orgs/1/workloads/5fe88f13-d22c-427e-be47-b9c3369e1e32")
                ],
                last_heartbeat_at="2022-08-01T17:14:08.830Z",
                last_goodbye_at=None,
                unpair_allowed=True,
                conditions=[
                    VENCondition(
                        first_reported_timestamp="2022-08-01T17:31:40.669Z",
                        latest_event=Event(
                            href="/orgs/1/events/0d2cec5f-5025-4e62-b867-b6e607397105",
                            notification_type="agent.missed_heartbeats",
                            severity="warning",
                            info={
                                ...
                            },
                            timestamp="2022-08-01T17:31:40.669Z",
                        ),
                    ),
                    ...
                ],
            ),
            ...
        ]
    """

    hostname: str = None
    status: str = None
    uid: str = None
    os_id: str = None
    os_detail: str = None
    os_platform: str = None
    version: str = None
    status: str = None
    activation_type: str = None
    active_pce_fqdn: str = None
    target_pce_fqdn: str = None
    labels: List[Reference] = None
    interfaces: List[Interface] = None
    workloads: List[Reference] = None
    container_cluster: ContainerCluster = None
    secure_connect: SecureConnect = None
    last_heartbeat_at: str = None
    last_goodbye_at: str = None
    unpair_allowed: bool = None
    conditions: List[VENCondition] = None
    ven_type: str = None

    def _validate(self):
        if self.ven_type and self.ven_type not in VENType:
            raise IllumioException("Invalid ven_type: {}".format(self.ven_type))
        super()._validate()


__all__ = [
    "AgentConfig",
    "SecureConnect",
    "AgentHealthErrors",
    "AgentHealth",
    "AgentStatus",
    "VENAgent",
    "VEN",
]
