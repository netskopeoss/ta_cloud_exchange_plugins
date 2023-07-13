# -*- coding: utf-8 -*-

"""This module provides common exception classes used throughout the application.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from .exceptions import IllumioException
from .util import (
    Reference,
    Error,
    ChangeType,
    EventStatus,
    EventSeverity,
    pce_api,
)


@dataclass
class BaseEvent(Reference):
    event: str = None
    event_type: str = None
    uuid: str = None
    timestamp: str = None
    pce_fqdn: str = None
    severity: str = None
    status: str = None
    created_by: dict = None
    info: dict = None

    def _validate(self):
        if self.severity and not self.severity in EventSeverity:
            raise IllumioException("Invalid event severity: {}".format(self.severity))
        if self.status and not self.status in EventStatus:
            raise IllumioException("Invalid event status: {}".format(self.status))
        super()._validate()


@dataclass
class NotificationEvent(BaseEvent):
    notification_type: str = None


@dataclass
class ResourceEvent(BaseEvent):
    version: str = None
    org_id: int = None
    resource: dict = None
    changes: dict = None
    change_type: str = None

    def _validate(self):
        if self.change_type and not self.change_type in ChangeType:
            raise IllumioException("Invalid change_type: {}".format(self.change_type))
        super()._validate()


@dataclass
class ActionEvent(BaseEvent):
    task_name: str = None
    api_endpoint: str = None
    api_method: str = None
    http_status_code: int = None
    src_ip: str = None
    errors: List[Error] = None


@dataclass
@pce_api('events')
class Event(BaseEvent):
    """Represents an event object in the PCE.

    **NOTE:** Events are read-only via the PCE API.

    See https://docs.illumio.com/core/21.5/Content/Guides/rest-api/pce-management/events.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> events = pce.events.get(params={'max_results': 5})
        >>> events
        [
            Event(
                href="/orgs/1/events/3764a636-4846-492f-a090-ae96cf33bddf",
                event_type="system_task.expire_service_account_api_keys",
                timestamp="2022-08-17T22:12:37.410Z",
                pce_fqdn="pce.company.com",
                severity="critical",
                status="success",
                created_by={"system": {}},
                action=ActionEvent(
                    uuid="1ebad14e-bd87-42b1-ae9a-22433951fbd3",
                    src_ip="FILTERED",
                    ...
                ),
                resource_changes=[],
                notifications=[],
            ),
            ...
        ]
    """
    status: str = None
    action: ActionEvent = None
    resource_changes: List[ResourceEvent] = None
    notifications: List[NotificationEvent] = None


__all__ = [
    'Event',
    'NotificationEvent',
    'ResourceEvent',
    'ActionEvent',
]
