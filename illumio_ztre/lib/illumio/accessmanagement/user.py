# -*- coding: utf-8 -*-

"""This module provides classes related to RBAC users in the PCE.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass

from illumio.util import IllumioObject, pce_api


@dataclass
@pce_api('users', is_global=True)
class User(IllumioObject):
    """Represents a user object in the PCE."""
    username: str = None
    last_login_on: str = None
    last_login_ip_address: str = None
    login_count: int = None
    full_name: str = None
    time_zone: str = None
    locked: bool = None
    effective_groups: list = None
    local_profile: dict = None
    type: str = None
    presence_status: str = None


__all__ = [
    'User',
]
