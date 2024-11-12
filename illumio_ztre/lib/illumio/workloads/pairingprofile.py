# -*- coding: utf-8 -*-

"""This module provides classes related to pairing profile objects.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List, Union

from illumio import IllumioException
from illumio.util import (
    Reference,
    MutableObject,
    EnforcementMode,
    VisibilityLevel,
    pce_api
)


@dataclass
@pce_api('pairing_profiles')
class PairingProfile(MutableObject):
    """Represents a pairing profile in the PCE.

    Pairing profiles are used to configure VEN defaults and generate keys
    for VEN pairing  on workloads that will be managed by the PCE.

    See https://docs.illumio.com/asp/20.1/Content/Guides/rest-api/workloads/pairing-profiles-and-pairing-keys.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> pairing_profile = illumio.PairingProfile(
        ...     name='PP-DATABASE-VENS',
        ...     enabled=True,
        ...     enforcement_mode='visibility_only',
        ...     visibility_level='flows_summary'
        ... )
        >>> pairing_profile = pce.pairing_profiles.create(pairing_profile)
        >>> pairing_profile
        PairingProfile(
            href='/orgs/1/pairing_profiles/19',
            name='PP-DATABASE-VENS',
            enabled=True,
            enforcement_mode='visibility_only',
            visibility_level='flows_summary',
            ...
        )
    """
    enabled: bool = None
    agent_software_release: str = None
    enforcement_mode: str = None
    enforcement_mode_lock: bool = None
    visibility_level: str = None
    visibility_level_lock: bool = None
    allowed_uses_per_key: Union[str, int] = None
    key_lifespan: Union[str, int] = None

    labels: List[Reference] = None
    role_label_lock: bool = None
    app_label_lock: bool = None
    env_label_lock: bool = None
    loc_label_lock: bool = None

    total_use_count: int = None
    is_default: bool = None
    last_pairing_at: str = None

    def _validate(self):
        if self.enforcement_mode and not self.enforcement_mode in EnforcementMode:
            raise IllumioException("Invalid enforcement_mode: {}".format(self.enforcement_mode))
        if self.visibility_level and not self.visibility_level in VisibilityLevel:
            raise IllumioException("Invalid visibility_level: {}".format(self.visibility_level))
        super()._validate()

    def _encode_field(self, field):
        """Encodes PairingProfile fields to JSON types.

        The allowed_uses_per_key and key_lifespan parameters have strict schema
        contraints in the PCE - values must either be 'unlimited' or an integer
        which we enforce here. All other fields use the default encoding method.
        """
        if field.name in ['allowed_uses_per_key', 'key_lifespan']:
            value = getattr(self, field.name)
            if isinstance(value, str) and value != 'unlimited':
                if not value.isnumeric():
                    raise IllumioException("Invalid '{}' value: must be 'unlimited' or int".format(field.name))
                value = int(value)
            return value
        return super()._encode_field(field)


__all__ = [
    'PairingProfile',
]
