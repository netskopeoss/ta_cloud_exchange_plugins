# -*- coding: utf-8 -*-

"""This module is a stub for security principal objects.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass

from illumio.util import MutableObject, pce_api


@dataclass
@pce_api('security_principals')
class SecurityPrincipal(MutableObject):
    sid: str = None


__all__ = [
    'SecurityPrincipal',
]
