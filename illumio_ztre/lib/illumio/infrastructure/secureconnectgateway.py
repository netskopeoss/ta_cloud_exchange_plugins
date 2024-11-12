# -*- coding: utf-8 -*-

"""This module is a stub for secure connect.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass

from illumio.util import MutableObject


@dataclass
class SecureConnectGateway(MutableObject):
    pass


__all__ = [
    'SecureConnectGateway',
]
