# -*- coding: utf-8 -*-

"""This module is a stub for network objects.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass

from illumio.util import MutableObject


@dataclass
class Network(MutableObject):
    pass


__all__ = [
    'Network',
]
