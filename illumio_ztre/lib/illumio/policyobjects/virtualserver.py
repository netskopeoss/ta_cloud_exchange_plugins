# -*- coding: utf-8 -*-

"""This module is a stub for virtual server objects.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass

from illumio.util import MutableObject


@dataclass
class VirtualServer(MutableObject):
    pass


__all__ = [
    'VirtualServer',
]
