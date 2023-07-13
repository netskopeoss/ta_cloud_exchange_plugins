# -*- coding: utf-8 -*-

"""This module provides classes related to iptables rules.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import JsonObject, MutableObject

from .actor import Actor


@dataclass
class IPTablesStatement(JsonObject):
    table_name: str = None
    chain_name: str = None
    parameters: str = None


@dataclass
class IPTablesRule(MutableObject):
    ip_version: str = None
    enabled: bool = None
    statements: List[IPTablesStatement] = None
    actors: List[Actor] = None


__all__ = [
    'IPTablesStatement',
    'IPTablesRule',
]
