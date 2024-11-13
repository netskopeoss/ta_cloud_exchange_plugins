# -*- coding: utf-8 -*-

"""This module provides classes related to policy rule sets.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import MutableObject, pce_api
from illumio.policyobjects import LabelSet

from .rule import Rule
from .iptablesrule import IPTablesRule


@dataclass
@pce_api('rule_sets', is_sec_policy=True)
class RuleSet(MutableObject):
    """Represents a rule set object in the PCE.

    Rule sets provide scope boundaries for security policy rules. Scopes are
    defined using application, environment, and location labels. Rules within
    the set will default to applying to workloads with these labels.

    See https://docs.illumio.com/core/21.5/Content/Guides/security-policy/create-security-policy/rulesets.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> app_label = pce.labels.create({'key': 'app', 'value': 'A-App'})
        >>> env_label = pce.labels.create({'key': 'env', 'value': 'E-Prod'})
        >>> loc_label = pce.labels.create({'key': 'loc', 'value': 'L-AWS'})
        >>> ruleset = illumio.RuleSet(
        ...     name='RS-RINGFENCE',
        ...     scopes=[
        ...         illumio.LabelSet(
        ...             labels=[app_label, env_label, loc_label]
        ...         )
        ...     ]
        ... )
        >>> ruleset = pce.rule_sets.create(ruleset)
        >>> ruleset
        Ruleset(
            href='/orgs/1/sec_policy/draft/rule_sets/19',
            name='RS-RINGFENCE'
        )
    """
    enabled: bool = None
    scopes: List[LabelSet] = None
    rules: List[Rule] = None
    ip_tables_rules: List[IPTablesRule] = None


__all__ = [
    'RuleSet',
]
