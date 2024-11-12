# -*- coding: utf-8 -*-

"""This module provides classes related to labels and label groups.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
import json
from dataclasses import dataclass
from typing import List

from illumio.util import JsonObject, Reference, MutableObject, pce_api


@dataclass
class LabelUsage(JsonObject):
    """Represents how a label object is being used in the PCE."""
    label_group: bool = None
    ruleset: bool = None
    rule: bool = None
    static_policy_scopes: bool = None
    containers_inherit_host_policy_scopes: bool = None
    blocked_connection_reject_scope: bool = None
    enforcement_boundary: bool = None


@dataclass
@pce_api('labels')
class Label(MutableObject):
    """Represents a label in the PCE.

    Labels help to configure the reach of policy rules in a dynamic way,
    without relying on precise identifiers like IP addresses.

    When fetching Labels from the PCE, a breakdown of the labels' usage can be
    optionally included.

    See https://docs.illumio.com/core/21.5/Content/Guides/security-policy/security-policy-objects/labels-and-label-groups.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> label = illumio.Label(key='role', value='R-DB')
        >>> label = pce.labels.create(label)
        >>> label
        Label(
            href='/orgs/1/labels/18',
            key='role',
            value='R-DB',
            ...
        )
    """
    key: str = None
    value: str = None
    deleted: bool = None
    usage: LabelUsage = None


@dataclass
@pce_api('label_groups', is_sec_policy=True)
class LabelGroup(Label):
    """Represents a label group in the PCE.

    Label groups can contain labels and other sub-groups to define broader
    categories that are often grouped when writing rules or otherwise
    referencing multiple labels.

    See https://docs.illumio.com/core/21.5/Content/Guides/security-policy/security-policy-objects/labels-and-label-groups.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> dev_label = pce.labels.create({'key': 'env', 'value': 'E-Dev'})
        >>> stage_label = pce.labels.create({'key': 'env', 'value': 'E-Stage'})
        >>> label_group = illumio.LabelGroup(
        ...     key='role',
        ...     name='LG-E-PreProd',
        ...     labels=[dev_label, stage_label]
        ... )
        >>> label_group = pce.label_groups.create(label_group)
        >>> label_group
        LabelGroup(
            href='/orgs/1/sec_policy/draft/label_groups/5704a6f4-e051-4f88-9149-713ee22b5d41',
            key='role',
            value='R-DB',
            ...
        )
    """
    labels: List[Reference] = None
    sub_groups: List['LabelGroup'] = None


@dataclass
class LabelSet(JsonObject):
    """Represents a set of labels with distinct keys.

    Used to define rule set scopes.

    Args:
        labels (List[Reference], optional): list of label and label group
            references in the set.
    """
    labels: List[Reference] = None

    def __eq__(self, o) -> bool:
        """Compares LabelSet instances based on label HREFs, ignoring list order"""
        if not isinstance(o, LabelSet):
            return False
        return len(self.labels) == len(o.labels) and \
            set([label.href for label in self.labels]) == set([label.href for label in o.labels])

    def _encode(self):
        json_array = []
        for label in self.labels:
            key = 'label_group' if '/label_groups/' in label.href else 'label'
            json_array.append({key: Reference(href=label.href).to_json()})
        return json_array

    @classmethod
    def from_json(cls, data) -> 'LabelSet':
        data = json.loads(data) if type(data) is str else data
        labels = []
        for label_entry in data:
            key = 'label' if 'label' in label_entry else 'label_group'
            labels.append(Label.from_json(label_entry[key]))
        return LabelSet(labels=labels)


__all__ = [
    'LabelUsage',
    'Label',
    'LabelGroup',
    'LabelSet',
]
