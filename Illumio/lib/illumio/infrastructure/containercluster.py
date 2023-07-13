# -*- coding: utf-8 -*-

"""This module is a stub for container cluster objects.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.exceptions import IllumioException
from illumio.util import (
    JsonObject,
    Reference,
    IllumioObject,
    MutableObject,
    EnforcementMode,
    VisibilityLevel,
    pce_api
)


@dataclass
class ContainerClusterNode(JsonObject):
    name: str = None
    pod_subnet: str = None


@dataclass
class ContainerClusterError(JsonObject):
    audit_event: Reference = None
    duplicate_ids: List[str] = None
    error_type: str = None


@dataclass
class LabelRestriction(JsonObject):
    """Represents a label or set of labels to restrict the workload profile to.

    Only one of ``assignment`` or ``restriction`` can be specified.

    Args:
        key (str, optional): label type, for example 'role', 'app'.
        assignment (Reference, optional): reference to label object to assign
            to container workloads using the profile.
        restriction (List[Reference], optional): restricts container workload
            label assignment for the given key to only the referenced labels.
    """
    key: str = None
    assignment: Reference = None
    restriction: List[Reference] = None


@dataclass
@pce_api('container_workload_profiles')
class ContainerWorkloadProfile(MutableObject):
    """Represents a workload profile within a container cluster object in the PCE.

    Workload profiles define management and scope for container workloads under
    a cluster namespace defined by the profile.

    The `assign_labels` field is DEPRECATED in favour of the more flexible `labels`
    for defining label assignments and restrictions on the profile. `assign_labels`
    is left in for compatibility with older PCE versions. In either case, label
    assignments can only be specified for managed workload profiles.

    **NOTE:** though the `enforcement_mode` value for a workload profile can be
    set to `selective`, it is currently not supported and may result in
    unexpected behaviour. The only supported enforcement modes for workload
    profiles are ``idle``, ``visibility_only``, and ``full``.

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> container_cluster = illumio.ContainerCluster(
        ...     name='CC-EKS-PROD',
        ...     description='Production Kubernetes cluster on AWS'
        ... )
        >>> container_cluster = pce.container_clusters.create(container_cluster)
        >>> env_label = pce.labels.create({'key': 'env', 'value': 'Production'})
        >>> loc_label = pce.labels.create({'key': 'loc', 'value': 'AWS'})
        >>> container_workload_profile = illumio.ContainerWorkloadProfile(
        ...     name='illumio-system',
        ...     managed=True,
        ...     labels=[
        ...         illumio.LabelRestriction(key='env', assignment=env_label),
        ...         illumio.LabelRestriction(key='loc', assignment=loc_label)
        ...     ],
        ...     enforcement_mode='visibility_only'
        ... )
        >>> container_workload_profile = pce.container_workload_profiles.create(
        ...     container_workload_profile, parent=container_cluster
        ... )
        >>> container_workload_profile
        ContainerWorkloadProfile(
            href='/orgs/1/container_clusters/f5bef182-8c55-4219-b35b-0a50b707e434/container_workload_profiles/d2d466b5-106d-48e9-ada9-68f6321d1da8',
            name='illumio-system',
            namespace=None,
            managed=True,
            labels=[
                LabelRestriction(
                    key='env',
                    assignment=Reference(href='/orgs/1/labels/23'),
                    ...
                ),
                ...
            ],
            enforcement_mode='visibility_only'
            ...
        )
    """
    namespace: str = None
    assign_labels: List[Reference] = None
    labels: List[LabelRestriction] = None
    enforcement_mode: str = None
    visibility_level: str = None
    linked: bool = None
    managed: bool = None

    def _validate(self):
        if self.enforcement_mode and self.enforcement_mode not in EnforcementMode:
            raise IllumioException("Invalid enforcement_mode: {}".format(self.enforcement_mode))
        if self.visibility_level and self.visibility_level not in VisibilityLevel:
            raise IllumioException("Invalid visibility_level: {}".format(self.visibility_level))
        return super()._validate()


@dataclass
@pce_api('container_clusters')
class ContainerCluster(IllumioObject):
    """Represents a container cluster object in the PCE.

    Container clusters are abstract representations of container orchestration
    systems linked to the PCE.

    **NOTE:** when a container cluster is created through the API, the
    `container_cluster_token` used by Kubelink and C-VEN containers
    to pair with the PCE is returned in the response. This token is
    only available after the initial POST request and cannot be
    retrieved via the API: make sure to store it in a persistent
    form after creating the cluster.

    See https://docs.illumio.com/core/21.5/Content/LandingPages/Guides/kubernetes-and-openshift.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> container_cluster = illumio.ContainerCluster(
        ...     name='CC-EKS-PROD',
        ...     description='Production Kubernetes cluster on AWS'
        ... )
        >>> container_cluster = pce.container_clusters.create(container_cluster)
        >>> container_cluster
        ContainerCluster(
            href='/orgs/1/container_clusters/f5bef182-8c55-4219-b35b-0a50b707e434',
            name='CC-EKS-PROD',
            description='Production Kubernetes cluster on AWS',
            container_cluster_token='1_016dace1ab35fafe8e71c6dda6695e0881393f1f4c494e6cd70178f1e743b372',
            ...
        )
    """
    pce_fqdn: str = None
    manager_type: str = None
    last_connected: str = None
    kubelink_version: str = None
    online: bool = None
    nodes: List[ContainerClusterNode] = None
    container_runtime: str = None
    errors: List[ContainerClusterError] = None
    container_cluster_token: str = None


__all__ = [
    'ContainerClusterNode',
    'ContainerClusterError',
    'LabelRestriction',
    'ContainerWorkloadProfile',
    'ContainerCluster',
]
