# -*- coding: utf-8 -*-

"""Provides utility functions for the Illumio plugin.

Copyright:
    © 2023 Illumio

License:
    Apache2
"""
from illumio import PolicyComputeEngine

from .config import IllumioPluginConfig


def parse_label_scope(scope: str) -> dict:
    """Parse label scopes passed as a string of the form k1:v1,k2:v2,...

    Args:
        scope (str): Policy scope as a comma-separated key:value pair list.

    Returns:
        dict: dict containing label key:value pairs.

    Raises:
        ValueError: if the given scope format is invalid.
    """
    label_dimensions = scope.split(",")
    labels = {}
    for label in label_dimensions:
        if not label.strip():
            continue

        try:
            k, v = label.split(":")
        except Exception:
            raise ValueError(
                "Invalid format: must be key1:value1,key2:value2..."
            )

        if k.strip() in labels:
            raise ValueError("Label scope keys must be unique")

        labels[k.strip()] = v.strip()
    if not labels:
        raise ValueError("Empty label scope provided")
    return labels


def connect_to_pce(conf: IllumioPluginConfig, proxies: dict = None,
                   headers: dict = None, verify: bool = True, **kwargs) -> PolicyComputeEngine:  # noqa: E501
    """Connect to the PCE, returning the PolicyComputeEngine client.

    Args:
        conf (dict): dict containing plugin configuration values.
        proxies (dict): dict containing HTTP/S proxy server settings.
        verify (bool): if False, disables TLS verification for PCE requests.

    Returns:
        PolicyComputeEngine: PCE API client object.

    Raises:
        IllumioException: if the PCE connection fails.
    """
    pce = PolicyComputeEngine(
        conf.pce_url, port=conf.pce_port, org_id=conf.org_id, **kwargs
    )
    pce._session.headers.update(headers)
    pce.set_credentials(conf.api_username, conf.api_secret)
    pce.set_tls_settings(verify=verify)
    if proxies:
        pce.set_proxies(
            http_proxy=proxies.get('http', ''),
            https_proxy=proxies.get('https', '')
        )
    pce.must_connect()
    return pce


__all__ = [
    "parse_label_scope",
    "connect_to_pce",
]
