# -*- coding: utf-8 -*-

"""This module provides helper functions and decorators for common use-cases.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
import functools
import re
import socket
import sys
import typing
import warnings
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from illumio._version import version
from illumio.exceptions import IllumioException, IllumioIntegerValidationException
from .constants import ACTIVE, DRAFT, PCE_APIS


def ignore_empty_keys(o: dict):
    """Removes keys with None-type values from the provided dict.

    Used for JSON encoding to avoid schema errors due to empty or invalid parameters.
    """
    return {k: v for (k, v) in o if v is not None}


def convert_draft_href_to_active(href: str) -> str:
    """Given an HREF string, converts policy version to active.

    If an active HREF is provided, this function has no effect.

    Args:
        href (str): PCE object HREF.

    Returns:
        str: active policy version HREF.
    """
    return href.replace('/{}/'.format(DRAFT), '/{}/'.format(ACTIVE))


def convert_active_href_to_draft(href: str) -> str:
    """Given an HREF string, converts policy version to draft.

    If a draft HREF is provided, this function has no effect.

    Args:
        href (str): PCE object HREF.

    Returns:
        str: draft policy version HREF.
    """
    return href.replace('/{}/'.format(ACTIVE), '/{}/'.format(DRAFT))


def deprecated(deprecated_in, message=None):
    """
    Deprecation decorator, adapted from https://stackoverflow.com/a/30253848
    Will emit a warning when the decorated function is called.
    """
    def _deprecated(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            default_message = "Call to deprecated function {}. Deprecated in version {}, current version is {}.".format(
                func.__name__, deprecated_in, version
            )
            warning_message = message or default_message
            warnings.warn(warning_message, category=DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)
        return wrapper
    return _deprecated


def pce_api(name: str, endpoint: str = None, is_sec_policy=False, is_global=False):
    """Decorates an IllumioObject subclass to denote it as a PCE API object type.

    This registers the type in the PCE_APIS mapping used to determine whether
    a given name corresponds to an API-accessible type.

    We can then leverage __getattr__ to instantiate a generic API interface for
    any registered type (with some caveats, see the _PCEObjectAPI documentation).

    By default, registers the endpoint as /{name}, but the endpoint can also be
    specified in the decorator function call.

    For example:

    >>> @pce_api('labels', endpoint='/labels')
    >>> class Label(IllumioObject):
    ...     ...
    >>> pce = PolicyComputeEngine(...)
    >>> # the 'labels' name is registered, and so we can
    >>> # call /labels endpoints through the _PCEObjectAPI interface
    >>> labels = pce.labels.get()
    >>> labels
    [
        Label(
            href='/orgs/1/labels/1',
            key='role',
            value='R-DB',
            ...
        ),
        ...
    ]

    Args:
        name (str): the name of the API. used as a PolicyComputeEngine attribute name
            to generate the API interface.
        endpoint (str, optional): _description_. Defaults to None.
        is_sec_policy (bool, optional): whether or not the object reflects a security
            policy API with the sec_policy/{pversion} prefix. Defaults to False.
        is_global (bool, optional): whether or not the object reflects a global API,
            such as /health or /users. These APIs operate on the entire PCE rather
            than a single tenant, and don't need the /orgs/{org_id} prefix.
    """
    def _decorator(cls):
        @dataclass
        class __PCEApi:
            name: str
            endpoint: str
            object_class: object
            is_sec_policy: bool
            is_global: bool
        PCE_APIS[name] = __PCEApi(
            name=name,
            endpoint=endpoint or '/{}'.format(name),
            object_class=cls,
            is_sec_policy=is_sec_policy,
            is_global=is_global
        )
        return cls
    return _decorator


def parse_url(url: str) -> tuple:
    """Parses given URL into its scheme and hostname, stripping port and path.

    Args:
        url (str): URL to parse.

    Returns:
        tuple: parsed (scheme, hostname)
    """
    pattern = re.compile('^\w+://')
    if not re.match(pattern, url):
        url = 'https://{}'.format(url)
    parsed = urlparse(url)
    scheme = parsed.scheme
    if scheme not in ('http', 'https'):
        scheme = 'https'     # only support http(s)
    return scheme, parsed.hostname


def convert_protocol(protocol: str) -> int:
    """Given a protocol name, returns the integer ID of that protocol.

    Usage:
        >>> convert_protocol('tcp')
        6

    Args:
        protocol (str): case-insensitive protocol string, e.g. 'tcp', 'UDP'

    Raises:
        IllumioException: if an invalid protocol name is provided.

    Returns:
        int: the integer ID of the given protocol, e.g. 17 for 'udp'
    """
    try:
        return socket.getprotobyname(protocol)
    except:
        raise IllumioException('Invalid protocol name: {}'.format(protocol))


def validate_int(val: Any, minimum: int=0, maximum: int=sys.maxsize) -> None:
    """Validates a given value is an integer and is within min <= val <= max.

    Args:
        val (Any): value to validate.
        min (int, optional): validation lower bound. Defaults to 0.
        max (int, optional): validation upper bound. Defaults to sys.maxsize.

    Raises:
        IllumioIntegerValidationException: if an invalid value is provided.
    """
    try:
        valid = minimum <= int(val) <= maximum
    except:  # catch the ValueError for invalid values
        valid = False
    if not valid:
        raise IllumioIntegerValidationException(val, minimum, maximum)

if hasattr(typing, 'get_origin'):
    # python 3.8+ - introduces the get_origin function
    def isunion(type_):
        return typing.get_origin(type_) is typing.Union

    def islist(type_):
        if type_ is list:
            return True
        return typing.get_origin(type_) is list

elif hasattr(typing, '_GenericAlias'):
    # python 3.7 - changes meta types to be based off the
    # _GenericAlias supertype. __extra__ is now __origin__
    def isunion(type_):
        if isinstance(type_, typing._GenericAlias):
            return type_.__origin__ is typing.Union
        return False

    def islist(type_):
        if type_ is list:
            return True
        if isinstance(type_, typing._GenericAlias):
            return type_.__origin__ is list
        return False

else:
    # python 3.6
    def isunion(type_):
        return isinstance(type_, typing._Union)

    def islist(type_):
        if type_ is list:
            return True
        # in 3.6, List's type is GenericMeta, so we
        # instead check the __extra__ param
        if hasattr(type_, '__extra__'):
            return type_.__extra__ is list
        return False


__all__ = [
    'ignore_empty_keys',
    'convert_draft_href_to_active',
    'convert_active_href_to_draft',
    'deprecated',
    'pce_api',
    'parse_url',
    'convert_protocol',
    'validate_int',
    'isunion',
    'islist',
]
