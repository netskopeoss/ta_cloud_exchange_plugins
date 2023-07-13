# -*- coding: utf-8 -*-

"""This module provides the core of the class model used in the client.

The base JsonObject class handles basic encoding and decoding to translate
responses from the PCE REST API into python objects. The implementation
leverages dataclasses to simplify the logic for these operations.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
import copy
import json
from abc import ABC
from dataclasses import Field, dataclass, fields
from inspect import signature, isclass
from typing import List, Any, Union

from illumio.exceptions import IllumioException

from .constants import IllumioEnumMeta
from .functions import ignore_empty_keys, isunion, islist

_default = json.JSONEncoder()  # fall back to the default encoder for non-Illumio API objects


class IllumioEncoder(json.JSONEncoder):
    """Convenience class for encoding JsonObjects.

    >>> json.dumps(flow, cls=IllumioEncoder, indent=4)
    """
    def default(self, o: Any) -> Any:
        return getattr(o.__class__, "to_json", _default.default)(o)


@dataclass
class JsonObject(ABC):
    """Base dataclass for all derived PCE objects.

    Provides custom encoding, decoding, and type validation to and from JSON.
    """

    def __post_init__(self):
        self._validate()

    def _validate(self):
        """Validates all dataclass fields against their indicated types."""
        for field in fields(self):
            value = getattr(self, field.name)
            if not self._validate_field(field.type, value):
                raise AttributeError("Invalid value for {}: {}. Must be of type {}".format(field.name, value, field.type))

    def _validate_field(self, expected_type, value) -> bool:
        if value is None:
            return True
        elif expected_type is object:
            return True
        elif type(value) == expected_type:
            return True
        elif isunion(expected_type):
            return any(self._validate_field(type_, value) for type_ in expected_type.__args__)
        elif isinstance(type(value), IllumioEnumMeta):
            # validate enum values if they are passed as enum consts
            return self._validate_field(expected_type, value.value)
        elif isclass(expected_type) and issubclass(expected_type, JsonObject):
            # if the object is already decoded, determine whether it's
            # a subtype of what the field expects
            if isinstance(value, JsonObject):
                return isinstance(value, expected_type)
            try:
                # XXX: otherwise, expand objects to run their own validation.
                #   this is *slow*, but needed to validate deeply nested types
                expected_type.from_json(value)
            except:
                return False
            return True
        elif islist(expected_type) and isinstance(value, list):
            if not value:
                return True  # empty lists are always valid
            expected_type = expected_type.__args__[0]
            return all(self._validate_field(expected_type, o) for o in value)
        return False

    def to_json(self) -> Any:
        """Converts the object to a JSON-compatible copy of itself.

        Objects are converted to dictionaries recursively.

        Returns:
            Any: the converted JSON-compatible object
        """
        return deep_encode(self)

    def _encode(self) -> Any:
        result = []
        for f in fields(self):
            result.append((f.name, self._encode_field(f)))
        return ignore_empty_keys(result)

    def _encode_field(self, field: Field) -> Any:
        value = flatten_ref(field.type, getattr(self, field.name))
        value = resolve_enum(value)
        return deep_encode(value)

    @classmethod
    def from_json(cls, data: Any) -> 'JsonObject':
        """
        Given a JSON object or dictionary, decodes the data as an object
        of the calling JsonObject subtype. Accepts arbitrary key/value pairs
        as a form of forwards-compatibility.

        Classes can optionally extend decoding with the _decode_complex_types
        function for complex-type members.

        Based in part on https://stackoverflow.com/a/55101438
        """
        data = json.loads(data) if type(data) is str else data
        cls_fields = {field for field in signature(cls).parameters}

        defined_params, undefined_params = {}, {}
        for k, v in data.items():
            if k in cls_fields:
                defined_params[k] = v
            else:
                undefined_params[k] = v

        o = cls(**defined_params)

        for k, v in undefined_params.items():
            setattr(o, k, v)

        o._decode_complex_types()
        return o

    def _decode_complex_types(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            decoded_value = self._decode_field(field.type, value)
            setattr(self, field.name, decoded_value)

    def _decode_field(self, type_, value) -> Any:
        if value is None:
            return None
        if isinstance(value, JsonObject):
            # if the value has already been decoded, return it
            return value
        elif isclass(type_) and issubclass(type_, JsonObject):
            return type_.from_json(value)
        elif isinstance(value, list):
            # if the value is a list, expect the field type to be List[T]
            type_ = type_.__args__[0]
            return list(self._decode_field(type_, o) for o in value)
        return value


def flatten_ref(type_, value):
    """Replaces Reference subclasses with a simplified Reference object.

    This allows clients to pass a Reference subclass instance without
    breaking the encoded object schema for API calls.
    """
    if value is None:
        return None
    if type_ is Reference:
        if isinstance(value, Reference):
            return Reference(value.href)
    elif islist(type_):
        if type_.__args__[0] is Reference:
            ref_list = []
            for ref in value:
                if isinstance(ref, Reference):
                    ref_list.append(Reference(href=ref.href))
                else:
                    ref_list.append(ref)
            return ref_list
    elif isunion(type_):
        if Reference in type_.__args__:
            if isinstance(value, Reference):
                return Reference(value.href)
    return value


def resolve_enum(value):
    """Replaces IllumioEnumMeta subtypes with their internal value.

    This allows clients to pass enums directly as attribute values.

    For example:

    >>> Workload(..., enforcement_mode=EnforcementMode.SELECTIVE)

    will be converted to

    >>> Workload(..., enforcement_mode='selective')
    """
    if value is None:
        return None
    if isinstance(type(value), IllumioEnumMeta):
        return value.value
    return value


def deep_encode(o: Any) -> Any:
    """
    Recursively encode members of the given object and return a JSON-compatible
    copy. Children of the JsonObject superclass can optionally implement _encode
    or _encode_field to provide a customized encoding response, otherwise the
    JsonObject defaults are called to remove null-value pairs.

    Functionally similar to the dataclasses asdict method, but with the necessary
    adjustment of calling an optional custom encoding function for types that
    don't strictly mirror their dataclass field pairs when encoded.
    """
    if isinstance(o, JsonObject):
        return o._encode()
    elif isinstance(o, (list, tuple)):
        return type(o)(deep_encode(o) for o in o)
    elif isinstance(o, dict):
        return type(o)((deep_encode(k), deep_encode(v)) for k, v in o.items())
    else:
        return copy.deepcopy(o)


@dataclass
class Reference(JsonObject):
    """Simplest PCE object type, containing only an HREF.

    Used in most API schema to refer to other PCE objects.

    Args:
        href (str, optional): PCE object HREF.
    """
    href: str = None


def href_from(reference: Union[Reference, dict, str]):
    """Attempts to parse HREF value from a provided source.

    Args:
        reference (Union[Reference, dict, str]): source reference. If a string
            value is passed, it is returned unchanged. The ``href`` field
            is returned from a Reference object or subclass instance, and the
            ``'href'`` key is returned from a provided dictionary.

    Raises:
        IllumioException: if an invalid reference type is provided, or if the
            href value is null or falsy.
    """
    if isinstance(reference, Reference):
        if reference.href:
            return reference.href
    elif type(reference) is dict:
        if 'href' in reference and reference['href']:
            return reference['href']
    elif type(reference) is str:
        return reference
    raise IllumioException('Failed to extract HREF from value: {}'.format(reference))


@dataclass
class IllumioObject(Reference):
    """Base class for most PCE objects.

    Args:
        name (str, optional): object name.
        description (str, optional): object description.
        external_data_set (str, optional): unique namespace identifier for an
            external source creating PCE objects. If set,
            ``external_data_reference`` must also be provided.
        external_data_reference (str, optional): unique identifier within the
            external_data_set. If set, ``external_data_set`` must also be
            provided. ``external_data_set`` + ``external_data_reference``
            must be globally unique.
        caps (List[str], optional): defines the requesting user's
            capabilities/permissions on the object.
    """
    name: str = None
    description: str = None
    external_data_set: str = None
    external_data_reference: str = None
    caps: List[str] = None


@dataclass
class MutableObject(IllumioObject):
    """Base class for PCE objects that can be updated/deleted."""
    created_at: str = None
    updated_at: str = None
    deleted_at: str = None
    update_type: str = None
    delete_type: str = None
    created_by: Reference = None
    updated_by: Reference = None
    deleted_by: Reference = None


@dataclass
class ImmutableObject(IllumioObject):
    """Base class for PCE objects that cannot be updated/deleted."""
    created_at: str = None
    created_by: Reference = None


@dataclass
class Error(JsonObject):
    """Wrapper class for error status/message.

    Args:
        token (str, optional): error status.
        message (str, optional): error message.
    """
    token: str = None
    message: str = None


__all__ = [
    'IllumioEncoder',
    'JsonObject',
    'Reference',
    'IllumioObject',
    'MutableObject',
    'ImmutableObject',
    'Error',
    'href_from',
]
