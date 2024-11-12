# -*- coding: utf-8 -*-

"""This module provides a helper for actor objects in rules and enforcement boundaries.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
import re
from dataclasses import dataclass

from illumio.exceptions import IllumioException
from illumio.util import href_from, JsonObject, Reference, HREF_REGEX, AMS


@dataclass
class Actor(JsonObject):
    actors: str = None
    label: Reference = None
    label_group: Reference = None
    workload: Reference = None
    virtual_service: Reference = None
    virtual_server: Reference = None
    ip_list: Reference = None

    @staticmethod
    def from_reference(reference):
        href = href_from(reference)
        if href.lower() == AMS:  # special case for all objects
            return Actor(actors=AMS)
        actor = Actor()
        match = re.match(HREF_REGEX, href)
        if match:
            # HREF object types are plural, so we remove the s
            object_type = match.group('type')[:-1]
            setattr(actor, object_type, Reference(href=href))
        else:
            raise IllumioException('Invalid HREF in policy provision changeset: {}'.format(href))
        return actor


__all__ = [
    'Actor',
    'AMS'  # v1.0.2 - backwards compatibility
]
