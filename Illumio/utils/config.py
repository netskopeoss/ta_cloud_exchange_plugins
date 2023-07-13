# -*- coding: utf-8 -*-

"""Provides configuration utilities for the Illumio plugin.

Copyright:
    © 2023 Illumio

License:
    Apache2
"""
import json
from pathlib import Path
from dataclasses import dataclass, fields

PLUGIN_ROOT = Path(__file__).resolve().parent.parent

# hold the manifest in module scope so we don't need to reread it
_manifest = {}


@dataclass
class IllumioPluginConfig:
    """Dataclass to use as plugin configuration object.

    Performs type validation on the parameters in post-init.

    Raises:
        ValueError: if the type of a given parameter is invalid or null.
    """

    pce_url: str
    pce_port: int
    org_id: int
    api_username: str
    api_secret: str
    label_scope: str
    enable_tagging: str = 'yes'

    def __post_init__(self):
        """Handle type conversion for all fields, ignoring nulls."""
        for field in fields(self):
            val = getattr(self, field.name)
            if val is None:
                field_label = _get_field_label_by_key(field.name)
                raise ValueError(f"{field_label}: field cannot be empty")
            if not isinstance(val, field.type):
                try:
                    setattr(self, field.name, field.type(val))
                except ValueError:
                    field_label = _get_field_label_by_key(field.name)
                    raise ValueError(f"{field_label}: invalid value {val}")


def load_manifest() -> dict:
    """Read the plugin manifest JSON and return it as a dict.

    Returns:
        dict: the plugin manifest converted to a dictionary.
    """
    if _manifest:
        return _manifest

    try:
        with open(str(PLUGIN_ROOT / 'manifest.json'), 'r') as f:
            # use update here since assignment will take priority
            # over the module-scoped _manifest var
            _manifest.update(json.load(f))
    except Exception:
        pass

    return _manifest


def _get_field_label_by_key(key: str) -> str:
    """Look up a config field label given its key.

    Args:
        key (str): the config field key to look up.

    Returns:
        str: the config field label, or the given key if not found.
    """
    manifest = load_manifest()
    config = manifest.get("configuration", [])
    for field in config:
        if field.get("key") == key:
            return field.get("label", key)  # fall back on the key name
    return key


__all__ = [
    "IllumioPluginConfig",
    "load_manifest",
]
