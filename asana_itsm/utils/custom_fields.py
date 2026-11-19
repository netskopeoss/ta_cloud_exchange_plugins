"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Asana custom field helpers.

Pure functions that decide which custom fields can be mapped, convert the
values entered in the CE queue mapping to the format Asana expects, and read
the Status and Severity values from a task.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .constants import (
    COMMENT_MAX_BYTES,
    CUSTOM_FIELD_PREFIX,
    DATE_FORMAT,
    TRUNCATION_SUFFIX,
    WRITABLE_CUSTOM_FIELD_TYPES,
)
from .exceptions import AsanaMappingException

DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def get_field_type(custom_field: Dict) -> str:
    """Return the type used to write a custom field.

    Asana reports a custom ID field with the subtype "text", so the
    representation type decides how the field is written.

    Args:
        custom_field (Dict): Custom field object returned by Asana.

    Returns:
        str: Representation type, or the resource subtype when missing.
    """
    return (
        custom_field.get("representation_type")
        or custom_field.get("resource_subtype")
        or ""
    )


def is_writable(custom_field: Dict) -> bool:
    """Check whether Cloud Exchange can write a custom field.

    Args:
        custom_field (Dict): Custom field object returned by Asana.

    Returns:
        bool: True for text, number, enum, multi_enum and date fields that
            are not formula fields.
    """
    if not custom_field.get("gid") or not custom_field.get("name"):
        return False
    if custom_field.get("is_formula_field") is True:
        return False
    return get_field_type(custom_field) in WRITABLE_CUSTOM_FIELD_TYPES


def build_field_entry(custom_field: Dict) -> Dict:
    """Build the dictionary entry of one project custom field.

    Args:
        custom_field (Dict): Custom field object returned by Asana.

    Returns:
        Dict: Entry with the name, the type, the enabled options keyed by
            lower-case name, and the option names in Asana order.
    """
    options = {}
    option_names = []
    for option in custom_field.get("enum_options") or []:
        if not isinstance(option, dict):
            continue
        name = str(option.get("name") or "").strip()
        if not name or not option.get("gid"):
            continue
        if option.get("enabled") is False:
            continue
        options.setdefault(name.lower(), option.get("gid"))
        option_names.append(name)
    return {
        "name": custom_field.get("name", ""),
        "type": get_field_type(custom_field),
        "writable": is_writable(custom_field),
        "options": options,
        "option_names": option_names,
    }


def build_project_field_index(
    settings: List[Dict],
) -> Tuple[Dict[str, Dict], Dict[str, List[str]]]:
    """Build the custom field dictionaries of a project.

    Args:
        settings (List[Dict]): Items of GET /projects/{gid}/
            custom_field_settings.

    Returns:
        Tuple[Dict[str, Dict], Dict[str, List[str]]]: Fields keyed by gid,
            and the lower-case field name mapped to the gids with that name.
    """
    fields = {}
    names = {}
    for setting in settings:
        if not isinstance(setting, dict):
            continue
        custom_field = setting.get("custom_field") or {}
        gid = custom_field.get("gid")
        if not gid:
            continue
        entry = build_field_entry(custom_field)
        fields[gid] = entry
        names.setdefault(entry.get("name", "").lower(), []).append(gid)
    return fields, names


def build_mapping_field_labels(
    custom_fields: List[Dict],
) -> List[Tuple[str, str]]:
    """Return the label and key of every writable custom field.

    The label is "<name> (<type>)", for example "Severity (enum)". The gid
    is never shown to the user; it is only the stored value of the field,
    so two fields with the same name and type have the same label.

    Args:
        custom_fields (List[Dict]): Custom field objects returned by Asana.

    Returns:
        List[Tuple[str, str]]: (label, key) pairs sorted by label.
    """
    writable = []
    seen_gids = set()
    for custom_field in custom_fields:
        if not isinstance(custom_field, dict) or not is_writable(
            custom_field
        ):
            continue
        gid = custom_field.get("gid")
        if gid in seen_gids:
            continue
        seen_gids.add(gid)
        writable.append(custom_field)

    labels = []
    for custom_field in writable:
        field_type = (
            custom_field.get("resource_subtype")
            or get_field_type(custom_field)
        )
        labels.append(
            (
                f"{custom_field.get('name', '')} ({field_type})",
                f"{CUSTOM_FIELD_PREFIX}{custom_field.get('gid')}",
            )
        )
    return sorted(labels, key=lambda item: (item[0].lower(), item[1]))


def describe_field(entry: Dict, project_label: str = "") -> str:
    """Describe a project custom field for error messages.

    Args:
        entry (Dict): Project field entry.
        project_label (str): Quoted project label of the queue, when known,
            for example "'Netskope Project' (gid '1219245697468891')".

    Returns:
        str: For example "the custom field 'Severity' (enum) of the Asana
            project 'Netskope Project' (gid '1219245697468891')".
    """
    text = (
        f"the custom field '{entry.get('name', '')}'"
        f" ({entry.get('type', '')})"
    )
    if project_label:
        text = f"{text} of the Asana project {project_label}"
    return text


def _invalid_option_error(
    value: str, entry: Dict, project_label: str
) -> AsanaMappingException:
    """Build the error of an enum value that is not an option.

    Args:
        value (str): Value from the queue mapping.
        entry (Dict): Project field entry.
        project_label (str): Name of the queue project.

    Returns:
        AsanaMappingException: Error that lists the valid options.
    """
    name = entry.get("name", "")
    valid_options = ", ".join(entry.get("option_names", [])) or "None"
    return AsanaMappingException(
        f"Value '{value}' is not a valid option of"
        f" {describe_field(entry, project_label)}. Valid options:"
        f" {valid_options}. If the value comes from the alert or event"
        " status or severity, update the Status or Severity Mapping in the"
        " plugin configuration.",
        resolution=(
            f"Ensure that the value mapped to the {name} field in the queue"
            " mapping is one of the options of the field in Asana; for a"
            " value that comes from the alert or event status or severity,"
            " ensure that the Status and Severity Mapping of the plugin"
            " configuration maps it to one of these options."
        ),
    )


def _convert_number(value: str, entry: Dict, project_label: str) -> Any:
    """Convert a mapping value to a number.

    Args:
        value (str): Value from the queue mapping.
        entry (Dict): Project field entry.
        project_label (str): Name of the queue project.

    Returns:
        Any: int when the value has no fractional part, otherwise float.

    Raises:
        AsanaMappingException: When the value is not a finite number.
    """
    name = entry.get("name", "")
    try:
        # int first, so that large integers keep their exact value.
        return int(value)
    except ValueError:
        pass
    try:
        number = float(value)
        if number != number or number in (float("inf"), float("-inf")):
            raise ValueError("Not a finite number.")
    except ValueError:
        raise AsanaMappingException(
            f"Value '{value}' is not a number, so it cannot be written to"
            f" {describe_field(entry, project_label)}.",
            resolution=(
                f"Ensure that the value mapped to the {name} field in the"
                " queue mapping is a number."
            ),
        )
    return int(number) if number.is_integer() else number


def _convert_date(value: str, entry: Dict, project_label: str) -> Dict:
    """Convert a mapping value to an Asana date object.

    Args:
        value (str): Value from the queue mapping.
        entry (Dict): Project field entry.
        project_label (str): Name of the queue project.

    Returns:
        Dict: {"date": "YYYY-MM-DD"}.

    Raises:
        AsanaMappingException: When the value is not a YYYY-MM-DD date.
    """
    name = entry.get("name", "")
    try:
        if not DATE_PATTERN.fullmatch(value):
            raise ValueError("Not a zero-padded YYYY-MM-DD date.")
        datetime.strptime(value, DATE_FORMAT)
    except ValueError:
        raise AsanaMappingException(
            f"Value '{value}' is not a valid date for"
            f" {describe_field(entry, project_label)}. Use the format"
            " YYYY-MM-DD.",
            resolution=(
                f"Ensure that the value mapped to the {name} field in the"
                " queue mapping is a date in the format YYYY-MM-DD."
            ),
        )
    return {"date": value}


def convert_value(entry: Dict, value: Any, project_label: str = "") -> Any:
    """Convert a queue mapping value to the value Asana expects.

    Args:
        entry (Dict): Project field entry built by build_field_entry.
        value (Any): Value from the queue mapping (not empty).
        project_label (str): Name of the queue project, for the errors.

    Returns:
        Any: Value to send in the custom_fields object of the request, or
            None when a multi_enum value contains no option (the field is
            then not sent, so Asana never clears it).

    Raises:
        AsanaMappingException: When the value is not valid for the field.
    """
    text = str(value).strip()
    field_type = entry.get("type")
    options = entry.get("options", {})
    if field_type == "enum":
        option_gid = options.get(text.lower())
        if not option_gid:
            raise _invalid_option_error(text, entry, project_label)
        return option_gid
    if field_type == "multi_enum":
        gids = []
        for item in text.split(","):
            item = item.strip()
            if not item:
                continue
            option_gid = options.get(item.lower())
            if not option_gid:
                raise _invalid_option_error(item, entry, project_label)
            if option_gid not in gids:
                gids.append(option_gid)
        return gids or None
    if field_type == "number":
        return _convert_number(text, entry, project_label)
    if field_type == "date":
        return _convert_date(text, entry, project_label)
    return str(value)


def find_named_fields(
    custom_fields: List[Dict], field_name: str
) -> List[Dict]:
    """Return the custom fields with exactly the given name.

    The comparison is case-sensitive; surrounding spaces are ignored.

    Args:
        custom_fields (List[Dict]): custom_fields array of a task or a
            workspace.
        field_name (str): Field name.

    Returns:
        List[Dict]: Matching fields, in the order of the array.
    """
    target = str(field_name or "").strip()
    return [
        field
        for field in custom_fields or []
        if isinstance(field, dict)
        and str(field.get("name") or "").strip() == target
    ]


def get_named_value(matches: List[Dict]) -> Optional[str]:
    """Return the value of the first matching field that has one.

    The first enum field that has a value wins; otherwise the first other
    field (for example a text field) with a display value is used.

    Args:
        matches (List[Dict]): Fields returned by find_named_fields.

    Returns:
        Optional[str]: The value, or None when no field has a value.
    """
    for field in matches:
        if "enum_value" in field:
            enum_name = (field.get("enum_value") or {}).get("name")
            if enum_name:
                return enum_name
    for field in matches:
        if "enum_value" not in field and field.get("display_value"):
            return str(field.get("display_value"))
    return None


def extract_named_value(
    custom_fields: List[Dict], field_name: str
) -> Optional[str]:
    """Read the value of the custom field with exactly the given name.

    Args:
        custom_fields (List[Dict]): custom_fields array of a task.
        field_name (str): Field name, for example "Status".

    Returns:
        Optional[str]: The value, or None when no field has a value.
    """
    return get_named_value(find_named_fields(custom_fields, field_name))


def truncate_comment(text: str) -> str:
    """Truncate a comment to the Asana limit of 65,400 UTF-8 bytes.

    The truncated text ends on a complete character and the suffix is
    included in the limit.

    Args:
        text (str): Comment text.

    Returns:
        str: The text unchanged, or truncated with the suffix appended.
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= COMMENT_MAX_BYTES:
        return text
    budget = COMMENT_MAX_BYTES - len(TRUNCATION_SUFFIX.encode("utf-8"))
    truncated = encoded[:budget].decode("utf-8", errors="ignore")
    return f"{truncated}{TRUNCATION_SUFFIX}"
