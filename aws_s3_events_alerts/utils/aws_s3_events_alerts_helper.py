"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

AWS S3 Events, Alerts Plugin helper utilities.
"""

from typing import Dict, Tuple


def get_mappings(mappings: Dict, data_type: str) -> Dict:
    """Return the subtype-keyed mapping dict for the given data type.

    Args:
        mappings (Dict): Full mappings dict (parsed from mappings.json).
        data_type (str): Data type — 'alerts', 'events', or 'webtx'.

    Returns:
        Dict: Subtype-keyed mapping dict for the given data type.
    """
    return mappings["taxonomy"]["json"][data_type]


def get_nested_field_value(data: Dict, field_path: str) -> Tuple:
    """Extract a value from a nested dict using dot-notation path.

    Some Netskope records expose values only under nested keys like
    ``host_info.device_make``, while the configured mapping references
    the field as a single dotted string. This walks the dict one segment
    at a time and returns the leaf value when the full path resolves.

    Args:
        data (Dict): The data dictionary.
        field_path (str): Dot-separated field path
            (e.g. 'host_info.device_make').

    Returns:
        Tuple: (value, True) if the path resolves, (None, False)
            otherwise.
    """
    try:
        current = data
        for part in field_path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None, False
        return current, True
    except Exception:
        return None, False


def map_json_data(mappings, data: Dict) -> Dict:
    """Filter raw Netskope data to only the fields listed in mappings.

    Supports both flat keys and dot-notation nested field paths
    (e.g. ``host_info.device_make``).

    Args:
        mappings: List of field names to retain, or [] to keep all
            fields.
        data (Dict): Raw record from Netskope.

    Returns:
        Dict: Record containing only the mapped fields, or the original
            data if mappings is empty or data is falsy.
    """
    if mappings == [] or not data:
        return data

    mapped_dict = {}
    data_keys = data.keys()
    for key in mappings:
        if key in data_keys:
            mapped_dict[key] = data[key]
        else:
            value, field_exist = get_nested_field_value(data, key)
            if field_exist:
                mapped_dict[key] = value
    return mapped_dict
