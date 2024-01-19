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

AWS S3 Events, Alerts Plugin.
"""

from typing import Dict, List
from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from .aws_s3_events_alerts_exception import (
    MappingValidationError,
)


def map_data(mappings: Dict, data: List) -> Dict:
    """Filter the raw data and returns the filtered data,
    which will be further pushed to AWS S3.

    Args:
        mappings (Dict): List of fields to be pushed to AWS S3
      (read from mapping string)
        data (List): Data to be mapped (retrieved from Netskope)

    Returns:
        Dict: Mapped Dictionary.
    """
    mapped_dict = {}
    ignored_fields = []
    for key in mappings:
        if key in data:
            mapped_dict[key] = data[key]
        else:
            ignored_fields.append(key)
    return mapped_dict


def validate_subtype(instance):
    """Validate the subtype object mapped in mapping JSON files.

    Args:
        instance: The subtype object to be validated
    """
    schema = {
        "type": "array",
    }

    validate(instance=instance, schema=schema)


def get_mappings(mappings: Dict, data_type: str, log_prefix) -> Dict:
    """Return the dict of mappings to be applied to raw data.

    Args:
        mappings (Dict): Mapping String
        data_type (str): Data type (alert/event) for which the
        mappings are to be fetched

    Returns:
        Dict: Read mappings
    """
    mappings = mappings["taxonomy"]["json"][data_type]

    # Validate each subtype
    for subtype, subtype_map in mappings.items():
        try:
            validate_subtype(subtype_map)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(err)
    return mappings
