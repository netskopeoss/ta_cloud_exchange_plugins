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

Microsoft Azure Sentinel Helper.
"""

import sys
import json
from datetime import datetime

from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from .sentinel_exception import MappingValidationError

from .sentinel_constants import TARGET_SIZE_MB


def map_sentinel_data(mappings, data):
    """Filter the raw data and returns the filtered data, which will be
    further pushed to Azure Sentinel.

    :param mappings: List of fields to be pushed to Azure Sentinel
    (read from mapping string)
    :param data: Data to be mapped (retrieved from Netskope)
    (for example DLP is a subtype of alerts data type)
    :return: Mapped data based on fields given in mapping file
    """
    mapped_dict = {}
    for key in mappings:
        if key in data:
            mapped_dict[key] = data[key]
    return mapped_dict


def validate_subtype(instance):
    """Validate the subtype object mapped in mapping JSON files.

    :param instance: The subtype object to be validated
    """
    schema = {
        "type": "array",
    }

    validate(instance=instance, schema=schema)


def get_sentinel_mappings(mappings, data_type):
    """Return the dict of mappings to be applied to raw data.

    :param mappings: Mapping String
    :param data_type: Data type (alert/event) for which the mappings are
    to be fetched
    :return: Read mappings
    """
    mappings = mappings["taxonomy"]["json"][data_type]

    # Validate each subtype
    for subtype, subtype_map in mappings.items():
        try:
            validate_subtype(subtype_map)
        except JsonSchemaValidationError as err:
            err_msg = (
                "Error occurred while validating Azure Sentinel mappings for "
                'type "{}".Error: {}'.format(subtype, err)
            )
            raise MappingValidationError(err_msg)
    return mappings


def split_into_size(data_list):
    """
    Split a list into parts, each approximately with a target size in MB.

    Parameters:
    - data_list: The list of data to be split.

    Returns:
    A list of parts, each with a total size approximately
    equal to the target size.
    """
    result = []
    current_part = []
    current_size_mb = 0

    for item in data_list:
        item_size_mb = sys.getsizeof(json.dumps(item)) / (
            1024**2
        )  # Convert bytes to MB
        if current_size_mb + item_size_mb <= TARGET_SIZE_MB:
            current_part.append(item)
            current_size_mb += item_size_mb
        else:
            result.append(current_part)
            current_part = [item]
            current_size_mb = item_size_mb

    if current_part:
        result.append(current_part)

    return result


conversion_map = {
    "datetime": lambda epoch: datetime.utcfromtimestamp(epoch).isoformat(
        sep="T", timespec="milliseconds"
    )
    + "Z",
    "string": lambda value: str(value),
}
