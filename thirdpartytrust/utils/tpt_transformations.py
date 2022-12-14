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
"""

"""Contains helper class for transforming data."""

import hashlib
from typing import List


class BitSightDataTransformer:
    """BitSightDataTransformer transform class."""

    def __init__(self, allowed_fields: List, fields_to_obfuscate: List):
        """Initialize variables.

        Args:
            allowed_fields (List): Allowed Fields
            fields_to_obfuscate (List): Fields to obfuscate.
        """
        self.allowed_fields = allowed_fields
        self.fields_to_obfuscate = fields_to_obfuscate

    def __call__(self, data: List) -> List:
        """Transforms Data.

        Args:
            data (List): Original data

        Returns:
            List: Transformed Data
        """
        new_transformed_data = []

        for row in data:
            new_transformed_row = {}

            for field_name in self.allowed_fields:
                if field_name in row:
                    new_value = row[field_name]

                    if field_name in self.fields_to_obfuscate:
                        new_value = str(
                            new_value if new_value is not None else ""
                        ).strip()
                        if new_value != "":
                            field_hash = hashlib.sha256(new_value.encode())
                            new_value = field_hash.hexdigest()

                    new_transformed_row[field_name] = new_value

            if new_transformed_row:
                new_transformed_data.append(new_transformed_row)

        return new_transformed_data


def get_allowed_fields():
    allowed_fields = [
        "timestamp",
        "access_method",
        "type",
        "traffic_type",
        "transaction_id",
        "connection_id",
        "conn_duration",
        "conn_starttime",
        "conn_endtime",
        "latency_total",
        "numbytes",
        "client_bytes",
        "server_bytes",
        "request_id",
        "app",
        "appcategory",
        "ccl",
        "site",
        "url",
        "page",
        "referer",
        "instance_id",
        "instance",
        "instance_name",
        "instance_type",
        "domain",
        "activity",
        "activity_type",
        "act_user",
        "activity_status",
        "ns_activity",
        "userkey",
        "user_id",
        "user",
        "user_name",
        "ur_normalized",
        "user_normalized",
        "user_role",
        "org",
    ]
    return allowed_fields


def get_fields_to_obfuscate():
    return [
        "userkey",
        "user_id",
        "user",
        "user_name",
        "ur_normalized",
        "user_normalized",
    ]


def are_valid_type_subtype(data_type: str, subtype: str) -> bool:
    """Verify datatype and subtype.

    Args:
        data_type (str): Datatype
        subtype (str): Subtype

    Returns:
        bool: True if valid otherwise False
    """
    if data_type != "events":
        return False

    if not (subtype == "application" or subtype == "page"):
        return False

    return True
