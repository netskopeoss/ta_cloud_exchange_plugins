"""
TODO: Copyright (c) 2022 ThirdPartyTrust
"""


import hashlib
from typing import List


class ThirdPartyTrustDataTransformer:
    def __init__(self, allowed_fields: List, fields_to_obfuscate: List):
        self.allowed_fields = allowed_fields
        self.fields_to_obfuscate = fields_to_obfuscate

    def __call__(self, data: List) -> List:
        new_transformed_data = []

        for row in data:
            new_transformed_row = {}

            for field_name in self.allowed_fields:
                if field_name in row:
                    new_value = row[field_name]

                    if field_name in self.fields_to_obfuscate:
                        new_value = str(new_value if new_value is not None else "").strip()
                        if new_value != "":
                            field_hash = hashlib.sha256(new_value.encode())
                            new_value = field_hash.hexdigest()

                    new_transformed_row[field_name] = new_value

            if new_transformed_row:
                new_transformed_data.append(new_transformed_row)

        return new_transformed_data


def get_allowed_fields():
    allowed_fields = ["timestamp",
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
                      "org"]
    return allowed_fields


def get_fields_to_obfuscate():
    return ["userkey",
            "user_id",
            "user",
            "user_name",
            "ur_normalized",
            "user_normalized"]


def are_valid_type_subtype(data_type, subtype) -> bool:
    if data_type != "events":
        return False

    if not (subtype == "application" or subtype == "page"):
        return False

    return True