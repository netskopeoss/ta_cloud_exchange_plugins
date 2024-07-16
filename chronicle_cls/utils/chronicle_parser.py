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

"""CLS Google Chronicle Plugin Parser."""
import json

mapping = {
    "GENERIC_EVENT": [],
    "EMAIL_UNCATEGORIZED": [],
    "USER_UNCATEGORIZED": [
        # Any of below
        "principal.hostname principal.user.userid principal.ip principal.asset_id",
    ],
    "NETWORK_HTTP": [
        # All of the below
        "principal.ip principal.asset_id principal.hostname",
        "target.ip target.asset_id target.hostname",
    ],
    "USER_LOGIN": [
        # All of the below
        "extensions.auth.type",
        "target",
        "principal",
    ],
    "NETWORK_CONNECTION": [
        # All of the below
        "principal.ip principal.asset_id principal.hostname",
        "target.ip target.asset_id target.hostname",
    ],
    "USER_RESOURCE_ACCESS": [],
    "STATUS_UPDATE": [
        "principal.ip principal.asset_id principal.hostname",
    ],
}


class UDMParser(object):
    """UDM Parser class."""

    def __init__(self, data, logger, log_prefix, pairs, data_type, subtype):
        """Init method."""
        self.logger = logger
        self.log_prefix = log_prefix
        self.data = data
        self.pairs = pairs
        self.data_type = data_type
        self.subtype = subtype

    def convert_str_to_list(self, values):
        """Converter method."""
        out = []
        values = values or []
        if isinstance(values, str) and values != "":
            values = values.split(",")
        for val in values:
            if "@" in val.strip():
                out.append(val.strip())
        return out

    def parse_data(self):
        try:
            severity = self.data.get("severity", "")
            dlp_rule_severity = self.data.get("dlp_rule_severity", "")
            _severity = ""
            if severity != "":
                _severity = severity.upper()
            elif dlp_rule_severity != "":
                _severity = dlp_rule_severity.upper()

            self._is_significant = False
            if _severity == "CRITICAL" or _severity == "HIGH":
                self._is_significant = True
            if _severity == "UNKNOWN":
                _severity = "UNKNOWN_SEVERITY"
            if _severity != "":
                self.pairs["security_result.severity"] = _severity
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "severity", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        # Header fields
        try:
            _id = self.data.get("_id", "")
            if _id != "":
                self.pairs["metadata.product_log_id"] = _id
            self.pairs["metadata.vendor_name"] = "Netskope"
            self.pairs["metadata.product_name"] = "Netskope Alert"
            self.pairs["metadata.event_type"] = "NETWORK_HTTP"
            # we can send only read_only_udm with API
            # self.pairs["idm.is_alert"] = self.data.get("alert", False)
            # self.pairs["idm.is_significant"] = self._is_significant
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f"UDM data for Header fields, Error: {e}. "
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        # Parse Activity to decide event type and action
        try:
            activity = self.data.get("activity", "")
            action = self.data.get("action", "")
            shared_with = self.data.get("shared_with", "")
            from_user = self.data.get("from_user", "")
            _action = ""

            if activity == "Introspection Scan":
                if shared_with != "" or from_user != "":
                    self.pairs["metadata.event_type"] = "EMAIL_UNCATEGORIZED"
            elif activity == "Login Failed":
                self.pairs["metadata.event_type"] = "USER_LOGIN"
                _action = "BLOCK"
                self.pairs["extensions.auth.type"] = "MACHINE"
            elif activity == "Login Successful":
                self.pairs["metadata.event_type"] = "USER_LOGIN"
                _action = "ALLOW"
                self.pairs["extensions.auth.type"] = "MACHINE"
            elif activity == "Login Attempt":
                self.pairs["metadata.event_type"] = "USER_LOGIN"
                self.pairs["extensions.auth.type"] = "MACHINE"
            elif action == "ALLOW":
                _action = "ALLOW"
            elif action == "BLOCK":
                _action = "BLOCK"

            if _action != "":
                self.pairs["security_result.action"] = _action

            url = self.data.get("url", "")
            hostname = self.data.get("hostname", "")
            srcip = self.data.get("srcip", "")
            # dstip = self.data.get("dstip", "")
            if self.pairs["metadata.event_type"] != "EMAIL_UNCATEGORIZED":
                if url == "" or (hostname == "" and srcip == ""):
                    self.pairs["metadata.event_type"] = "GENERIC_EVENT"
                    self.pairs["metadata.description"] = json.dumps(self.data)

            # if srcip != "":
            #     self.pairs["principal.ip"] = srcip
            # if dstip != "":
            #     self.pairs["target.ip"] = dstip

            e_type = self.data.get("type", "")
            if e_type == "connection":
                self.pairs["metadata.event_type"] = "NETWORK_CONNECTION"
            elif e_type == "application":
                self.pairs["metadata.event_type"] = "USER_RESOURCE_ACCESS"

        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "activity", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        # Parse Additional information
        try:
            file_path = self.data.get("file_path", "")
            dlp_file = self.data.get("dlp_file", "")

            if file_path != "" and dlp_file == "":
                self.pairs["target.file.full_path"] = file_path
            elif dlp_file != "":
                self.pairs["target.file.full_path"] = dlp_file
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "file_path", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        self.parse_field(
            "organization_unit", "principal.administrative_domain"
        )

        try:
            browser = self.data.get("browser", "")
            if browser != "" and browser != "unknown":
                self.pairs["network.http.user_agent"] = browser
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "browser", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        try:
            from_user = self.data.get("from_user", "")
            from_user = self.convert_str_to_list(from_user)
            if len(from_user):
                self.pairs["principal.user.email_addresses"] = from_user
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "from_user", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        try:
            file_type = self.data.get("file_type", "")
            if file_type != "" and file_type.lower() != "unknown":
                self.pairs["target.file.mime_type"] = file_type
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "file_type", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        try:
            value = str(self.data.get("category", ""))
            if value != "":
                if (
                    self.pairs.get("security_result.category_details", [])
                    != []
                ):
                    self.pairs["security_result.category_details"].append(
                        value
                    )
                else:
                    self.pairs["security_result.category_details"] = [value]
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "category", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        try:
            value = str(self.data.get("alert_type", ""))
            if value != "":
                if (
                    self.pairs.get("security_result.category_details", [])
                    != []
                ):
                    self.pairs["security_result.category_details"].append(
                        value
                    )
                else:
                    self.pairs["security_result.category_details"] = [value]
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "alert_type", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        self.parse_field("malware_name", "security_result.threat_name")

        # Parse shared_with array field
        try:
            shared_with = self.data.get("shared_with", None)
            shared_with = self.convert_str_to_list(shared_with)
            if len(shared_with):
                self.pairs[
                    "intermediary.user.email_addresses"
                ] = shared_with
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "shared_with", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        self.parse_field("sha256", "target.file.sha256")
        self.parse_field("md5", "target.file.md5")
        self.parse_field("referer", "network.http.referral_url")
        self.parse_field("url", "target.url")
        self.parse_field("user", "principal.user.userid")
        self.parse_field("src_country", "principal.location.country_or_region")
        self.parse_field("src_location", "principal.location.city")
        self.parse_field("src_region", "principal.location.name")
        self.parse_field("dst_country", "target.location.country_or_region")
        self.parse_field("dst_location", "target.location.city")
        self.parse_field("dst_region", "target.location.name")
        self.parse_field("app", "target.application")
        self.parse_field("browser_session_id", "network.session_id")
        self.parse_field("os_version", "principal.platform_version")
        self.parse_field("hostname", "principal.hostname")
        self.parse_field("activity", "security_result.description")
        self.parse_field("policy", "security_result.summary")

        try:
            user = self.data.get("user", "")
            user = self.convert_str_to_list(user)
            if len(user):
                self.pairs["principal.user.email_addresses"] = user
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "user", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        try:
            value = self.data.get("protocol", "")
            if value.upper() in ["QUIC", "HTTP", "HTTPS", "DNS", "DHCP"]:
                self.pairs["network.application_protocol"] = value.upper()
            elif value != "":
                self.pairs[
                    "network.application_protocol"
                ] = "UNKNOWN_APPLICATION_PROTOCOL"
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "protocol", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        try:
            value = int(self.data.get("file_size", -1))
            if value != -1:
                self.pairs["target.file.size"] = value
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "file_size", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        try:
            value = self.data.get("nsdeviceuid", "")
            if value != "":
                self.pairs["principal.asset_id"] = f"NS:{value}"
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "device id", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

        # Check whether the all the required fields are present or not based on event_types
        self.check_event_type()

        return self.pairs

    def parse_field(self, field_name, udm_field_name):
        """Parse the field."""
        try:
            value = str(self.data.get(field_name, ""))
            if value != "":
                self.pairs[udm_field_name] = value
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while generating "
                f'UDM data for field: "{field_name}", Error: {e}. '
                f"Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")

    def is_valid_type(self, event_type, all_keys):
        """Validate type."""
        all_keys = " , ".join(all_keys)
        valid = True
        for field in mapping[event_type]:
            is_valid = False
            for x in field.split(" "):
                if x in all_keys:
                    is_valid = True
                    break
            if not is_valid:
                valid = False
                break
        return valid

    def check_event_type(self):
        """Check event type."""
        try:
            all_keys = self.pairs.keys()
            if self.is_valid_type(self.pairs["metadata.event_type"], all_keys):
                return

            if self.is_valid_type("USER_UNCATEGORIZED", all_keys):
                self.pairs["metadata.event_type"] = "USER_UNCATEGORIZED"
            else:
                self.pairs["metadata.event_type"] = "GENERIC_EVENT"
        except Exception as e:
            err_msg = (
                f"[{self.data_type}][{self.subtype}]: An error occurred while validating "
                f"Event type for chronicle, Error: {e}. Field will be ignored."
            )
            self.logger.warn(f"{self.log_prefix}: {err_msg}")
