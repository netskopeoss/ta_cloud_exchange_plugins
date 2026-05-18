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

AWS Inspector helper module.
"""

import ipaddress
import traceback
from datetime import datetime, timezone
from packaging import version

from netskope.common.api import __version__ as CE_VERSION

from .constants import (
    DEVICE_FIELD_MAPPING,
    EC2_IPV4_KEY,
    MAXIMUM_CE_VERSION,
)


class AWSInspectorPluginHelper(object):
    """Helper for AWS Inspector field extraction and normalization.

    The helper is intentionally stateless w.r.t. the boto3 client - it only
    transforms Inspector v2 finding payloads into the CRE record schema
    advertised by ``get_entities`` in main.py.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """Init method.

        Args:
            logger: CE logger object.
            log_prefix (str): Log prefix used by the plugin.
            plugin_name (str): Plugin name from manifest.
            plugin_version (str): Plugin version from manifest.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.resolution_support = version.parse(CE_VERSION) > version.parse(
            MAXIMUM_CE_VERSION
        )
        self._patch_logger_methods()

    def _patch_logger_methods(self):
        """Monkey-patch logger.error to swallow resolution on older CE.

        resolution was added in CE > 5.1.2. Calling logger.error with that
        keyword on an older CE raises a TypeError, so we strip it when not
        supported. This mirrors the OCSF plugin so the same source works on
        both releases.

        Returns:
            None
        """
        original_error = self.logger.error

        def patched_error(
            message=None, details=None, resolution=None, **kwargs
        ):
            """Patched error method that conditionally includes resolution.

            Args:
                message: Error message.
                details: Error details.
                resolution: Resolution suggestion (only included if supported).
                **kwargs: Additional keyword arguments.

            Returns:
                Result of original error method call.
            """
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self.resolution_support:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        self.logger.error = patched_error

    def _extract_path(self, key: str, value, default=None):
        """Walk a dotted key path through nested dicts/lists.

        Args:
            key (str): Dotted key path (e.g. openPortRange.begin).
            value: Source object to traverse.
            default: Returned when the key path is not resolvable.

        Returns:
            Any: Value at the path, or default if missing.
        """
        if not key:
            return value if value is not None else default

        keys = key.split(".")

        def extract(remaining_keys, current):
            if not remaining_keys:
                return current
            head = remaining_keys[0]
            tail = remaining_keys[1:]
            if isinstance(current, list):
                results = []
                for item in current:
                    extracted = extract(remaining_keys, item)
                    if extracted is not None and extracted != default:
                        if isinstance(extracted, list):
                            results.extend(extracted)
                        else:
                            results.append(extracted)
                return results if results else default
            if not isinstance(current, dict) or head not in current:
                return default
            return extract(tail, current.get(head))

        return extract(keys, value)

    def _format_tags(self, tags) -> list:
        """Normalize the resource tags dict to a ["key:value"] list.

        AWS Inspector returns tags as a flat dict {"Name": "web-01"}. CRE
        expects Resource Tags to be a list, so we serialize each entry to
        "key:value" to keep parity with the OCSF plugin's tag handling.

        Args:
            tags: Tags dictionary or list from AWS Inspector.

        Returns:
            list: List of tag strings in "key:value" format.
        """
        if not tags:
            return []
        if isinstance(tags, dict):
            return [f"{k}:{v}" for k, v in tags.items()]
        if isinstance(tags, list):
            return [str(t) for t in tags]
        return [str(tags)]

    def _flatten_field(self, value):
        """Collapse single-element lists; join multi-element lists with comma.

        Used for fields that should surface in the CRE UI as scalar strings
        (VPC, Subnet, Region, Resource ID/Name, IP Address) but which may
        come back as lists when extracted via the dotted path walker.

        Args:
            value: Value to flatten (can be list, dict, or scalar).

        Returns:
            str: Flattened string representation of the value.
        """
        if isinstance(value, list):
            if len(value) == 1:
                return value[0]
            if len(value) > 1:
                return ", ".join(str(v) for v in value)
            return ""
        if isinstance(value, dict):
            return str(value)
        return value

    def _classify_ips(self, ip_list):
        """Split an IPv4 list into (private, public) by RFC1918 / link-local.

        Args:
            ip_list: List of IP addresses to classify.

        Returns:
            tuple: (private_ips: list, public_ips: list) classified IPs.
        """
        private_ips = []
        public_ips = []
        if not ip_list:
            return private_ips, public_ips
        if not isinstance(ip_list, list):
            ip_list = [ip_list]
        for ip in ip_list:
            try:
                addr = ipaddress.ip_address(str(ip))
            except (ValueError, TypeError):
                continue
            if (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
            ):
                private_ips.append(str(ip))
            else:
                public_ips.append(str(ip))
        return private_ips, public_ips

    def _parse_datetime(self, value):
        """Convert an Inspector datetime field into a Python datetime.

        Inspector v2 returns firstObservedAt/lastObservedAt as Unix
        epoch seconds in raw JSON responses, but boto3 typically converts
        them to native datetime objects. We accept both, plus ISO-8601
        strings, so the same helper works whether the call goes through
        boto3 or a future raw-HTTP path.

        Args:
            value: Datetime value (datetime, int/float timestamp, or str).

        Returns:
            datetime: Parsed datetime object, or None if parsing fails.
        """
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(value, tz=timezone.utc)
            except (OSError, ValueError, OverflowError):
                return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except Exception:
            return None

    def _build_record(self, finding: dict, resource: dict) -> dict:
        """Build a single CRE record from a (finding, resource) pair.

        One Inspector finding can list multiple resources, so the caller
        invokes this once per EC2 resource in the finding's resources
        array. Non-EC2 resources are filtered out by the caller.

        Args:
            finding (dict): Inspector finding object.
            resource (dict): Resource object from the finding.

        Returns:
            dict: CRE record with all mapped fields.
        """
        record = {}
        ec2_details = (resource.get("details") or {}).get(
            "awsEc2Instance"
        ) or {}
        tags = resource.get("tags") or {}
        network_reach = finding.get("networkReachabilityDetails") or {}

        for field_name, field_meta in DEVICE_FIELD_MAPPING.items():
            key = field_meta.get("key")
            context = field_meta.get("context", "event")

            if context == "event":
                value = self._extract_path(key, finding)
            elif context == "resource":
                value = self._extract_path(key, resource)
            elif context == "ec2_details":
                value = self._extract_path(key, ec2_details)
            elif context == "tags":
                value = tags.get(key) if isinstance(tags, dict) else None
            elif context == "network_reach":
                value = self._extract_path(key, network_reach)
            else:
                value = None

            if field_name == "Resource Tags":
                value = self._format_tags(tags)

            record[field_name] = value
        # Inspector returns a single ipV4Addresses list per EC2 resource;
        # classify it into Private IP / Public IP buckets so the CRE schema
        # matches the OCSF Security Hub plugin.
        ip_v4_list = ec2_details.get(EC2_IPV4_KEY) or []
        private_ips, public_ips = self._classify_ips(ip_v4_list)
        record["Private IP"] = private_ips
        record["Public IP"] = public_ips

        record = self._post_process_fields(record)

        record["First Seen"] = self._parse_datetime(record.get("First Seen"))
        record["Last Seen"] = self._parse_datetime(record.get("Last Seen"))
        return record

    def _post_process_fields(self, record: dict) -> dict:
        """Flatten list-valued scalar fields after extraction.

        Args:
            record (dict): CRE record to post-process.

        Returns:
            dict: Post-processed record with flattened fields.
        """
        fields_to_flatten = [
            "Resource ID",
            "Resource Name",
            "Region",
            "VPC ID",
            "Subnet ID",
            "Private IP",
            "Public IP",
            "Port",
            "Protocol",
        ]
        for field in fields_to_flatten:
            if field in record:
                record[field] = self._flatten_field(record[field])
        return record

    def extract_records_from_finding(self, finding: dict) -> list:
        """Convert a single Inspector finding into one CRE record per EC2.

        Inspector v2 findings carry a resources array. Even though EC2
        findings typically have exactly one resource, we iterate to be
        defensive about future schema changes and to skip any non-EC2
        resources that might appear inadvertently.

        Args:
            finding (dict): Inspector finding object.

        Returns:
            list: List of CRE records extracted from the finding.
        """
        records = []
        for resource in finding.get("resources") or []:
            if resource.get("type") != "AWS_EC2_INSTANCE":
                continue
            try:
                records.append(self._build_record(finding, resource))
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unable to process finding"
                        f" '{finding.get('findingArn', 'unknown')}'."
                        f" This record will be skipped. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                    resolution=(
                        "If this error persists for multiple records,"
                        " verify the AWS Inspector finding schema matches"
                        " the expected format."
                    ),
                )
        return records
