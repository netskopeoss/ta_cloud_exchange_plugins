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

CTE HarfangLab plugin — pull, push, and retraction implementation.
"""

import ipaddress
import json
import re
import traceback
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Dict, Generator, List, Optional, Tuple, Union
from dateutil import parser as dateutil_parser

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
    TagIn,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)
from netskope.integrations.cte.utils import TagUtils
from pydantic import ValidationError

from .utils.constants import (
    ALLOWED_GLOBAL_STATES,
    ALLOWED_HL_STATUSES,
    ALLOWED_SOURCE_TYPES,
    ALLOWED_THREAT_DATA_TYPES,
    DATE_FORMAT,
    DATE_FORMAT_FOR_FILTER,
    DATE_FORMAT_WITH_MS,
    DBL_SUPPORTED_TYPES,
    DRIVER_BLOCK_LIST_TAG,
    DRIVER_BLOCKLIST_ENDPOINT,
    MAX_DAYS,
    IOC_RULE_CHECKPOINT_FIELD,
    IOC_RULE_ENDPOINT,
    IOC_RULE_FILTER_END_PARAM,
    IOC_RULE_FILTER_PARAM,
    CE_TAG,
    IOC_SOURCE_ENDPOINT,
    MODULE_NAME,
    NETSKOPE_CE_LIST_DESCRIPTION,
    NO_OVERRIDE_VALUE,
    PAGE_LIMIT,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RETRACTION,
    SOURCE_TYPE_DRIVER_BLOCK_LIST,
    SOURCE_TYPE_IOC_SOURCE,
    TAG_COLOR,
    VALIDATION_ERROR_MSG,
)
from .utils.helper import (
    HarfangLabPluginException,
    HarfangLabPluginHelper,
)

# Regex for FQDN: ≥2 labels before TLD (e.g. www.example.com), total ≤253.
FQDN_REGEX = re.compile(
    r"^(?=.{1,253}$)"
    r"((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.){2,}"
    r"[A-Za-z]{2,63}$"
)

# Regex for Domain: ≥1 label before TLD, optional leading wildcard.
DOMAIN_REGEX = re.compile(
    r"^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}"
)

SEVERITY_MAPPING = {
    "critical": SeverityType.CRITICAL,
    "high": SeverityType.HIGH,
    "medium": SeverityType.MEDIUM,
    "low": SeverityType.LOW,
    "informational": SeverityType.UNKNOWN,
    "": SeverityType.UNKNOWN,
}

# HarfangLab rule_confidence_override → CE reputation (max of each band).
CONFIDENCE_TO_REPUTATION = {
    "weak": 3,
    "moderate": 7,
    "strong": 10,
}

# HarfangLab raw API type → UI-visible label used in harfanglab-type tags.
HARFANGLAB_TYPE_LABELS = {
    "hash": "Hash",
    "url": "URL",
    "domain_name": "Domain name",
    "ip_src": "Source IP",
    "ip_dst": "Destination IP",
    "ip_both": "Dest. or Source IP",
}

# CE → HarfangLab type string (used in push).
INTERNAL_TYPES_TO_HARFANGLAB = {
    IndicatorType.SHA256: "hash",
    IndicatorType.MD5: "hash",
    IndicatorType.URL: "url",
    getattr(IndicatorType, "IPV4", IndicatorType.URL): "ip_both",
    getattr(IndicatorType, "IPV6", IndicatorType.URL): "ip_both",
    getattr(IndicatorType, "IPV4_CIDR", IndicatorType.URL): "ip_both",
    getattr(IndicatorType, "IPV6_CIDR", IndicatorType.URL): "ip_both",
    getattr(IndicatorType, "DOMAIN", IndicatorType.URL): "domain_name",
    getattr(IndicatorType, "FQDN", IndicatorType.URL): "domain_name",
    getattr(IndicatorType, "HOSTNAME", IndicatorType.URL): "url",
}

# Hostname regex: simple hostname pattern (alphanumeric and hyphens).
HOSTNAME_REGEX = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$"
)

# CIDR regexes used in push to detect IP/CIDR values that fell back to URL.
IPV4_CIDR_REGEX = re.compile(
    r"(?<![:/.])(?:\d{1,3}\.){3}\d{1,3}/(?:3[0-2]|[12]?\d)(?![\d./])"
)
IPV6_CIDR_REGEX = re.compile(
    r"(?<![:\w/.])"  # noqa: E501
    r"(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|::"
    r")"
    r"/(?:12[0-8]|1[01][0-9]|[1-9][0-9]|[0-9])"
    r"(?![\w:/.])"  # noqa: E501
)

# Supported CE IndicatorTypes for push (used to filter unsupported types).
SUPPORTED_PUSH_TYPES = list(INTERNAL_TYPES_TO_HARFANGLAB.keys())


class HarfangLabPlugin(PluginBase):
    """HarfangLab CTE plugin — pull, push, and retraction."""

    def __init__(self, name, *args, **kwargs):
        """Initialise plugin.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.harfanglab_helper = HarfangLabPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    # ─────────────────────────── Plugin metadata ────────────────────────────

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Return (plugin_name, plugin_version) from manifest metadata."""
        try:
            manifest_json = HarfangLabPlugin.metadata
            return (
                manifest_json.get("name", PLUGIN_NAME),
                manifest_json.get("version", PLUGIN_VERSION),
            )
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
                resolution="Check logs for more details.",
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _get_storage(self) -> Dict:
        """Return storage dict, defaulting to empty dict if None."""
        return self.storage if self.storage is not None else {}

    # ─────────────────────────── Auth helpers ───────────────────────────────

    def _get_auth_headers(self, configuration: Optional[Dict] = None) -> Dict:
        """Build Authorization header from configuration.

        Args:
            configuration (Dict): Configuration to read the API Token
                from. Defaults to self.configuration when not provided.

        Returns:
            Dict: Headers dict with Authorization and Content-Type.
        """
        configuration = (
            configuration if configuration is not None else self.configuration
        )
        api_token = configuration.get("apikey", "")
        return {
            "Authorization": f"Token {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ─────────────────────────── Tag helpers ────────────────────────────────

    def _create_tags(
        self,
        tag_utils: TagUtils,
        tag_name: str,
        color: str = TAG_COLOR,
    ) -> List[str]:
        """Ensure a tag exists in CE and return it as a list of strings.

        Args:
            tag_utils (TagUtils): TagUtils instance.
            tag_name (str): Tag name to create/verify.
            color (str): Hex color for new tags.

        Returns:
            List[str]: Single-element list with the tag name string.
        """
        tag_name = tag_name.strip()
        try:
            if not tag_utils.exists(tag_name):
                tag_utils.create_tag(
                    TagIn(name=tag_name, color=color)
                )
            return [tag_name]
        except ValueError as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Value error occurred while"
                    f" creating tag '{tag_name}'. Error: {err}"
                ),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure the tag name does not contain invalid"
                    " characters and is within the allowed length."
                ),
            )
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred"
                    f" while creating tag '{tag_name}'. Error: {err}"
                ),
                details=str(traceback.format_exc()),
                resolution=(
                    "Check CE permissions for tag creation and retry."
                ),
            )
        return []

    # ─────────────────────────── Indicator type helpers ─────────────────────

    def _determine_indicator_type(
        self, value: str
    ) -> IndicatorType:
        """Classify a HarfangLab `type: "url"` value into a CE type.

        Priority:
            1. IPv4
            2. IPv6
            3. FQDN
            4. Domain
            5. Hostname (single label)
            6. URL (fallback)

        Args:
            value (str): Raw indicator value string.

        Returns:
            IndicatorType: Mapped CE IndicatorType.
        """
        try:
            ipaddress.IPv4Address(value)
            return getattr(IndicatorType, "IPV4", IndicatorType.URL)
        except ValueError:
            pass
        try:
            ipaddress.IPv6Address(value)
            return getattr(IndicatorType, "IPV6", IndicatorType.URL)
        except ValueError:
            pass
        if FQDN_REGEX.match(value):
            return getattr(IndicatorType, "FQDN", IndicatorType.URL)
        if DOMAIN_REGEX.match(value):
            return getattr(IndicatorType, "DOMAIN", IndicatorType.URL)
        if HOSTNAME_REGEX.match(value):
            return getattr(IndicatorType, "HOSTNAME", IndicatorType.URL)
        return IndicatorType.URL

    def _determine_hash_type(
        self, value: str
    ) -> Optional[IndicatorType]:
        """Classify a hash value as SHA256 or MD5 by length.

        Args:
            value (str): Hash string.

        Returns:
            IndicatorType or None if length is unrecognised.
        """
        if len(value) == 64:
            return IndicatorType.SHA256
        if len(value) == 32:
            return IndicatorType.MD5
        return None

    def _parse_datetime(self, value: str) -> Optional[datetime]:
        """Parse ISO 8601 timestamp string to naive datetime.

        Args:
            value (str): Timestamp string (with or without milliseconds).

        Returns:
            datetime or None on parse failure.
        """
        if not value:
            return None
        for fmt in (DATE_FORMAT, DATE_FORMAT_WITH_MS, DATE_FORMAT_FOR_FILTER):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=None)
            except ValueError:
                continue
        # Fallback: strip timezone and try
        try:
            return dateutil_parser.parse(value).replace(tzinfo=None)
        except Exception:
            return None

    # ─────────────────────────── IOC Sources ────────────────────────────────

    def get_ioc_sources(
        self, configuration: Optional[Dict] = None
    ) -> Dict[str, str]:
        """Fetch all IOC source lists from HarfangLab.

        Args:
            configuration (Dict): Plugin configuration to use. Defaults
                to self.configuration when not provided.

        Returns:
            Dict[str, str]: Mapping of {name: id} for each source.
        """
        configuration = (
            configuration if configuration is not None else self.configuration
        )
        headers = self._get_auth_headers(configuration)
        url = self.harfanglab_helper.build_url(
            IOC_SOURCE_ENDPOINT, configuration
        )
        sources: Dict[str, str] = {}
        offset = 0
        while True:
            resp = self.harfanglab_helper.api_helper(
                logger_msg="fetching IOC source lists",
                url=url,
                method="GET",
                headers=headers,
                params={"limit": PAGE_LIMIT, "offset": offset},
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
            )
            for source in resp.get("results", []):
                name = source.get("name", "")
                sid = source.get("id", "")
                if name and sid:
                    sources[name] = sid
            if not resp.get("next"):
                break
            offset += PAGE_LIMIT
        return sources

    # ─────────────────────────── Pull flow ──────────────────────────────────

    def _get_ioc_source_indicators(
        self,
        start_time: datetime,
        end_time: datetime,
        threat_data_types: List[str],
        enable_tagging: bool,
        is_retraction: bool = False,
    ) -> Generator:
        """Fetch IOC Rule indicators from all non-Netskope IOC Sources.

        Sends both last_update__gte (start_time) and last_update__lte
        (end_time) to define a fixed time window per sync.  Paginates
        in PAGE_LIMIT=500 batches.  Yields (batch, end_ts) so the
        caller saves end_time as the next run's gte checkpoint.

        Args:
            start_time (datetime): Window start — last_update__gte.
            end_time (datetime): Window end — last_update__lte (now).
            threat_data_types (List[str]): Types the user wants to pull.
            enable_tagging (bool): Attach source-name tag to indicators.
            is_retraction (bool): When True, skip checkpoint updates.

        Yields:
            Tuple[List[Indicator], str]: (batch, end_ts)
        """
        if is_retraction and f"[{RETRACTION}]" not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        raw_ioc_source_list_names = self.configuration.get(
            "ioc_source_list_names", ""
        ).strip()
        source_names_filter = (
            [
                n.strip()
                for n in raw_ioc_source_list_names.split(",")
                if n.strip()
            ]
            if raw_ioc_source_list_names
            else []
        )

        all_sources = self.get_ioc_sources()

        if source_names_filter:
            sources = {
                name: sid
                for name, sid in all_sources.items()
                if name in source_names_filter
            }
            not_found = [
                n for n in source_names_filter if n not in all_sources
            ]
            if not_found:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: The following IOC Source"
                        f" list(s) were not found on {PLATFORM_NAME}"
                        f" and will be skipped: {not_found}."
                    ),
                    resolution=(
                        "Verify the 'IOC Sources Name' configuration"
                        " parameter. Ensure the source names exist on"
                        f" {PLATFORM_NAME}."
                    ),
                )
            self.logger.info(
                f"{self.log_prefix}: Fetched {len(sources)} IOC Source"
                f" list(s) based on 'IOC Source List Names' configuration."
            )
        else:
            sources = all_sources

        headers = self._get_auth_headers()
        start_ts = start_time.strftime(DATE_FORMAT_FOR_FILTER)
        end_ts = end_time.strftime(DATE_FORMAT_FOR_FILTER)
        ioc_rule_url = self.harfanglab_helper.build_url(
            IOC_RULE_ENDPOINT, self.configuration
        )

        tag_utils = TagUtils() if enable_tagging else None
        total_indicators = 0
        total_sha256 = 0
        total_md5 = 0
        total_domain = 0
        total_ipv4 = 0
        total_ipv6 = 0
        total_fqdn = 0
        total_hostname = 0
        total_url = 0

        for source_name, source_id in sources.items():
            offset = 0
            page = 1
            source_total = 0
            source_skip = 0
            ce_shared_skip = 0

            while True:
                params = {
                    "source_id": source_id,
                    IOC_RULE_FILTER_PARAM: start_ts,
                    IOC_RULE_FILTER_END_PARAM: end_ts,
                    "limit": PAGE_LIMIT,
                    "offset": offset,
                }
                resp = self.harfanglab_helper.api_helper(
                    logger_msg=(
                        f"fetching IOC rules for page {page} "
                        f"from source '{source_name}'"
                    ),
                    url=ioc_rule_url,
                    method="GET",
                    headers=headers,
                    params=params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=True,
                    is_retraction=is_retraction,
                )
                results = resp.get("results", [])
                batch: List[Indicator] = []
                sha256_count = md5_count = domain_count = ipv4_count = 0
                ipv6_count = fqdn_count = hostname_count = url_count = 0

                for record in results:
                    value = record.get("value")
                    if not value:
                        source_skip += 1
                        continue

                    # Skip indicators shared by Netskope CE to avoid
                    # re-ingestion of indicators pushed by this plugin.
                    indicator_description = record.get("description", "") or ""
                    if CE_TAG in indicator_description:
                        source_skip += 1
                        ce_shared_skip += 1
                        continue

                    raw_type = record.get("type", "")
                    ioc_type: Optional[IndicatorType] = None

                    if raw_type == "hash":
                        ioc_type = self._determine_hash_type(value)
                        if ioc_type is None:
                            source_skip += 1
                            continue
                        type_str = (
                            "sha256"
                            if ioc_type == IndicatorType.SHA256
                            else "md5"
                        )
                        if type_str not in threat_data_types:
                            source_skip += 1
                            continue
                    elif raw_type == "url":
                        ioc_type = self._determine_indicator_type(value)
                        # Map resolved CE type to threat_data_type filter
                        # string. Use if/elif (not a dict) to avoid key
                        # collisions when FQDN/DOMAIN/IPV4/IPV6 fall back to
                        # URL on older CE versions.
                        _ipv4 = getattr(IndicatorType, "IPV4", None)
                        _ipv6 = getattr(IndicatorType, "IPV6", None)
                        _ipv4_cidr = getattr(
                            IndicatorType, "IPV4_CIDR", None
                        )
                        _ipv6_cidr = getattr(
                            IndicatorType, "IPV6_CIDR", None
                        )
                        _fqdn = getattr(IndicatorType, "FQDN", None)
                        _domain = getattr(IndicatorType, "DOMAIN", None)
                        _hostname = getattr(
                            IndicatorType, "HOSTNAME", None
                        )
                        # Pre-compute CIDR flags so they can be used
                        # cleanly in the elif chain below.
                        _is_ipv4_cidr = False
                        _is_ipv6_cidr = False
                        if _ipv4_cidr is not None:
                            try:
                                ipaddress.IPv4Network(value, strict=False)
                                _is_ipv4_cidr = True
                            except ValueError:
                                pass
                        if not _is_ipv4_cidr and _ipv6_cidr is not None:
                            try:
                                ipaddress.IPv6Network(value, strict=False)
                                _is_ipv6_cidr = True
                            except ValueError:
                                pass
                        if _ipv4 and ioc_type == _ipv4:
                            type_str = "ipv4"
                        elif _ipv6 and ioc_type == _ipv6:
                            type_str = "ipv6"
                        elif _fqdn and ioc_type == _fqdn:
                            type_str = "fqdn"
                        elif _domain and ioc_type == _domain:
                            type_str = "domain"
                        elif _hostname and ioc_type == _hostname:
                            type_str = "hostname"
                        elif _is_ipv4_cidr:
                            ioc_type = _ipv4_cidr
                            type_str = "ipv4_cidr"
                        elif _is_ipv6_cidr:
                            ioc_type = _ipv6_cidr
                            type_str = "ipv6_cidr"
                        else:
                            # URL fallback, or old CE where subtypes don't
                            # exist and all resolve to IndicatorType.URL.
                            type_str = "url"
                        if type_str not in threat_data_types:
                            source_skip += 1
                            continue
                    elif raw_type == "domain_name":
                        # HarfangLab Domain Name type → FQDN or Domain only;
                        # hostname (single label) is not supported.
                        if FQDN_REGEX.match(value):
                            ioc_type = getattr(
                                IndicatorType, "FQDN", IndicatorType.URL
                            )
                            type_str = "fqdn"
                        elif DOMAIN_REGEX.match(value):
                            ioc_type = getattr(
                                IndicatorType, "DOMAIN", IndicatorType.URL
                            )
                            type_str = "domain"
                        else:
                            source_skip += 1
                            continue
                        if type_str not in threat_data_types:
                            source_skip += 1
                            continue
                    elif raw_type in ("ip_src", "ip_dst", "ip_both"):
                        # HarfangLab IP types → IPv4 or IPv6.
                        try:
                            ipaddress.IPv4Address(value)
                            ioc_type = getattr(
                                IndicatorType, "IPV4", IndicatorType.URL
                            )
                            type_str = "ipv4"
                        except ValueError:
                            pass
                        if ioc_type is None:
                            try:
                                ipaddress.IPv6Address(value)
                                ioc_type = getattr(
                                    IndicatorType, "IPV6", IndicatorType.URL
                                )
                                type_str = "ipv6"
                            except ValueError:
                                pass
                        if ioc_type is None:
                            try:
                                ipaddress.IPv4Network(value, strict=True)
                                _ipv4_cidr = getattr(
                                    IndicatorType, "IPV4_CIDR", None
                                )
                                ioc_type = (
                                    _ipv4_cidr
                                    if _ipv4_cidr is not None
                                    else IndicatorType.URL
                                )
                                type_str = (
                                    "ipv4_cidr"
                                    if _ipv4_cidr is not None
                                    else "url"
                                )
                            except ValueError:
                                pass
                        if ioc_type is None:
                            try:
                                ipaddress.IPv6Network(value, strict=True)
                                _ipv6_cidr = getattr(
                                    IndicatorType, "IPV6_CIDR", None
                                )
                                ioc_type = (
                                    _ipv6_cidr
                                    if _ipv6_cidr is not None
                                    else IndicatorType.URL
                                )
                                type_str = (
                                    "ipv6_cidr"
                                    if _ipv6_cidr is not None
                                    else "url"
                                )
                            except ValueError:
                                pass
                        if ioc_type is None:
                            ioc_type = IndicatorType.URL
                            type_str = "url"
                        if type_str not in threat_data_types:
                            source_skip += 1
                            continue
                    else:
                        source_skip += 1
                        continue

                    creation_date = record.get("creation_date", "")
                    last_update = record.get(IOC_RULE_CHECKPOINT_FIELD, "")
                    comment = record.get("comment") or ""
                    severity = SEVERITY_MAPPING.get(
                        (record.get("rule_effective_level") or "").lower(),
                        SeverityType.UNKNOWN,
                    )
                    raw_confidence = (
                        record.get("rule_confidence_override") or ""
                    ).lower()
                    reputation = CONFIDENCE_TO_REPUTATION.get(raw_confidence)

                    tags = []
                    if enable_tagging:
                        tags = self._create_tags(tag_utils, source_name)
                        type_label = HARFANGLAB_TYPE_LABELS.get(
                            raw_type, raw_type
                        )
                        tags.extend(
                            self._create_tags(
                                tag_utils,
                                f"Harfanglab-Type:{type_label}",
                            )
                        )

                    ind_kwargs = dict(
                        value=value,
                        type=ioc_type,
                        comments=comment,
                        firstSeen=self._parse_datetime(creation_date),
                        lastSeen=self._parse_datetime(last_update),
                        severity=severity,
                        tags=tags,
                    )
                    if reputation is not None:
                        ind_kwargs["reputation"] = reputation

                    try:
                        indicator = Indicator(**ind_kwargs)
                        batch.append(indicator)
                        source_total += 1
                        total_indicators += 1
                        if ioc_type == IndicatorType.SHA256:
                            sha256_count += 1
                            total_sha256 += 1
                        elif ioc_type == IndicatorType.MD5:
                            md5_count += 1
                            total_md5 += 1
                        elif ioc_type == getattr(IndicatorType, "IPV4", None):
                            ipv4_count += 1
                            total_ipv4 += 1
                        elif ioc_type == getattr(IndicatorType, "IPV6", None):
                            ipv6_count += 1
                            total_ipv6 += 1
                        elif ioc_type == getattr(IndicatorType, "FQDN", None):
                            fqdn_count += 1
                            total_fqdn += 1
                        elif ioc_type == getattr(
                            IndicatorType, "DOMAIN", None
                        ):
                            domain_count += 1
                            total_domain += 1
                        elif ioc_type == getattr(
                            IndicatorType, "HOSTNAME", None
                        ):
                            hostname_count += 1
                            total_hostname += 1
                        elif ioc_type == IndicatorType.URL:
                            url_count += 1
                            total_url += 1
                    except ValidationError as err:
                        source_skip += 1
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Validation error occurred"
                                f" while parsing indicator '{value}' fetched"
                                f" from IOC Source '{source_name}'."
                                f" This indicator will be skipped."
                                f" Error: {err}."
                            ),
                            details=str(traceback.format_exc()),
                            resolution=(
                                "Check the indicator data format in IOC Source"
                                f" '{source_name}'. The record may contain an"
                                " unsupported value or field type."
                            ),
                        )
                    except Exception as err:
                        source_skip += 1
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Unexpected error occurred"
                                f" while parsing indicator '{value}' fetched"
                                f" from IOC Source '{source_name}'."
                                f" This indicator will be skipped."
                                f" Error: {err}."
                            ),
                            details=str(traceback.format_exc()),
                            resolution=(
                                "Check the indicator data returned by"
                                f" HarfangLab IOC Source '{source_name}'"
                                " and verify the API response structure."
                            ),
                        )

                page_skip = len(results) - len(batch)
                page_stats = ", ".join(
                    f"{label}: {count}"
                    for label, count in [
                        ("SHA256", sha256_count),
                        ("MD5", md5_count),
                        ("Domain", domain_count),
                        ("IPv4", ipv4_count),
                        ("IPv6", ipv6_count),
                        ("FQDN", fqdn_count),
                        ("Hostname", hostname_count),
                        ("URL", url_count),
                    ]
                    if count > 0
                )
                self.logger.info(
                    f"{self.log_prefix}: Pulled {len(batch)} indicator(s)"
                    f" from page {page} of IOC Source '{source_name}'"
                    f" from {PLATFORM_NAME} platform."
                    + (f" Pull Stats: {page_stats}." if page_stats else "")
                    + (f" Skipped: {page_skip}." if page_skip else "")
                    + f" Total indicator(s) pulled - {total_indicators}."
                )
                if batch:
                    # Yield end_ts as checkpoint — next run's gte value.
                    yield batch, end_ts

                if not resp.get("next"):
                    break
                offset += PAGE_LIMIT
                page += 1

            if ce_shared_skip > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {ce_shared_skip}"
                    f" indicator(s) from IOC Source '{source_name}'"
                    " as they were shared by Netskope CE to avoid"
                    " re-ingestion."
                )
            if source_skip - ce_shared_skip > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped"
                    f" {source_skip - ce_shared_skip} indicator(s)"
                    f" from IOC Source '{source_name}' as indicator"
                    " value(s) might be empty or invalid."
                )

        self.logger.info(
            f"{self.log_prefix}: Successfully pulled {total_indicators}"
            f" indicator(s) from {PLATFORM_NAME} IOC Source."
        )

    def _get_driver_block_list_indicators(
        self,
        threat_data_types: List[str],
        enable_tagging: bool,
    ) -> Generator:
        """Fetch ALL indicators from the Driver Block List every pull.

        The Driver Block List has no date-filter API, so the full list
        is fetched on every sync in PAGE_LIMIT=500 batches.  No
        checkpoint is maintained for this source.

        Args:
            threat_data_types (List[str]): Types the user wants to pull.
            enable_tagging (bool): Attach fixed tag to indicators.

        Yields:
            List[Indicator]: One batch of up to PAGE_LIMIT indicators.
        """
        headers = self._get_auth_headers()
        url = self.harfanglab_helper.build_url(
            DRIVER_BLOCKLIST_ENDPOINT, self.configuration
        )

        tag_utils = TagUtils() if enable_tagging else None
        total_fetched = 0
        total_skipped = 0
        total_sha256 = 0
        total_md5 = 0
        page = 1
        offset = 0

        self.logger.info(
            f"{self.log_prefix}: Pulling Driver Block List indicators"
            f" from {PLATFORM_NAME} platform."
        )

        while True:
            resp = self.harfanglab_helper.api_helper(
                logger_msg=f"fetching Driver Block List (page {page})",
                url=url,
                method="GET",
                headers=headers,
                params={"limit": PAGE_LIMIT, "offset": offset},
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
            )
            results = resp.get("results", [])
            batch: List[Indicator] = []
            sha256_count = md5_count = 0
            source_skip = 0

            for record in results:
                value = record.get("value")
                if not value:
                    total_skipped += 1
                    source_skip += 1
                    continue

                ioc_type = self._determine_hash_type(value)
                if ioc_type is None:
                    total_skipped += 1
                    source_skip += 1
                    continue

                type_str = (
                    "sha256"
                    if ioc_type == IndicatorType.SHA256
                    else "md5"
                )
                if type_str not in threat_data_types:
                    total_skipped += 1
                    source_skip += 1
                    continue

                creation_date = record.get("creation_date", "")
                last_update = record.get("last_update", "")
                comment = record.get("comment") or ""
                severity = SEVERITY_MAPPING.get(
                    (record.get("rule_effective_level") or "").lower(),
                    SeverityType.UNKNOWN,
                )
                tags = []
                if enable_tagging:
                    tags = self._create_tags(
                        tag_utils, DRIVER_BLOCK_LIST_TAG
                    )

                try:
                    indicator = Indicator(
                        value=value,
                        type=ioc_type,
                        comments=comment,
                        firstSeen=self._parse_datetime(creation_date),
                        lastSeen=self._parse_datetime(last_update),
                        severity=severity,
                        tags=tags,
                    )
                    batch.append(indicator)
                    total_fetched += 1
                    if ioc_type == IndicatorType.SHA256:
                        sha256_count += 1
                        total_sha256 += 1
                    elif ioc_type == IndicatorType.MD5:
                        md5_count += 1
                        total_md5 += 1
                except ValidationError as err:
                    total_skipped += 1
                    source_skip += 1
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Validation error occurred"
                            f" while parsing indicator '{value}' fetched"
                            f" from Driver Block List."
                            f" This indicator will be skipped."
                            f" Error: {err}."
                        ),
                        details=str(traceback.format_exc()),
                        resolution=(
                            "Check the indicator data format in Driver Block"
                            " List. The record may contain an unsupported"
                            " value or field type."
                        ),
                    )
                except Exception as err:
                    total_skipped += 1
                    source_skip += 1
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Unexpected error occurred"
                            f" while parsing indicator '{value}' fetched"
                            f" from Driver Block List."
                            f" This indicator will be skipped."
                            f" Error: {err}."
                        ),
                        details=str(traceback.format_exc()),
                        resolution=(
                            "Check the indicator data returned by HarfangLab"
                            " Driver Block List and verify the API response"
                            " structure."
                        ),
                    )

            page_skip = len(results) - len(batch)
            page_stats = ", ".join(
                f"{label}: {count}"
                for label, count in [
                    ("SHA256", sha256_count),
                    ("MD5", md5_count),
                ]
                if count > 0
            )
            self.logger.info(
                f"{self.log_prefix}: Pulled {len(batch)} indicator(s)"
                f" from page {page} of Driver Block List from"
                f" {PLATFORM_NAME} platform."
                + (f" Pull Stats: {page_stats}." if page_stats else "")
                + (f" Skipped: {page_skip}." if page_skip else "")
                + f" Total indicator(s) pulled - {total_fetched}."
            )
            if batch:
                yield batch

            if not resp.get("next"):
                break
            offset += PAGE_LIMIT
            page += 1

        total_stats = ", ".join(
            f"{label}: {count}"
            for label, count in [
                ("SHA256", total_sha256),
                ("MD5", total_md5),
            ]
            if count > 0
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully pulled {total_fetched}"
            f" indicator(s) from {PLATFORM_NAME} Driver Block List."
            + (
                f" Skipped {total_skipped} indicator(s) due to empty"
                " or None indicator value."
                if total_skipped
                else ""
            )
        )

    def _pull(
        self, is_retraction: bool = False, retraction_start_time=None
    ) -> Generator:
        """Internal pull generator.

        Handles checkpoint resolution, routes to per-source fetch
        methods, and yields (indicators, checkpoints) tuples when
        sub_checkpoint is supported by the CE host.

        Args:
            is_retraction (bool): When True, only fetch IOC Source
                indicators using the supplied retraction_start_time;
                skip Driver Block List and do not update storage.
            retraction_start_time (datetime): Start of retraction window
                (used only when is_retraction=True).

        Yields:
            Tuple[List[Indicator], Optional[Dict]]:
                (batch, checkpoints_dict)
        """
        plugin_storage = self._get_storage()
        current_sub_checkpoint = getattr(self, "sub_checkpoint", {})
        plugin_configuration = self.configuration

        selected_source_types = plugin_configuration.get(
            "source_type",
            [SOURCE_TYPE_IOC_SOURCE, SOURCE_TYPE_DRIVER_BLOCK_LIST],
        ) or [SOURCE_TYPE_IOC_SOURCE, SOURCE_TYPE_DRIVER_BLOCK_LIST]

        selected_threat_data_types = plugin_configuration.get(
            "threat_data_type", list(ALLOWED_THREAT_DATA_TYPES)
        )
        if not selected_threat_data_types:
            selected_threat_data_types = list(ALLOWED_THREAT_DATA_TYPES)

        # Driver Block List supports hash types only.
        dbl_threat_data_types = [
            data_type
            for data_type in selected_threat_data_types
            if data_type in DBL_SUPPORTED_TYPES
        ]

        is_tagging_enabled = (
            plugin_configuration.get("enable_tagging", "yes").lower() == "yes"
        )
        initial_range_in_days = int(plugin_configuration.get("days", 7))

        # end_time is fixed once per pull run; becomes the next gte checkpoint.
        pull_end_time = datetime.now(timezone.utc).replace(tzinfo=None)

        # ── IOC Source pull (time-window: gte → lte) ─────────────────
        if SOURCE_TYPE_IOC_SOURCE in selected_source_types:
            # Resolve IOC Source start checkpoint (gte)
            if is_retraction and retraction_start_time:
                ioc_source_start_time = retraction_start_time
            elif current_sub_checkpoint:
                ioc_source_start_time = current_sub_checkpoint.get(
                    "ioc_source_checkpoint"
                )
                if ioc_source_start_time is None:
                    ioc_source_start_time = self.last_run_at
            elif self.last_run_at:
                ioc_source_start_time = self.last_run_at
            else:
                ioc_source_start_time = pull_end_time - timedelta(
                    days=initial_range_in_days
                )
                self.logger.info(
                    f"{self.log_prefix}: This is initial data fetch since"
                    f" checkpoint is empty. Pulling IOC Source indicators"
                    f" from {PLATFORM_NAME} for the last"
                    f" {initial_range_in_days} day(s)."
                )

            # Parse string checkpoint to datetime if needed.
            if isinstance(ioc_source_start_time, str):
                ioc_source_start_time = (
                    self._parse_datetime(ioc_source_start_time)
                    or pull_end_time - timedelta(days=initial_range_in_days)
                )

            self.logger.info(
                f"{self.log_prefix}: Pulling IOC Source indicators from"
                f" {PLATFORM_NAME} platform using checkpoint:"
                f" {ioc_source_start_time.strftime(DATE_FORMAT)}."
            )
            ioc_src_batches = self._get_ioc_source_indicators(
                start_time=ioc_source_start_time,
                end_time=pull_end_time,
                threat_data_types=selected_threat_data_types,
                enable_tagging=is_tagging_enabled,
                is_retraction=is_retraction,
            )
            for ioc_source_batch, ioc_source_end_ts in ioc_src_batches:
                if not is_retraction:
                    # Save end_time as checkpoint; next run's gte = this lte.
                    plugin_storage["checkpoints"] = {
                        "ioc_source_checkpoint": ioc_source_end_ts,
                    }
                if ioc_source_batch:
                    if hasattr(self, "sub_checkpoint"):
                        yield (
                            ioc_source_batch,
                            plugin_storage.get("checkpoints"),
                        )
                    else:
                        yield ioc_source_batch, None

        # ── Driver Block List pull (full refresh every run) ───────────
        if (
            SOURCE_TYPE_DRIVER_BLOCK_LIST in selected_source_types
            and not is_retraction
        ):
            if dbl_threat_data_types:
                for dbl_batch in self._get_driver_block_list_indicators(
                    threat_data_types=dbl_threat_data_types,
                    enable_tagging=is_tagging_enabled,
                ):
                    if dbl_batch:
                        if hasattr(self, "sub_checkpoint"):
                            yield dbl_batch, plugin_storage.get("checkpoints")
                        else:
                            yield dbl_batch, None
            else:
                self.logger.info(
                    f"{self.log_prefix}: No supported hash types (SHA256/MD5)"
                    " selected for Driver Block List. Skipping."
                )

    def pull(self) -> List[Indicator]:
        """Pull indicators from HarfangLab (public CE entry point).

        Returns:
            List[Indicator]: Pulled indicators, or a generator when
                the CE host supports sub_checkpoint.
        """
        is_pull_required = self.configuration.get(
            "is_pull_required", "Yes"
        )
        if is_pull_required.lower() == "no":
            self.logger.info(
                f"{self.log_prefix}: Polling is disabled in configuration "
                "parameter hence skipping pulling of indicators from"
                f" {PLATFORM_NAME}."
            )
            return []

        if hasattr(self, "sub_checkpoint"):
            def _wrapper(plugin):
                yield from plugin._pull()
            return _wrapper(self)

        indicators: List[Indicator] = []
        for batch, _ in self._pull():
            indicators.extend(batch)
        self.logger.info(
            f"{self.log_prefix}: Successfully pulled {len(indicators)}"
            f" indicator(s) from {PLATFORM_NAME}."
        )
        return indicators

    # ─────────────────────────── Push flow ──────────────────────────────────

    def get_actions(self) -> List[ActionWithoutParams]:
        """Return available push actions."""
        return [
            ActionWithoutParams(
                label="Create IOCs",
                value="create_iocs",
            ),
        ]

    def get_action_fields(self, action: Action) -> list:
        """Return parameter fields for the given action."""
        if action.value != "create_iocs":
            return []
        create_new_list_sentinel = {"create_new_list": "id"}
        try:
            ioc_sources = self.get_ioc_sources()
        except Exception as err:
            err_msg = "Error occurred while fetching IOC Sources."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Verify the HarfangLab connectivity and the API Token"
                    " permissions."
                ),
            )
            ioc_sources = {}
        choice_list = [
            {
                "key": name,
                "value": json.dumps({name: sid}),
            }
            for name, sid in ioc_sources.items()
        ] + [
            {
                "key": "Create New IOC List",
                "value": json.dumps(create_new_list_sentinel),
            }
        ]
        no_override_choice = {"key": "No override", "value": NO_OVERRIDE_VALUE}
        return [
            {
                "label": "IOC Source Name",
                "key": "ioc_list_name",
                "type": "choice",
                "choices": choice_list,
                "default": choice_list[0]["value"] if choice_list else "",
                "mandatory": True,
                "description": (
                    "Select an existing IOC Source list dropdown"
                    " or select 'Create New IOC List'."
                ),
            },
            {
                "label": "New IOC Sources Name",
                "key": "new_source",
                "type": "text",
                "mandatory": False,
                "description": (
                    "Name of the new IOC Sources to create on"
                    f" {PLATFORM_NAME}. Required when 'Create New IOC"
                    " List' is selected."
                ),
            },
            {
                "label": "Name",
                "key": "name",
                "type": "text",
                "mandatory": False,
                "description": (
                    "Optional display name for the IOC."
                ),
            },
            {
                "label": "Description",
                "key": "description",
                "type": "text",
                "mandatory": False,
                "description": (
                    "Optional description for the IOC."
                ),
            },
            {
                "label": "Comment",
                "key": "comment",
                "type": "text",
                "mandatory": False,
                "description": (
                    "Optional comment for the IOC."
                ),
            },
            {
                "label": "References",
                "key": "references",
                "type": "text",
                "mandatory": False,
                "description": (
                    "Optional comma-separated list of reference URLs or"
                    " identifiers."
                    " Each entry will be sent as a separate item."
                ),
            },
            {
                "label": "Confidence Override",
                "key": "rule_confidence_override",
                "type": "choice",
                "choices": [
                    no_override_choice,
                    {"key": "IOC Reputation", "value": "ioc_reputation"},
                ],
                "default": NO_OVERRIDE_VALUE,
                "mandatory": False,
                "description": (
                    "Override the confidence for all pushed IOC(s)."
                    " Select 'IOC Reputation' to derive confidence from"
                    " the indicator's reputation score (1-3: weak,"
                    " 4-7: moderate, 8-10: strong)."
                ),
            },
            {
                "label": "Action",
                "key": "global_state",
                "type": "choice",
                "choices": [
                    {"key": "Disabled", "value": "disabled"},
                    {"key": "Backend Alert", "value": "backend_alert"},
                    {"key": "Alert", "value": "alert"},
                    {"key": "Block", "value": "block"},
                    {"key": "Quarantine", "value": "quarantine"},
                ],
                "default": "alert",
                "mandatory": False,
                "description": (
                    "Select the action for all pushed IOC(s)."
                    " Default value is 'Alert'."
                ),
            },
            {
                "label": "Maturity",
                "key": "hl_status",
                "type": "choice",
                "choices": [
                    {"key": "Stable", "value": "stable"},
                    {"key": "Testing", "value": "testing"},
                    {"key": "Experimental", "value": "experimental"},
                ],
                "default": "stable",
                "mandatory": False,
                "description": (
                    "Select the maturity status for all pushed IOC(s)."
                    " Default value is 'Stable'."
                ),
            },
        ]

    def validate_list(
        self,
        ioc_list_name: str,
        ioc_list_id: str,
        new_source_name: str,
    ) -> Tuple[str, str]:
        """Validate or create the IOC List before pushing.

        Args:
            ioc_list_name (str): Selected list name (or 'create_new_list').
            ioc_list_id (str): Selected list ID.
            new_source_name (str): Name for new list (when creating).

        Returns:
            Tuple[str, str]: (resolved_name, resolved_id)

        Raises:
            HarfangLabPluginException: If the list does not exist and
                cannot be created.
        """
        try:
            all_lists = self.get_ioc_sources()
            if ioc_list_name != "create_new_list":
                if ioc_list_name not in all_lists:
                    err_msg = (
                        f"The selected IOC List '{ioc_list_name}'"
                        f" does not exist on {PLATFORM_NAME}."
                        " Select a valid list or choose"
                        " 'Create New IOC List'."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=(
                            f"'{ioc_list_name}' not found in"
                            f" {PLATFORM_NAME} IOC sources."
                        ),
                        resolution=(
                            f"Navigate to {PLATFORM_NAME} Threat Intelligence"
                            " > IOC to verify the list exists, or choose"
                            " 'Create New IOC List'."
                        ),
                    )
                    raise HarfangLabPluginException(err_msg)
                self.logger.info(
                    f"{self.log_prefix}: Verified IOC List"
                    f" '{ioc_list_name}'."
                )
                return ioc_list_name, ioc_list_id

            # "create_new_list" — check if the name already exists
            if new_source_name in all_lists:
                existing_id = all_lists[new_source_name]
                self.logger.info(
                    f"{self.log_prefix}: IOC List '{new_source_name}'"
                    f" already exists."
                    " Indicators will be shared to the existing list."
                )
                return new_source_name, existing_id

            # Create the new list
            headers = self._get_auth_headers()
            url = self.harfanglab_helper.build_url(
                IOC_SOURCE_ENDPOINT, self.configuration
            )
            create_resp = self.harfanglab_helper.api_helper(
                logger_msg=(
                    f"creating new IOC List '{new_source_name}'"
                ),
                url=url,
                method="POST",
                headers=headers,
                json_body={
                    "name": new_source_name,
                    "description": NETSKOPE_CE_LIST_DESCRIPTION,
                },
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
            )
            new_id = create_resp.get("id", "")
            self.logger.info(
                f"{self.log_prefix}: Created new IOC List"
                f" '{new_source_name}' (ID: {new_id})."
            )
            return new_source_name, new_id

        except HarfangLabPluginException:
            raise
        except Exception as err:
            err_msg = "Error occurred while resolving IOC List."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Verify the IOC List configuration and HarfangLab"
                    " connectivity. Check the API Token permissions."
                ),
            )
            raise HarfangLabPluginException(err_msg)

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate push action configuration.

        Args:
            action (Action): Action to validate.

        Returns:
            ValidationResult: Result with success flag and message.
        """
        try:
            if action.value not in ["create_iocs"]:
                return ValidationResult(
                    success=False,
                    message=(
                        f"Invalid action '{action.value}'."
                        " Supported action: 'create_iocs'."
                    ),
                )

            params = action.parameters
            ioc_list_raw = params.get("ioc_list_name", "")
            if not ioc_list_raw:
                return ValidationResult(
                    success=False,
                    message="IOC List Name is a required field.",
                )
            if not isinstance(ioc_list_raw, str):
                return ValidationResult(
                    success=False,
                    message="Invalid IOC List Name provided.",
                )

            try:
                ioc_list_dict = json.loads(ioc_list_raw)
            except (json.JSONDecodeError, ValueError):
                return ValidationResult(
                    success=False,
                    message=(
                        "IOC List Name value could not be parsed."
                        " Please re-select from the dropdown."
                    ),
                )

            ioc_list_name = next(iter(ioc_list_dict), None)
            if not ioc_list_name:
                return ValidationResult(
                    success=False,
                    message=(
                        "IOC List Name value could not be parsed."
                        " Please re-select from the dropdown."
                    ),
                )
            ioc_list_id = ioc_list_dict.get(ioc_list_name, "")
            new_source_name = params.get("new_source", "").strip()

            if ioc_list_name == "create_new_list" and not new_source_name:
                return ValidationResult(
                    success=False,
                    message=(
                        "New IOC List Name is required when"
                        " 'Create New IOC List' is selected."
                    ),
                )

            # Validate action choice fields using the common validator
            action_field_specs = [
                (
                    "rule_confidence_override",
                    "Confidence Override",
                    [NO_OVERRIDE_VALUE, "ioc_reputation"],
                ),
                (
                    "global_state",
                    "Action",
                    sorted(ALLOWED_GLOBAL_STATES),
                ),
                (
                    "hl_status",
                    "Maturity",
                    sorted(ALLOWED_HL_STATUSES),
                ),
            ]
            for field_key, field_label, allowed in action_field_specs:
                validation_result = self._validate_configuration_parameters(
                    field_name=field_label,
                    field_value=params.get(field_key, ""),
                    field_type=str,
                    is_required=False,
                    allowed_values=allowed,
                )
                if validation_result:
                    return validation_result

            _, resolved_id = self.validate_list(
                ioc_list_name, ioc_list_id, new_source_name
            )
            if resolved_id:
                return ValidationResult(
                    success=True,
                    message="Validation successful.",
                )
            return ValidationResult(
                success=False,
                message=(
                    f"Could not find or create the IOC List on"
                    f" {PLATFORM_NAME}."
                ),
            )

        except HarfangLabPluginException as err:
            return ValidationResult(
                success=False, message=str(err)
            )
        except Exception as err:
            err_msg = "Error occurred while validating action."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Re-select the IOC List from the dropdown and save"
                    " the action configuration."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

    def push(
        self,
        indicators: List[Indicator],
        action_dict: Dict,
        source=None,
        business_rule=None,
        plugin_name=None,
    ) -> PushResult:
        """Share indicators to a HarfangLab IOC List.

        Args:
            indicators (List[Indicator]): Indicators to push.
            action_dict (Dict): Action configuration dict.

        Returns:
            PushResult: Result with success flag and message.
        """
        action_label = action_dict.get("label", "")
        action_params = action_dict.get("parameters", {})
        self.logger.info(
            f"{self.log_prefix}: Executing push method for"
            f' "{action_label}" target action.'
        )

        try:
            ioc_list_dict = json.loads(
                action_params.get("ioc_list_name", "{}")
            )
            ioc_list_name = next(iter(ioc_list_dict), None)
            if not ioc_list_name:
                raise HarfangLabPluginException(
                    "IOC List Name value could not be parsed."
                    " Please re-select from the dropdown."
                )
            ioc_list_id = ioc_list_dict.get(ioc_list_name, "")
            new_list_name = action_params.get("new_source", "").strip()

            list_name, list_id = self.validate_list(
                ioc_list_name, ioc_list_id, new_list_name
            )
            if not list_id:
                err_msg = (
                    f"The IOC List '{list_name}' does not exist on"
                    f" {PLATFORM_NAME}."
                )
                raise HarfangLabPluginException(err_msg)

            headers = self._get_auth_headers()
            ioc_rule_url = self.harfanglab_helper.build_url(
                IOC_RULE_ENDPOINT, self.configuration
            )

            # Extract optional push-action fields (applied to every indicator)
            opt_name = action_params.get("name", "").strip() or None
            opt_description = (
                action_params.get("description", "").strip() or None
            )
            opt_comment = action_params.get("comment", "").strip() or None
            raw_references = action_params.get("references", "").strip()
            # Split comma-separated entries into a list; each entry is a
            # separate item in the API's `references` array.
            opt_references = (
                [r.strip() for r in raw_references.split(",") if r.strip()]
                if raw_references
                else None
            )
            opt_rule_confidence = action_params.get(
                "rule_confidence_override", NO_OVERRIDE_VALUE
            )
            opt_global_state = action_params.get("global_state", "alert")
            opt_hl_status = action_params.get("hl_status", "stable")

            # Materialise generator before filtering
            indicators = list(indicators)
            # Filter by supported types
            valid_indicators = [
                ind
                for ind in indicators
                if ind.type in SUPPORTED_PUSH_TYPES
            ]
            skipped_type = len(indicators) - len(valid_indicators)
            self.logger.info(
                f"{self.log_prefix}: Executing '{action_label}' action"
                f" for {len(valid_indicators)} indicator(s)."
                + (
                    f" {skipped_type} indicator(s) will be skipped"
                    " as they are of unsupported types."
                    if skipped_type
                    else ""
                )
            )

            total_pushed = 0
            total_duplicated = 0
            total_failed = 0
            failed_iocs = []

            if action_dict.get("value") == "create_iocs":
                for indicator in valid_indicators:
                    value = indicator.value
                    if not value:
                        total_failed += 1
                        continue

                    hl_type = INTERNAL_TYPES_TO_HARFANGLAB.get(
                        indicator.type, "url"
                    )
                    if indicator.type == IndicatorType.URL:
                        if (
                            IPV4_CIDR_REGEX.search(value)
                            or IPV6_CIDR_REGEX.search(value)
                        ):
                            try:
                                ipaddress.IPv4Network(value, strict=False)
                                hl_type = "ip_both"
                            except ValueError:
                                try:
                                    ipaddress.IPv6Network(value, strict=False)
                                    hl_type = "ip_both"
                                except ValueError:
                                    hl_type = "url"
                        else:
                            hl_type = "url"
                    # For ip_both (including CIDR), honour the original
                    # HarfangLab direction tag from pull.
                    if hl_type == "ip_both":
                        ind_tag_names = {
                            t if isinstance(t, str)
                            else getattr(t, "name", "")
                            for t in (indicator.tags or [])
                        }
                        if "Harfanglab-Type:Source IP" in ind_tag_names:
                            hl_type = "ip_src"
                        elif "Harfanglab-Type:Destination IP" in ind_tag_names:
                            hl_type = "ip_dst"
                    json_body = {
                        "value": value,
                        "source_id": list_id,
                        "type": hl_type,
                        "global_state": opt_global_state,
                        "hl_status": opt_hl_status,
                    }
                    if opt_name is not None:
                        json_body["name"] = opt_name
                    # Always stamp the CE description so pull can identify and
                    # skip re-ingestion of indicators pushed by this plugin.
                    ce_description = (
                        f"{CE_TAG} | {plugin_name}"
                        if plugin_name else CE_TAG
                    )
                    json_body["description"] = (
                        f"{ce_description} | {opt_description}"
                        if opt_description is not None
                        else ce_description
                    )
                    if opt_comment is not None:
                        json_body["comment"] = opt_comment
                    if opt_references is not None:
                        json_body["references"] = opt_references
                    severity_to_level = {
                        SeverityType.CRITICAL: "critical",
                        SeverityType.HIGH: "high",
                        SeverityType.MEDIUM: "medium",
                        SeverityType.LOW: "low",
                        SeverityType.UNKNOWN: "informational",
                    }
                    rule_level = severity_to_level.get(indicator.severity)
                    if rule_level:
                        json_body["rule_level_override"] = rule_level
                    if opt_rule_confidence == "ioc_reputation":
                        reputation = getattr(indicator, "reputation", None)
                        if reputation is not None:
                            if reputation <= 3:
                                confidence = "weak"
                            elif reputation <= 7:
                                confidence = "moderate"
                            else:
                                confidence = "strong"
                            json_body["rule_confidence_override"] = confidence
                    else:
                        json_body["rule_confidence_override"] = None

                    resp = self.harfanglab_helper.api_helper(
                        logger_msg=(
                            f"sharing indicator '{value}'"
                        ),
                        url=ioc_rule_url,
                        method="POST",
                        headers=headers,
                        json_body=json_body,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        is_handle_error_required=False,
                    )
                    if resp.status_code == 201:
                        total_pushed += 1
                    elif resp.status_code == 400:
                        body = resp.text or ""
                        if (
                            "Ioc rule with this Type, Value"
                            " and Source already exists." in body
                        ):
                            total_duplicated += 1
                        else:
                            self.logger.warning(
                                f"{self.log_prefix}: Skipping indicator"
                                f" '{value}' as {PLATFORM_NAME} does not"
                                f" support this indicator value format."
                                f" API response: {body}"
                            )
                    else:
                        # Let handle_error raise for 4xx/5xx
                        try:
                            self.harfanglab_helper.handle_error(
                                resp,
                                f"sharing indicator '{value}'",
                            )
                            total_pushed += 1
                        except HarfangLabPluginException as err:
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: Failed to"
                                    f" share indicator '{value}'."
                                    f" Error: {err}"
                                ),
                                resolution=(
                                    "Verify the API Token has write"
                                    " permissions for the selected"
                                    f" IOC List on {PLATFORM_NAME}."
                                ),
                            )
                            total_failed += 1
                            failed_iocs.append(value)

            self.logger.info(
                f"{self.log_prefix}: Successfully shared"
                f" {total_pushed} indicator(s), {total_duplicated}"
                " already present, failed to share"
                f" {total_failed} indicator(s)."
            )
            return PushResult(
                success=True,
                message=(
                    f"Successfully executed '{action_label}' action."
                ),
                failed_iocs=failed_iocs,
            )

        except HarfangLabPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error sharing indicators"
                    f" with {PLATFORM_NAME}. Error: {err}"
                ),
                details=str(traceback.format_exc()),
                resolution=(
                    f"Verify the IOC List exists on {PLATFORM_NAME}"
                    " and the API Token has write permissions."
                ),
            )
            return PushResult(
                success=False,
                message=str(err),
            )
        except Exception as err:
            err_msg = (
                f"Unexpected error while sharing indicators"
                f" with {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Verify HarfangLab connectivity, API Token"
                    " permissions, and the selected IOC List."
                ),
            )
            return PushResult(success=False, message=err_msg)

    # ─────────────────────────── Retraction flow ────────────────────────────

    def get_modified_indicators(
        self,
        source_indicators: List[List[Indicator]],
    ):
        """Get all modified indicators status for retraction.

        Called by the CE framework when 'IoC(s) Retraction' is enabled.

        - IOC Source: re-pulls active indicators from HarfangLab for the
          configured retraction_interval (in days).  CE IOC Source indicators
          NOT found in that window are considered retracted.
        - Driver Block List: pulls ALL current indicators (no time filter).
          CE DBL indicators (tagged with DRIVER_BLOCK_LIST_TAG) NOT present in
          the current full list are considered deleted/retracted. Only runs
          when dbl_retraction is set to 'yes'.
        - Both selected: both workflows run concurrently; retracted sets are
          combined and yielded per source batch.
        - Only IOC Source selected with no retraction_interval: skip entirely
          (yield [], True).
        - Only DBL selected with dbl_retraction='no': skip entirely.

        Args:
            source_indicators: CE indicator batches (List[List[Indicator]]).

        Yields:
            tuple: (list_of_retracted_indicator_values, skip_bool)
                skip_bool=True  → skip retraction for this batch
                skip_bool=False → retraction list is valid
        """
        if f"[{RETRACTION}]" not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        
        plugin_configuration = self.configuration

        selected_source_types = plugin_configuration.get(
            "source_type",
            [SOURCE_TYPE_IOC_SOURCE, SOURCE_TYPE_DRIVER_BLOCK_LIST],
        ) or [SOURCE_TYPE_IOC_SOURCE, SOURCE_TYPE_DRIVER_BLOCK_LIST]

        ioc_source_selected = SOURCE_TYPE_IOC_SOURCE in selected_source_types
        dbl_selected = SOURCE_TYPE_DRIVER_BLOCK_LIST in selected_source_types

        enable_retraction = (
            plugin_configuration.get("enable_retraction", "no").lower() == "yes"
        )

        if not enable_retraction:
            self.logger.info(
                f"{self.log_prefix}: Retraction is not enabled"
                f" in configuration '{self.config_name}'."
                f" Skipping retraction of IoC(s) for {PLATFORM_NAME}."
            )
            yield [], True
            return

        retraction_interval = plugin_configuration.get("retraction_interval")
        if retraction_interval is not None:
            try:
                retraction_interval = int(retraction_interval)
            except (ValueError, TypeError):
                retraction_interval = None

        retraction_interval_valid = bool(
            retraction_interval and isinstance(retraction_interval, int)
        )
        ioc_source_retraction_applicable = (
            ioc_source_selected and retraction_interval_valid
        )
        dbl_retraction_enabled = enable_retraction and dbl_selected

        if ioc_source_selected and not retraction_interval_valid:
            self.logger.warning(
                f"{self.log_prefix}: Enable Retraction is 'yes' and IOC"
                " Sources is selected, but Retraction Interval is not"
                " configured. IOC Source retraction will be skipped."
            )

        if not ioc_source_selected and retraction_interval_valid:
            self.logger.info(
                f"{self.log_prefix}: Retraction Interval is configured but"
                " IOC Sources is not selected. Retraction Interval will"
                " be ignored."
            )

        if not ioc_source_retraction_applicable and not dbl_selected:
            self.logger.info(
                f"{self.log_prefix}: Retraction Interval is not configured"
                f" and Driver Block List is not selected"
                f" in configuration '{self.config_name}'."
                f" Skipping retraction of IoC(s) for {PLATFORM_NAME}."
            )
            yield [], True
            return

        self.logger.info(
            f"{self.log_prefix}: Getting all modified indicators"
            f" from {PLATFORM_NAME}."
        )

        # ── IOC Source retraction ─────────────────────────────────────────
        active_ioc_source_values: set = set()

        if ioc_source_retraction_applicable:
            end_time = datetime.now(timezone.utc).replace(tzinfo=None)
            start_time = end_time - timedelta(days=retraction_interval)

            self.logger.info(
                f"{self.log_prefix}: Pulling IOC Source indicators from"
                f" {PLATFORM_NAME} for retraction using retraction"
                f" interval of {retraction_interval} day(s)."
                f" Checkpoint: {start_time.strftime(DATE_FORMAT)}."
            )

            selected_threat_data_types = (
                plugin_configuration.get("threat_data_type")
                or list(ALLOWED_THREAT_DATA_TYPES)
            )

            for batch, _ in self._get_ioc_source_indicators(
                start_time=start_time,
                end_time=end_time,
                threat_data_types=selected_threat_data_types,
                enable_tagging=False,
                is_retraction=True,
            ):
                for indicator in batch:
                    if indicator and indicator.value:
                        active_ioc_source_values.add(indicator.value)

            self.logger.info(
                f"{self.log_prefix}: Pulled {len(active_ioc_source_values)}"
                f" active IOC Source indicator(s) from {PLATFORM_NAME}"
                " for retraction comparison."
            )

        # ── Driver Block List retraction ──────────────────────────────────
        # The Driver Block List has no time-based filter API, so ALL current
        # indicators are pulled on every retraction run.  Any CE indicator
        # tagged with DRIVER_BLOCK_LIST_TAG that is absent from this full set
        # is treated as deleted on the HarfangLab platform.
        active_dbl_values: set = set()

        if dbl_retraction_enabled:
            self.logger.info(
                f"{self.log_prefix}: Pulling all Driver Block List"
                f" indicators from {PLATFORM_NAME} for retraction."
            )

            dbl_threat_data_types = [
                t
                for t in (
                    plugin_configuration.get("threat_data_type")
                    or list(DBL_SUPPORTED_TYPES)
                )
                if t in DBL_SUPPORTED_TYPES
            ] or list(DBL_SUPPORTED_TYPES)

            for batch in self._get_driver_block_list_indicators(
                threat_data_types=dbl_threat_data_types,
                enable_tagging=False,
            ):
                for indicator in batch:
                    if indicator and indicator.value:
                        active_dbl_values.add(indicator.value)

            self.logger.info(
                f"{self.log_prefix}: Pulled {len(active_dbl_values)} active"
                f" Driver Block List indicator(s) from {PLATFORM_NAME}"
                " for retraction comparison."
            )

        # ── Early exit: nothing to retract ───────────────────────────────
        # Reached only when IOC Source has no retraction_interval AND Driver
        # Block List is not selected — nothing useful can be compared.
        if not ioc_source_retraction_applicable and not dbl_selected:
            log_msg = (
                "IOC Source retraction interval is not configured"
                f" in configuration '{self.config_name}' and Driver Block"
                " List retraction is not enabled. Skipping retraction of"
                f" IoC(s) for {PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True
            return

        # ── Compare each CE source batch against the active sets ─────────
        for source_ioc_list in source_indicators:
            try:
                retracted_iocs = []
                total_iocs = 0

                for ioc in source_ioc_list:
                    if not ioc or not ioc.value:
                        continue
                    total_iocs += 1

                    # Determine source of this CE indicator by its tag.
                    ioc_tags = {
                        getattr(tag, "name", tag)
                        for tag in (ioc.tags or [])
                    }
                    is_dbl_indicator = DRIVER_BLOCK_LIST_TAG in ioc_tags

                    if is_dbl_indicator:
                        # DBL indicator: retract if DBL not selected (req 4)
                        # or if absent from the current full Driver Block List.
                        if not dbl_selected or (
                            dbl_retraction_enabled
                            and ioc.value not in active_dbl_values
                        ):
                            retracted_iocs.append(ioc.value)
                    else:
                        # IOC Source indicator: retract if IOC Source not
                        # selected (req 4) or if absent from the retraction
                        # window pulled above.
                        if not ioc_source_selected or (
                            ioc_source_retraction_applicable
                            and ioc.value not in active_ioc_source_values
                        ):
                            retracted_iocs.append(ioc.value)

                self.logger.info(
                    f"{self.log_prefix}: {len(retracted_iocs)} indicator(s)"
                    f" will be marked as retracted from {total_iocs} total"
                    " indicator(s) present in Cloud Exchange"
                    f" for {PLATFORM_NAME}."
                )
                if retracted_iocs:
                    yield retracted_iocs, False

            except Exception as err:
                err_msg = (
                    "Unexpected error occurred while fetching modified"
                    f" indicators from {PLATFORM_NAME} for retraction."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=str(traceback.format_exc()),
                    resolution=(
                        "Check IOC Source configuration and"
                        f" {PLATFORM_NAME} connectivity."
                    ),
                )
                raise HarfangLabPluginException(err_msg)

    def retract_indicators(
        self,
        retracted_indicators_lists: List[List[Indicator]],
        list_action_dict: List[Action],
    ) -> Generator[ValidationResult, None, None]:
        """Delete retracted indicators from HarfangLab IOC Source lists.

        Workflow per configured action (IOC list):
        1. Resolve the target IOC list name and source_id from action
           parameters. "Create New IOC List" is resolved to the actual
           list via the 'new_source' parameter name.
        2. Fetch ALL current indicators from that IOC list (PAGE_LIMIT
           per page) and build a value → rule_id lookup map.
        3. For each CE-retracted IOC Source indicator whose value is in
           the map, call DELETE /api/data/threat_intelligence/IOCRule/{id}/.

        All configured HarfangLab actions in list_action_dict are
        processed independently (same pattern as Darktrace), so
        indicators pushed to multiple IOC lists are all cleaned up.
        Driver Block List indicators are skipped — no DELETE API exists.

        Args:
            retracted_indicators_lists: Batches of CE indicators to delete.
            list_action_dict: One entry per configured action (IOC list).

        Yields:
            ValidationResult: Final result after all actions are processed.
        """
        if f"[{RETRACTION}]" not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        self.logger.info(
            f"{self.log_prefix}: Starting retraction of indicator(s)"
            f" from {PLATFORM_NAME} platform."
        )

        headers = self._get_auth_headers()
        ioc_rule_url = self.harfanglab_helper.build_url(
            IOC_RULE_ENDPOINT, self.configuration
        )

        # ── Early guard ──────────────────────────────────────────────────────
        if not list_action_dict:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: No action configuration found."
                    " Cannot determine target IOC list(s) for push"
                    " retraction."
                ),
                resolution=(
                    "Verify the 'Create IOCs' action is configured with"
                    " a valid IOC List selection."
                ),
            )
            yield ValidationResult(
                success=False,
                message="No action configuration found for push retraction.",
            )
            return

        # ── Step 1: Resolve actions and build value→rule_id maps once ────────
        # Fetching the full IOC list per action is expensive; build the maps
        # once up front so every batch can reuse them without re-fetching.
        # Structure: {ioc_list_key: {indicator_value: rule_id}}
        action_maps: Dict[str, Dict[str, str]] = {}

        for action_dict in list_action_dict:
            action_params = action_dict.parameters
            ioc_list_raw = action_params.get("ioc_list_name", "")
            if not ioc_list_raw:
                self.logger.info(
                    f"{self.log_prefix}: Action has no IOC List Name"
                    " configured. Skipping."
                )
                continue

            try:
                ioc_list_dict = json.loads(ioc_list_raw)
                ioc_list_key = next(iter(ioc_list_dict), None)
                if not ioc_list_key:
                    raise ValueError("Empty IOC List dict.")
                source_id = ioc_list_dict.get(ioc_list_key, "")
            except Exception:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Could not parse IOC List"
                        " Name value. Skipping this action."
                    ),
                    resolution=(
                        "Re-select the IOC List in the action"
                        " configuration and save."
                    ),
                )
                continue

            # "Create New IOC List" sentinel — resolve to actual list.
            if ioc_list_key == "create_new_list":
                new_source_name = action_params.get(
                    "new_source", ""
                ).strip()
                if not new_source_name:
                    self.logger.info(
                        f"{self.log_prefix}: 'Create New IOC List'"
                        " is configured but 'New IOC List Name' is"
                        " empty. Skipping this action."
                    )
                    continue
                all_sources = self.get_ioc_sources()
                if new_source_name not in all_sources:
                    self.logger.info(
                        f"{self.log_prefix}: IOC List"
                        f" '{new_source_name}' not found on"
                        f" {PLATFORM_NAME}. Skipping this action."
                    )
                    continue
                ioc_list_key = new_source_name
                source_id = all_sources[new_source_name]

            if not source_id or source_id == "id":
                self.logger.info(
                    f"{self.log_prefix}: Could not resolve a valid"
                    f" source ID for IOC List '{ioc_list_key}'."
                    " Skipping this action."
                )
                continue

            ioc_list_value_map: Dict[str, str] = {}
            offset = 0
            page = 1
            try:
                while True:
                    list_resp = self.harfanglab_helper.api_helper(
                        logger_msg=(
                            f"fetching indicators from IOC List"
                            f" '{ioc_list_key}' page {page}"
                            " for push retraction"
                        ),
                        url=ioc_rule_url,
                        method="GET",
                        headers=headers,
                        params={
                            "source_id": source_id,
                            "limit": PAGE_LIMIT,
                            "offset": offset,
                        },
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        is_handle_error_required=True,
                        is_retraction=True,
                    )
                    for record in list_resp.get("results", []):
                        record_value = record.get("value")
                        record_id = record.get("id")
                        if record_value and record_id:
                            ioc_list_value_map[record_value] = record_id
                    if not list_resp.get("next"):
                        break
                    offset += PAGE_LIMIT
                    page += 1
            except HarfangLabPluginException as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error fetching indicators"
                        f" from IOC List '{ioc_list_key}'."
                        f" Skipping this IOC List. Error: {err}"
                    ),
                    resolution=(
                        "Verify the API Token has read permissions"
                        " for IOC Rules and the Tenant URL is correct."
                    ),
                )
                continue
            action_maps[ioc_list_key] = ioc_list_value_map

        if not action_maps:
            self.logger.info(
                f"{self.log_prefix}: No valid IOC List(s) resolved"
                f" for push retraction on {PLATFORM_NAME}."
            )
            yield ValidationResult(
                success=True,
                message="No valid IOC List(s) found for push retraction.",
            )
            return

        total_deleted = 0
        total_not_found = 0
        total_failed = 0
        total_skipped = 0

        # ── Step 2: Batch-wise processing ────────────────────────────────────
        # Each batch from CE is processed independently against the pre-built
        # maps. Successfully deleted entries are removed from the map so
        # subsequent batches do not re-attempt the same delete.
        for indicator_batch in retracted_indicators_lists:
            batch_retracted_values: set = set()

            for indicator in indicator_batch:
                if not indicator or not indicator.value:
                    total_skipped += 1
                    continue
                ioc_tags = {
                    getattr(tag, "name", tag)
                    for tag in (indicator.tags or [])
                }
                if DRIVER_BLOCK_LIST_TAG in ioc_tags:
                    continue
                batch_retracted_values.add(indicator.value)

            if not batch_retracted_values:
                yield ValidationResult(
                    success=True,
                    message="No IOC Source indicator(s) to retract.",
                )
                continue

            for ioc_list_key, ioc_list_value_map in action_maps.items():
                action_deleted = 0
                action_not_found = 0
                action_failed = 0

                for value in batch_retracted_values:
                    rule_id = ioc_list_value_map.get(value)
                    if not rule_id:
                        action_not_found += 1
                        continue

                    delete_url = f"{ioc_rule_url}{rule_id}/"
                    try:
                        self.harfanglab_helper.api_helper(
                            logger_msg=(
                                f"deleting indicator '{value}'"
                                f" (ID: {rule_id}) from IOC List"
                                f" '{ioc_list_key}'"
                            ),
                            url=delete_url,
                            method="DELETE",
                            headers=headers,
                            verify=self.ssl_validation,
                            proxies=self.proxy,
                            is_handle_error_required=True,
                            is_retraction=True,
                        )
                        action_deleted += 1
                        ioc_list_value_map.pop(value, None)
                    except HarfangLabPluginException as err:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Failed to delete"
                                f" indicator '{value}' (ID: {rule_id})"
                                f" from IOC List '{ioc_list_key}'."
                                f" Error: {err}"
                            ),
                            resolution=(
                                "Verify the API Token has delete permissions"
                                " for IOC Rules in HarfangLab."
                            ),
                        )
                        action_failed += 1

                self.logger.info(
                    f"{self.log_prefix}: Successfully deleted"
                    f" {action_deleted} indicator(s) from IOC"
                    f" Sources '{ioc_list_key}'."
                    + (
                        f" Not found: {action_not_found}."
                        if action_not_found
                        else ""
                    )
                    + (
                        f" Failed: {action_failed}."
                        if action_failed
                        else ""
                    )
                )
                total_deleted += action_deleted
                total_not_found += action_not_found
                total_failed += action_failed

            yield ValidationResult(
                success=True,
                message=(
                    "Push retraction completed."
                ),
            )

        success_logger = (
            f"Successfully deleted {total_deleted} indicator(s)"
            f" from {PLATFORM_NAME} platform."
        )
        if total_not_found:
            success_logger += (
                f" {total_not_found} indicator(s) were not found"
                " in the target IOC Source(s)."
            )
        if total_skipped:
            success_logger += (
                f" Skipped deleting {total_skipped} indicator(s) due"
                f" unsupported or empty indicator value on {PLATFORM_NAME} platform."
            )
        self.logger.info(f"{self.log_prefix}: {success_logger}")
        if total_failed:
            self.logger.info(
                f"{self.log_prefix}: Failed to delete {total_failed}"
                f" indicator(s) from {PLATFORM_NAME} platform as they are not"
                " present on the platform or were of invalid type."
            )

    # ─────────────────────────── Validation ─────────────────────────────────

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, int, list],
        field_type: type,
        allowed_values: list = None,
        allowed_values_display: list = None,
        is_required: bool = False,
        range_validation: bool = False,
        range_values: Tuple[int, int] = None,
        custom_validation_func: callable = None,
        skip_strip: bool = False,
    ) -> Union[ValidationResult, None]:
        """Validate a single configuration field value.

        Args:
            field_name (str): Human-readable name shown in error messages.
            field_value: Value to validate.
            field_type (type): Expected Python type (str, int, list).
            allowed_values (list): Allowed values; checked for str/list types.
            allowed_values_display (list): Display names shown in errors.
            is_required (bool): Return error if value is empty.
            range_validation (bool): Check numeric value against range_values.
            range_values (Tuple[int, int]): (min, max) inclusive range.
            custom_validation_func (callable): Extra check; must return True.
            skip_strip (bool): Skip stripping (use for password fields).

        Returns:
            None if validation passes; ValidationResult(success=False) on fail.
        """
        # Strip string values unless it's a password field.
        if (
            field_type is str
            and isinstance(field_value, str)
            and not skip_strip
        ):
            field_value = field_value.strip()

        # Integer: coerce from string and validate.
        if field_type is int:
            if isinstance(field_value, str):
                if not field_value.strip():
                    if is_required:
                        err_msg = (
                            f"{field_name} is a required"
                            " configuration parameter."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}:"
                                f" {VALIDATION_ERROR_MSG}{err_msg}"
                            ),
                            resolution=(
                                f"Ensure that the field '{field_name}'"
                                " is not empty."
                            ),
                        )
                        return ValidationResult(
                            success=False, message=err_msg
                        )
                    return None
                try:
                    field_value = int(field_value)
                except (ValueError, TypeError):
                    err_msg = (
                        f"{field_name} must be a valid integer."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}:"
                            f" {VALIDATION_ERROR_MSG}{err_msg}"
                        ),
                        resolution=(
                            f"Ensure that the value provided for"
                            f" '{field_name}' is a valid integer."
                        ),
                    )
                    return ValidationResult(
                        success=False, message=err_msg
                    )
            elif not isinstance(field_value, int):
                err_msg = (
                    f"Invalid value provided for '{field_name}'."
                    " It should be an integer."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}:"
                        f" {VALIDATION_ERROR_MSG}{err_msg}"
                    ),
                    resolution=(
                        f"Ensure that '{field_name}' is a valid"
                        " integer value."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

        # Required check (non-integer).
        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = (
                f"{field_name} is a required configuration parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}:"
                    f" {VALIDATION_ERROR_MSG}{err_msg}"
                ),
                resolution=(
                    f"Ensure that the field '{field_name}' is not empty."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Type check + optional custom function.
        if (field_value and not isinstance(field_value, field_type)) or (
            custom_validation_func
            and field_value
            and not custom_validation_func(field_value)
        ):
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}:"
                    f" {VALIDATION_ERROR_MSG}{err_msg}"
                ),
                resolution=(
                    f"Ensure that '{field_name}' has a valid value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Range check (integers only).
        if range_validation and range_values and isinstance(field_value, int):
            if not (range_values[0] <= field_value <= range_values[1]):
                err_msg = (
                    f"Invalid value provided for the configuration"
                    f" parameter '{field_name}'. Value must be between"
                    f" {range_values[0]} and {range_values[1]}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}:"
                        f" {VALIDATION_ERROR_MSG}{err_msg}"
                    ),
                    resolution=(
                        f"Ensure that '{field_name}' is in the range"
                        f" {range_values[0]} to {range_values[1]}."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

        # Allowed-values check (str and list).
        if allowed_values and field_value:
            display_values = (
                allowed_values_display
                if allowed_values_display
                else allowed_values
            )
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            if field_type is str and field_value not in allowed_values:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}:"
                        f" {VALIDATION_ERROR_MSG}{err_msg}"
                    ),
                    details=(
                        "Allowed values are:"
                        f" {', '.join(str(v) for v in display_values)}."
                    ),
                    resolution=(
                        "Ensure the value is one of the allowed values."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
            elif field_type is list:
                invalid_items = [
                    item
                    for item in field_value
                    if item not in allowed_values
                ]
                if invalid_items:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}:"
                            f" {VALIDATION_ERROR_MSG}{err_msg}"
                        ),
                        details=(
                            f"Invalid item(s): {invalid_items}."
                            " Allowed values are:"
                            f" {', '.join(str(v) for v in display_values)}."
                        ),
                        resolution=(
                            "Ensure all selected values are from the"
                            " allowed values."
                        ),
                    )
                    return ValidationResult(success=False, message=err_msg)

        return None

    def _validate_url(self, url: str) -> bool:
        """Validate URL has non-empty scheme and netloc, root path only.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True if valid.
        """
        parsed = urllib.parse.urlparse(url.strip())
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and parsed.path.strip() in ("", "/")
        )

    def _validate_auth_credentials(
        self, configuration: Dict
    ) -> ValidationResult:
        """Perform a live connectivity check against HarfangLab.

        Args:
            configuration (Dict): Plugin configuration dict.

        Returns:
            ValidationResult: Success or failure.
        """
        try:
            url = self.harfanglab_helper.build_url(
                IOC_SOURCE_ENDPOINT, configuration
            )
            self.harfanglab_helper.api_helper(
                logger_msg="validating API credentials",
                url=url,
                method="GET",
                headers={
                    "Authorization": (
                        "Token "
                        + configuration.get("apikey", "")
                    ),
                    "Accept": "application/json",
                },
                params={"limit": 1},
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
                is_validation=True,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated"
                f" connectivity with {PLATFORM_NAME}."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        except HarfangLabPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = (
                "Error occurred while validating credentials."
                " Check the Tenant URL and API Token."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Verify the Tenant URL and the API Token"
                    " is valid and has not expired."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate all plugin configuration parameters.

        Parameters are validated in manifest order using
        _validate_configuration_parameters; auth connectivity check
        is performed last.

        Args:
            configuration (Dict): Configuration parameter dict.

        Returns:
            ValidationResult: Success or failure with a message.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration parameters."
        )

        # 1. fqdn — Tenant URL
        if fqdn_validation := self._validate_configuration_parameters(
            field_name="Tenant URL",
            field_value=configuration.get("fqdn", "").rstrip("/"),
            field_type=str,
            is_required=True,
            custom_validation_func=self._validate_url,
        ):
            return fqdn_validation

        # 2. apikey — API Token (password field; do NOT strip)
        if apikey_validation := self._validate_configuration_parameters(
            field_name="API Token",
            field_value=configuration.get("apikey"),
            field_type=str,
            is_required=True,
            skip_strip=True,
        ):
            return apikey_validation

        # 3. is_pull_required — Enable Polling
        if pull_validation := self._validate_configuration_parameters(
            field_name="Enable Polling",
            field_value=configuration.get("is_pull_required", "Yes"),
            field_type=str,
            is_required=True,
            allowed_values=["Yes", "No"],
        ):
            return pull_validation

        # 4. source_type — mandatory multichoice
        source_type_value = configuration.get("source_type", [])
        if source_type_validation := self._validate_configuration_parameters(
            field_name="Source Type",
            field_value=source_type_value,
            field_type=list,
            is_required=True,
            allowed_values=sorted(ALLOWED_SOURCE_TYPES),
        ):
            return source_type_validation

        # 5. enable_tagging — Enable Tagging
        if tagging_validation := self._validate_configuration_parameters(
            field_name="Enable Tagging",
            field_value=configuration.get("enable_tagging", "yes"),
            field_type=str,
            is_required=True,
            allowed_values=["yes", "no"],
        ):
            return tagging_validation

        # 6. threat_data_type — optional multichoice; validate if provided
        threat_data_type = configuration.get("threat_data_type", [])
        if threat_data_type:
            threat_type_validation = self._validate_configuration_parameters(
                field_name="Type of Threat data to pull",
                field_value=threat_data_type,
                field_type=list,
                is_required=False,
                allowed_values=sorted(ALLOWED_THREAT_DATA_TYPES),
            )
            if threat_type_validation:
                return threat_type_validation

            # Cross-field: Driver Block List only supports hash types.
            source_type = configuration.get("source_type", [])
            if set(source_type) == {SOURCE_TYPE_DRIVER_BLOCK_LIST}:
                non_hash_types = [
                    t for t in threat_data_type if t not in DBL_SUPPORTED_TYPES
                ]
                if non_hash_types:
                    return ValidationResult(
                        success=False,
                        message=(
                            "Driver Block List only supports SHA256 and MD5."
                            f" Remove unsupported type(s): {non_hash_types}."
                        ),
                    )

        # days and retraction_interval are dynamic fields shown only when
        # IOC Source is selected; skip for Driver Block List only.
        selected_source_types = configuration.get(
            "source_type",
            [SOURCE_TYPE_IOC_SOURCE, SOURCE_TYPE_DRIVER_BLOCK_LIST],
        ) or [SOURCE_TYPE_IOC_SOURCE, SOURCE_TYPE_DRIVER_BLOCK_LIST]

        ioc_source_selected = SOURCE_TYPE_IOC_SOURCE in selected_source_types

        # 7. ioc_source_list_names — optional; only when IOC Source selected
        if ioc_source_selected:
            ioc_source_list_names_raw = configuration.get(
                "ioc_source_list_names", ""
            )
            if ioc_source_list_names_raw is not None:
                ioc_src_names_validation = (
                    self._validate_configuration_parameters(
                        field_name="IOC Source List Names",
                        field_value=ioc_source_list_names_raw,
                        field_type=str,
                        is_required=False,
                    )
                )
                if ioc_src_names_validation:
                    return ioc_src_names_validation

        # 8. days — Initial Range (applicable when IOC Source is selected)
        if ioc_source_selected:
            if days_validation := self._validate_configuration_parameters(
                field_name="Initial Range (in days)",
                field_value=configuration.get("days"),
                field_type=int,
                is_required=True,
                range_validation=True,
                range_values=(0, MAX_DAYS),
            ):
                return days_validation

        # 9. retraction_interval handled below after enable_retraction check

        # 10. enable_retraction — mandatory choice
        if enable_retraction_validation := self._validate_configuration_parameters(
            field_name="Enable Retraction",
            field_value=configuration.get("enable_retraction", "no"),
            field_type=str,
            is_required=True,
            allowed_values=["yes", "no"],
        ):
            return enable_retraction_validation

        # 11. retraction_interval — mandatory when enable_retraction=yes AND
        #     IOC Source is selected (req 3); optional otherwise.
        retraction_required = (
            configuration.get("enable_retraction", "no").lower() == "yes"
            and ioc_source_selected
        )
        retraction_interval = configuration.get("retraction_interval")
        if retraction_required and not retraction_interval:
            err_msg = (
                "Retraction Interval (in days) is required when Enable"
                " Retraction is 'Yes' and IOC Sources is selected."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}"
                ),
                resolution=(
                    "Provide a valid Retraction Interval (1 to 100000 days)."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if retraction_interval is not None:
            retraction_validation = self._validate_configuration_parameters(
                field_name="Retraction Interval (in days)",
                field_value=retraction_interval,
                field_type=int,
                is_required=retraction_required,
                range_validation=True,
                range_values=(1, MAX_DAYS),
            )
            if retraction_validation:
                return retraction_validation

        # 12. Auth connectivity check
        auth_validation = self._validate_auth_credentials(configuration)
        if not auth_validation.success:
            return auth_validation

        # 13. IOC Sources Name — verify each configured name exists on the
        # platform (only when IOC Source is selected and names are provided).
        if ioc_source_selected:
            raw_source_names = (
                configuration.get("ioc_source_list_names", "") or ""
            ).strip()
            if raw_source_names:
                source_names = [
                    name.strip()
                    for name in raw_source_names.split(",")
                    if name.strip()
                ]
                all_sources = self.get_ioc_sources(configuration)
                invalid_names = [
                    name for name in source_names if name not in all_sources
                ]
                if invalid_names:
                    err_msg = (
                        "Invalid IOC Sources Name provided. The following"
                        f" source name(s) do not exist on {PLATFORM_NAME}:"
                        f" {', '.join(invalid_names)}."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {VALIDATION_ERROR_MSG}"
                            f"{err_msg}"
                        ),
                        resolution=(
                            "Verify the 'IOC Sources Name' configuration"
                            f" parameter. Ensure the source names exist on"
                            f" {PLATFORM_NAME} or leave the field empty to"
                            " pull from all available IOC Sources."
                        ),
                    )
                    return ValidationResult(success=False, message=err_msg)

        return auth_validation
