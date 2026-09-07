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

Netskope CRE plugin helper module."""

import copy
import json
import ipaddress
import re
import requests
import time
import traceback
from typing import Dict, List, Optional, Tuple, Union

from netskope.common.utils import (
    add_installation_id,
    add_user_agent,
)
from netskope.common.utils.handle_exception import (
    handle_exception,
    handle_status_code,
)
from netskope.integrations.crev2.plugin_base import ValidationResult
from .constants import (
    DEFAULT_WAIT_TIME,
    DESTINATION_PROFILE_EXACT_TOTAL_LIMIT,
    DESTINATION_PROFILE_EXACT_PER_PROFILE_LIMIT,
    DESTINATION_PROFILE_REGEX_TOTAL_LIMIT,
    DEVICE_CLASSIFICATION_TAGS_PER_GROUP,
    MAX_NETWORK_PROFILES,
    MAX_RETRY_COUNT,
    NETWORK_PROFILE_EMPTY_PLACEHOLDER,
    NETWORK_PROFILE_PER_PROFILE_LIMIT,
    NETWORK_PROFILE_TENANT_TOTAL_LIMIT,
    PRIVATE_APP_MIN_CIDR_PREFIX,
    PRIVATE_APP_TAG_MAX_LENGTH,
    REGEX_HOSTNAME_LABEL,
    REGEX_TAG,
    TAG_DEVICE_TAG_LENGTH,
)


def _capitalize_first(text: str) -> str:
    """Upper-case only the first character, preserving the rest's casing.

    Used for log messages instead of ``str.capitalize()``, which also
    lower-cases the remainder and would mangle interpolated values such as
    profile, classification, app or tag names.
    """
    return text[:1].upper() + text[1:]


class NetskopeException(Exception):
    """Netskope exception class."""

    pass


class NetskopePluginHelper(object):
    """NetskopePluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self, logger, log_prefix: str
    ):
        """Netskope Plugin Helper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger

    def is_valid_domain_length(self, domain: str) -> bool:
        """Check whether a domain name meets RFC length limits.

        Total length must not exceed 253 characters and each label
        (between dots) must be 1-63 characters.

        Args:
            domain (str): Domain name to validate.

        Returns:
            bool: True if the domain satisfies the RFC length limits,
                False otherwise.
        """
        if not domain or len(domain) > 253:
            return False
        return all(
            label and len(label) <= 63 for label in domain.split(".")
        )

    def _get_retry_after(self, headers) -> int:
        """
        Get the retry after value from the headers.

        Args:
            headers (Dict): Headers.

        Returns:
            int: Retry after value.
        """
        try:
            if retry_after := headers.get("Retry-After"):
                return int(retry_after)
            if retry_after := headers.get("RateLimit-Reset"):
                return int(retry_after)
            return DEFAULT_WAIT_TIME
        except Exception:
            return DEFAULT_WAIT_TIME

    def _api_call_helper(
        self,
        url: str,
        method,
        error_codes,
        logger_msg,
        message="",
        params: Dict = {},
        headers: Dict = {},
        data=None,
        json=None,
        proxies=None,
        show_params: bool = True,
        is_handle_error_required=True
    ):
        """Call the API helper for getting application related data."""
        request_func = getattr(requests, method)
        try:
            headers = add_installation_id(add_user_agent(headers))
            response = {}
            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" Endpoint: {method.upper()} {url}"
            )
            if params and show_params:
                debug_log_msg += f", params: {params}."
            self.logger.debug(debug_log_msg)
            for attempt in range(MAX_RETRY_COUNT):
                success, response = handle_exception(
                    request_func,
                    error_code=error_codes[0],
                    custom_message=message,
                    plugin=self.log_prefix,
                    url=url,
                    headers=headers,
                    data=data,
                    json=json,
                    params=params,
                    proxies=proxies,
                    timeout=300,
                )
                if not success:
                    raise response
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )

                if (
                    status_code == 429
                    or 500 <= status_code <= 600
                ):
                    api_err_msg = str(response.text)
                    if attempt == MAX_RETRY_COUNT - 1:
                        err_msg = (
                            f"Received exit code {status_code}, "
                            f"API rate limit exceeded while {logger_msg}. "
                            "Max retries for rate limit handler exceeded "
                            f"hence returning status code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise NetskopeException(err_msg)
                    if status_code == 429:
                        log_err_msg = "API rate limit exceeded"
                    else:
                        log_err_msg = "HTTP server error occurred"
                    retry_after = DEFAULT_WAIT_TIME
                    try:
                        retry_after = self._get_retry_after(response.headers)
                    except Exception:
                        pass
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code "
                            f"{status_code}, "
                            f"{log_err_msg} while {logger_msg}. "
                            f"Retrying after {retry_after} seconds. "
                            f"{MAX_RETRY_COUNT - 1 - attempt} "
                            "retries remaining."
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(retry_after)
                else:
                    if is_handle_error_required:
                        response = handle_status_code(
                            response,
                            error_code=error_codes[1],
                            custom_message=message,
                            plugin=self.log_prefix,
                            notify=False,
                            log=True,
                        )
                    return response
            else:
                self.logger.error(
                    f"{self.log_prefix}: Maximum retry "
                    f"limit reached for url {url}."
                )
                raise requests.exceptions.HTTPError(
                    "Maximum retry limit reached"
                )
        except NetskopeException:
            raise
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise NetskopeException(err_msg)

    # ------------------------------------------------------------------
    # Shared validation helpers
    # ------------------------------------------------------------------

    def _validate_max_length(
        self,
        field_name: str,
        field_value: str,
        max_length: int,
    ) -> Union[ValidationResult, None]:
        """Validate that a field value does not exceed max_length.

        Args:
            field_name (str): Display name of the field.
            field_value (str): Value to validate.
            max_length (int): Maximum allowed character count.

        Returns:
            ValidationResult on failure, None when valid.
        """
        if len(field_value) > max_length:
            err_msg = (
                f"'{field_name}' should be less than or equal"
                f" to {max_length} characters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Ensure that '{field_name}' does not"
                    f" exceed {max_length} characters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        return None

    def _validate_forbidden_chars(
        self,
        field_name: str,
        field_value: str,
        forbidden_chars,
        disallow_non_printable: bool = False,
    ) -> Union[ValidationResult, None]:
        """Validate that a field value contains no forbidden characters.

        Args:
            field_name (str): Display name of the field.
            field_value (str): Value to validate.
            forbidden_chars: Iterable of single characters to reject.
            disallow_non_printable (bool): When True, also reject any
                non-printable character (e.g. control characters), in
                addition to ``forbidden_chars``.

        Returns:
            ValidationResult on failure, None when valid.
        """
        has_forbidden_char = any(
            char in field_value for char in forbidden_chars
        )
        has_non_printable = disallow_non_printable and any(
            not char.isprintable() for char in field_value
        )
        if has_forbidden_char or has_non_printable:
            chars_str = ", ".join(
                f"'{c}'" for c in forbidden_chars
            )
            desc = chars_str
            if disallow_non_printable:
                desc = f"{chars_str}, or non-printable"
            err_msg = (
                f"'{field_name}' should not contain"
                f" {desc} characters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Ensure that '{field_name}' does not"
                    f" contain {desc} characters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        return None

    def _validate_ip_address(self, value: str) -> bool:
        """Return True if value is a valid IP address.

        Args:
            value (str): String to validate.

        Returns:
            bool: True if valid IP, False otherwise.
        """
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Shared execution utilities
    # ------------------------------------------------------------------

    def _normalize_csv_values(
        self, raw_value: Union[str, list]
    ) -> List[str]:
        """Normalize a Source/Static value field into a value list.

        A Source field resolves to either a list (already split) or a
        comma-separated string; a Static field is a comma-separated
        string. A parameter declared with ``allowMultipleSource`` adds a
        third shape: one entry per mapped field, nested one level deeper
        wherever a mapped Source field's record value is itself a list.
        This flattens that nesting, trims whitespace, drops empty
        entries, and de-duplicates while preserving the original order.

        Args:
            raw_value (Union[str, list]): Resolved field value, either
                a list (optionally nested one level) or a
                comma-separated string.

        Returns:
            List[str]: Cleaned, de-duplicated values in original order.
        """
        if isinstance(raw_value, (list, tuple, set)):
            candidates = []
            for item in raw_value:
                if isinstance(item, (list, tuple, set)):
                    for nested_item in item:
                        if nested_item is not None:
                            candidates.extend(str(nested_item).split(","))
                elif item is not None:
                    candidates.extend(str(item).split(","))
        else:
            candidates = str(raw_value or "").split(",")
        cleaned = []
        seen = set()
        for candidate in candidates:
            value = candidate.strip()
            if value and value not in seen:
                seen.add(value)
                cleaned.append(value)
        return cleaned

    def _join_multi_source_value(self, raw_value: Union[str, list]) -> str:
        """Collapse a multi-source parameter value to its Static form.

        A parameter declared with ``allowMultipleSource`` arrives as one
        entry per mapped field instead of a single string. Joining the
        flattened values with commas yields exactly what the same
        configuration would look like as one Static comma-separated
        field, so the string-based checks in ``validate_action`` apply
        unchanged. A value that is already a string is returned as-is so
        Static validation keeps seeing the user's literal input.

        Args:
            raw_value (Union[str, list]): Configured field value.

        Returns:
            str: Comma-separated equivalent of the configured value.
        """
        if isinstance(raw_value, str):
            return raw_value
        return ",".join(self._normalize_csv_values(raw_value))

    def _has_source_field_value(self, raw_value: Union[str, list]) -> bool:
        """Whether a Source field is mapped to this parameter.

        A parameter declared with ``allowMultipleSource`` can mix Static
        values and Source fields, so any entry naming a record field
        makes the whole parameter Source-bound and defers its validation
        to action execution.

        Args:
            raw_value (Union[str, list]): Configured field value.

        Returns:
            bool: True when at least one entry is a Source field.
        """
        if isinstance(raw_value, str):
            return raw_value.startswith("$")
        if isinstance(raw_value, (list, tuple, set)):
            return any(
                self._has_source_field_value(item) for item in raw_value
            )
        return False

    def _attribute_failed_ids(
        self,
        not_applied: list,
        value_to_ids: dict,
        failed_action_ids: list,
    ) -> None:
        """Attribute not-applied IOC values back to their action ids.

        Each profile action (destination/DNS/service) contributes one
        or more IOC values; the bulk handler unions those values per
        target profile before sharing them. When the push helper reports
        values that failed or were skipped, this maps every such value
        back to the action id(s) that contributed it and records them in
        ``failed_action_ids`` (extended in place). A single value may
        originate from more than one action, so every contributing id
        is recorded.

        Args:
            not_applied (list): IOC values that failed or were skipped.
            value_to_ids (dict): Map of IOC value to the set of action
                ids that contributed it.
            failed_action_ids (list): List extended in place with the
                action ids of every not-applied value.
        """
        for value in not_applied:
            failed_action_ids.extend(value_to_ids.get(value, set()))

    # ------------------------------------------------------------------
    # Destination profile helpers
    # ------------------------------------------------------------------

    def _destination_profile_capacity(
        self,
        existing_profiles: Dict,
        target_profile_name: str,
        match_type: str,
        requested_count: int,
        exact_total_limit: Optional[int] = None,
    ) -> Tuple[int, str]:
        """Compute how many values may still be added to a profile.

        Mirrors the Netskope capacity model: exact-match profiles
        (sensitive/insensitive) share a tenant-wide budget and a
        per-profile budget, while regex profiles share a single
        tenant-wide budget. The smaller of the relevant limits and
        the requested count is returned, together with a label naming
        the binding budget so callers can report exactly which limit
        was hit.

        Args:
            existing_profiles (Dict): All destination profiles keyed
                by name (must include ``values_count`` and ``type``).
            target_profile_name (str): Name of the profile being
                written to (empty for a brand new profile).
            match_type (str): Match type of the target profile.
            requested_count (int): Number of values the caller wants
                to add.
            exact_total_limit (Optional[int]): Tenant-wide exact-match
                value limit to use instead of
                ``DESTINATION_PROFILE_EXACT_TOTAL_LIMIT``. When ``None``
                (the action parameter is left empty) the default
                constant is used.

        Returns:
            Tuple[int, str]: ``(max_shareable, limit_label)`` where
                ``max_shareable`` is the maximum number of values that
                may be added (>= 0) and ``limit_label`` is a
                human-readable description of the binding capacity
                budget.
        """
        exact_total_limit = (
            exact_total_limit
            if exact_total_limit is not None
            else DESTINATION_PROFILE_EXACT_TOTAL_LIMIT
        )
        if match_type in ["sensitive", "insensitive"]:
            total_exact_usage = sum(
                profile.get("values_count", 0)
                for profile in existing_profiles.values()
                if profile.get("type") in ["sensitive", "insensitive"]
            )
            target_usage = existing_profiles.get(
                target_profile_name, {}
            ).get("values_count", 0)
            total_available = (
                exact_total_limit
                - total_exact_usage
            )
            per_profile_available = (
                DESTINATION_PROFILE_EXACT_PER_PROFILE_LIMIT
                - target_usage
            )
            # The per-profile budget is the binding one on a tie,
            # since it is the more actionable limit for the operator.
            if per_profile_available <= total_available:
                limit_label = (
                    "the per-profile value limit of "
                    f"{DESTINATION_PROFILE_EXACT_PER_PROFILE_LIMIT}"
                )
            else:
                limit_label = (
                    "the tenant-wide exact-match value limit of "
                    f"{exact_total_limit}"
                )
            max_shareable = min(
                total_available,
                per_profile_available,
                requested_count,
            )
        else:
            total_regex_usage = sum(
                profile.get("values_count", 0)
                for profile in existing_profiles.values()
                if profile.get("type") == "regex"
            )
            total_regex_available = (
                DESTINATION_PROFILE_REGEX_TOTAL_LIMIT
                - total_regex_usage
            )
            limit_label = (
                "the tenant-wide regex value limit of "
                f"{DESTINATION_PROFILE_REGEX_TOTAL_LIMIT}"
            )
            max_shareable = min(
                total_regex_available, requested_count
            )
        return max(0, max_shareable), limit_label

    def _format_destination_profile_value(
        self, value: str
    ) -> Optional[str]:
        """Prefix a CIDR block or IP range value for a destination profile.

        The destination profile API accepts a bare CIDR block or IP range
        without error, but only treats a value as a network when it is
        prefixed with ``CIDR:`` / ``RANGE:`` respectively; without the
        prefix the value is matched as a literal string, which never
        matches real traffic. Only applies to exact-match profiles: a
        regex profile's values are patterns, not addresses, so this must
        not be called for one. Netskope's destination profile does not
        support IPv6 in any form (plain address, CIDR block, or range),
        so such a value is dropped (``None``) rather than shared.
        Destination profiles also reject ``http://``/``https://`` values
        for both exact-match and regex types, so any value containing
        either is dropped (``None``) as well.

        IPv4 is parsed with ``ipaddress.IPv4Network``/``IPv4Address``
        specifically rather than the generic ``ip_network``/``ip_address``
        dispatchers, since those raise immediately on IPv6 input instead
        of silently succeeding as a valid IPv6 network/address. Whether a
        ``/``-containing value is a CIDR attempt at all is decided by the
        address portion alone (before the ``/``): if that parses as an
        IPv4 or IPv6 address, the value is a CIDR attempt and its prefix
        length is validated (dropped as ``None`` if out of the 0-32 /
        0-128 range, e.g. ``/33``, rather than passed through unprefixed);
        otherwise it is not IP-shaped at all (a URL or path) and is
        returned unchanged. A range entered as ``start - end`` (with
        spaces around the hyphen) has those spaces stripped, mirroring
        the network profile action's formatting.

        Args:
            value (str): Raw destination profile value.

        Returns:
            Optional[str]: The value prefixed with ``CIDR:``/``RANGE:``
                when it is a valid IPv4 CIDR block or range (with any
                spaces around a range's hyphen removed), ``value``
                unchanged when it is not a CIDR/range attempt at all
                (e.g. a plain address or a URL), or ``None`` when it is
                an IPv6 address, CIDR block, or range, an out-of-range
                IPv4 CIDR prefix (e.g. ``/33``), an ``http://``/
                ``https://`` value, or an IPv4 range whose start is not
                less than its end.
        """

        def _is_ipv6(candidate: str) -> bool:
            try:
                ipaddress.IPv6Address(candidate)
            except ValueError:
                return False
            return True

        def _is_ipv4(candidate: str) -> bool:
            try:
                ipaddress.IPv4Address(candidate)
            except ValueError:
                return False
            return True

        value = value.strip()
        if "http://" in value or "https://" in value:
            return None
        if "/" in value:
            addr_part = value.split("/", 1)[0]
            if _is_ipv4(addr_part):
                try:
                    ipaddress.IPv4Network(value, strict=False)
                except ValueError:
                    return None
                return f"CIDR:{value}"
            if _is_ipv6(addr_part):
                return None
            return value
        if "-" in value:
            parts = value.split("-")
            if len(parts) != 2:
                return value
            start = parts[0].strip()
            end = parts[1].strip()
            try:
                start_ip = ipaddress.IPv4Address(start)
                end_ip = ipaddress.IPv4Address(end)
            except ValueError:
                if _is_ipv6(start) or _is_ipv6(end):
                    return None
                return value
            if int(start_ip) >= int(end_ip):
                return None
            return f"RANGE:{start}-{end}"
        if _is_ipv6(value):
            return None
        return value

    def _split_values_within_budget(
        self,
        values: List[str],
        base_overhead_bytes: int,
        budget_bytes: int,
    ) -> Tuple[List[str], List[str]]:
        """Split a value list at the request payload byte budget.

        Greedily packs the longest prefix of ``values`` whose
        JSON-encoded size stays within ``budget_bytes``. The running
        size starts at ``base_overhead_bytes`` (the encoded size of the
        surrounding request body with an empty values list) and each
        value adds its ``json.dumps(...)`` byte length plus a 2-byte
        item separator once the chunk already holds at least one value
        (matching the default ``", "`` separator). Returns the prefix
        that fits and the remaining values.

        Args:
            values (List[str]): Values to pack, in order.
            base_overhead_bytes (int): Encoded size of the request body
                excluding the values (the empty-list body).
            budget_bytes (int): Maximum encoded payload size in bytes.

        Returns:
            Tuple[List[str], List[str]]: ``(chunk, remaining)`` where
                ``chunk`` is the longest fitting prefix and ``remaining``
                is everything that did not fit.
        """
        chunk_count = 0
        current_size = base_overhead_bytes
        item_sep_bytes = 2  # default item separator is ", "
        for value in values:
            encoded_len = len(json.dumps(value).encode("utf-8"))
            delta = encoded_len + (item_sep_bytes if chunk_count else 0)
            if current_size + delta > budget_bytes:
                break
            current_size += delta
            chunk_count += 1
        return (
            list(values[:chunk_count]),
            list(values[chunk_count:]),
        )

    # ------------------------------------------------------------------
    # Network profile helpers
    # ------------------------------------------------------------------

    def _is_network_profile_placeholder(
        self, value: str, default_value: str = ""
    ) -> bool:
        """Check whether a stored value is *this plugin's* placeholder.

        A comment-prefixed entry is a comment to the network profile API
        rather than an IP value, but it still occupies a slot out of the
        per-profile and tenant-wide value limits. So a comment is *not*
        free room: a member holding 95 addresses and 5 comments is full
        at a limit of 100, and writing 95 + 5 + 5 back is rejected. Every
        comment is therefore treated as a real value - counted towards
        capacity, preserved when the member is rewritten, and carried
        over when the group is re-packed.

        The one exception is the placeholder this plugin wrote itself,
        which it is free to overwrite: it is matched here so that its
        slot counts as reclaimable room, it is cleared as real values
        arrive, and a member reduced to nothing but the placeholder is
        still recognized as empty and its profile slot released.

        Matched by exact content rather than by prefix, against both the
        currently configured ``default_value`` and the built-in default,
        so a placeholder written before the parameter was customized is
        still recognized. The consequence is that an operator who
        happens to write ``NETWORK_PROFILE_EMPTY_PLACEHOLDER`` verbatim
        as their own comment has it treated as the plugin's - the two
        are indistinguishable, and the string is the plugin's own.

        Args:
            value (str): Stored profile value.
            default_value (str): Placeholder configured on the action.
                Empty falls back to
                ``NETWORK_PROFILE_EMPTY_PLACEHOLDER``.

        Returns:
            bool: True when the value is this plugin's placeholder.
        """
        stripped = str(value or "").strip()
        if not stripped:
            return False
        return stripped in {
            str(default_value or "").strip()
            or NETWORK_PROFILE_EMPTY_PLACEHOLDER,
            NETWORK_PROFILE_EMPTY_PLACEHOLDER,
        }

    def _ordered_network_profile_group(
        self,
        existing_profiles: Dict,
        base_name: str,
        default_value: str = "",
    ) -> List[Dict]:
        """Return the roll-over group for ``base_name`` ordered by number.

        A logical network profile is stored as a base profile ``base``
        plus numbered roll-over siblings ``base 2``, ``base 3`` ...
        created when the per-profile value limit is hit. This collects
        the matching profiles and orders them by number (the base counts
        as number 1).

        Unlike the private app group the names carry no brackets, so an
        unrelated profile that happens to be named ``base 2`` is picked
        up as a sibling. That is accepted and documented rather than
        detected - the same behaviour the private app group has.

        **This function is the only authority on group membership.**
        ``existing_profiles`` may be a filtered fetch
        (``_get_network_profiles(name_contains=...)`` uses the endpoint's
        ``filter=name co "..."``), and ``co`` is a *case-insensitive
        partial* match - so it also returns profiles that merely contain
        the base name (``base-Legacy``, ``My-base``, ``BASE 4``). The
        pattern below is anchored at both ends and case-sensitive, so
        every one of those is rejected here. Never treat "the API
        returned it" as "it belongs to the group".

        Args:
            existing_profiles (Dict): Profiles keyed by stored name. May
                contain profiles outside the group; they are filtered out.
            base_name (str): The base profile name.
            default_value (str): Placeholder configured on the action, so
                the plugin's own placeholder can be told apart from an
                operator's comment. Empty falls back to
                ``NETWORK_PROFILE_EMPTY_PLACEHOLDER``.

        Returns:
            List[Dict]: ``{name, id, number, values, real_values,
                values_count, description, status}`` entries sorted by
                number. ``values`` is every stored value and
                ``real_values`` excludes only this plugin's own
                placeholder - an operator's comment counts as a real
                value, since it occupies a value slot just as an address
                does.
        """
        # ``\Z`` rather than ``$``: ``$`` also matches just before a
        # trailing newline, so ``$`` would accept "base 2\n" as a member.
        pattern = re.compile(rf"^{re.escape(base_name)}( (\d+))?\Z")
        members = []
        for name, details in existing_profiles.items():
            match = pattern.match(str(name))
            if not match:
                continue
            number = int(match.group(2)) if match.group(2) else 1
            values = [
                value for value in details.get("values", []) or [] if value
            ]
            real_values = [
                value
                for value in values
                if not self._is_network_profile_placeholder(
                    value, default_value
                )
            ]
            members.append(
                {
                    "name": name,
                    "id": details.get("id", ""),
                    "number": number,
                    "values": values,
                    "real_values": real_values,
                    # values_count comes from the API on the light fetch
                    # (where ``values`` is absent), so prefer it and fall
                    # back to the fetched list only when it is missing.
                    "values_count": details.get(
                        "values_count", len(values)
                    ),
                    "description": details.get("description", ""),
                    "status": details.get("status", ""),
                }
            )
        members.sort(key=lambda member: member["number"])
        return members

    def _network_profile_group_capacity(
        self,
        existing_profiles: Dict,
        members: List[Dict],
        per_profile_limit: Optional[int] = None,
    ) -> Tuple[int, List[int], int]:
        """Compute the room available across a whole profile group.

        Roll-over needs three numbers at once: how much room the tenant
        still has in total, how much room each existing member has, and
        how many brand new profiles may still be created. All three are
        computed from one tenant snapshot so the tenant budget is never
        counted twice.

        Args:
            existing_profiles (Dict): Every profile on the tenant, keyed
                by name (each carrying ``values_count``).
            members (List[Dict]): The group's members, ordered by number,
                as returned by ``_ordered_network_profile_group``.
            per_profile_limit (Optional[int]): Per-profile value limit
                override; ``None`` uses
                ``NETWORK_PROFILE_PER_PROFILE_LIMIT``.

        Returns:
            Tuple[int, List[int], int]: ``(tenant_room, member_room,
                sibling_slots)`` where ``tenant_room`` is how many more
                values the tenant can hold, ``member_room`` is the room
                on each member in ``members`` order (never negative, so a
                member already over the limit simply reports 0), and
                ``sibling_slots`` is how many more profiles may be
                created before the tenant profile cap is reached.
        """
        per_profile_limit = (
            per_profile_limit
            if per_profile_limit is not None
            else NETWORK_PROFILE_PER_PROFILE_LIMIT
        )
        total_usage = sum(
            profile.get("values_count", 0)
            for profile in existing_profiles.values()
        )
        tenant_room = max(
            0, NETWORK_PROFILE_TENANT_TOTAL_LIMIT - total_usage
        )
        # Only this plugin's own placeholder is added back as free room:
        # it is discarded when the member is written to, and counting it
        # would make the member look one value fuller than it is,
        # spilling a value into a brand new profile that compaction then
        # immediately reclaims. An operator's comment is NOT free room -
        # it stays on the profile and occupies a value slot, so a member
        # holding 95 addresses and 5 comments is full at a limit of 100
        # and a write of 95 + 5 + 5 would be rejected by the API. Such
        # comments are already inside ``real_values``, so they add
        # nothing back here. Writing the add-back as a delta, rather
        # than using ``len(real_values)`` directly, keeps a light fetch
        # (no ``values``) degrading to plain ``values_count`` instead of
        # reporting the whole limit as free.
        member_room = [
            max(
                0,
                per_profile_limit
                - member.get("values_count", 0)
                + (
                    len(member.get("values", []))
                    - len(member.get("real_values", []))
                ),
            )
            for member in members
        ]
        sibling_slots = max(
            0, MAX_NETWORK_PROFILES - len(existing_profiles)
        )
        return tenant_room, member_room, sibling_slots

    def _format_network_profile_value(
        self, value: str
    ) -> Optional[str]:
        """Validate and format a network profile IP value in one pass.

        A valid value is one of:
        - a single IPv4 or IPv6 address (e.g. ``10.50.2.2``),
        - an IPv4 or IPv6 CIDR block, prefix 0-32 for IPv4 and 0-128
          for IPv6 (e.g. ``10.50.0.0/12``); the Netskope API accepts
          ``/0`` as a valid (if unusual) network,
        - an IPv4 or IPv6 range ``start-end`` where both sides are
          valid addresses of the same IP version and
          ``start < end`` (e.g. ``10.0.0.0-10.0.0.240``).

        Each network profile element has an 80-character limit. An
        uncompressed IPv6 range entered as ``start - end`` (with spaces
        around the hyphen) can run to 81 characters, one over the limit,
        while the same range with the spaces removed (``start-end``)
        fits, so a recognized range is reformatted here as well as
        validated. A single address or CIDR block is returned unchanged.

        Args:
            value (str): Raw network profile value.

        Returns:
            Optional[str]: The value, formatted as ``start-end`` (no
                surrounding spaces) when it is a valid IP range, or
                unchanged when it is a valid single address or CIDR
                block. ``None`` when the value does not match any of
                the allowed formats.
        """
        value = value.strip()
        if not value:
            return None
        if "/" in value:
            try:
                # ip_network already rejects a prefix outside the
                # valid 0-32 (IPv4) / 0-128 (IPv6) range on its own;
                # /0 is a valid, if unusual, network and is accepted.
                ipaddress.ip_network(value, strict=False)
            except ValueError:
                return None
            return value
        if "-" in value:
            parts = value.split("-")
            if len(parts) != 2:
                return None
            start = parts[0].strip()
            end = parts[1].strip()
            try:
                start_ip = ipaddress.ip_address(start)
                end_ip = ipaddress.ip_address(end)
            except ValueError:
                return None
            if (
                start_ip.version != end_ip.version
                or int(start_ip) >= int(end_ip)
            ):
                return None
            return f"{start}-{end}"
        return value if self._validate_ip_address(value) else None

    # ------------------------------------------------------------------
    # DNS profile helpers
    # ------------------------------------------------------------------

    def _build_dns_create_body(
        self,
        profile_name: str,
        action_params: Dict,
        action_type: str,
        security_categories: List[Dict],
    ) -> Dict:
        """Build the POST body for creating a DNS profile.

        Returns a skeleton body with an empty ``domain_names`` list in
        the target ``allow_list``/``block_list`` entry; the packer
        fills in the domains afterwards under the payload budget.

        Args:
            profile_name (str): Name for the new DNS profile.
            action_params (Dict): Resolved action parameters.
            action_type (str): ``add_to_allow_list`` or
                ``add_to_block_list``.
            security_categories (List[Dict]): Pre-parsed security
                categories for the profile.

        Returns:
            Dict: The DNS profile create request body.
        """
        list_key = (
            "allow_list"
            if action_type == "add_to_allow_list"
            else "block_list"
        )
        has_sinkhole_category = any(
            c["action"] == "Sinkhole" for c in security_categories
        )
        domain_config: Dict = {
            list_key: [
                {
                    "record_types": list(
                        action_params.get("dns_record_types", [])
                    ),
                    "domain_names": [],
                }
            ],
            "security_categories": security_categories,
            "block_all_except_allow_list": (
                action_params.get(
                    "block_all_except_allow_list", "False"
                ) == "True"
            ),
        }
        if has_sinkhole_category:
            sinkhole_ip = action_params.get(
                "sinkhole_ip", ""
            ).strip()
            if sinkhole_ip:
                domain_config["sinkhole_ip"] = sinkhole_ip
        return {
            "name": profile_name,
            "description": action_params.get(
                "new_profile_description", ""
            ).strip(),
            "domain_config": domain_config,
        }

    def _build_dns_patch_body(
        self,
        existing_profile: Dict,
        action_params: Dict,
        action_type: str,
        operation: str = "append",
        security_categories: List[Dict] = None,
    ) -> Dict:
        """Build a minimal-diff PATCH body for a DNS profile.

        Includes only the fields that need to change. For the modified
        list, if an existing entry has the same set of ``record_types``
        as the user's selection, the new domains are merged into that
        entry: for an ``append`` operation they are added to the
        existing domains; for a ``replace`` operation the entry starts
        empty so the new domains overwrite the existing ones for those
        record types.

        Args:
            existing_profile (Dict): The current DNS profile object.
            action_params (Dict): Resolved action parameters.
            action_type (str): ``add_to_allow_list`` or
                ``add_to_block_list``.
            operation (str): ``append`` or ``replace``.
            security_categories (List[Dict]): Pre-parsed security
                categories; defaults to empty list when not provided.

        Returns:
            Dict: The DNS profile PATCH request body.
        """
        new_security_categories = security_categories or []
        existing_dc = existing_profile.get("domain_config", {})
        patch_dc: Dict = {}
        existing_security_categories = existing_dc.get(
            "security_categories", []
        )
        new_sc_pairs = {
            (c["name"], c["action"])
            for c in new_security_categories
        }
        existing_sc_pairs = {
            (c.get("name"), c.get("action"))
            for c in existing_security_categories
        }
        if new_sc_pairs != existing_sc_pairs:
            patch_dc["security_categories"] = new_security_categories
        has_sinkhole_category = any(
            c["action"] == "Sinkhole"
            for c in new_security_categories
        )
        new_sinkhole_ip = action_params.get(
            "sinkhole_ip", ""
        ).strip()
        existing_sinkhole_ip = existing_dc.get("sinkhole_ip", "")
        if has_sinkhole_category:
            # A Sinkhole category is selected: send the user's IP
            # when it differs from the value already on the profile.
            if (
                new_sinkhole_ip
                and new_sinkhole_ip != existing_sinkhole_ip
            ):
                patch_dc["sinkhole_ip"] = new_sinkhole_ip
        elif existing_sinkhole_ip:
            # No Sinkhole category is selected but the profile still
            # carries a sinkhole_ip. Clear it so the profile stays
            # consistent with the rule that a sinkhole_ip only exists
            # alongside a Sinkhole category.
            patch_dc["sinkhole_ip"] = ""
        new_block_all = (
            action_params.get(
                "block_all_except_allow_list", "False"
            ) == "True"
        )
        if new_block_all != existing_dc.get(
            "block_all_except_allow_list", False
        ):
            patch_dc["block_all_except_allow_list"] = new_block_all
        list_key = (
            "allow_list"
            if action_type == "add_to_allow_list"
            else "block_list"
        )
        new_record_types = list(
            action_params.get("dns_record_types", [])
        )
        existing_entries = existing_dc.get(list_key, [])
        target_entry = None
        other_entries: List[Dict] = []
        for entry in existing_entries:
            if (
                target_entry is None
                and set(entry.get("record_types", []))
                == set(new_record_types)
            ):
                target_entry = {
                    "record_types": list(
                        entry.get("record_types", [])
                    ),
                    "domain_names": (
                        []
                        if operation == "replace"
                        else list(entry.get("domain_names", []))
                    ),
                }
            else:
                other_entries.append(
                    {
                        "record_types": list(
                            entry.get("record_types", [])
                        ),
                        "domain_names": list(
                            entry.get("domain_names", [])
                        ),
                    }
                )
        if target_entry is None:
            target_entry = {
                "record_types": new_record_types,
                "domain_names": [],
            }
        patch_dc[list_key] = other_entries + [target_entry]
        body: Dict = {"domain_config": patch_dc}
        new_description = action_params.get(
            "new_profile_description", ""
        ).strip()
        existing_description = existing_profile.get("description", "")
        if new_description and new_description != existing_description:
            body["description"] = new_description
        return body

    def _pack_domains_within_budget(
        self,
        body: Dict,
        list_key: str,
        candidate_domains: List[str],
        budget_bytes: int,
    ) -> tuple:
        """Pack the longest fitting prefix of candidates into body.

        Walks ``candidate_domains`` once, maintaining a running byte
        count of the JSON-encoded body. Each domain's incremental cost
        is its ``json.dumps`` byte length plus 2 bytes for the
        separator (only when ``domain_names`` already has at least one
        item). Mutates the last ``domain_config[list_key]`` entry of
        ``body`` in place.

        Args:
            body (Dict): The create/patch body to mutate in place.
            list_key (str): ``allow_list`` or ``block_list``.
            candidate_domains (List[str]): Domains to attempt to add.
            budget_bytes (int): Maximum encoded payload size in bytes.

        Returns:
            tuple: ``(accepted, skipped)`` lists of domain strings.
        """
        target_entry = body.get("domain_config", {}).get(
            list_key, []
        )[-1]
        domain_names = target_entry["domain_names"]
        current_size = len(json.dumps(body).encode("utf-8"))
        if current_size > budget_bytes:
            return [], list(candidate_domains)
        item_sep_bytes = 2  # default item separator is ", "
        accepted_count = 0
        for domain in candidate_domains:
            encoded_len = len(json.dumps(domain).encode("utf-8"))
            delta = encoded_len + (
                item_sep_bytes if domain_names else 0
            )
            if current_size + delta > budget_bytes:
                break
            domain_names.append(domain)
            current_size += delta
            accepted_count += 1
        return (
            list(candidate_domains[:accepted_count]),
            list(candidate_domains[accepted_count:]),
        )

    # ------------------------------------------------------------------
    # Device classification helpers
    # ------------------------------------------------------------------

    def _build_rule_conditions(
        self,
        tag_ids: List,
        operator: str,
        group_operator: str = "and",
    ) -> Dict:
        """Build the nested condition tree for a classification rule.

        The tag ids are split into chunks of
        ``DEVICE_CLASSIFICATION_TAGS_PER_GROUP`` (5). Each chunk
        becomes a group wrapped as ``$and -> <operator> -> [checks]``
        and all groups are joined under a top-level
        ``<group_operator>`` container.

        Args:
            tag_ids (List): Device tag ids referenced by the rule.
            operator (str): ``and`` or ``or`` (mapped to
                ``$and``/``$or``) for each inner tag-check group.
            group_operator (str): ``and`` or ``or`` for the outer
                container that joins multiple groups.  Defaults to
                ``"and"``.

        Returns:
            Dict: The nested ``conditions`` object for the rule body.
        """
        operator_key = "$or" if operator == "or" else "$and"
        group_operator_key = (
            "$or" if group_operator == "or" else "$and"
        )
        groups = []
        for start in range(
            0, len(tag_ids), DEVICE_CLASSIFICATION_TAGS_PER_GROUP
        ):
            chunk = tag_ids[
                start:start + DEVICE_CLASSIFICATION_TAGS_PER_GROUP
            ]
            checks = [
                {"device_tag_check": {"tag_id": tag_id}}
                for tag_id in chunk
            ]
            groups.append({"$and": [{operator_key: checks}]})
        return {group_operator_key: groups}

    def _replace_rule_tag_checks(
        self,
        conditions,
        tag_ids: List,
        operator: str,
        group_operator: str = "and",
    ) -> Dict:
        """Swap the device tag checks in an existing rule's conditions.

        Updating a rule must touch ONLY its device tags and leave every
        other condition (``min_os_version_check``,
        ``device_not_compromised_check`` ...) untouched. EVERY existing
        device tag check is removed from the condition tree — across all
        groups, not just the first — and the provided ``tag_ids`` are
        re-added as fresh groups of at most
        ``DEVICE_CLASSIFICATION_TAGS_PER_GROUP`` checks each. The Match
        Type operator (``operator``) applies inside each tag group; the
        Group Match Type (``group_operator``) joins the groups at the
        top level.

        Behaviour:

        - **Non-tag conditions are preserved** in place; only device
          tag checks are stripped, and any container left empty by the
          strip is pruned.
        - **Multiple existing tag groups are all replaced** — the rule
          ends with exactly the groups built from ``tag_ids`` plus the
          surviving non-tag conditions, so no stale tag remains and no
          tag is duplicated.
        - **No device tag checks yet**: the new tag groups are appended
          to the existing structure.
        - **No usable conditions**: a fresh condition tree is built.

        Args:
            conditions: The existing rule's ``conditions`` object.
            tag_ids (List): Device tag ids the rule should reference.
                May exceed ``DEVICE_CLASSIFICATION_TAGS_PER_GROUP``;
                excess ids become additional groups.
            operator (str): ``and`` or ``or`` (mapped to
                ``$and``/``$or``) for each inner tag group, from Match
                Type.
            group_operator (str): ``and`` or ``or`` for the outer
                container joining multiple groups, from Group Match
                Type.  Defaults to ``"and"``.

        Returns:
            Dict: A new ``conditions`` object with only the device tag
                checks changed.
        """
        operator_key = "$or" if operator == "or" else "$and"
        group_operator_key = (
            "$or" if group_operator == "or" else "$and"
        )
        if not isinstance(conditions, dict) or not conditions:
            return self._build_rule_conditions(
                tag_ids, operator, group_operator
            )

        # Never wipe a rule's tags to empty: with no tags to apply the
        # existing conditions are returned unchanged (the caller already
        # guards against this, but stay defensive).
        if not tag_ids:
            return copy.deepcopy(conditions)

        # Build the tag groups (chunks of at most
        # DEVICE_CLASSIFICATION_TAGS_PER_GROUP) the rule must end with.
        new_groups = []
        for start in range(
            0, len(tag_ids), DEVICE_CLASSIFICATION_TAGS_PER_GROUP
        ):
            chunk = tag_ids[
                start:start + DEVICE_CLASSIFICATION_TAGS_PER_GROUP
            ]
            checks = [
                {"device_tag_check": {"tag_id": tid}}
                for tid in chunk
            ]
            new_groups.append({"$and": [{operator_key: checks}]})

        new_conditions = copy.deepcopy(conditions)
        # Rename the existing top-level operator key to match the
        # requested Group Match Type so every group is joined by it.
        for old_key in ("$and", "$or"):
            if (
                old_key in new_conditions
                and old_key != group_operator_key
            ):
                new_conditions[group_operator_key] = (
                    new_conditions.pop(old_key)
                )
                break

        # Strip EVERY device tag check from the tree, pruning any
        # container left empty, while keeping all non-tag conditions
        # (min OS version, not-compromised, ...) exactly as they were.
        # Returns the cleaned node, or None when nothing remains.
        def _strip(node):
            if isinstance(node, dict):
                if "device_tag_check" in node:
                    return None
                cleaned = {}
                for key, value in node.items():
                    new_value = _strip(value)
                    if new_value is None:
                        continue
                    if (
                        isinstance(new_value, list)
                        and not new_value
                    ):
                        continue
                    cleaned[key] = new_value
                return cleaned if cleaned else None
            if isinstance(node, list):
                result = []
                for item in node:
                    cleaned = _strip(item)
                    if cleaned is None:
                        continue
                    if (
                        isinstance(cleaned, (dict, list))
                        and not cleaned
                    ):
                        continue
                    result.append(cleaned)
                return result
            return node

        stripped = _strip(new_conditions)

        # Re-attach the freshly built tag groups to whatever non-tag
        # structure survived. When nothing survived (the rule only ever
        # held device tags) build a fresh tree from the new groups.
        if not stripped or not isinstance(stripped, dict):
            return {group_operator_key: list(new_groups)}
        for top_key in (group_operator_key, "$and", "$or"):
            top_value = stripped.get(top_key)
            if isinstance(top_value, list):
                top_value.extend(new_groups)
                return stripped
        # No usable top-level operator list (atypical): join the lone
        # surviving condition with the new tag groups.
        return {group_operator_key: [stripped] + list(new_groups)}

    def _extract_rule_tag_ids(self, conditions) -> List:
        """Collect the device tag ids referenced in a rule's conditions.

        Walks the nested ``$and``/``$or`` condition tree and returns
        every ``device_tag_check.tag_id`` found, de-duplicated with
        order preserved.

        Args:
            conditions: The rule's ``conditions`` object (nested
                dict/list structure).

        Returns:
            List: Device tag ids referenced by the rule, in order.
        """
        found = []
        seen = set()

        def _walk(node):
            if isinstance(node, dict):
                tag_check = node.get("device_tag_check")
                if isinstance(tag_check, dict):
                    tag_id = tag_check.get("tag_id")
                    if tag_id is not None and tag_id not in seen:
                        seen.add(tag_id)
                        found.append(tag_id)
                for value in node.values():
                    _walk(value)
            elif isinstance(node, list):
                for item in node:
                    _walk(item)

        _walk(conditions)
        return found

    def _resolve_classification_tag_ids(
        self,
        tags: List[str],
        tag_cache: Dict,
    ) -> tuple:
        """Resolve device tag names to their ids using a tag cache.

        Device classification rules reference device tags by id. Tags
        that do not exist are NOT created — they are reported back so
        the caller can skip them and attribute them to the originating
        action id(s).

        Args:
            tags (List[str]): Device tag names provided on the action.
            tag_cache (Dict): Mapping of lower-cased tag name to
                tag id.

        Returns:
            tuple: ``(tag_ids, not_found)`` where ``tag_ids`` are the
                resolved ids (de-duplicated, order preserved) and
                ``not_found`` lists the provided tag names with no
                matching tag on the Netskope Tenant.
        """
        tag_ids = []
        not_found = []
        seen = set()
        for tag in tags:
            normalized = str(tag).strip().lower()
            if not normalized:
                continue
            tag_stripped = str(tag).strip()
            if (
                not re.match(REGEX_TAG, tag_stripped)
                or len(tag_stripped) > TAG_DEVICE_TAG_LENGTH
            ):
                not_found.append(tag)
                continue
            tag_id = tag_cache.get(normalized)
            if tag_id is None:
                not_found.append(tag)
            elif tag_id not in seen:
                seen.add(tag_id)
                tag_ids.append(tag_id)
        return tag_ids, not_found

    def validate_tags_for_private_app(
        self,
        tags_to_push: List[str],
        private_app_name: str
    ) -> Tuple[List[Dict], List[str], int]:
        """Validate and sanitize tags before pushing to a private app.

        For each tag, the ``<`` and ``>`` characters are replaced with their
        HTML-escaped equivalents (``&lt;`` and ``&gt;``) and the resulting
        length is checked against ``PRIVATE_APP_TAG_MAX_LENGTH``. Tags that
        are empty, exceed the maximum length, or raise an error during
        length computation are skipped and recorded.

        Args:
            tags_to_push (List[str]): Tags to be validated for the private
                app.
            private_app_name (str): Name of the private app the tags will
                be pushed to. Used in error/log messages for context.

        Returns:
            Tuple[List[Dict], List[str], int]: A tuple of
                (valid_tags, skipped_tags, skip_count) where
                ``valid_tags`` is a list of ``{"tag_name": <tag>}`` dicts
                ready to be sent in the API payload, ``skipped_tags`` is
                the list of tag strings that were skipped, and
                ``skip_count`` is the total number of skipped tags
                (including those skipped due to errors).
        """
        valid_tags = []
        skipped_tags = []
        skip_count = 0
        for tag in tags_to_push:
            try:
                tag = tag.replace("<", "&lt;").replace(">", "&gt;")
                tag_length = len(tag)
            except Exception as err:
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while determining"
                    f" length of tag, hence skipped sharing tag {tag} to"
                    f" private app {private_app_name}. Error: {err}."
                )
                skip_count += 1
                continue
            if tag_length == 0 or tag_length > PRIVATE_APP_TAG_MAX_LENGTH:
                skipped_tags.append(tag)
                skip_count += 1
            else:
                valid_tags.append({"tag_name": tag})
        return valid_tags, skipped_tags, skip_count

    def _is_valid_private_app_host(self, host: str) -> bool:
        """Check whether a host value is valid for a private app.

        A host is considered valid if it is a non-empty value that is
        one of the following:
        - a valid IPv4 address (e.g. ``10.0.0.1``),
        - a valid IPv4 CIDR block no wider than ``/8`` (e.g. ``10.0.0.0/8``;
          ``0.0.0.0/0`` and any prefix below /8 such as ``1.0.0.0/7`` are
          rejected), or
        - a hostname / domain (optionally a wildcard) whose total length is
          at most 253 characters and whose every label is a valid hostname
          label (1-63 characters of letters/digits/hyphen/underscore, not
          starting or ending with a hyphen). A wildcard ``*`` is allowed only
          as the leftmost label and only when the host has at least three
          labels (e.g. ``*.netskope.com``).

        IPv6 addresses and IPv6 CIDR blocks are explicitly rejected as
        private apps do not accept IPv6 values (this also covers the IPv6
        equivalents of ``0/0`` such as ``::`` and
        ``0:0:0:0:0:0:0:0``).

        Args:
            host (str): Host value to validate.

        Returns:
            bool: True if the host satisfies one of the accepted formats,
                False otherwise.
        """
        if not host:
            return False
        # Reject IPv6 addresses / CIDR blocks; private apps do not accept
        # IPv6 values (an IPv6 literal would otherwise slip through the
        # hostname/domain length check below).
        try:
            ipaddress.IPv6Interface(host)
            return False
        except ValueError:
            pass
        # Valid IPv4 address or IPv4 CIDR block (with the /8 lower bound).
        try:
            interface = ipaddress.IPv4Interface(host)
        except ValueError:
            pass
        else:
            return self._is_valid_private_app_ipv4(host, interface)
        # Otherwise validate as a hostname / domain (incl. wildcard).
        return self._is_valid_private_app_domain(host)

    def _is_valid_private_app_ipv4(
        self, host: str, interface: "ipaddress.IPv4Interface"
    ) -> bool:
        """Apply the private app IPv4 CIDR restrictions.

        A bare IPv4 address (parsed as ``/32``) is always accepted. A CIDR
        block is rejected when it is wider than ``/8`` (network prefix below
        ``PRIVATE_APP_MIN_CIDR_PREFIX``) - this rejects ``0.0.0.0/0`` and
        anything such as ``1.0.0.0/7`` while still allowing ``10.0.0.0/8``.

        Args:
            host (str): The original host value (used to detect CIDR input).
            interface (ipaddress.IPv4Interface): The parsed interface.

        Returns:
            bool: True if the IPv4 value is acceptable, False otherwise.
        """
        if (
            "/" in host
            and interface.network.prefixlen < PRIVATE_APP_MIN_CIDR_PREFIX
        ):
            return False
        return True

    def _is_valid_private_app_domain(self, host: str) -> bool:
        """Validate a private app hostname / domain (including wildcards).

        Enforces the RFC length limits (total <= 253) and validates every
        label against ``REGEX_HOSTNAME_LABEL``. A wildcard ``*`` is allowed
        only as the leftmost label, and a wildcard host must have at least
        three labels (e.g. ``*.netskope.com``); the ``*`` label itself is
        stripped before the per-label check so the remaining labels are
        validated normally.

        Args:
            host (str): Host value to validate.

        Returns:
            bool: True if the host is a valid hostname / domain, otherwise
                False.
        """
        if not self.is_valid_domain_length(host):
            return False
        labels = host.split(".")
        if labels[0] == "*":
            # Wildcard must be the leftmost label of an at-least-3-part host.
            if len(labels) < 3:
                return False
            labels = labels[1:]
        # Every remaining label must be a valid hostname label (this also
        # rejects a stray '*' anywhere other than the leftmost position).
        return all(
            re.match(REGEX_HOSTNAME_LABEL, label) for label in labels
        )

    def validate_hosts_for_private_app(
        self,
        hosts_to_push: List[str],
        private_app_name: str
    ) -> Tuple[List[str], List[str], int]:
        """Validate host values before pushing to a private app.

        Each host is stripped of surrounding whitespace and checked with
        ``_is_valid_private_app_host``. Hosts that are empty, fail the
        format/length checks, or raise an error during validation are
        skipped and recorded.

        Args:
            hosts_to_push (List[str]): Host values to validate for the
                private app.
            private_app_name (str): Name of the private app the hosts will
                be pushed to. Used in error/log messages for context.

        Returns:
            Tuple[List[str], List[str], int]: A tuple of
                (valid_hosts, skipped_hosts, skip_count) where
                ``valid_hosts`` is the list of accepted host values ready
                to be sent in the API payload, ``skipped_hosts`` is the
                list of host values that were skipped, and ``skip_count``
                is the total number of skipped hosts (including those
                skipped due to errors).
        """
        valid_hosts = []
        skipped_hosts = []
        skip_count = 0
        for host in hosts_to_push:
            try:
                host = host.strip()
                is_valid = self._is_valid_private_app_host(host)
            except Exception as err:
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while validating"
                    f" host, hence skipped sharing host {host} to"
                    f" private app {private_app_name}. Error: {err}."
                )
                skip_count += 1
                continue
            if not is_valid:
                skipped_hosts.append(host)
                skip_count += 1
            else:
                valid_hosts.append(host)
        return valid_hosts, skipped_hosts, skip_count

    def _validate_port(self, port):
        """Validate the port or port range.

        Args:
            port: Port number as int/str or port range as 'lower-upper' string

        Returns:
            bool: True if port or port range is valid, False otherwise
        """
        # Handle port range (e.g., '1000-2000')
        if isinstance(port, str) and '-' in port:
            try:
                lower, upper = port.split('-')
                lower_port = int(lower.strip())
                upper_port = int(upper.strip())
                # Check if ports are within valid range
                if not (0 <= lower_port <= 65535 and 0 <= upper_port <= 65535):
                    return False
                # Check if lower is less than upper and they are not equal
                if lower_port >= upper_port:
                    return False
                return True
            except (ValueError, AttributeError):
                return False

        # Handle single port
        try:
            port = int(port)
            return 0 <= port <= 65535
        except (ValueError, TypeError):
            return False

    def _build_private_app_protocols(
        self, protocol_type, tcp_ports, udp_ports
    ):
        """Build the protocols payload for a private app.

        Args:
            protocol_type (list[str]): Selected protocols (TCP/UDP).
            tcp_ports (list[str]): Ports for the TCP protocol.
            udp_ports (list[str]): Ports for the UDP protocol.

        Returns:
            list[dict]: Protocol entries for the private app payload.
        """
        protocols_list = []
        for protocol in protocol_type:
            if protocol == "TCP":
                protocols_list.append(
                    {"type": "tcp", "ports": ",".join(tcp_ports)}
                )
            if protocol == "UDP":
                protocols_list.append(
                    {"type": "udp", "ports": ",".join(udp_ports)}
                )
        return protocols_list

    def _ordered_private_app_group(self, existing_private_apps, base_name):
        """Return the roll-over group for ``base_name`` ordered by number.

        A logical private app is stored as a base app ``[base]`` plus
        numbered roll-over siblings ``[base 2]``, ``[base 3]`` ... created
        when the per-app host cap is hit. This collects the matching apps
        and orders them by number (the base app counts as number 1).

        Args:
            existing_private_apps (dict): Apps keyed by stored name.
            base_name (str): The logical app name without brackets.

        Returns:
            list[dict]: ``{name, id, number, hosts, tags, protocols,
                publishers, use_publisher_dns}`` entries sorted by number.
        """
        pattern = re.compile(rf"^\[{re.escape(base_name)}( (\d+))?\]$")
        members = []
        for name, details in existing_private_apps.items():
            match = pattern.match(name)
            if not match:
                continue
            number = int(match.group(2)) if match.group(2) else 1
            members.append(
                {
                    "name": name,
                    "id": details.get("id", ""),
                    "number": number,
                    "hosts": [
                        host for host in details.get("hosts", []) if host
                    ],
                    "tags": details.get("tags", []),
                    "protocols": details.get("protocols", []),
                    "publishers": details.get("publishers", []),
                    "use_publisher_dns": details.get(
                        "use_publisher_dns", False
                    ),
                }
            )
        members.sort(key=lambda member: member["number"])
        return members

    def _private_app_metadata_changed(
        self,
        member,
        publishers_list,
        use_publisher_dns,
        protocols_list,
        target_tag_names,
    ):
        """Check whether the action's metadata differs from an app's.

        Compares the publishers, use-publisher-DNS flag, protocols/ports and
        tags resolved from the action parameters against the values fetched
        for ``member``. Returns True if any of them differs (so a PATCH is
        warranted), False if the app already matches (the PATCH would be a
        no-op and can be skipped).

        ``protocols_list`` follows the body-builder rule: an empty list is
        not sent and therefore never clears existing protocols, so it is
        treated as "no protocol change".

        Args:
            member (dict): Fetched app entry (carries ``protocols``,
                ``publishers``, ``use_publisher_dns``, ``tags``).
            publishers_list (list[dict]): Resolved ``{publisher_id,
                publisher_name}`` entries from the action.
            use_publisher_dns (bool): The action's use-publisher-DNS flag.
            protocols_list (list[dict]): ``{type, ports}`` entries built
                from the action's protocol/port params.
            target_tag_names (Iterable[str]): The tag names the refresh
                would set on the app.

        Returns:
            bool: True if a metadata update is needed, else False.
        """
        # use-publisher-DNS flag.
        if bool(member.get("use_publisher_dns", False)) != bool(
            use_publisher_dns
        ):
            return True
        # Publishers (compare by id set, normalised to str).
        existing_publisher_ids = {
            str(pub.get("publisher_id"))
            for pub in member.get("publishers", [])
        }
        new_publisher_ids = {
            str(pub.get("publisher_id")) for pub in publishers_list
        }
        if existing_publisher_ids != new_publisher_ids:
            return True
        # Protocols (compare by {(transport, port)} set). An empty
        # protocols_list is never sent, so it is not treated as a change.
        new_protocols = set()
        for protocol in protocols_list:
            transport = protocol.get("type", "")
            for port in protocol.get("ports", "").split(","):
                port = port.strip()
                if port:
                    new_protocols.add((transport, port))
        if new_protocols:
            existing_protocols = {
                (proto.get("transport", ""), str(proto.get("port", "")))
                for proto in member.get("protocols", [])
            }
            if new_protocols != existing_protocols:
                return True
        # Tags (compare by name set).
        if set(target_tag_names) != set(member.get("tags", [])):
            return True
        return False

    def _extract_private_app_tag_names(self, tags_field):
        """Extract tag-name strings from a private app's ``tags`` field.

        The Netskope GET response shape is handled defensively: a list of
        plain strings, or a list of dicts keyed by ``tag_name``/``name``.

        Args:
            tags_field: The ``tags`` value from a private app record.

        Returns:
            list[str]: The tag names found (empty entries dropped).
        """
        names = []
        for tag in tags_field or []:
            if isinstance(tag, str):
                name = tag
            elif isinstance(tag, dict):
                name = tag.get("tag_name") or tag.get("name") or ""
            else:
                name = ""
            if name:
                names.append(name)
        return names

    def _private_app_body(
        self,
        hosts,
        host_to_tags,
        publishers_list,
        use_publisher_dns,
        protocols_list,
        base_tags=(),
    ):
        """Build a create/PATCH body for a private app from a host list.

        The app's ``tags`` are scoped to this batch: the union of the tag
        names contributed by the records whose hosts are in ``hosts``
        (via ``host_to_tags``), plus any ``base_tags`` (e.g. an existing
        app's current tags, for the Append union). Tag names are sorted
        for determinism and rebuilt into the ``{"tag_name": ...}`` shape
        the API expects.

        Args:
            hosts (list[str]): Hosts for this app/chunk.
            host_to_tags (dict[str, set[str]]): host -> contributing tag
                names.
            publishers_list (list[dict]): Resolved publisher entries.
            use_publisher_dns (bool): Whether to use the publisher DNS.
            protocols_list (list[dict]): Protocol entries for the app.
            base_tags (Iterable[str], optional): Tag names to seed the set
                with (preserved/unioned). Defaults to empty.
        """
        tag_names = set(base_tags)
        for host in hosts:
            tag_names |= host_to_tags.get(host, set())
        data = {
            "host": ",".join(hosts),
            "tags": [{"tag_name": name} for name in sorted(tag_names)],
            "publishers": publishers_list,
            "use_publisher_dns": use_publisher_dns,
        }
        if protocols_list:
            data["protocols"] = protocols_list
        return data
