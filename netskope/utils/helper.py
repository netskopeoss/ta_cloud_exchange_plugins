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

CRE Netskope Threat Exchange helper module.
"""

import ipaddress
import json
import time
import re
import requests
import traceback
from typing import Dict, List, Tuple, Union

from netskope.integrations.cte.plugin_base import PushResult
from netskope.common.utils import (
    add_user_agent,
    add_installation_id
)
from netskope.common.utils.handle_exception import (
    handle_exception,
    handle_status_code,
)

from .constants import (
    DEFAULT_SLEEP_TIME,
    MAX_RETRIES,
    NO_MORE_RETRIES_ERROR_MSG,
    PLUGIN_NAME,
    RETRY_ERROR_MSG,
    BYTES_TO_MB,
    URLS,
    DESTINATION_PROFILE_BATCH_SIZE,
    RETRACTION,
    PENDING_CHANGES_DETECTED,
    DESTINATION_PROFILE_EXACT_MATCH_PATTERN,
    DESTINATION_PROFILE_EXACT_TOTAL_LIMIT,
    DESTINATION_PROFILE_EXACT_PER_PROFILE_LIMIT,
    DESTINATION_PROFILE_REGEX_TOTAL_LIMIT,
)


class NetskopeThreatExchangeException(Exception):
    """Custom exception for Netskope Threat Exchange operations."""

    pass


class NetskopeThreatExchangeHelper:
    """Netskope Threat Exchange helper class."""

    def __init__(
        self,
        logger,
        log_prefix: str,
    ):
        """Netskope Threat Exchange Helper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
        """
        self.logger = logger
        self.log_prefix = log_prefix

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        error_codes,
        method: str = "get",
        message="",
        params=None,
        data: Dict = None,
        headers: Dict = None,
        json: Dict = None,
        verify: bool = None,
        proxies=None,
        is_validation: bool = False,
        is_handle_error_required=True,
        show_params: bool = True
    ):
        """Make API call to Netskope with retry and error handling.

        Args:
            logger_msg (str): Message for logging the API request.
            url (str): API endpoint URL.
            error_codes (list): Error codes for error handling.
            method (str, optional): HTTP method. Defaults to "get".
            message (str, optional): Custom error message. Defaults to "".
            params (dict, optional): Query parameters. Defaults to None.
            data (dict, optional): Request body data. Defaults to None.
            headers (dict, optional): HTTP headers. Defaults to None.
            json (dict, optional): JSON request body. Defaults to None.
            verify (bool, optional): SSL verification. Defaults to None.
            proxies (dict, optional): Proxy configuration. Defaults to None.
            is_validation (bool, optional): Whether this is a validation
                call. Defaults to False.
            is_handle_error_required (bool, optional): Whether to handle
                error status codes. Defaults to True.
            show_params (bool, optional): Whether to log parameters.
                Defaults to True.

        Returns:
            Response: API response object.

        Raises:
            NetskopeThreatExchangeException: If API call fails after
                retries.
        """
        request_func = getattr(requests, method)
        headers = add_installation_id(add_user_agent(headers))
        debug_log_msg = (
            f"{self.log_prefix}: API Request for {logger_msg}. "
            f"Endpoint: {method.upper()} {url}"
        )
        if params and show_params:
            debug_log_msg += f", params: {params}."
        self.logger.debug(debug_log_msg)
        try:
            response = {}
            for retry_count in range(MAX_RETRIES):
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
                    verify=verify
                )
                if not success:
                    err_msg = f"Error occurred while {logger_msg}."
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=str(response),
                    )
                    raise NetskopeThreatExchangeException(err_msg)
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )

                # Handle Rate limit (429) and 5xx errors
                if not is_validation and (
                    status_code == 429 or 500 <= status_code <= 600
                ):
                    api_err_msg = str(response.text)
                    if retry_count == MAX_RETRIES - 1:
                        err_msg = NO_MORE_RETRIES_ERROR_MSG.format(
                            status_code=status_code,
                            logger_msg=logger_msg,
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}"
                        )
                        raise NetskopeThreatExchangeException(
                            err_msg
                        )
                    if status_code == 429:
                        error_reason = "API rate limit exceeded"
                    else:
                        error_reason = "HTTP server error occurred"
                    retry_after = DEFAULT_SLEEP_TIME
                    err_msg = RETRY_ERROR_MSG.format(
                        status_code=status_code,
                        error_reason=error_reason,
                        logger_msg=logger_msg,
                        wait_time=retry_after,
                        retry_remaining=MAX_RETRIES - 1 - retry_count,
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
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
        except NetskopeThreatExchangeException:
            raise
        except Exception as error:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing API call to"
                    f" {PLUGIN_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Please verify the configuration parameters provided."
                )
            )
            raise NetskopeThreatExchangeException(err_msg)

    def push_destination_profile_create(
        self,
        profile_name: str,
        description: str,
        match_type: str,
        indicators: List[str],
        headers: Dict,
        tenant_name: str,
        verify: bool,
        proxies: dict
    ):
        """Create a new destination profile with indicators.

        Args:
            profile_name (str): Name of the destination profile.
            description (str): Description of the destination profile.
            match_type (str): Type of matching (e.g., 'insensitive',
                'sensitive', 'regex').
            indicators (List[str]): List of indicator values to add.
            headers (Dict): HTTP headers for the API request.
            tenant_name (str): Name of the Netskope tenant.
            verify (bool): Whether to verify SSL certificates.
            proxies (dict): Proxy configuration for the API request.

        Returns:
            tuple: Tuple containing (profile_id, overflow_values,
                invalid_indicators, ipv6_iocs, shared_count) or
                PushResult object on error.
        """
        max_bytes = DESTINATION_PROFILE_BATCH_SIZE * BYTES_TO_MB
        bounded_values = []
        overflow_values = []
        current_size = 0
        for value in indicators:
            value_size = len(json.dumps(value)) + 10
            if current_size + value_size > max_bytes:
                overflow_values.append(value)
                continue
            bounded_values.append(value)
            current_size += value_size

        invalid_indicators = []
        ipv6_iocs = []

        payload = {
            "name": profile_name,
            "description": description,
            "type": match_type,
            "values": bounded_values,
        }
        logger_msg = f"creating new destination profile '{profile_name}'"
        try:
            create_profile = self.api_helper(
                logger_msg=logger_msg,
                url=URLS["V2_DESTINATION_PROFILE"].format(tenant_name),
                method="post",
                json=payload,
                error_codes=["CTE_1057", "CTE_1057"],
                message=f"Error occurred while {logger_msg}",
                headers=headers,
                verify=verify,
                proxies=proxies,
                is_handle_error_required=False,
            )

            if create_profile.status_code in [400, 422]:
                response_json = create_profile.json()
                (
                    invalid_indicators,
                    ipv6_iocs
                ) = self._extract_invalid_destination_values(
                    response_json, bounded_values
                )
                bounded_values = list(
                    set(bounded_values) - set(invalid_indicators)
                )
                if not bounded_values:
                    log_msg = (
                        "No indicators to share after excluding "
                        "invalid indicators."
                    )
                    self.logger.info(f"{self.log_prefix}: {log_msg}")
                    return self.return_push_result(
                        success=True,
                        message=log_msg,
                        failed_iocs=list(
                            set(invalid_indicators + ipv6_iocs)
                        ),
                    )
                payload["values"] = bounded_values
                create_profile = self.api_helper(
                    logger_msg=logger_msg,
                    url=URLS["V2_DESTINATION_PROFILE"].format(tenant_name),
                    method="post",
                    json=payload,
                    error_codes=["CTE_1057", "CTE_1057"],
                    message=f"Error occurred while {logger_msg}",
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                )
                if not create_profile.get("id", None):
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while "
                        f"{logger_msg} after excluding invalid indicators."
                    )
                    return self.return_push_result(
                        success=False,
                        message="Could not share indicators.",
                    )
            elif create_profile.status_code not in [200, 201]:
                err_msg = (
                    f"Error occurred while {logger_msg}."
                )
                self.logger.error(
                    f"{self.log_prefix}: {err_msg}"
                )
                return self.return_push_result(
                    success=False,
                    message=err_msg,
                )
            else:
                handle_status_code(
                    create_profile,
                    error_code="CTE_1057",
                    custom_message=f"Error occurred while {logger_msg}",
                    plugin=self.log_prefix,
                    log=True,
                )
        except NetskopeThreatExchangeException:
            raise
        except Exception as err:
            error_message = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise NetskopeThreatExchangeException(error_message)

        profile_id = (
            create_profile.json().get("id")
            if hasattr(create_profile, "json") else None
        )
        log_msg = ""
        if overflow_values:
            log_msg += (
                " Remaining indicators will be shared batch wise."
            )
        if invalid_indicators:
            log_msg += (
                f" Failed to share {len(invalid_indicators)} "
                "indicators due to invalid value."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully shared "
            f"{len(bounded_values)} indicators out of "
            f"{len(indicators)} indicators to "
            f"destination profile '{profile_name}'.{log_msg}"
        )
        return (
            profile_id,
            overflow_values,
            invalid_indicators,
            ipv6_iocs,
            len(bounded_values),
        )

    def push_destination_profile_append(
        self,
        profile_id: str,
        profile_name: str,
        indicators: List[str],
        existing_values: List[str],
        headers: Dict,
        tenant_name: str,
        verify: bool,
        proxies: dict,
        apply_pending_changes: str = "No",
        is_retraction: bool = False
    ) -> Union[Tuple[List[str], List[str], List[str]], PushResult]:
        """Append indicators to existing destination profile in batches.

        Args:
            profile_id (str): ID of the destination profile.
            profile_name (str): Name of the destination profile.
            indicators (List[str]): List of indicator values to append.
            existing_values (List[str]): List of values already in profile.
            headers (Dict): HTTP headers for the API request.
            tenant_name (str): Name of the Netskope tenant.
            verify (bool): Whether to verify SSL certificates.
            proxies (dict): Proxy configuration for the API request.
            apply_pending_changes (str): Apply pending changes to
            the destination profile.
            is_retraction (bool): Whether this is a retraction operation.

        Returns:
            tuple: Tuple containing (invalid_indicators, ipv6_iocs,
                unshared_indicators, shared_count, existing_count) or
                PushResult object on error.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        existing_set = set(existing_values)
        invalid_indicators = []
        ipv6_iocs = []
        unshared_indicators = []
        shared_indicators_append = 0
        existing_count = 0

        def _build_batches(values: List[str]):
            nonlocal existing_count
            batch = []
            for value in values:
                if value in existing_set:
                    existing_count += 1
                    continue
                batch.append(value)
                if len(batch) == DESTINATION_PROFILE_BATCH_SIZE:
                    yield batch
                    batch = []
            if batch:
                yield batch

        for batch_index, batch in enumerate(
            _build_batches(indicators), start=1
        ):
            payload = {
                "operation": {
                    "op": "remove" if is_retraction else "append",
                    "values": batch,
                },
            }
            logger_msg = (
                f"sharing indicators to destination profile "
                f"'{profile_name}' for batch {batch_index}"
            )
            if is_retraction:
                logger_msg = (
                    f"retracting indicators from the destination profile "
                    f"'{profile_name}' for batch {batch_index}"
                )
            try:
                append_response = self.api_helper(
                    logger_msg=logger_msg,
                    url=URLS["V2_DESTINATION_PROFILE_VALUES"].format(
                        tenant_name, profile_id
                    ),
                    method="patch",
                    json=payload,
                    error_codes=["CTE_1058", "CTE_1058"],
                    message=f"Error occurred while {logger_msg}",
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                    is_handle_error_required=False,
                )
                response_text = (
                    append_response.text
                    if hasattr(append_response, "text")
                    else str(append_response)
                )
                if append_response.status_code in [400, 422]:
                    response_json = append_response.json()
                    batch_invalid, batch_ipv6 = (
                        self._extract_invalid_destination_values(
                            response_json, batch
                        )
                    )
                    invalid_indicators.extend(batch_invalid)
                    ipv6_iocs.extend(batch_ipv6)
                    batch = list(set(batch) - set(batch_invalid))
                    if not batch:
                        log_msg = (
                            f"No indicators to "
                            f"{'retract' if is_retraction else 'share'} "
                            f"after excluding invalid "
                            f"indicators from batch {batch_index}."
                        )
                        self.logger.info(f"{self.log_prefix}: {log_msg}")
                        continue
                    payload["operation"]["values"] = batch
                    append_response = self.api_helper(
                        logger_msg=logger_msg,
                        url=URLS["V2_DESTINATION_PROFILE_VALUES"].format(
                            tenant_name, profile_id
                        ),
                        method="patch",
                        json=payload,
                        error_codes=["CTE_1059", "CTE_1059"],
                        message=f"Error occurred while {logger_msg}",
                        headers=headers,
                        verify=verify,
                        proxies=proxies,
                    )
                    if not append_response.get("id", None):
                        self.logger.error(
                            f"{self.log_prefix}: Error occurred "
                            f"while {logger_msg} "
                            "after excluding invalid indicators."
                        )
                        unshared_indicators.extend(batch)
                        continue
                elif (
                    append_response.status_code in [409]
                    and PENDING_CHANGES_DETECTED in response_text
                ):
                    log_msg = (
                        "Pending changes detected "
                        f"for profile {profile_name}."
                    )
                    if apply_pending_changes == "Yes":
                        self.logger.info(
                            f"{self.log_prefix}: {log_msg} "
                            "Applying pending changes and sharing indicators."
                        )
                        success, deploy_response = self._apply_pending_changes(
                            profile_id=profile_id,
                            tenant_name=tenant_name,
                            headers=headers,
                            verify=verify,
                            proxies=proxies,
                        )
                        if not success:
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: Error occurred "
                                    "while applying pending changes."
                                ),
                                details=str(deploy_response)
                            )
                            unshared_indicators.extend(batch)
                            continue

                        append_result = self.push_destination_profile_append(  # noqa
                            profile_id=profile_id,
                            profile_name=profile_name,
                            indicators=batch,
                            existing_values=existing_values,
                            headers=headers,
                            tenant_name=tenant_name,
                            verify=verify,
                            proxies=proxies,
                            apply_pending_changes="No",
                            is_retraction=is_retraction,
                        )
                        (
                            invalid_append,
                            ipv6_append,
                            unshared_from_append,
                            shared_from_append,
                            _,
                        ) = append_result
                        invalid_indicators.extend(invalid_append)
                        ipv6_iocs.extend(ipv6_append)
                        unshared_indicators.extend(unshared_from_append)
                        shared_indicators_append += shared_from_append
                        continue  # Skip the normal success counting below
                    else:
                        resolution = (
                            f"Ensure that the Destination Profile "
                            f"'{profile_name}' has no pending changes. "
                            f"To resolve this:\n"
                            f"1. Set 'Apply Pending Changes' to 'Yes' in the "
                            f"action configuration to automatically apply "
                            f"pending changes, OR\n"
                            f"2. Manually apply the pending changes for "
                            f"Destination Profile '{profile_name}' from the "
                            f"Netskope Tenant UI before sharing indicators."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {log_msg} "
                                "Skipping indicator sharing to "
                                f"Destination Profile '{profile_name}'."
                            ),
                            resolution=resolution,
                            details=response_text,
                        )
                        unshared_indicators.extend(batch)
                        continue
                elif append_response.status_code not in [200, 201]:
                    err_msg = f"Error occurred while {logger_msg}."
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=response_text,
                    )
                    unshared_indicators.extend(batch)
                    continue
                else:
                    handle_status_code(
                        append_response,
                        error_code="CTE_1060",
                        custom_message=f"Error occurred while {logger_msg}",
                        plugin=self.log_prefix,
                        log=True,
                    )
            except NetskopeThreatExchangeException:
                unshared_indicators.extend(batch)
                continue
            except Exception as err:
                error_message = f"Error occurred while {logger_msg}."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} "
                        f"Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                unshared_indicators.extend(batch)
                continue

            log_msg = ""
            if invalid_indicators:
                log_msg = (
                    f" Failed to {'retract' if is_retraction else 'share'} "
                    f"{len(invalid_indicators)} "
                    "indicators due to invalid value."
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully "
                f"{'retracted' if is_retraction else 'shared'} "
                f"{len(batch)} indicators to destination profile "
                f"'{profile_name}' in batch {batch_index}.{log_msg}"
            )
            shared_indicators_append += len(batch)

        return (
            invalid_indicators,
            ipv6_iocs,
            unshared_indicators,
            shared_indicators_append,
            existing_count,
        )

    def _apply_pending_changes(
        self,
        profile_id: str,
        tenant_name: str,
        headers: dict,
        verify: bool,
        proxies: dict,
    ) -> tuple[bool, dict]:
        """Apply pending changes to a destination profile.

        Args:
            profile_id (str): ID of the destination profile.

        Returns:
            bool: True if pending changes were applied successfully,\
                False otherwise.
            dict: Deploy changes response
        """
        logger_msg = (
            "applying pending changes"
        )
        payload = {
            "ids": [
                profile_id
            ]
        }
        deploy_response = {}
        try:
            deploy_response = self.api_helper(
                logger_msg=logger_msg,
                url=URLS["V2_DESTINATION_PROFILE_DEPLOY"].format(
                    tenant_name
                ),
                method="post",
                json=payload,
                error_codes=["CTE_1062", "CTE_1062"],
                message=f"Error occurred while {logger_msg}",
                headers=headers,
                verify=verify,
                proxies=proxies,
            )
            if deploy_response and isinstance(deploy_response, dict):
                resp_id = deploy_response.get("applied", [])
                if resp_id and len(resp_id) > 0 and resp_id[0] == profile_id:
                    return True, deploy_response
            return False, deploy_response
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while {logger_msg}. "
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            return False, deploy_response

    def _validate_destination_profile_indicator(
        self,
        indicator_value: str,
        match_type: str
    ) -> bool:
        """
        Validate destination profile indicators based on match type.

        Args:
            indicators: List of indicator values to validate
            match_type: Match type - "sensitive", "insensitive", or "regex"

        Returns:
            Tuple of (valid_indicators, invalid_indicators)
        """
        # For regex match type, accept all non-empty strings
        if match_type == "regex":
            return True

        # For exact match types, validate format
        if match_type not in ["sensitive", "insensitive"]:
            return True

        exact_match_pattern = re.compile(
            DESTINATION_PROFILE_EXACT_MATCH_PATTERN
        )

        # Check for schemes (not allowed)
        if (
            indicator_value.startswith('http://')
            or indicator_value.startswith('https://')
        ):
            return False

        # Check for port ranges (not allowed)
        if re.search(r':[0-9]+-[0-9]+', indicator_value):
            return False

        # Validate RANGE notation - start IP must be < end IP
        if indicator_value.startswith('RANGE:'):
            range_match = re.match(
                r'RANGE:((?:\d{1,3}\.){3}\d{1,3})-((?:\d{1,3}\.){3}\d{1,3})',  # noqa
                indicator_value
            )
            if range_match:
                start_ip = range_match.group(1)
                end_ip = range_match.group(2)
                try:
                    start_ip_obj = ipaddress.IPv4Address(start_ip)
                    end_ip_obj = ipaddress.IPv4Address(end_ip)
                    if start_ip_obj >= end_ip_obj:
                        return False
                except ValueError:
                    return False

        # Validate against pattern
        if not exact_match_pattern.match(indicator_value):
            return False

        return True

    def calculate_destination_profile_capacity(
        self,
        profiles: Dict[str, Dict],
        target_profile_name: str,
        match_type: str,
        indicators_count: int
    ) -> Tuple[int, Dict[str, int]]:
        """
        Calculate available capacity for destination profile sharing.

        Args:
            profiles: Dictionary of all destination profiles
            target_profile_name: Name of the profile to share to
            match_type: Type of profile (sensitive/insensitive/regex)
            indicators_count: Number of indicators to share

        Returns:
            Tuple of (max_shareable_count, usage_stats)
            - max_shareable_count: Maximum indicators that can be shared
            - usage_stats: Dictionary with current usage statistics
        """
        # Calculate current usage
        if match_type in ["sensitive", "insensitive"]:
            # Exact-type profile
            total_exact_usage = sum(
                profile.get("values_count", 0)
                for _, profile in profiles.items()
                if profile.get("type") in ["sensitive", "insensitive"]
            )

            target_profile_usage = profiles.get(
                target_profile_name, {}
            ).get("values_count", 0)

            # Calculate available capacity
            total_exact_available = (
                DESTINATION_PROFILE_EXACT_TOTAL_LIMIT - total_exact_usage
            )
            per_profile_available = (
                DESTINATION_PROFILE_EXACT_PER_PROFILE_LIMIT - target_profile_usage  # noqa
            )

            # Take minimum of both limits
            max_shareable = min(
                total_exact_available,
                per_profile_available,
                indicators_count
            )

            # Ensure non-negative
            max_shareable = max(0, max_shareable)

            usage_stats = {
                "total_exact_available": total_exact_available,
                "profile_available": per_profile_available,
            }

        else:
            # Regex-type profile
            total_regex_usage = sum(
                profile.get("values_count", 0)
                for _, profile in profiles.items()
                if profile.get("type") == "regex"
            )

            total_regex_available = (
                DESTINATION_PROFILE_REGEX_TOTAL_LIMIT - total_regex_usage
            )

            max_shareable = min(
                total_regex_available,
                indicators_count
            )

            # Ensure non-negative
            max_shareable = max(0, max_shareable)

            usage_stats = {
                "total_regex_available": total_regex_available,
            }

        return max_shareable, usage_stats

    def _extract_invalid_destination_values(
        self, response_json: dict, values: list[str]
    ) -> tuple[list[str], list[str]]:
        """Extract invalid and IPv6 values from API validation errors.

        Args:
            response_json (dict): API response containing validation errors.
            values (list[str]): List of values that were sent to the API.

        Returns:
            tuple[list[str], list[str]]: Tuple of (invalid_values,
                ipv6_iocs).
        """
        errors = response_json.get("validation_errors", [])
        values_len = len(values)
        is_valid_ipv6 = self.is_valid_ipv6

        invalid = []
        ipv6_iocs = []

        for err in errors:
            field = err.get("field")
            if not field:
                continue

            # Fast index extraction
            start = field.rfind("[")
            end = field.rfind("]")
            if start == -1 or end == -1 or end < start:
                continue

            try:
                idx = int(field[start + 1:end])
            except ValueError:
                continue

            if 0 <= idx < values_len:
                val = values[idx]
                invalid.append(val)

                if is_valid_ipv6(val):
                    ipv6_iocs.append(val)

        return invalid, ipv6_iocs

    def return_push_result(
        self,
        success: bool,
        message: str,
        failed_iocs: list = [],
    ) -> PushResult:
        """Return a PushResult object with optional failed IOCs.

        Args:
            success (bool): Whether the push operation was successful.
            message (str): Message describing the push result.
            failed_iocs (list): List of IOCs that failed to push.

        Returns:
            PushResult: PushResult object with success status, message,
                and optionally failed_iocs.
        """
        if failed_iocs and "failed_iocs" in PushResult.model_fields:
            return PushResult(
                success=success,
                message=message,
                failed_iocs=failed_iocs,
            )
        return PushResult(
            success=success,
            message=message,
        )

    def is_valid_ipv6(self, address: str) -> bool:
        """Validate if the given address is a valid IPv6 address.

        Args:
            address (str): Address string to validate.

        Returns:
            bool: True if valid IPv6 address, False otherwise.
        """
        try:
            ipaddress.IPv6Address(address)
            return True
        except Exception:
            return False

    def get_configuration_parameters(
        self, configuration: Dict
    ) -> Tuple[str, str, int, str, str]:
        """Extract configuration parameters from configuration dict.

        Args:
            configuration (Dict): Configuration dictionary containing
                plugin settings.

        Returns:
            Tuple[str, str, int, str, str]: Tuple containing
                (is_pull_required, threat_data_type, initial_range,
                enable_tagging, enable_retrohunt).
        """
        is_pull_required = configuration.get("is_pull_required")
        threat_data_type = configuration.get("threat_data_type")
        initial_range = configuration.get("days")
        enable_tagging = configuration.get("enable_tagging")
        enable_retrohunt = configuration.get("enable_retrohunt_and_fp")

        return (
            is_pull_required,
            threat_data_type,
            initial_range,
            enable_tagging,
            enable_retrohunt
        )
