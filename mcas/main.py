"""BSD 3-Clause License.

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

Microsoft Defender for Cloud Apps CTE Plugin.
"""

import re
import traceback
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from pydantic import ValidationError

from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.utils import TagUtils

from .utils.constants import (
    STATUS_TYPES,
    STATUS_LABELS,
    YES_NO_LABELS,
    VALIDATION_ERR_MSG,
    DISCOVERY_ENDPOINT,
    DOMAIN_REGEX,
    FQDN_REGEX,
    HOSTNAME_REGEX,
    MODULE_NAME,
    PAGE_SIZE,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RETRACTION,
)
from .utils.helper import MCASPluginException, MCASPluginHelper


class MicrosoftCASBPlugin(PluginBase):
    """Microsoft Defender for Cloud Apps CTE plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize the plugin.

        Args:
            name (str): Configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.mcas_helper = MCASPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version pulled from manifest.
        """
        try:
            manifest_json = MicrosoftCASBPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _validate_url(self, url: str) -> bool:
        """Validate URL using urlparse.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True if URL is valid, False otherwise.
        """
        if not url or not isinstance(url, str):
            return False
        try:
            parsed = urlparse(url.strip())
            return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""
        except Exception:
            return False

    def _get_indicator_type(self, value: str) -> IndicatorType:
        """Determine indicator type: FQDN, Domain, or Hostname.

        Args:
            value (str): Indicator value (original domain, before wildcard).

        Returns:
            IndicatorType: FQDN, DOMAIN, or HOSTNAME based on value structure.
        """
        value = value.strip()
        if re.fullmatch(FQDN_REGEX, value):
            return IndicatorType.FQDN
        if re.fullmatch(DOMAIN_REGEX, value):
            return IndicatorType.DOMAIN
        if re.fullmatch(HOSTNAME_REGEX, value):
            return getattr(IndicatorType, "HOSTNAME", IndicatorType.DOMAIN)
        return IndicatorType.DOMAIN

    def _create_tags(
        self, tags: List, enable_tagging: str
    ) -> Tuple[List, List]:
        """Create Tags.

        Args:
            tags (List): Tags list.
            enable_tagging (str): Enable tagging flag.

        Returns:
            tuple: Tuple of created tags and skipped tags.
        """
        if enable_tagging == "no":
            return [], []

        tag_utils = TagUtils()
        created_tags, skipped_tags = set(), set()

        for tag in tags:
            tag_name = tag.strip()
            try:
                if not tag_utils.exists(tag_name):
                    tag_utils.create_tag(TagIn(name=tag_name, color="#ED3347"))
                created_tags.add(tag_name)
            except ValueError:
                skipped_tags.add(tag_name)
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred while "
                        f"creating tag {tag_name}. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_tags.add(tag_name)

        return list(created_tags), list(skipped_tags)

    def get_dynamic_fields(self):
        """Get dynamic fields based on current configuration."""
        if self.configuration.get("add_wildcard_prefix") == "yes":
            return [
                {
                    "label": "Wildcard",
                    "key": "wildcard",
                    "type": "text",
                    "mandatory": True,
                    "default": "*",
                    "placeholder": "*",
                    "description": (
                        "Wildcard character to prepend to each IOC "
                        "when Add Wildcard Prefix to IOC(s) is set to Yes. "
                        "A dot (.) is automatically inserted between wildcard "
                        "character and the IOC."
                    ),
                }
            ]
        return []

    def pull(self) -> List[Indicator]:
        """Pull IOC(s) from Microsoft Defender for Cloud Apps.

        Returns:
            List[Indicator]: List of IOC(s).
        """
        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._pull()

            return wrapper(self)
        else:
            indicators = []
            for batch in self._pull():
                indicators.extend(batch)
            return indicators

    def _pull_indicators_for_status(
        self,
        status: str,
        url: str,
        headers: Dict,
        enable_tagging: str,
        add_wildcard_prefix: str = "no",
        wildcard: str = "*",
        is_retraction: bool = False,
        totals: Dict = None,
        exclude_domains: set = None,
        exclusion_only: bool = False,
    ):
        """Pull IOC(s) for a specific status.

        Args:
            status (str): Status type to pull IOC(s) for.
            url (str): Base URL for the API.
            headers (Dict): Headers for API requests.
            enable_tagging (str): Enable tagging flag.
            add_wildcard_prefix (str): Whether to prepend wildcard prefix.
            wildcard (str): Wildcard character(s) to prepend.
            is_retraction (bool): Is retraction call.
            totals (Dict): Mutable accumulator for cross-status type counts.
            exclude_domains (set): Mutable set of indicator values to skip.
                For non-allow statuses this set is written into (invalid
                indicator values are registered so allow can skip them without
                double-counting). For the allow status it is read-only.
            exclusion_only (bool): When True this status is fetched purely to
                populate the exclusion set for the Allow superset — its IOC
                values are returned as raw strings and NO log messages are
                emitted (the user did not select this status, so it should be
                invisible in the pull/retraction logs).

        Yields:
            List[Indicator] or Tuple[List[Indicator], Dict]: IOC(s) or
            tuple with checkpoint.
        """
        raw_mode = is_retraction or exclusion_only
        if not exclusion_only:
            self.logger.info(
                f"{self.log_prefix}: Pulling IOC(s) for "
                f"status '{status}' from {PLUGIN_NAME}."
            )
        api_status_type = STATUS_TYPES.get(status, "banned")
        skip = 0
        page = 1
        status_indicators = 0
        status_skipped = 0
        total_domain_count = 0
        total_fqdn_count = 0
        total_hostname_count = 0

        # Create tags once per status before pagination loop begins
        indicator_tags = []
        if not raw_mode and enable_tagging == "yes":
            created_tags, _ = self._create_tags(
                [status.title()], enable_tagging
            )
            indicator_tags = created_tags

        while True:
            params = {
                "type": api_status_type, "limit": PAGE_SIZE, "skip": skip
            }
            endpoint = f"{url}{DISCOVERY_ENDPOINT}"
            logger_msg = (
                f"pulling IOC(s) for status '{status}' in page {page}"
            )

            response = self.mcas_helper.api_helper(
                url=endpoint,
                method="GET",
                params=params,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=logger_msg,
                is_retraction=is_retraction,
            )

            response_data = response.get("data", [])
            page_indicators = set() if raw_mode else []
            indicator_skipped = 0

            for item in response_data:
                domain_list = item.get("domainList", [])
                app_name = item.get("name", "")

                for domain in domain_list:
                    try:
                        if not domain or not isinstance(domain, str):
                            indicator_skipped += 1
                            continue

                        domain = domain.strip()
                        if not domain:
                            indicator_skipped += 1
                            continue

                        indicator_value = (
                            f"{wildcard}.{domain}"
                            if add_wildcard_prefix == "yes"
                            else domain
                        )

                        # Check before the length guard so that invalid
                        # indicator values registered by prior non-allow pulls
                        # are skipped silently in allow (no double-count).
                        if (
                            exclude_domains is not None
                            and indicator_value in exclude_domains
                        ):
                            continue

                        if len(indicator_value) <= 3:
                            indicator_skipped += 1
                            if totals is not None:
                                totals["skipped"] += 1
                            # Register in the shared set so the allow pull
                            # skips this value without counting it again.
                            if exclude_domains is not None:
                                exclude_domains.add(indicator_value)
                            continue

                        if raw_mode:
                            page_indicators.add(indicator_value)
                        else:
                            comments = (
                                f"Application: {app_name}" if app_name else ""
                            )
                            indicator_type = self._get_indicator_type(domain)
                            indicator = Indicator(
                                value=indicator_value,
                                type=indicator_type,
                                comments=comments,
                                tags=indicator_tags,
                            )
                            page_indicators.append(indicator)
                            if indicator_type == IndicatorType.FQDN:
                                total_fqdn_count += 1
                                if totals is not None:
                                    totals["fqdn"] += 1
                            elif indicator_type == getattr(
                                IndicatorType, "HOSTNAME", None
                            ):
                                total_hostname_count += 1
                                if totals is not None:
                                    totals["hostname"] += 1
                            else:
                                total_domain_count += 1
                                if totals is not None:
                                    totals["domain"] += 1

                    except ValidationError as error:
                        indicator_skipped += 1
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Validation error "
                                f"occurred while creating IOC "
                                f"for domain {domain}. "
                                f"This record will be skipped. Error: {error}."
                            ),
                            details=str(traceback.format_exc()),
                        )
                    except Exception as error:
                        indicator_skipped += 1
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Unexpected error "
                                f"occurred while creating IOC "
                                f"for domain {domain}. "
                                f"This record will be skipped. Error: {error}."
                            ),
                            details=str(traceback.format_exc()),
                        )

            status_indicators += len(page_indicators)
            status_skipped += indicator_skipped

            # Yield IOC(s) per page
            if page_indicators:
                if not exclusion_only:
                    modified_logger = "modified " if is_retraction else ""
                    if is_retraction:
                        self.logger.info(
                            f"{self.log_prefix}: Successfully pulled "
                            f"{len(page_indicators)} {modified_logger}IOC(s) "
                            f"for status '{status}' from page {page} of "
                            f"{PLUGIN_NAME}. Total {modified_logger}IOC(s) "
                            f"pulled for this status: {status_indicators}."
                        )
                    else:
                        page_type_stats = ", ".join(
                            f"{label}: {count}"
                            for label, count in [
                                ("Domains", total_domain_count),
                                ("FQDNs", total_fqdn_count),
                                ("Hostnames", total_hostname_count),
                            ]
                            if count > 0
                        )
                        self.logger.info(
                            f"{self.log_prefix}: Successfully pulled "
                            f"{len(page_indicators)} IOC(s) for status "
                            f"'{status}' from page {page} of {PLUGIN_NAME}. "
                            f"Pull Stats - {page_type_stats}. "
                            f"Total IOC(s) pulled for this status: "
                            f"{status_indicators}."
                        )
                if (
                    not is_retraction
                    and not exclusion_only
                    and hasattr(self, "sub_checkpoint")
                ):
                    yield page_indicators, {}
                else:
                    yield page_indicators

            if len(response_data) < PAGE_SIZE:
                break
            skip += PAGE_SIZE
            page += 1

        if not is_retraction and not exclusion_only:
            skipped_msg = (
                f" and skipped {status_skipped} IOC(s) due to"
                f" invalid or unsupported IOC types"
                if status_skipped > 0
                else ""
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully pulled "
                f"{status_indicators} IOC(s){skipped_msg} for status "
                f"'{status}' from {PLUGIN_NAME}."
            )

    def _pull(self, is_retraction: bool = False):
        """Pull IOC(s) from Microsoft Defender for Cloud Apps.

        Args:
            is_retraction (bool): Is retraction call.

        Yields:
            List[Indicator]: List of IOC(s).
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        try:
            (
                url,
                token,
                selected_statuses,
                enable_tagging,
                add_wildcard_prefix,
                wildcard,
            ) = self.mcas_helper.get_config_params(self.configuration)

            self.logger.info(
                f"{self.log_prefix}: Pulling IOC(s) from {PLUGIN_NAME}."
            )
            headers = {"Authorization": f"Token {token}"}
            totals = {"domain": 0, "fqdn": 0, "hostname": 0, "skipped": 0}
            total_indicators = 0

            # Allow API returns a superset of ALL statuses. To get true-Allow
            # apps we must subtract every non-allow status from it.
            all_non_allow = [s for s in STATUS_TYPES.keys() if s != "allow"]
            selected_non_allow = set(
                s for s in selected_statuses if s != "allow"
            )
            has_allow = "allow" in selected_statuses
            exclude_domains: set = set()

            for status in all_non_allow:
                is_selected = status in selected_non_allow
                if is_selected:
                    for batch in self._pull_indicators_for_status(
                        status=status,
                        url=url,
                        headers=headers,
                        enable_tagging=enable_tagging,
                        add_wildcard_prefix=add_wildcard_prefix,
                        wildcard=wildcard,
                        is_retraction=is_retraction,
                        totals=(
                            totals if not is_retraction else None
                        ),
                        exclude_domains=(
                            exclude_domains
                            if not is_retraction
                            else None
                        ),
                    ):
                        indicators_in_batch = (
                            batch[0]
                            if isinstance(batch, tuple)
                            else batch
                        )
                        if is_retraction:
                            exclude_domains.update(indicators_in_batch)
                        else:
                            for ind in indicators_in_batch:
                                exclude_domains.add(ind.value)
                        total_indicators += len(indicators_in_batch)
                        yield batch
                elif has_allow:
                    # Not selected, but Allow is — pull silently (no logs,
                    # raw strings) only to populate exclude_domains so the
                    # Allow superset is de-duplicated.
                    for batch in self._pull_indicators_for_status(
                        status=status,
                        url=url,
                        headers=headers,
                        enable_tagging="no",
                        add_wildcard_prefix=add_wildcard_prefix,
                        wildcard=wildcard,
                        exclusion_only=True,
                    ):
                        exclude_domains.update(batch)

            if has_allow:
                for batch in self._pull_indicators_for_status(
                    status="allow",
                    url=url,
                    headers=headers,
                    enable_tagging=enable_tagging,
                    add_wildcard_prefix=add_wildcard_prefix,
                    wildcard=wildcard,
                    is_retraction=is_retraction,
                    totals=totals if not is_retraction else None,
                    exclude_domains=exclude_domains,
                ):
                    indicators_in_batch = (
                        batch[0]
                        if isinstance(batch, tuple)
                        else batch
                    )
                    total_indicators += len(indicators_in_batch)
                    yield batch

            if not is_retraction:
                total_skipped = totals.get("skipped", 0)
                skipped_msg = (
                    f" and skipped {total_skipped} IOC(s)"
                    if total_skipped > 0
                    else ""
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully pulled "
                    f"{total_indicators} IOC(s){skipped_msg} in total from "
                    f"{PLUGIN_NAME} across {len(selected_statuses)} selected "
                    f"statuses."
                )
        except MCASPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while pulling IOC(s) "
                f"from {PLUGIN_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(err_msg)

    def get_modified_indicators(self, indicators: List[List[Indicator]]):
        """Get modified IOC(s) for retraction.

        Args:
            indicators: List of IOC batches to check.

        Yields:
            Tuple[List[str], bool]: List of retracted IOC(s) and False.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        self.logger.info(
            f"{self.log_prefix}: Getting all modified IOC(s) "
            f"from {PLUGIN_NAME}."
        )
        try:
            url, token, selected_statuses, _, add_wildcard_prefix, wildcard = (
                self.mcas_helper.get_config_params(self.configuration)
            )

            headers = {"Authorization": f"Token {token}"}

            all_non_allow = [
                s for s in STATUS_TYPES.keys() if s != "allow"
            ]
            selected_non_allow = set(
                s for s in selected_statuses if s != "allow"
            )
            has_allow = "allow" in selected_statuses
            current_by_status: Dict[str, set] = {}
            exclude_domains: set = set()

            for status in all_non_allow:
                is_selected = status in selected_non_allow
                if is_selected:
                    status_set = set()
                    for batch in self._pull_indicators_for_status(
                        status=status,
                        url=url,
                        headers=headers,
                        enable_tagging="no",
                        add_wildcard_prefix=add_wildcard_prefix,
                        wildcard=wildcard,
                        is_retraction=True,
                    ):
                        status_set.update(batch)
                    exclude_domains.update(status_set)
                    current_by_status[status] = status_set
                elif has_allow:
                    # Not selected, but Allow is — pull silently only to
                    # de-duplicate the Allow superset. Not stored in
                    # current_by_status.
                    for batch in self._pull_indicators_for_status(
                        status=status,
                        url=url,
                        headers=headers,
                        enable_tagging="no",
                        add_wildcard_prefix=add_wildcard_prefix,
                        wildcard=wildcard,
                        exclusion_only=True,
                    ):
                        exclude_domains.update(batch)

            if has_allow:
                current_by_status["allow"] = set()
                for batch in self._pull_indicators_for_status(
                    status="allow",
                    url=url,
                    headers=headers,
                    enable_tagging="no",
                    add_wildcard_prefix=add_wildcard_prefix,
                    wildcard=wildcard,
                    is_retraction=True,
                    exclude_domains=exclude_domains,
                ):
                    current_by_status["allow"].update(batch)

            # Flat union used as fallback when a stored IOC carries
            # no status tag (e.g. tagging was disabled during its pull).
            current_all = (
                set().union(*current_by_status.values())
                if current_by_status
                else set()
            )

            # Map title-cased tag names back to status keys so we can look
            # up the original status from the stored IOC's tags.
            # e.g. "Unsanctioned" -> "unsanctioned"
            tag_to_status = {s.title(): s for s in selected_statuses}
            all_status_tags = {s.title() for s in STATUS_TYPES.keys()}

            # Yield retracted IOC(s) per source batch
            for source_batch in indicators:
                try:
                    retracted = []
                    for indicator in source_batch:
                        if not indicator:
                            continue
                        value = indicator.value

                        # Determine the status this IOC was originally
                        # pulled under by inspecting its stored tags.
                        original_status = None
                        has_unselected_status_tag = False
                        for tag in (getattr(indicator, "tags", None) or []):
                            tag_name = (
                                tag
                                if isinstance(tag, str)
                                else getattr(tag, "name", "")
                            )
                            if tag_name in tag_to_status:
                                original_status = tag_to_status[tag_name]
                                break
                            elif tag_name in all_status_tags:
                                # Known but deselected status tag —
                                # mark for forced retraction.
                                has_unselected_status_tag = True

                        if original_status:
                            # Status-aware: retract if no longer present
                            # under the IOC's original status.
                            if value not in current_by_status.get(
                                original_status, set()
                            ):
                                retracted.append(value)
                        elif has_unselected_status_tag:
                            # IOC was pulled under a status that is no longer
                            # selected — always retract regardless of allow
                            # overlap.
                            retracted.append(value)
                        else:
                            # No recognizable status tag (tagging was disabled
                            # during the original pull). Retract only if absent
                            # from all currently configured statuses.
                            if value not in current_all:
                                retracted.append(value)

                    self.logger.info(
                        f"{self.log_prefix}: {len(retracted)} IOC(s) "
                        f"will be marked as retracted from "
                        f"{len(source_batch)} total IOC(s) present in "
                        f"Cloud Exchange for {PLUGIN_NAME}."
                    )
                    if retracted:
                        yield retracted, False
                except MCASPluginException:
                    raise
                except Exception as exp:
                    err_msg = (
                        "Unexpected error occurred while performing "
                        f"retraction check for {PLUGIN_NAME}."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                        details=str(traceback.format_exc()),
                    )
                    raise MCASPluginException(err_msg)

        except MCASPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while performing retraction "
                f"check for {PLUGIN_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise MCASPluginException(err_msg)

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value,
        field_type: type,
        is_required: bool = False,
        allowed_values: List = None,
        is_password: bool = False,
        allowed_labels: Dict = None,
    ) -> ValidationResult:
        """Validate configuration parameter.

        Args:
            field_name (str): Name of the configuration field.
            field_value: Value of the configuration field.
            field_type (type): Expected type of the configuration field.
            is_required (bool): Whether the field is required.
            allowed_values (List): List of allowed values for the field.
            is_password (bool): Whether the field is a password field.
            allowed_labels (Dict): Mapping of values to UI labels for
                error messages.

        Returns:
            ValidationResult: Validation result or None if validation passes.
        """
        validation_err_msg = VALIDATION_ERR_MSG
        # Strip string values (except password fields)
        if (
            field_type is str and isinstance(field_value, str)
            and not is_password
        ):
            field_value = field_value.strip()
        # Check if required field is empty
        if is_required and not field_value:
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    f"Ensure that a valid {field_name} is provided in the "
                    "configuration parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        # Check type
        if field_value and not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid {field_name} provided in configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    f"Ensure that a valid {field_name} is provided in the "
                    "configuration parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        # Check allowed values for string fields
        if (
            allowed_values and field_type is str
            and field_value not in allowed_values
        ):
            err_msg = (
                f"Invalid {field_name} value provided in configuration "
                "parameters."
            )
            if allowed_labels:
                display_values = ", ".join(allowed_labels.values())
            else:
                display_values = ", ".join(allowed_values)
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    f"Ensure {field_name} is one of: {display_values}."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        # Check allowed values for list fields
        if allowed_values and field_type is list and field_value:
            if not all(item in allowed_values for item in field_value):
                err_msg = (
                    f"Invalid {field_name} value provided in configuration "
                    "parameters."
                )
                if allowed_labels:
                    display_values = ", ".join(allowed_labels.values())
                else:
                    display_values = ", ".join(allowed_values)
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg} "
                        f"{err_msg}"
                    ),
                    resolution=(
                        f"Ensure {field_name} values are from: "
                        f"{display_values}."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
        return None

    def _validate_credentials(self, configuration: Dict) -> ValidationResult:
        """Validate API credentials.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result.
        """
        try:
            url, token, selected_statuses, _, _, _ = (
                self.mcas_helper.get_config_params(configuration)
            )
            api_status_type = STATUS_TYPES.get(
                selected_statuses[0] if selected_statuses else "unsanctioned",
                "banned",
            )
            headers = {"Authorization": f"Token {token}"}
            params = {"type": api_status_type, "limit": 1}
            endpoint = f"{url}{DISCOVERY_ENDPOINT}"
            self.mcas_helper.api_helper(
                url=endpoint,
                method="GET",
                params=params,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg="validating credentials",
                is_validation=True,
            )
            logger_msg = (
                "Successfully validated "
                f"credentials for {PLUGIN_NAME} platform."
            )
            self.logger.debug(
                f"{self.log_prefix}: {logger_msg}"
            )
            return ValidationResult(
                success=True, message=logger_msg,
            )

        except MCASPluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details."
            )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the configuration.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result.
        """
        validation_err_msg = VALIDATION_ERR_MSG
        url, token, status, enable_tagging, add_wildcard_prefix, wildcard = (
            self.mcas_helper.get_config_params(configuration)
        )
        # Validate URL
        if url_validation := self._validate_configuration_parameters(
            field_name="URL",
            field_value=url,
            field_type=str,
            is_required=True,
        ):
            return url_validation
        # Additional URL format validation
        if not self._validate_url(url):
            err_msg = (
                "Invalid URL format provided in configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    "Ensure that a valid URL is provided in the format: "
                    "https://your-instance.portal.cloudappsecurity.com"
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        # Validate API Token
        if token_validation := self._validate_configuration_parameters(
            field_name="API Token",
            field_value=token,
            field_type=str,
            is_required=True,
            is_password=True,
        ):
            return token_validation
        # Validate Enable Tagging
        if tagging_validation := self._validate_configuration_parameters(
            field_name="Enable Tagging",
            field_value=enable_tagging,
            field_type=str,
            is_required=True,
            allowed_values=["yes", "no"],
            allowed_labels=YES_NO_LABELS,
        ):
            return tagging_validation
        # Validate Status
        if status_validation := self._validate_configuration_parameters(
            field_name="Status",
            field_value=status,
            field_type=list,
            is_required=True,
            allowed_values=list(STATUS_TYPES.keys()),
            allowed_labels=STATUS_LABELS,
        ):
            return status_validation
        # Validate Add Wildcard Prefix to IOCs
        if wildcard_prefix_validation := (
            self._validate_configuration_parameters(
                field_name="Add Wildcard Prefix to IOCs",
                field_value=add_wildcard_prefix,
                field_type=str,
                is_required=True,
                allowed_values=["yes", "no"],
                allowed_labels=YES_NO_LABELS,
            )
        ):
            return wildcard_prefix_validation
        # Validate Wildcard (required when Add Wildcard Prefix is enabled)
        if add_wildcard_prefix == "yes":
            if wildcard_validation := self._validate_configuration_parameters(
                field_name="Wildcard",
                field_value=wildcard,
                field_type=str,
                is_required=True,
            ):
                return wildcard_validation
        return self._validate_credentials(configuration)
