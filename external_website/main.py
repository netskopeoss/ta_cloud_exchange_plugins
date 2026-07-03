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

CTE Web Page IOC Scraper Plugin.
"""

import html
import json
import re
import traceback
import xml.etree.ElementTree as ET
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Dict, Iterator, List, Tuple, Union

from html.parser import HTMLParser
from urllib.parse import urlparse
from pydantic import ValidationError

from packaging import version
from netskope.common.api import __version__ as CE_VERSION

from netskope.integrations.cte.models import Indicator, IndicatorType

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)

from .utils.externalwebsite_constants import (
    DEFAULT_BATCH_SIZE,
    DOMAIN_REGEX,
    DOMAIN_REGEX_2,
    FILE_TYPES,
    FILE_TYPES_LABELS,
    IPV4_REGEX,
    IPV6_REGEX,
    MAXIMUM_CORE_VERSION,
    MD5_REGEX,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    RESPONSE_LIST_REGEX,
    RETRACTION,
    RETRACTION_IOC_TAG,
    SHA256_REGEX,
    THREAT_TYPES,
    THREAT_TYPES_LABELS,
    VALIDATION_ERROR_MESSAGE,
)

from .utils.externalwebsite_helper import (
    WebPageIOCScraperPluginException,
    WebPageIOCScraperPluginHelper,
)


class WebPageIOCScraperPlugin(PluginBase):
    """Web Page IOC Scraper Plugin class template implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize Plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.resolution_support = version.parse(CE_VERSION) > version.parse(
            MAXIMUM_CORE_VERSION
        )
        self._patch_logger_methods()
        self.web_page_ioc_scraper_helper = WebPageIOCScraperPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = WebPageIOCScraperPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _get_indicator_types(self, threat_types: List) -> Dict:
        """Return a mapping of Indicator Types, Based on the threat types to \
        pull configuration parameter And, Depending on Neskope CE Version.

        Args:
            - threat_types: A list of threat types to pull.
        Returns:
            - Dictionary mapping of Indicator Types to Netskope CE Supported
            Indicator Types.
        """
        indicator_types = {}

        if "md5" in threat_types:
            indicator_types["md5"] = IndicatorType.MD5

        if "sha256" in threat_types:
            indicator_types["sha256"] = IndicatorType.SHA256

        if "url" in threat_types:
            indicator_types["url"] = IndicatorType.URL

        if "domain" in threat_types:
            indicator_types["domain"] = getattr(
                IndicatorType, "DOMAIN", IndicatorType.URL
            )

        if "ipv4" in threat_types:
            indicator_types["ipv4"] = getattr(
                IndicatorType, "IPV4", IndicatorType.URL
            )

        if "ipv6" in threat_types:
            indicator_types["ipv6"] = getattr(
                IndicatorType, "IPV6", IndicatorType.URL
            )
        return indicator_types

    def pull(self) -> List[Indicator]:
        """Pull indicators from Web Page IOC Scraper Plugin."""
        url = self.configuration["url"].strip().strip("/")

        try:
            indicator_types = self._get_indicator_types(
                threat_types=self.configuration.get("type", "")
            )
            ioc_label = (
                "modified IOC(s)"
                if RETRACTION in self.log_prefix
                else "IOC(s)"
            )
            self.logger.info(
                f"{self.log_prefix}: Pulling {ioc_label} from {url}."
            )
            response = self.web_page_ioc_scraper_helper.api_helper(
                url=url,
                method="GET",
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=f"pulling {ioc_label}",
            )
            indicators, skipped_count, indicator_type_count = (
                self.extract_indicators(response, indicator_types)
            )

            pull_stats = ", ".join(
                [
                    f"{str(val)} {key.upper()}"
                    for key, val in indicator_type_count.items()
                ]
            )
            self.logger.debug(
                f"{self.log_prefix}: Pull Stats: {pull_stats} "
                f"{ioc_label} pulled."
            )
            total_fetched = sum(indicator_type_count.values())
            skipped_log = (
                f" Skipped {skipped_count} record(s) as IOC value might be"
                " duplicate, invalid or the IOC type does not match the"
                ' "Type of Threat data to pull" selected in the'
                " configuration parameter."
                if skipped_count > 0
                else ""
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully pulled {total_fetched}"
                f" {ioc_label} from '{url}'.{skipped_log}"
            )
            if hasattr(self, "sub_checkpoint"):

                def _indicator_generator():
                    for batch in self._yield_indicator_batches(indicators):
                        yield batch, None

                return _indicator_generator()

            return indicators

        except WebPageIOCScraperPluginException as exp:
            err_msg = "Error occurred while pulling IOC(s)."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {str(exp)}"),
                details=str(traceback.format_exc()),
            )
            raise exp
        except Exception as exp:
            err_msg = "Error occurred while pulling IOC(s)."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {str(exp)}"),
                details=str(traceback.format_exc()),
            )
            raise exp

    def get_modified_indicators(self, indicators):
        """Get all modified indicators status for retraction.

        Re-fetches the configured URL, extracts fresh IOC(s), and compares
        them against the previously stored indicators. Any stored indicator
        no longer present in the fresh response is yielded for retraction.
        """
        if RETRACTION not in self.log_prefix:
            self.log_prefix = f"{self.log_prefix} {RETRACTION}"
            self.web_page_ioc_scraper_helper.log_prefix = self.log_prefix

        url = self.configuration["url"].strip().strip("/")
        fresh_indicators = []
        try:
            fresh_iocs = self.pull()
            if isinstance(fresh_iocs, list):
                fresh_indicators = [ioc.value for ioc in fresh_iocs]
            else:
                for batch in fresh_iocs:
                    batch_indicators = batch
                    if isinstance(batch, tuple):
                        batch_indicators = batch[0]
                    fresh_indicators.extend(
                        [ioc.value for ioc in batch_indicators]
                    )
            self.logger.info(
                f"{self.log_prefix}: Successfully pulled "
                f"{len(fresh_indicators)} IOC(s) from '{url}' "
                f"as part of {RETRACTION_IOC_TAG} task."
            )
            if not fresh_indicators:
                self.logger.info(
                    f"{self.log_prefix}: No IOC(s) were returned from '{url}' "
                    f"during {RETRACTION_IOC_TAG} task. "
                    "All stored IOC(s) will be considered for retraction."
                )
        except WebPageIOCScraperPluginException as exp:
            err_msg = (
                f"Error occurred while pulling IOC(s) for "
                f"{RETRACTION_IOC_TAG} task."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                details=str(traceback.format_exc()),
            )
            raise exp
        except Exception as exp:
            err_msg = (
                f"Error occurred while pulling IOC(s) for "
                f"{RETRACTION_IOC_TAG} task."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                details=str(traceback.format_exc()),
            )
            raise exp

        stored_indicators = set()
        for indicator_list in indicators:
            for indicator in indicator_list:
                stored_indicators.add(indicator.value)

        if not stored_indicators:
            self.logger.info(
                f"{self.log_prefix}: No stored IOC(s) found in CE "
                f"for {RETRACTION_IOC_TAG} task."
            )

        retracted_indicators = list(stored_indicators - set(fresh_indicators))
        self.logger.info(
            f"{self.log_prefix}: Total {len(retracted_indicators)} "
            f"IOC(s) will be retracted as part of {RETRACTION_IOC_TAG} task "
            f"out of {len(stored_indicators)} total stored IOC(s)."
        )
        if not retracted_indicators:
            yield retracted_indicators, False
            return

        for batch in self._yield_value_batches(retracted_indicators):
            yield batch, False

    def extract_indicators(
        self, response, indicator_types: Dict
    ) -> Tuple[List[Indicator], int, Dict]:
        """Extract IOCs from response for all configured indicator types."""
        response = self._prepare_response_text(response)

        all_indicators_set = set()
        indicators = []
        skipped_count = 0
        indicator_type_count = {
            "sha256": 0,
            "md5": 0,
            "url": 0,
            "domain": 0,
            "ipv4": 0,
            "ipv6": 0,
        }

        if "sha256" in indicator_types:
            iocs, skipped = self._extract_sha256_iocs(
                response, indicator_types["sha256"], all_indicators_set
            )
            indicators.extend(iocs)
            indicator_type_count["sha256"] = len(iocs)
            skipped_count += skipped

        if "md5" in indicator_types:
            iocs, skipped = self._extract_md5_iocs(
                response, indicator_types["md5"], all_indicators_set
            )
            indicators.extend(iocs)
            indicator_type_count["md5"] = len(iocs)
            skipped_count += skipped

        if "ipv4" in indicator_types:
            iocs, skipped = self._extract_ipv4_iocs(
                response, indicator_types["ipv4"], all_indicators_set
            )
            indicators.extend(iocs)
            indicator_type_count["ipv4"] = len(iocs)
            skipped_count += skipped

        if "ipv6" in indicator_types:
            iocs, skipped = self._extract_ipv6_iocs(
                response, indicator_types["ipv6"], all_indicators_set
            )
            indicators.extend(iocs)
            indicator_type_count["ipv6"] = len(iocs)
            skipped_count += skipped

        if "url" in indicator_types or "domain" in indicator_types:
            url_iocs, domain_iocs, skipped = self._extract_url_domain_iocs(
                response, indicator_types, all_indicators_set
            )
            indicators.extend(url_iocs + domain_iocs)
            indicator_type_count["url"] = len(url_iocs)
            indicator_type_count["domain"] = len(domain_iocs)
            skipped_count += skipped

        return indicators, skipped_count, indicator_type_count

    def _extract_sha256_iocs(
        self,
        response: str,
        ioc_type,
        all_indicators_set: set,
    ) -> Tuple[List[Indicator], int]:
        """Extract SHA256 hash IOCs from response."""
        extracted, skipped = [], 0
        for value in re.findall(SHA256_REGEX, response):
            try:
                value = value.strip()
                if value not in all_indicators_set:
                    extracted.append(Indicator(value=value, type=ioc_type))
                    all_indicators_set.add(value)
            except (ValidationError, Exception):
                skipped += 1
        return extracted, skipped

    def _extract_md5_iocs(
        self,
        response: str,
        ioc_type,
        all_indicators_set: set,
    ) -> Tuple[List[Indicator], int]:
        """Extract MD5 hash IOCs from response."""
        extracted, skipped = [], 0
        for value in re.findall(MD5_REGEX, response):
            try:
                value = value.strip()
                if value not in all_indicators_set:
                    extracted.append(Indicator(value=value, type=ioc_type))
                    all_indicators_set.add(value)
            except (ValidationError, Exception):
                skipped += 1
        return extracted, skipped

    def _extract_ipv4_iocs(
        self,
        response: str,
        ioc_type,
        all_indicators_set: set,
    ) -> Tuple[List[Indicator], int]:
        """Extract IPv4 address IOCs from response."""
        extracted, skipped = [], 0
        for value in re.findall(IPV4_REGEX, response):
            try:
                value = value.strip().strip("/")
                if isinstance(ip_address(value), IPv4Address) and value not in all_indicators_set:  # noqa: E501
                    extracted.append(Indicator(value=value, type=ioc_type))
                    all_indicators_set.add(value)
            except (ValidationError, Exception):
                skipped += 1
        return extracted, skipped

    def _extract_ipv6_iocs(
        self,
        response: str,
        ioc_type,
        all_indicators_set: set,
    ) -> Tuple[List[Indicator], int]:
        """Extract IPv6 address IOCs from response."""
        extracted, skipped = [], 0
        pattern = re.compile(IPV6_REGEX, re.VERBOSE | re.MULTILINE)
        ipv6_list = [
            match[0]
            for token in re.findall(RESPONSE_LIST_REGEX, str(response))
            for match in re.findall(pattern, token)
        ]
        for value in ipv6_list:
            try:
                value = value.strip().strip("/")
                if isinstance(ip_address(value), IPv6Address) and value not in all_indicators_set:  # noqa: E501
                    extracted.append(Indicator(value=value, type=ioc_type))
                    all_indicators_set.add(value)
            except (ValidationError, Exception):
                skipped += 1
        return extracted, skipped

    def _extract_url_domain_iocs(
        self,
        response: str,
        indicator_types: Dict,
        all_indicators_set: set,
    ) -> Tuple[List[Indicator], List[Indicator], int]:
        """Extract URL and Domain IOCs from response."""
        extract_domains_setting = self.configuration.get(
            "extract_domains", "yes"
        )
        has_url = "url" in indicator_types
        has_domain = "domain" in indicator_types
        should_extract_domains = has_domain or (
            has_url and extract_domains_setting == "yes"
        )
        add_full_urls = has_url and extract_domains_setting == "no"
        domain_type = getattr(IndicatorType, "DOMAIN", IndicatorType.URL)
        url_indicators, domain_indicators = [], []
        skipped_count = 0

        for indicator in re.findall(RESPONSE_LIST_REGEX, response):
            try:
                try:
                    parse_result = urlparse(indicator)
                except Exception as e:
                    err_msg = f"Error while parsing IOC {indicator}."
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {e}",
                        details=traceback.format_exc(),
                    )
                    if indicator not in all_indicators_set:
                        all_indicators_set.add(indicator)
                        skipped_count += 1
                    continue

                netloc = parse_result.netloc.strip()
                fragment = parse_result.fragment.strip()
                path = parse_result.path.strip()

                if should_extract_domains:
                    if netloc and netloc not in all_indicators_set:
                        domain_indicators.append(
                            Indicator(value=netloc, type=domain_type)
                        )
                        all_indicators_set.add(netloc)
                    else:
                        extracted_domain = re.findall(DOMAIN_REGEX, path)
                        if not extracted_domain:
                            extracted_domain = re.findall(DOMAIN_REGEX_2, path)
                        if (
                            extracted_domain
                            and extracted_domain[0] != fragment
                            and extracted_domain[0] not in all_indicators_set
                        ):
                            domain_indicators.append(
                                Indicator(
                                    value=extracted_domain[0],
                                    type=domain_type,
                                )
                            )
                            all_indicators_set.add(extracted_domain[0])
                        elif indicator not in all_indicators_set:
                            if not add_full_urls:
                                skipped_count += 1
                                all_indicators_set.add(indicator)

                if add_full_urls and indicator not in all_indicators_set:
                    url_indicators.append(
                        Indicator(value=indicator, type=IndicatorType.URL)
                    )
                    all_indicators_set.add(indicator)

            except Exception as e:
                err_msg = f"Error while parsing IOC {indicator}."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {e}",
                    details=traceback.format_exc(),
                )
                if has_url and indicator not in all_indicators_set:
                    url_indicators.append(
                        Indicator(value=indicator, type=IndicatorType.URL)
                    )
                    all_indicators_set.add(indicator)
                elif indicator not in all_indicators_set:
                    skipped_count += 1
                    all_indicators_set.add(indicator)
                continue

        return url_indicators, domain_indicators, skipped_count

    def _patch_logger_methods(self):
        """Patch logger.error to accept resolution for supported
        CE versions."""

        original_error = self.logger.error

        def patched_error(
            message=None, details=None, resolution=None, **kwargs
        ):
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self.resolution_support:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        self.logger.error = patched_error

    def _prepare_response_text(self, response):
        """Normalize API response into plain text based on the
        configured file_type."""
        file_type = self.configuration.get("file_type", "plain_text")

        if isinstance(response, (bytes, bytearray)):
            response = response.decode("utf-8", errors="ignore")

        if not isinstance(response, str):
            response = str(response)

        if file_type == "json":
            try:
                json_payload = json.loads(response.strip())
            except (ValueError, TypeError):
                json_payload = (
                    response if isinstance(response, (dict, list)) else None
                )
            if json_payload is not None:
                flattened_values = self._flatten_json_values(json_payload)
                response = "\n".join(flattened_values)

        elif file_type == "xml":
            try:
                root = ET.fromstring(response.strip())
                texts: List[str] = []
                for elem in root.iter():
                    if elem.text and elem.text.strip():
                        texts.append(elem.text.strip())
                response = "\n".join(texts)
            except ET.ParseError:
                pass

        elif file_type == "html":

            class _HTMLValueExtractor(HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.values: List[str] = []

                def handle_data(self, data):
                    value = html.unescape(data).strip()
                    if value:
                        self.values.append(value)

            parser = _HTMLValueExtractor()
            parser.feed(response)
            response = "\n".join(parser.values)
        return response

    def _flatten_json_values(self, payload) -> List[str]:
        """Recursively extract only string values from a JSON payload
        (int/float skipped)."""
        flattened_values: List[str] = []
        if isinstance(payload, dict):
            for value in payload.values():
                flattened_values.extend(self._flatten_json_values(value))
        elif isinstance(payload, list):
            for item in payload:
                flattened_values.extend(self._flatten_json_values(item))
        elif isinstance(payload, str):
            value = payload.strip()
            if value:
                flattened_values.append(value)
        return flattened_values

    def is_url(self, url: str) -> bool:
        """Validate URL.

        Args:
            url (str): URL for validation.
        Returns:
            bool: True if URL is valid else False
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except (ValueError, Exception):
            return False

    def _validate_url(self, url, file_type="plain_text"):
        """Validate URL connectivity and verify the response format
        in one call."""
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating URL provided in "
                "configuration parameters."
            )
            response = self.web_page_ioc_scraper_helper.api_helper(
                url=url,
                method="GET",
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=f"verifying the connectivity with {url}",
                is_validation=True,
            )

            if file_type != "plain_text":
                if isinstance(response, (bytes, bytearray)):
                    response = response.decode("utf-8", errors="ignore")
                if not isinstance(response, str):
                    response = str(response)
                raw = response.strip()

                if file_type == "json":
                    try:
                        json.loads(raw)
                    except (ValueError, TypeError):
                        err_msg = (
                            "File Type is set to 'JSON' but the response "
                            "is not valid JSON. "
                            "Please verify the URL or change the File Type."
                        )
                        self.logger.error(
                            f"{self.log_prefix}: {err_msg}",
                            resolution=(
                                "Ensure that the feed returns JSON content "
                                "or select the appropriate File Type."
                            ),
                        )
                        return ValidationResult(success=False, message=err_msg)

                elif file_type == "xml":
                    err_msg = (
                        "File Type is set to 'XML' but the response "
                        "is not valid XML. "
                        "Please verify the URL or change the File Type."
                    )
                    resolution = (
                        "Ensure that the feed returns XML content "
                        "or select the appropriate File Type."
                    )
                    try:
                        ET.fromstring(raw)
                        html_pattern = re.search(
                            r"<!DOCTYPE\s+html|<(?:html|head|body|div|p|br"
                            r"|span|table|tr|td|script|meta)[\s>\/]",
                            raw[:2000],
                            re.IGNORECASE,
                        )
                        if html_pattern:
                            self.logger.error(
                                f"{self.log_prefix}: {err_msg}",
                                resolution=resolution
                            )
                            return ValidationResult(
                                success=False, message=err_msg
                            )
                    except ET.ParseError:
                        self.logger.error(
                            f"{self.log_prefix}: {err_msg}",
                            resolution=resolution,
                        )
                        return ValidationResult(success=False, message=err_msg)

                elif file_type == "html":
                    has_html = re.search(
                        r"<!DOCTYPE\s+html"
                        r"|<(?:html|head|body|div|p|br|span|table"
                        r"|tr|td|th|ul|ol|li|h[1-6]|script|style"
                        r"|meta|form|input|a\b|img\b)[\s>\/]",
                        raw,
                        re.IGNORECASE,
                    )
                    if not has_html:
                        err_msg = (
                            "File Type is set to 'HTML' but the response "
                            "does not appear to contain HTML markup. "
                            "Please verify the URL or change the File Type."
                        )
                        self.logger.error(
                            f"{self.log_prefix}: {err_msg}",
                            resolution=(
                                "Ensure that the feed returns HTML content "
                                "or select the appropriate File Type."
                            ),
                        )
                        return ValidationResult(success=False, message=err_msg)

            validation_msg = (
                f"Validation successful for {MODULE_NAME} "
                f"{self.plugin_name} Plugin."
            )
            self.logger.debug(f"{self.log_prefix}: {validation_msg}")
            return ValidationResult(
                success=True,
                message=validation_msg,
            )
        except WebPageIOCScraperPluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            validation_err = "Validation error occurred."
            err_msg = f"{validation_err} Check logs for more details."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=err_msg)

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        is_required: bool = True,
        allowed_values: list = None,
        display_values: list = None,
        validation_err_msg: str = VALIDATION_ERROR_MESSAGE,
        required_field_message: str = None,
    ) -> Union[ValidationResult, None]:
        """
        Validate the given configuration field value.

        Args:
            field_name (str): Name of the configuration field.
            field_value (str, List, bool, int): Value of the configuration
                field.
            field_type (type): Expected type of the configuration field.
            allowed_values (Dict, optional): Dictionary of allowed values for
                the configuration field. Defaults to None.
            custom_validation_func (Callable, optional): Custom validation
                function to be applied. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.
            validation_err_msg (str, optional): Error message to be logged in
                case of validation failure. Defaults to "Validation error
                occurred. ".

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """

        validation_err = validation_err_msg
        display_field_name = field_name

        def _log_and_return(
            message: str, resolution: str = None
        ) -> ValidationResult:
            self.logger.error(
                f"{self.log_prefix}: {validation_err} {message}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=message)

        value = field_value

        if isinstance(value, str):
            value = value.strip()

        if is_required:
            missing = value is None
            if isinstance(value, str):
                missing = not value
            elif isinstance(value, list):
                missing = len(value) == 0
            if missing:
                err_msg = (
                    required_field_message
                    or f"{display_field_name} is a required "
                    "configuration parameter."
                )
                resolution = (
                    f"Ensure that {display_field_name} is provided "
                    "in the configuration parameters."
                )
                return _log_and_return(err_msg, resolution)

        if value is not None and not isinstance(value, field_type):
            err_msg = f"Invalid value for {display_field_name} provided."
            resolution = (
                f"Ensure that {display_field_name} value matches "
                f"type {field_type.__name__}."
            )
            return _log_and_return(err_msg, resolution)

        if allowed_values and value is not None:
            labels = display_values or allowed_values
            if isinstance(value, list):
                invalid_values = [
                    val for val in value if val not in allowed_values
                ]
                if invalid_values:
                    err_msg = (
                        f"Invalid value for {display_field_name} provided."
                        f" Allowed values are {', '.join(map(str, labels))}."
                    )
                    resolution = (
                        f"Ensure that the value for "
                        f"{display_field_name} is one of: "
                        f"{', '.join(map(str, labels))}."
                    )
                    return _log_and_return(err_msg, resolution)
            else:
                if value not in allowed_values:
                    err_msg = (
                        f"Invalid value for {display_field_name} provided."
                        f" Allowed values are {', '.join(map(str, labels))}."
                    )
                    resolution = (
                        f"Ensure that the value for "
                        f"{display_field_name} is one of: "
                        f"{', '.join(map(str, labels))}."
                    )
                    return _log_and_return(err_msg, resolution)

        return None

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters."""

        url, threat_types, extract_domains, file_type = (
            self.web_page_ioc_scraper_helper.get_config_params(
                configuration,
                ["url", "threat_types", "extract_domains", "file_type"],
            )
        )

        if url_validation := self._validate_configuration_parameters(
            field_name="Website URL",
            field_value=url,
            field_type=str,
            required_field_message=(
                "Website URL is a required configuration parameter."
            ),
        ):
            return url_validation

        if threat_type_validation := self._validate_configuration_parameters(
            field_name="Type of Threat data to pull",
            field_value=threat_types,
            field_type=list,
            allowed_values=THREAT_TYPES,
            display_values=THREAT_TYPES_LABELS,
            required_field_message=(
                "Type of Threat data to pull is a required "
                "configuration parameter."
            ),
        ):
            return threat_type_validation

        if file_type_validation := self._validate_configuration_parameters(
            field_name="File Type",
            field_value=file_type,
            field_type=str,
            allowed_values=FILE_TYPES,
            display_values=FILE_TYPES_LABELS,
            required_field_message=(
                "File Type is a required configuration parameter."
            ),
        ):
            return file_type_validation

        if extract_domains_validation := self._validate_configuration_parameters(  # noqa: E501
            field_name="Extract Domains from URL",
            field_value=extract_domains,
            field_type=str,
            allowed_values=["yes", "no"],
            required_field_message=(
                "Extract Domains from URL is a required "
                "configuration parameter."
            ),
        ):
            return extract_domains_validation

        if not self.is_url(url):
            err_msg = (
                "Invalid website URL provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} {err_msg}",
                resolution="Ensure that the Website URL is valid.",
            )
            return ValidationResult(success=False, message=err_msg)

        return self._validate_url(url, file_type)

    def _yield_indicator_batches(
        self, indicators: List[Indicator], batch_size: int = None
    ) -> Iterator[List[Indicator]]:
        """Yield indicators in fixed-size batches."""

        if batch_size is None:
            batch_size = DEFAULT_BATCH_SIZE

        total = len(indicators)
        for start_index in range(0, total, batch_size):
            yield indicators[start_index: start_index + batch_size]

    def _yield_value_batches(
        self, values: List[str], batch_size: int = None
    ) -> Iterator[List[str]]:
        """Yield list values (e.g., retractions) in fixed-size batches."""

        if batch_size is None:
            batch_size = DEFAULT_BATCH_SIZE

        total = len(values)
        for start_index in range(0, total, batch_size):
            batch = values[start_index: start_index + batch_size]
            yield batch
