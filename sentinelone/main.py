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

SentinelOne CTE Plugin implementation to push and pull the data from
SentinelOne Platform.
"""

import ast
import json
import traceback
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Set, Tuple, Union
from urllib.parse import urlparse

from requests import Response

from netskope.common.api import __version__ as CE_VERSION
from netskope.integrations.cte.models import Indicator
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
from netskope.integrations.cte.models.tags import TagIn
from packaging import version

from .utils.constants import (
    ANALYST_VERDICT_OPTIONS,
    API_VERSION,
    DATE_FORMAT,
    ENABLE_TAGGING_OPTIONS,
    INTEGER_THRESHOLD,
    MAXIMUM_CE_VERSION,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PREFIX_IOC_SOURCE,
    PULL_PAGE_SIZE,
    PUSH_DATE_FORMAT,
    PUSH_PAGE_SIZE,
    RETRACTION,
    USER_TYPE_OPTIONS,
)
from .utils.helper import SentinelOnePluginException, SentinelOnePluginHelper


class SentinelOnePlugin(PluginBase):
    """The SentinelOne cte plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """SentinelOne plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        # Flag to check if CE version is more than v5.1.2
        self._is_ce_post_v512 = self._check_ce_version()
        # Method to decide which logger to use with or without
        # resolutions based on the CE version
        self._patch_error_logger()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.sentinelone_helper = SentinelOnePluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = SentinelOnePlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _check_ce_version(self) -> bool:
        """Check if CE version is greater than v5.1.2.

        Returns:
            bool: True if CE version is greater than v5.1.2, False otherwise.
        """
        return version.parse(CE_VERSION) > version.parse(MAXIMUM_CE_VERSION)

    def _patch_error_logger(self):
        """Monkey patch logger methods to handle resolution parameter
        compatibility.
        """
        # Store original methods
        original_error = self.logger.error

        def patched_error(
            message=None,
            details=None,
            resolution=None,
            **kwargs,
        ):
            """Patched error method that handles resolution compatibility."""
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self._is_ce_post_v512:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        # Replace logger methods with patched versions
        self.logger.error = patched_error

    def _get_site_id(
        self,
        name: str,
        url: str = None,
        token: str = None,
        is_validate: bool = False,
        is_retraction: bool = False,
    ) -> str:
        """Get Site ID.

        Args:
            name (str): Site Name.
            url (str, optional): URL of SentinelOne. Defaults to None.
            token (str, optional): API Token. Defaults to None.
            is_validate (bool, optional): Is this validate call?
              Defaults to False.
            is_retraction (bool, optional): Is this an retraction call?
              Defaults to False.

        Returns:
            str: Site ID.
        """
        resp_json = self.sentinelone_helper.api_helper(
            method="GET",
            url=f"{url}{API_VERSION}/sites",
            params={"name": name},
            headers=self.sentinelone_helper.get_headers(api_token=token),
            is_validation=is_validate,
            logger_msg=f'getting site id for site "{name}"',
            proxies=self.proxy,
            verify=self.ssl_validation,
            is_retraction=is_retraction,
        )
        try:
            return (
                resp_json.get("data", {}).get("sites", [])[0].get("id", None)
            )
        except Exception:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Site {name} does not exist"
                    f" on {PLATFORM_NAME}."
                ),
                details=str(resp_json),
            )
            return None

    def _str_to_datetime(self, string: str) -> datetime:
        """Convert ISO formatted string to datetime object.

        Args:
            string (str): ISO formatted string.

        Returns:
            datetime: Converted datetime object.
        """
        try:
            return datetime.strptime(string.replace(".", ""), DATE_FORMAT)
        except Exception:
            return datetime.now()

    def pull(self) -> List[Indicator]:
        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._pull()

            return wrapper(self)
        else:
            indicators = []
            for batch, _ in self._pull():
                indicators.extend(batch)
            self.logger.info(
                f"Successfully fetched {len(indicators)} indicator(s) "
                f"from {PLATFORM_NAME}."
            )
            return indicators

    def _create_tags(
        self, tags: List, enable_tagging: str
    ) -> Tuple[List, List]:
        """Create Tags.

        Args:
            tags (List): Tags list from API Response.

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
                        f"{self.log_prefix}: Unexpected error occurred"
                        f" while creating tag {tag_name}. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_tags.add(tag_name)

        return list(created_tags), list(skipped_tags)

    def _create_ioc_comment(self, alert: Dict) -> str:
        classification = alert.get("classification", "")
        detection_engine = ", ".join(alert.get("engines", []))
        confidence_level = alert.get("confidenceLevel", "")
        comment = (
            f"Classification: {classification} | Detection Engine:"
            f" {detection_engine} | Confidence Level: {confidence_level}"
        )
        return comment

    def _create_indicators(
        self, ioc_type: str, alert: Dict, url: str, enable_tagging: str
    ) -> Indicator:
        """Create indicators.

        Args:
            ioc_type (str): IOC Type.
            alert (Dict): Alert Dictionary.
            url (str): URL.
            enable_tagging (str): Enable Tagging.

        Returns:
            Indicator: Create indicator.
        """
        threatInfo = alert.get("threatInfo", {})
        if ioc_type == "sha256":
            ioc_value = threatInfo.get("sha256")
        elif ioc_type == "md5":
            ioc_value = threatInfo.get("md5")

        alert_id = alert.get("id", "")
        last_seen = self._str_to_datetime(threatInfo.get("updatedAt", ""))
        analyst_verdict = threatInfo.get("analystVerdictDescription")
        created_tags, skipped_tags = [], []
        if analyst_verdict:
            created_tags, skipped_tags = self._create_tags(
                tags=[analyst_verdict], enable_tagging=enable_tagging
            )
        return (
            Indicator(
                value=ioc_value,
                type=ioc_type,
                comments=self._create_ioc_comment(threatInfo),
                firstSeen=self._str_to_datetime(
                    threatInfo.get("createdAt", "")
                ),
                lastSeen=last_seen,
                extendedInformation=(
                    f"{url}/analyze/threats/{alert_id}/overview"
                ),
                tags=created_tags,
            ),
            f"{last_seen.isoformat()}Z",
        )

    def _pull(self, is_retraction: bool = False, retraction_time: str = ""):
        """Pull indicators from SentinelOne.

        Args:
            is_retraction (bool, optional): Is this retraction call?
                Defaults to False.
            retraction_time (str, optional): Retraction Time. Defaults to
                empty string.

        Yields:
            Tuple|List: Tuple of indicator list and checkpoint or only
                indicator list.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}] "
        end_time = datetime.now()
        (
            url,
            token,
            site_name,
            user_type,
            analyst_verdict,
            _,
            enable_tagging,
            initial_range,
        ) = self.sentinelone_helper.get_config_params(self.configuration)
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if is_retraction and retraction_time:
            start_time = retraction_time
        elif sub_checkpoint:
            start_time = sub_checkpoint.get("checkpoint")
        elif not self.last_run_at:
            start_time = datetime.now() - timedelta(
                days=int(initial_range)
            )
            start_time = f"{start_time.isoformat()}Z"
        else:
            start_time = self.last_run_at
            start_time = f"{start_time.isoformat()}Z"

        self.logger.info(
            f"{self.log_prefix}: Pulling indicators from checkpoint: "
            f"{str(start_time)}"
        )
        params = {
            "updatedAt__gte": start_time,
            "updatedAt__lte": f"{end_time.isoformat()}Z",
            "limit": PULL_PAGE_SIZE,
        }

        if user_type == "global":
            params["tenant"] = True
        if analyst_verdict:
            params["analystVerdicts"] = ','.join(analyst_verdict)

        cursor = None
        if site_name:
            site_id = self._get_site_id(
                name=site_name,
                url=url,
                token=token,
                is_retraction=is_retraction,
            )
            if site_id is None:
                err_msg = (
                    f"Site {site_name} does not exist on {PLATFORM_NAME}."
                    f" Validate Site Name provided in configuration "
                    "parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure Site Name provided in configuration "
                        "parameters is correct."
                    )
                )
                raise SentinelOnePluginException(err_msg)
            params["siteIds"] = site_id
        api_endpoint = f"{url}{API_VERSION}/threats"
        headers = self.sentinelone_helper.get_headers(api_token=token)
        page = 1
        checkpoint = start_time
        skip_count = 0
        fail_count = 0
        total_ioc_count = 0
        try:
            while True:
                page_indicators = set() if is_retraction else []
                ioc_counts = {"sha256": 0, "md5": 0}
                if cursor:
                    params["cursor"] = cursor
                resp_json = self.sentinelone_helper.api_helper(
                    method="GET",
                    url=api_endpoint,
                    params=params,
                    headers=headers,
                    logger_msg=f"pulling threats for page {page}",
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    is_retraction=is_retraction,
                )
                for alert in resp_json.get("data", []):
                    threatInfo = alert.get("threatInfo", {})
                    if not (threatInfo.get("sha256") or threatInfo.get("md5")):
                        skip_count += 1
                        continue
                    if threatInfo.get("sha256"):
                        try:
                            if is_retraction:
                                page_indicators.add(threatInfo.get("sha256"))
                            else:
                                sha256_indicator, checkpoint = (
                                    self._create_indicators(
                                        "sha256", alert, url, enable_tagging
                                    )
                                )
                                page_indicators.append(sha256_indicator)
                            ioc_counts["sha256"] += 1
                        except Exception as err:
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: Error occurred while "
                                    f"fetching indicators from threat with id "
                                    f"{alert.get('id','NA')}. Hence skipping "
                                    f"{threatInfo.get('sha256')}. Error: {err}"
                                ),
                                details=traceback.format_exc(),
                            )
                            fail_count += 1
                    if threatInfo.get("md5"):
                        try:
                            if is_retraction:
                                page_indicators.add(threatInfo.get("md5"))
                            else:
                                md5_indicator, checkpoint = (
                                    self._create_indicators(
                                        "md5", alert, url, enable_tagging
                                    )
                                )
                                page_indicators.append(md5_indicator)
                            ioc_counts["md5"] += 1
                        except Exception as err:
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: Error occurred while "
                                    f"fetching indicators from threat with id "
                                    f"{alert.get('id', 'NA')}. Hence skipping "
                                    f"{threatInfo.get('md5')}. Error: {err}"
                                ),
                                details=traceback.format_exc(),
                            )
                            fail_count += 1
                total_ioc_count += len(page_indicators)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{len(page_indicators)} indicator(s) in page {page}. Pull"
                    f" Stats: SHA256: {ioc_counts['sha256']}, MD5: "
                    f"{ioc_counts['md5']}. Skipped: {skip_count}. Failed: "
                    f"{fail_count}. Total indicator(s) fetched:"
                    f" {total_ioc_count}."
                )
                if hasattr(self, "sub_checkpoint") and not is_retraction:
                    yield page_indicators, {"checkpoint": checkpoint}
                else:
                    yield page_indicators
                cursor = resp_json.get("pagination", {}).get("nextCursor")
                if cursor is None:
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched "
                        f"{total_ioc_count} indicator(s) from {PLATFORM_NAME}."
                    )
                    break

                page += 1

        except SentinelOnePluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while pulling"
                f" indicators from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise SentinelOnePluginException(err_msg)

    def divide_in_chunks(self, indicators: List, chunk_size: int):
        """Return Fixed size chunks from list.

        Args:
            indicators (List): Indicators list
            chunk_size (int): Chunk size

        Yields:
            List: Indicators chunk list.
        """
        for i in range(0, len(indicators), chunk_size):
            yield indicators[i : i + chunk_size]  # noqa

    def push(
        self,
        indicators: List[Indicator],
        action_dict: Dict,
        source: str = None,
        business_rule: str = None,
        plugin_name: str = None,
    ) -> PushResult:
        """Push indicators to the SentinelOne.

        Args:
            indicators (List[Indicator]): List of Indicators
            action_dict (dict): Action dictionary
            source (str): Source configuration name.
            business_rule (str): Business rule name.
            plugin_name (str): Source plugin name.

        Returns:
            PushResult: return PushResult with success and message parameters.
        """
        self.logger.info(
            f"{self.log_prefix}: Sharing indicators to {PLATFORM_NAME}."
        )
        if action_dict["value"] != "create_iocs":
            err_msg = (
                "Invalid action provided in action "
                "parameters. Valid action is: Create IoCs."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return PushResult(
                success=False,
                message=err_msg,
            )

        indicators_data = []
        url, token, _, user_type, *_ = (
            self.sentinelone_helper.get_config_params(self.configuration)
        )
        headers = self.sentinelone_helper.get_headers(
            api_token=token, include_content_type=True
        )
        url = f"{url}/{API_VERSION}/threat-intelligence/iocs"

        # Threat IoCs
        self.logger.info(
            f"{self.log_prefix}: Preparing payload for indicators"
            f" to send to {PLATFORM_NAME}."
        )
        ioc_source = f"{PREFIX_IOC_SOURCE}"
        if plugin_name:
            ioc_source = ioc_source + " | " + plugin_name
        for indicator in indicators:
            ioc_type = indicator.type
            if ioc_type in ["sha256", "md5", "url", "ipv4", "ipv6"]:
                ioc_type = ioc_type.upper()
            else:
                ioc_type = "DNS"
            indicators_data.append(
                {
                    "value": indicator.value,
                    "type": ioc_type,
                    "source": ioc_source,
                    "externalId": indicator.value,
                    "method": "EQUALS",
                    "creationTime": indicator.firstSeen.strftime(
                        PUSH_DATE_FORMAT,
                    ),
                    "validUntil": (
                        indicator.expiresAt.strftime(
                            PUSH_DATE_FORMAT,
                        )
                        if indicator.expiresAt
                        else None
                    ),
                    "description": indicator.comments,
                }
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully created payload for "
            f"{len(indicators_data)} indicator(s) to share to "
            f"{PLATFORM_NAME}. Indicators will be shared in batches"
            f" of {PUSH_PAGE_SIZE}."
        )
        batch = 1
        total_success_count = 0
        total_failed_count = 0

        filters = {}
        if user_type == "global":
            filters = {"tenant": True}

        for chunked_list in self.divide_in_chunks(
            indicators_data, PUSH_PAGE_SIZE
        ):
            batch_failed_count = 0
            total_success_count, total_failed_count = self._push(
                chunked_list=chunked_list,
                filters=filters,
                headers=headers,
                url=url,
                batch=batch,
                total_success_count=total_success_count,
                total_failed_count=total_failed_count,
                batch_failed_count=batch_failed_count,
            )
            batch += 1
        log_msg = (
            f"Successfully shared {total_success_count} indicator(s) to "
            f"{PLATFORM_NAME}."
        )
        if total_failed_count > 0:
            log_msg += (
                f" skipped sharing {total_failed_count} indicator(s)."
            )
        self.logger.info(f"{self.log_prefix}: {log_msg}")
        return PushResult(
            success=True,
            message=log_msg,
        )

    def _push(
        self,
        chunked_list: List[Dict],
        filters: Dict,
        headers: Dict,
        url: str,
        batch: int,
        total_success_count: int,
        total_failed_count: int,
        batch_failed_count: int,
        is_retry: bool = False,
    ):
        logger_msg = (
            f"sharing indicators for batch {batch}"
            f" to {PLATFORM_NAME}"
        )
        chunked_list_len = len(chunked_list)
        request_body = {
            "data": chunked_list,
            "filter": filters,
        }
        try:
            response = self.sentinelone_helper.api_helper(
                method="POST",
                url=url,
                headers=headers,
                json=request_body,
                proxies=self.proxy,
                verify=self.ssl_validation,
                logger_msg=logger_msg,
                is_handle_error_required=False,
            )
            status_code = response.status_code
            if status_code == 200:
                total_success_count += chunked_list_len
                count_log = (
                    f"Successfully shared {chunked_list_len} indicator(s)"
                )
                if batch_failed_count > 0:
                    count_log += (
                        f", skipped sharing {batch_failed_count} indicator(s)"
                    )
                self.logger.info(
                    f"{self.log_prefix}: {count_log} in batch {batch} to"
                    f" platform {PLATFORM_NAME}. Total indicator(s) shared:"
                    f" {total_success_count}."
                )
            elif status_code == 400 and not is_retry:
                total_success_count, total_failed_count, batch_failed_count = (
                    self._remove_failed_ioc_and_retry_push(
                        response=response,
                        chunked_list=chunked_list,
                        filters=filters,
                        headers=headers,
                        url=url,
                        batch=batch,
                        total_success_count=total_success_count,
                        total_failed_count=total_failed_count,
                        batch_failed_count=batch_failed_count,
                    )
                )
            else:
                self.sentinelone_helper.handle_error(
                    resp=response,
                    logger_msg=logger_msg,
                    is_validation=False,
                )
        except SentinelOnePluginException as err:
            err_msg = (
                f"Error occurred while {logger_msg}. Error: {err}."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}"
            )
            total_failed_count += chunked_list_len
        except Exception as exp:
            self.logger.error(
                f"{self.log_prefix}: Unexpected error occurred while "
                f"sharing {chunked_list_len} indicator(s) in batch "
                f"{batch} to {PLATFORM_NAME}. Error: {exp}",
                details=traceback.format_exc(),
            )
            total_failed_count += chunked_list_len
        return total_success_count, total_failed_count

    def _remove_failed_ioc_and_retry_push(
        self,
        response: Response,
        chunked_list: List[Dict],
        filters: Dict,
        headers: Dict,
        url: str,
        batch: int,
        total_success_count: int,
        total_failed_count: int,
        batch_failed_count: int,
    ):
        chunked_list_len = len(chunked_list)
        try:
            response_json = response.json()
        except Exception:
            err_msg = (
                "Could not parse API response hence skipping sharing"
                f" of indicator batch {batch}"
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}."
            )
            raise SentinelOnePluginException(err_msg)
        errors = response_json.get("errors", [])
        invalid_iocs = set()
        for error in errors:
            if error_details := error.get("detail"):
                try:
                    error_details_json = self._parse_error_details(error_details)
                    if not error_details_json:
                        continue
                    for invalid_ioc in error_details_json.get("errors", []):
                        invalid_iocs.add(
                            (invalid_ioc.get("value"), invalid_ioc.get("type"))
                        )
                except Exception:
                    continue
        invalid_iocs_len = len(invalid_iocs)
        if invalid_iocs and chunked_list_len - invalid_iocs_len > 0:
            debug_log = (
                f"Skipped sharing of {invalid_iocs_len} indicator(s) to"
                f" {PLATFORM_NAME} as they were of invalid type. Retrying"
                f" sharing for {chunked_list_len - invalid_iocs_len}"
                f" valid indicator(s) for batch {batch}."
            )
            self.logger.debug(
                f"{self.log_prefix}: {debug_log}",
                details=(
                    "Invalid indicator(s): "
                    f"{','.join([value for value, _ in invalid_iocs])}"
                )
            )
            total_failed_count += invalid_iocs_len
            batch_failed_count += invalid_iocs_len
            chunked_list = self._remove_invalid_iocs(
                chunked_list=chunked_list,
                invalid_iocs=invalid_iocs,
            )
            total_success_count, total_failed_count = self._push(
                chunked_list=chunked_list,
                filters=filters,
                headers=headers,
                url=url,
                batch=batch,
                total_success_count=total_success_count,
                total_failed_count=total_failed_count,
                batch_failed_count=batch_failed_count,
                is_retry=True,
            )
        else:
            err_msg = (
                f"Received exit code 400, HTTP client error while sharing"
                f" {chunked_list_len} indicator(s) in batch {batch} to"
                f" {PLATFORM_NAME}"
            )
            raise SentinelOnePluginException(err_msg)
        return total_success_count, total_failed_count, batch_failed_count

    def _remove_invalid_iocs(
        self,
        chunked_list: List[Dict],
        invalid_iocs: Set[Tuple[str, str]],
    ) -> List[Dict]:
        return [
            ioc
            for ioc in chunked_list
            if (ioc.get("value"), ioc.get("type")) not in invalid_iocs
        ]

    def _parse_error_details(
        self, error_details: Union[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Safely parse error detail payload regardless of quoting style."""
        if isinstance(error_details, dict):
            return error_details
        if isinstance(error_details, str):
            try:
                return json.loads(error_details)
            except json.JSONDecodeError:
                try:
                    # literal_eval (Caution: A complex expression can overflow
                    # the C stack and cause a crash.)
                    parsed_details = ast.literal_eval(error_details)
                    if isinstance(parsed_details, dict):
                        return parsed_details
                except (ValueError, SyntaxError):
                    raise
                except Exception:
                    raise
        return {}

    def _validate_credentials(
        self, url: str, token: str, site: str, user_type: str
    ) -> ValidationResult:
        """Validate API Credentials.

        Args:
            url (str): URL.
            token (str): API Token.
            site (str): Site name.

        Returns:
            ValidationResult: Validation result.
        """
        try:
            params = {"limit": 1}
            if user_type == "global":
                params["tenant"] = True
            if site:
                site_id = self._get_site_id(site, url, token, True)
                if site_id is None:
                    err_msg = (
                        f"Could not find the Site {site}"
                        f" on {PLATFORM_NAME}. Verify Site Name "
                        "provided in configuration parameters."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Ensure Site Name provided in "
                            "configuration parameters is correct."
                        )
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
                params["siteIds"] = site_id

            self.sentinelone_helper.api_helper(
                method="GET",
                url=f"{url}{API_VERSION}/threats",
                params=params,
                headers=self.sentinelone_helper.get_headers(api_token=token),
                is_validation=True,
                logger_msg="validating API credentials",
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            log_msg = "Successfully validated plugin configuration."
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(
                success=True,
                message=log_msg,
            )
        except SentinelOnePluginException as exp:
            return ValidationResult(
                success=False,
                message=str(exp),
            )
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while validating API credentials."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed_url = urlparse(url)
        return parsed_url.scheme and parsed_url.netloc

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the configuration.

        Args:
            configuration (Dict): Configuration Parameters.

        Returns:
            ValidationResult: Validation Result.
        """
        (
            url,
            token,
            site,
            user_type,
            analyst_verdict,
            retraction_interval,
            enable_tagging,
            initial_range,
        ) = self.sentinelone_helper.get_config_params(configuration)

        # Validate Management URL
        if validation_error := self._validate_parameters(
            field_name="Management URL",
            field_value=url,
            field_type=str,
            custom_validation_func=self._validate_url,
            is_required=True
        ):
            return validation_error

        # Validate API Token
        if validation_error := self._validate_parameters(
            field_name="API Token",
            field_value=token,
            field_type=str,
            is_required=True
        ):
            return validation_error

        # Validate Site Name
        if validation_error := self._validate_parameters(
            field_name="Site Name",
            field_value=site,
            field_type=str,
            is_required=False,
        ):
            return validation_error

        # Validate User Type
        if validation_error := self._validate_parameters(
            field_name="User Type",
            field_value=user_type,
            field_type=str,
            allowed_values=USER_TYPE_OPTIONS,
            is_required=True,
        ):
            return validation_error

        # Validate Analyst Verdict
        if validation_error := self._validate_parameters(
            field_name="Analyst Verdict",
            field_value=analyst_verdict,
            field_type=List,
            allowed_values=ANALYST_VERDICT_OPTIONS,
            is_required=True
        ):
            return validation_error

        # Validate Initial Range
        if validation_error := self._validate_parameters(
            field_name="Initial Range (in days)",
            field_type=int,
            field_value=initial_range,
            min_value=0,
            max_value=INTEGER_THRESHOLD,
            is_required=True,
        ):
            return validation_error

        # Validate Enable Tagging
        if validation_error := self._validate_parameters(
            field_name="Enable Tagging",
            field_type=str,
            field_value=enable_tagging,
            allowed_values=ENABLE_TAGGING_OPTIONS,
            is_required=True
        ):
            return validation_error

        # Validate Retraction Interval
        if validation_error := self._validate_parameters(
            field_name="Retraction Interval",
            field_type=int,
            field_value=retraction_interval,
            min_value=1,
            max_value=INTEGER_THRESHOLD,
            is_required=False,
        ):
            return validation_error

        return self._validate_credentials(
            url=url,
            token=token,
            site=site,
            user_type=user_type,
        )

    def _validate_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: Dict = None,
        min_value: int = None,
        max_value: int = None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
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
            min_value (int, optional): Minimum allowed value for the
                configuration field. Defaults to None.
            max_value (int, optional): Maximum allowed value for the
                configuration field. Defaults to None.
            custom_validation_func (Callable, optional): Custom validation
                function to be applied. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        validation_err_msg = "Validation error occurred. "
        if isinstance(field_value, str):
            field_value = field_value.strip()
        if is_required and not isinstance(field_value, int) and not field_value:
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
                resolution=(
                    f"Ensure you provide a value for the field {field_name}."
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if is_required and not isinstance(field_value, field_type) or (
            custom_validation_func and not custom_validation_func(field_value)
        ):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
                resolution=(
                    "Ensure a valid value is provided for the field"
                    f" {field_name}."
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if allowed_values:
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            allowed_values_str = ", ".join(allowed_values.values())
            if field_type is str and field_value not in allowed_values.keys():
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                    ),
                    details=f"Allowed values are: {allowed_values_str}.",
                    resolution=(
                        "Ensure the value selected is from the allowed values."
                    )
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif field_type == List:
                for value in field_value:
                    if value not in allowed_values.keys():
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {validation_err_msg}"
                                f"{err_msg}"
                            ),
                            details=(
                                f"Allowed values are: {allowed_values_str}."
                            ),
                            resolution=(
                                "Ensure the values selected are from the"
                                " allowed values."
                            )
                        )
                        return ValidationResult(
                            success=False,
                            message=err_msg,
                        )
        if max_value and isinstance(field_value, int) and (
            field_value > max_value or field_value < min_value
        ):
            if max_value == INTEGER_THRESHOLD:
                max_value = "2^62"
            err_msg = (
                f"Invalid {field_name} provided in configuration"
                " parameters. Valid value should be an integer "
                f"greater than {min_value} and less than {max_value}."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}{err_msg}",
                resolution=(
                    f"Ensure the value provided is between {min_value}"
                    f" and {max_value}."
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Create IoCs",
                value="create_iocs",
            ),
        ]

    def validate_action(self, action: Action):
        """Validate SentinelOne Action Configuration."""
        if action.value not in ["create_iocs"]:
            return ValidationResult(success=False, message="Invalid action.")
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []

    def get_modified_indicators(
        self, source_indicators: List[List[Indicator]]
    ):
        """Get all modified indicators status.

        Args:
            source_indicators (List[List[Indicator]]): Source Indicators.

        Yields:
            tuple: Modified Indicators and Status.
        """
        self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        self.logger.info(
            f"{self.log_prefix}: Getting all modified indicators status"
            f" from {PLATFORM_NAME}."
        )
        retraction_interval = self.configuration.get("retraction_interval")
        if not (retraction_interval and isinstance(retraction_interval, int)):
            log_msg = (
                "Retraction Interval is not available for the configuration"
                f' "{self.config_name}". Skipping retraction of indicator(s)'
                f" for {PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True
        retraction_interval = int(retraction_interval)
        end_time = datetime.now()
        start_time = end_time - timedelta(days=int(retraction_interval))
        start_time = f"{start_time.isoformat()}Z"
        modified_indicators = set()
        for modified_indicator in self._pull(
            is_retraction=True, retraction_time=start_time
        ):
            modified_indicators.update(modified_indicator)
        for source_ioc_list in source_indicators:
            try:
                iocs = set()
                for ioc in source_ioc_list:
                    if ioc:
                        iocs.add(ioc.value)
                retracted_iocs = iocs - modified_indicators
                self.logger.info(
                    f"{self.log_prefix}: {len(retracted_iocs)} indicator(s) "
                    f"will be marked as retracted from {len(iocs)} total "
                    "indicator(s) present in cloud exchange for"
                    f" {PLATFORM_NAME}."
                )
                yield list(retracted_iocs), False
            except Exception as err:
                err_msg = (
                    f"Error while fetching modified indicators from"
                    f" {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {err_msg} Error: {err}"),
                    details=traceback.format_exc(),
                )
                raise SentinelOnePluginException(err_msg)

    def retract_indicators(
        self,
        retracted_indicators_lists: List[List[Indicator]],
        list_action_dict: List[Action],
    ):
        """Retract/Delete Indicators from SentinelOne IOC Management.

        Args:
            retracted_indicators_lists (List[List[Indicator]]):
                Retract indicators list
            list_action_dict (List[Action]): List of action dict

        Yields:
            ValidationResult: Validation result.
        """
        self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        (
            url,
            token,
            _,
            user_type,
            *_,
        ) = self.sentinelone_helper.get_config_params(self.configuration)

        self.logger.info(
            f"{self.log_prefix}: Starting retraction of indicator(s) from"
            f" {PLATFORM_NAME} platform."
        )

        filters = {}
        api_endpoint = f"{url}/{API_VERSION}/threat-intelligence/iocs"
        headers = self.sentinelone_helper.get_headers(
            api_token=token, include_content_type=True
        )
        batch = 1
        for retraction_batch in retracted_indicators_lists:
            retraction_count = 0
            fail_count = 0
            ioc_values = [ioc.value for ioc in retraction_batch]
            for ioc_value in ioc_values:
                try:
                    if user_type == "global":
                        filters = {
                            "filter": {"value": ioc_value, "tenant": True},
                        }
                    else:
                        filters = {
                            "filter": {"value": ioc_value},
                        }
                    self.sentinelone_helper.api_helper(
                        method="DELETE",
                        url=api_endpoint,
                        json=filters,
                        headers=headers,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        logger_msg=(
                            f"retracting indicator with value {ioc_value}"
                            f" from batch {batch} from Threat Intelligence"
                            f" of {PLATFORM_NAME}"
                        ),
                        is_retraction=True,
                    )
                    retraction_count += 1
                    self.logger.debug(
                        f"{self.log_prefix}: Successfully retracted indicator"
                        f" with value {ioc_value} from Threat Intelligence. "
                        f"Total retracted indicators: {retraction_count}."
                    )

                except SentinelOnePluginException:
                    fail_count += 1
                    continue
                except Exception as err:
                    err_msg = (
                        "Unexpected error occurred while retracting "
                        f"indicator with value {ioc_value} for batch {batch} "
                        f"from Threat Intelligence of {PLATFORM_NAME}."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {err_msg} Error: {err}",
                        details=traceback.format_exc(),
                    )
                    fail_count += 1
            log_msg = f"Successfully retracted {retraction_count} indicator(s)"
            if fail_count > 0:
                log_msg += (
                    f" and {fail_count} indicator(s) were failed to retract"
                )
            log_msg += (
                f" in batch {batch} from Threat Intelligence of "
                f"{PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield ValidationResult(
                success=True,
                message=(
                    f"Completed execution for batch {batch} for retraction."
                ),
            )
            batch += 1
