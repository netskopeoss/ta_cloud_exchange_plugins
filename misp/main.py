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

Implementation of MISP CTE plugin.
"""

import ipaddress
import re
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Union

from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
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
    ATTRIBUTE_CATEGORIES,
    ATTRIBUTE_TYPES,
    BATCH_SIZE,
    BIFURCATE_INDICATOR_TYPES,
    DEFAULT_IOC_TAG,
    INTEGER_THRESHOLD,
    MAX_LOOK_BACK,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PULL_PAGE_SIZE,
)
from .utils.helper import MISPPluginException, MISPPluginHelper

MISP_TO_INTERNAL_TYPE = {
    "md5": IndicatorType.MD5,
    "sha256": IndicatorType.SHA256,
    "url": IndicatorType.URL,
    "domain": getattr(IndicatorType, "DOMAIN", IndicatorType.URL),
}


class MISPPlugin(PluginBase):
    """The MISP plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init function.

        Args:
            name (str): Configuration Name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

        self.misp_helper = MISPPluginHelper(
            logger=self.logger,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            log_prefix=self.log_prefix,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            metadata = MISPPlugin.metadata
            plugin_name = metadata.get("name", PLUGIN_NAME)
            plugin_version = metadata.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.info(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details."
                ),
                details=str(exp),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _pull(self):
        """Pull indicators from MISP."""
        existing_tag = f"{self.name} Latest"
        pulling_mechanism = self.configuration.get(
            "pulling_mechanism", "incremental"
        )

        end_time = datetime.now()
        tag_utils = TagUtils()
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        start_time = None
        if pulling_mechanism == "look_back":
            look_back = self.configuration.get("look_back", 24)
            if not look_back:
                err_msg = (
                    "Look Back is a required configuration "
                    'parameter when "Look Back" is selected as '
                    "Pulling Mechanism."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise MISPPluginException(err_msg)
            else:
                # Removing the <config_name> Latest tag from the existing
                # indicators
                query = {"sources": {"$elemMatch": {"source": f"{self.name}"}}}
                TagUtils().on_indicators(query).remove(existing_tag)
                start_time = end_time - timedelta(hours=int(look_back))
                if self.last_run_at and self.last_run_at < start_time:
                    start_time = self.last_run_at
                new_indicator_tag = self._create_marking_tag(
                    tag_utils, existing_tag
                )
        else:
            start_time = self.last_run_at  # datetime.datetime object.

            if not start_time and not sub_checkpoint:
                initial_range = self.configuration.get("days", 7)
                self.logger.info(
                    f"{self.log_prefix}: This is initial data fetch since "
                    "checkpoint is empty. Querying indicators for "
                    f"last {initial_range} days."
                )
                start_time = end_time - timedelta(days=int(initial_range))

        if start_time:
            self.logger.info(
                f"{self.log_prefix}: Pulling indicators from "
                f"checkpoint: {str(start_time)}"
            )
        # create set of excluded events for
        event_ids = []
        include_event_name = self.configuration.get("include_event_name")
        exclude_event = self.configuration.get("event_name")
        base_url, api_key = self.misp_helper.get_credentials(
            self.configuration
        )

        if include_event_name:
            for inc_event in include_event_name.strip().split(","):
                event_id = self._event_exists(inc_event, base_url, api_key)[1]
                event_ids.append(event_id)

        # Convert to epoch
        if start_time:
            start_time = int(start_time.timestamp())
        end_time = int(end_time.timestamp())

        misp_tags = [f"!{DEFAULT_IOC_TAG}"]
        tags = self.configuration.get("tags", "").strip()
        if tags:
            misp_tags.extend(tags.split(","))
        body = None

        if sub_checkpoint is None:
            body = {
                "returnFormat": "json",
                "limit": PULL_PAGE_SIZE,
                "page": 1,
                "timestamp": [str(start_time), str(end_time)],
                # Filter attributes based on type, category and tags
                "category": self.configuration.get("attr_category"),
                "type": self.configuration.get("attr_type"),
                "tags": misp_tags,
                "includeDecayScore": 1,
            }
            published = self.configuration.get("published", [])
            if published == ["published"]:
                body["published"] = 1
            elif published == ["unpublished"]:
                body["published"] = 0

            to_ids = self.configuration.get("to_ids", [])
            if to_ids == ["enabled"]:
                body["to_ids"] = 1
            elif to_ids == ["disabled"]:
                body["to_ids"] = 0

            enforce_warning_list = self.configuration.get(
                "enforce_warning_list", "no"
            ).strip()
            if enforce_warning_list == "yes":
                body["enforceWarninglist"] = 1
            elif enforce_warning_list == "no":
                body["enforceWarninglist"] = 0

            if event_ids:
                body["eventid"] = event_ids

        else:
            body = sub_checkpoint
            self.logger.info(
                f"{self.log_prefix}: Resuming the pull from page "
                f"{body['page']}."
            )

        score_threshold = self.configuration.get("score_threshold")
        decaying_models = (
            self.configuration.get("decaying_models", "").strip().split(",")
        )
        enable_tagging = self.configuration.get("enable_tagging", "yes")
        if score_threshold is not None:
            model_ids = [
                int(model_id) for model_id in decaying_models if model_id
            ]
            score_params = {
                "excludeDecayed": 1,
                "decayingModel": model_ids,
                "modelOverrides": {"threshold": score_threshold},
            }
            body.update(score_params)

        last_page = False
        total_ioc_count = 0
        while True:
            ioc_counts = {
                "sha256": 0,
                "md5": 0,
                "domain": 0,
                "ipv4": 0,
                "ipv6": 0,
                "url": 0,
            }
            page_skip_count = 0
            indicators, skipped_tags = [], []
            try:
                resp_json = self.misp_helper.api_helper(
                    method="POST",
                    url=f"{base_url}/attributes/restSearch",
                    headers=self.misp_helper.get_header(api_key),
                    json=body,
                    logger_msg=(
                        f"pulling indicators for page {body['page']}"
                        f" from {PLATFORM_NAME}"
                    ),
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )

                for attr in resp_json.get("response", {}).get("Attribute", []):

                    if (
                        attr.get("type") in ATTRIBUTE_TYPES
                        # Filter already pushed attributes/indicators
                        and (
                            attr.get("Event", {}).get("info", "")
                            != exclude_event
                        )
                    ):

                        # Deep link of event corresponding to the attribute
                        event_id, deep_link = attr.get("event_id"), ""
                        tag_list = attr.get("Tag", [])
                        tag_list.append(
                            {
                                "name": attr.get("category", ""),
                                "type": "misp_category",
                            }
                        )
                        if event_id:
                            deep_link = f"{base_url}/events/view/{event_id}"
                        tags, skipped = self._create_tags(
                            tag_utils,
                            tag_list,
                            enable_tagging,
                        )
                        skipped_tags.extend(skipped)
                        if pulling_mechanism == "look_back" and look_back:
                            tags.append(new_indicator_tag)
                        ioc_type = ioc_type = MISP_TO_INTERNAL_TYPE.get(
                            attr.get("type")
                        )
                        if attr.get(
                            "type"
                        ) == "ip-src" and self._is_valid_ipv4(
                            attr.get("value")
                        ):
                            ioc_type = getattr(
                                IndicatorType, "IPV4", IndicatorType.URL
                            )
                        elif attr.get(
                            "type"
                        ) == "ip-src" and self._is_valid_ipv6(
                            attr.get("value")
                        ):
                            ioc_type = getattr(
                                IndicatorType, "IPV6", IndicatorType.URL
                            )
                        try:
                            score_comment = []
                            decay_score = attr.get("decay_score", [])
                            if decay_score:
                                for decay in decay_score:
                                    model = decay.get("DecayingModel", {})
                                    if decay.get("score"):
                                        cmt = (
                                            "Decaying Score: "
                                            + str(round(decay.get("score"), 2))
                                            + ", Decaying Model ID: "
                                            + str(model.get("id", "Unknown"))
                                            + ", Decaying Model Name: "
                                            + str(model.get("name", "Unknown"))
                                        )
                                        score_comment.append(cmt)
                            comment = attr.get("comment", "")

                            if score_comment:
                                if comment:
                                    comment += str(
                                        f" | {' | '.join(score_comment)}"  # noqa
                                    )
                                else:
                                    comment += (
                                        f"{' | '.join(score_comment)}"  # noqa
                                    )

                            indicators.append(
                                Indicator(
                                    value=attr.get("value"),
                                    type=ioc_type,
                                    firstSeen=attr.get("first_seen", None),
                                    comments=comment,
                                    tags=tags,
                                    extendedInformation=deep_link,
                                )
                            )
                            ioc_counts[ioc_type] += 1
                            total_ioc_count += 1
                        except (ValidationError, Exception) as error:
                            page_skip_count += 1
                            error_message = (
                                "Validation error occurred"
                                if isinstance(error, ValidationError)
                                else "Unexpected error occurred"
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {error_message} while"
                                    " creating indicator for page "
                                    f"{body['page']}. This record will be"
                                    f" skipped. Error: {error}."
                                ),
                                details=str(traceback.format_exc()),
                            )

                if (
                    len(resp_json.get("response", {}).get("Attribute", []))
                    < body["limit"]
                ):
                    last_page = True
                if len(skipped_tags) > 0:
                    self.logger.info(
                        f"{self.log_prefix}: Skipping following tag(s) in "
                        f"page {body['page']} because they are too "
                        f"long: {', '.join(skipped_tags)}"
                    )
                self.logger.debug(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{sum(ioc_counts.values())} indicator(s) and "
                    f"skipped {page_skip_count} indicator(s) in "
                    f"page {body['page']} from {PLATFORM_NAME}. Pull Stats:"
                    f" SHA256: {ioc_counts['sha256']}, MD5:"
                    f" {ioc_counts['md5']}, URLs: {ioc_counts['url']},"
                    f" Domain: {ioc_counts['domain']},"
                    f" IPv4: {ioc_counts['ipv4']} "
                    f"and IPv6: {ioc_counts['ipv6']}"
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{sum(ioc_counts.values())} indicator(s) in "
                    f"page {body['page']} from {PLATFORM_NAME}. Total "
                    f" indicator(s) fetched - {total_ioc_count}."
                )
                body["page"] += 1
                yield indicators, None if last_page else body
                if last_page:
                    break
            except MISPPluginException:
                raise
            except Exception:
                err_msg = (
                    f"Unexpected error occurred while pulling "
                    f"indicators for page {body['page']} from {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )

    def pull(self) -> List[Indicator]:
        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._pull()

            return wrapper(self)
        else:
            indicators = []
            for batch, _ in self._pull():
                indicators.extend(batch)
            return indicators

    def _is_valid_ipv4(self, address: str) -> bool:
        """Validate IPv4 address.

        Args:
            address (str): Address to validate.

        Returns:
            bool: True if valid else False.
        """
        try:
            ipaddress.IPv4Address(address)
            return True
        except Exception:
            return False

    def _is_valid_domain(self, value: str) -> bool:
        """Validate domain name.

        Args:
            value (str): Domain name.

        Returns:
            bool: Whether the name is valid or not.
        """
        if re.match(
            r"^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$",  # noqa
            value,
        ):
            return True
        else:
            return False

    def _is_valid_ipv6(self, address: str) -> bool:
        """Validate IPv6 address.

        Args:
            address (str): Address to validate.

        Returns:
            bool: True if valid else False.
        """
        try:
            ipaddress.IPv6Address(address)
            return True
        except Exception:
            return False

    def _is_valid_fqdn(self, fqdn: str) -> bool:
        """Validate FQDN (Absolute domain).

        Args:
            - fqdn (str): FQDN to validate.

        Returns:
            - bool: True if valid else False.
        """
        if re.match(
            r"^(?=.{1,255}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+(?:[A-Za-z]{2,})\.?$",  # noqa
            fqdn,
            re.IGNORECASE,
        ):
            return True
        else:
            return False

    def is_valid_hostname(self, hostname: str) -> bool:
        """Validate hostname.

        Args:
            hostname (str): Hostname

        Returns:
            bool:  True if valid else False.
        """
        if re.match(
            r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$",
            hostname,
            re.IGNORECASE,
        ):
            return True
        else:
            return False

    def _create_marking_tag(self, utils: TagUtils, tag_name: str) -> str:
        """Create new tag in database if required.

        Args:
            utils (TagUtils): Tag utils.
            tag_name (str): Tag name

        Returns:
            str: Tag name
        """
        try:
            if not utils.exists(tag_name):
                utils.create_tag(
                    TagIn(
                        name=tag_name,
                        color="#ED3347",
                    )
                )

        except ValueError as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while creating "
                    f"an internal tag. Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            raise err
        else:
            return tag_name

    def _create_tags(
        self, utils: TagUtils, tags: List[dict], enable_tagging: str
    ) -> Union[List[str], List[str]]:
        """Create new tag(s) in database if required.

        Args:
            utils (TagUtils): Utils
            tags (List[dict]): Tags
            enable_tagging (str): Enable/disable tagging

        Returns:
            Union[List[str], List[str]]: Created tags, Skipped tags
        """
        if enable_tagging != "yes":
            return [], []

        tag_names, skipped_tags = [], []
        for tag in tags:
            tag_name = (
                f"MISPCATEGORY-{tag.get('name', '').strip()}"
                if tag.get("type") == "misp_category"
                else tag.get("name", "").strip()
            )
            try:
                if not utils.exists(tag_name):
                    utils.create_tag(
                        TagIn(
                            name=tag_name,
                            color=tag.get("colour", "#ED3347"),
                        )
                    )
            except ValueError:
                skipped_tags.append(tag_name)
            else:
                tag_names.append(tag_name)
        return tag_names, skipped_tags

    def _event_exists(
        self,
        event_name: str,
        base_url: str,
        api_key: str,
        is_validation: bool = False,
    ) -> tuple:
        """Check if event exists on MISP instance.

        Args:
            event_name (str): MISP event name.
            base_url (str): Base URL.
            api_key (str): Authentication Key

        Returns:
            tuple: True if exists else False, event_id
        """
        try:
            logger_msg = (
                f"checking existence of {event_name} on {PLATFORM_NAME}"
            )
            resp_json = self.misp_helper.api_helper(
                url=f"{base_url}/events/restSearch",
                method="POST",
                headers=self.misp_helper.get_header(api_key),
                json={
                    "returnFormat": "json",
                    "limit": 1,
                    "page": 1,
                    "eventinfo": event_name,
                    "metadata": True,  # skips attributes
                },
                logger_msg=logger_msg,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
            if resp_json.get("response", []):
                return True, resp_json.get("response")[0].get("Event", {}).get(
                    "id", None
                )
            return False, None
        except MISPPluginException:
            if is_validation:
                raise
            return False, None
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise MISPPluginException(err_msg)

    def _create_event(
        self, base_url: str, api_key: str, payload: dict
    ) -> bool:
        """Create a new event on MISP instance with given name/info and
           attributes.

         Args:
             base_url (str): Base URL
             api_key (str): Authentication Key
             payload (dict): Payload Dictionary

        Returns:
             bool: True if success else False
        """
        try:
            payload_size = len(payload["Attribute"])
            self.misp_helper.api_helper(
                method="POST",
                url=f"{base_url}/events/add",
                headers=self.misp_helper.get_header(api_key),
                json=payload,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"pushing {payload_size} "
                    f"indicator(s) to {PLATFORM_NAME}"
                ),
                show_payload=False,
            )
            return True

        except Exception:
            err_msg = (
                f"Unable to push {payload_size} indicator(s) to "
                f"{PLATFORM_NAME}. Hence skipping this batch."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return False

    def _update_event(
        self, base_url: str, api_key: str, event_id: str, payload: dict
    ) -> bool:
        """Update given event's info and attribute(s).

        Args:
            base_url (str): Base URL
            api_key (str): Authentication Key
            event_id (str): Event ID
            payload (dict): Payload dictionary

        Returns:
            bool: True if api call is success else False.
        """
        try:
            payload_size = len(payload["Attribute"])

            self.misp_helper.api_helper(
                method="POST",
                url=f"{base_url}/events/edit/{event_id}",
                headers=self.misp_helper.get_header(api_key),
                json=payload,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f'updating {len(payload["Attribute"])} '
                    f"indicator(s) to {PLATFORM_NAME}"
                ),
                show_payload=False,
            )

            return True

        except Exception:
            err_msg = (
                f"Unable to update {payload_size} attributes to "
                f"{PLATFORM_NAME}. Hence skipping this batch."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return False

    def _is_tag_exists(self, base_url: str, api_key: str) -> bool:
        """Is netskope-ce tag exists on MISP.

        Args:
            base_url (str): Base URL for MISP.
            api_key (str): Authentication Key for MISP.

        Returns:
            bool: True if tag exists else False.
        """
        endpoint = f"{base_url}/tags/search/{DEFAULT_IOC_TAG}"
        headers = self.misp_helper.get_header(api_key)
        resp_json = self.misp_helper.api_helper(
            method="POST",
            url=endpoint,
            headers=headers,
            json=[],
            verify=self.ssl_validation,
            proxies=self.proxy,
            logger_msg=(
                f"checking existence of '{DEFAULT_IOC_TAG}' tag "
                f"on {PLATFORM_NAME}"
            ),
        )
        if (
            resp_json
            and resp_json[0].get("Tag", {}).get("name") == DEFAULT_IOC_TAG
        ):
            self.logger.debug(
                f"{self.log_prefix}: '{DEFAULT_IOC_TAG}' tag "
                f"exists on {PLATFORM_NAME}."
            )
            return True
        else:
            return False

    def push(
        self, indicators: List[Indicator], action_dict: Dict
    ) -> PushResult:
        """Push given indicators to MISP Event.

        Args:
            indicators (List[Indicator]): List of indicators received from
            business rule.
            action_dict (Dict): Action Dictionary

        Returns:
            PushResult: PushResult containing flag and message.
        """
        action_label = action_dict.get("label")
        self.logger.info(
            f"{self.log_prefix}: Executing push method for "
            f'"{action_label}" target action.'
        )
        action_value = action_dict.get("value")
        if action_value != "event":
            err_msg = (
                "Invalid action parameter selected. Allowed "
                "value is Add to event."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise MISPPluginException(err_msg)

        event_name = action_dict.get("parameters", {}).get("event_name")
        # Check if event already exists
        base_url, api_key = self.misp_helper.get_credentials(
            self.configuration
        )

        result = self._is_tag_exists(base_url, api_key)
        if not result:
            # Create it
            endpoint = f"{base_url}/tags/add"
            body = {"name": DEFAULT_IOC_TAG, "colour": "#ff0000"}
            headers = self.misp_helper.get_header(api_key)
            resp_json = self.misp_helper.api_helper(
                method="POST",
                url=endpoint,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(
                    f"creating '{DEFAULT_IOC_TAG}' tag on {PLATFORM_NAME}"
                ),
                json=body,
            )
            if (
                resp_json
                and resp_json.get("Tag", {}).get("name") == DEFAULT_IOC_TAG
            ):
                self.logger.info(
                    f"{self.log_prefix}: Successfully created "
                    f"'{DEFAULT_IOC_TAG}' tag on {PLATFORM_NAME}."
                )
            else:
                err_msg = (
                    f"Unable to create '{DEFAULT_IOC_TAG}' "
                    f"tag on {PLATFORM_NAME}."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise MISPPluginException(err_msg)

        exists, event_id = self._event_exists(
            event_name=event_name,
            base_url=base_url,
            api_key=api_key,
        )

        # Map Netskope indicators to MISP attributes
        attributes = []
        action_dict = action_dict.get("parameters")
        for indicator in indicators:
            ioc_type = indicator.type.value
            if ioc_type in BIFURCATE_INDICATOR_TYPES:
                if (
                    self._is_valid_domain(indicator.value)
                    or self._is_valid_fqdn(indicator.value)
                    or self.is_valid_hostname(indicator.value)
                ):
                    ioc_type = "domain"
                elif self._is_valid_ipv4(
                    indicator.value
                ) or self._is_valid_ipv6(indicator.value):
                    ioc_type = "ip-src"
                else:
                    ioc_type = "url"

            attributes.append(
                {
                    "type": ioc_type,
                    "value": indicator.value,
                    "comment": indicator.comments,
                    "first_seen": (
                        indicator.firstSeen.isoformat(timespec="microseconds")
                        if indicator.firstSeen
                        else None
                    ),
                    "last_seen": (
                        indicator.lastSeen.isoformat(timespec="microseconds")
                        if indicator.lastSeen
                        else None
                    ),
                    "Tag": [{"name": DEFAULT_IOC_TAG}],
                }
            )

        self.logger.info(
            f"{self.log_prefix}: {len(attributes)} indicators will "
            f"be sent in batch of {BATCH_SIZE} to {PLATFORM_NAME}."
        )
        base_url, api_key = self.misp_helper.get_credentials(
            self.configuration
        )
        success_count, failed_count = 0, 0
        for i in range(0, len(attributes), BATCH_SIZE):
            payload = attributes[i : i + BATCH_SIZE]  # noqa

            if exists:
                # Push attributes/indicators to existing event
                flag = self._update_event(
                    base_url, api_key, event_id, {"Attribute": payload}
                )
                if not flag:
                    failed_count += len(payload)
                    self.logger.info(
                        f"{self.log_prefix}: Unable to update {len(payload)}"
                        f" indicator(s) to {PLATFORM_NAME}."
                        f" Total indicator(s) sent: {success_count}"
                    )
                else:

                    success_count += len(payload)
                    self.logger.info(
                        f"{self.log_prefix}: Successfully updated"
                        f" {len(payload)} indicator(s) to {PLATFORM_NAME}."
                        f" Total indicator(s) sent: {success_count}"
                    )
            else:
                # Create new event with all the attributes
                flag = self._create_event(
                    base_url,
                    api_key,
                    {
                        "info": event_name,
                        "Attribute": payload,
                    },
                )
                if not flag:
                    failed_count += len(payload)
                    self.logger.info(
                        f"{self.log_prefix}: Unable to push {len(payload)}"
                        f" indicator(s) to {PLATFORM_NAME}."
                        f" Total indicator(s) sent: {success_count}"
                    )
                else:

                    success_count += len(payload)
                    self.logger.info(
                        f"{self.log_prefix}: Successfully pushed"
                        f" {len(payload)} indicator(s) to {PLATFORM_NAME}."
                        f" Total indicator(s) sent: {success_count}"
                    )
                exists, event_id = self._event_exists(
                    event_name=event_name,
                    base_url=base_url,
                    api_key=api_key,
                )
        log_msg = (
            f"Successfully pushed/update {success_count} "
            f"indicator(s) and failed to push/update "
            f"{failed_count} indicator(s)"
            f" to {event_name} event."
        )
        self.logger.info(f"{self.log_prefix}: {log_msg}")
        return PushResult(message=f"{log_msg}", success=True)

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration."""

        validation_err_msg = "Validation error occurred"
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            err_msg = "MISP Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(base_url, str):
            err_msg = (
                "Invalid MISP Base URL provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        api_key = configuration.get("api_key")
        if not api_key:
            err_msg = (
                "Authentication Key is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(api_key, str):
            err_msg = (
                "Invalid Authentication Key provided in "
                "configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        attr_type = configuration.get("attr_type", [])
        if attr_type is None:
            err_msg = (
                "MISP Attribute Type is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not all(x in ATTRIBUTE_TYPES for x in attr_type):
            err_msg = (
                "Invalid MISP Attribute Type provided in "
                "configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        attr_category = configuration.get("attr_category", [])
        if attr_category is None or not all(
            x in ATTRIBUTE_CATEGORIES for x in attr_category
        ):
            err_msg = (
                "Invalid MISP Attribute Category provided in "
                "configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        tags = configuration.get("tags", "").strip()
        if tags is None or not isinstance(tags, str):
            err_msg = (
                "Invalid MISP Attribute Tags provided in "
                "configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        validate_result = self._validate_auth(base_url, api_key)
        if isinstance(validate_result, ValidationResult):
            return validate_result

        include_event_name = configuration.get(
            "include_event_name", ""
        ).strip()
        if not isinstance(include_event_name, str):
            err_msg = (
                "Invalid Event Names provided in configuration parameters."
                " Event Names should be a valid string with comma "
                "separated values."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        elif include_event_name:

            events_to_include = include_event_name.split(",")
            event_to_exclude = configuration.get("event_name", "").strip()

            for event in events_to_include:
                event = event.strip()
                if not event:
                    err_msg = (
                        "Invalid Event Name provided in configuration "
                        "parameters"
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {validation_err_msg}."
                        f" {err_msg}."
                    )
                    return ValidationResult(success=False, message=err_msg)

                if event == event_to_exclude:
                    err_msg = (
                        f"{event} is present in Event Names and "
                        "Exclude IoCs from Event. Event Names and Exclude"
                        " IoCs from Event can't contain same value."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {validation_err_msg}. {err_msg}."
                    )

                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
                try:
                    exist = self._event_exists(
                        event, base_url, api_key, is_validation=True
                    )[0]
                except Exception as exp:
                    err_msg = (
                        f"Unable to check the existence of {event}"
                        f" event on {PLATFORM_NAME}"
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {validation_err_msg}."
                            f" {err_msg} Error: {exp}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    return ValidationResult(
                        success=False,
                        message=f"{err_msg}. Check logs for more details.",
                    )

                if not exist:
                    err_msg = (
                        f'Event "{event}" does not exist on {PLATFORM_NAME}'
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {validation_err_msg}. {err_msg}."
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
        published = configuration.get("published", [])
        if published and not all(
            x in ["published", "unpublished"] for x in published
        ):
            err_msg = (
                "Invalid IoC Event Type selected in configuration parameters."
                " Allowed values are Published and Unpublished."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        score_threshold = configuration.get("score_threshold")
        if score_threshold:
            if not (
                isinstance(score_threshold, int)
                or isinstance(score_threshold, float)
            ):
                err_msg = (
                    "Invalid Decaying Score Threshold provided in "
                    "configuration parameters. Valid value should "
                    "be an integer/float in range 0-100."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        decaying_models = configuration.get("decaying_models", "").strip()
        if decaying_models:
            if not isinstance(decaying_models, str):
                err_msg = (
                    "Invalid Decaying Model IDs provided in"
                    " configuration parameters."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            decaying_model_ids = decaying_models.split(",")
            try:
                for model_id in decaying_model_ids:
                    model_id = int(model_id)
                    if not model_id or not isinstance(model_id, int):
                        err_msg = (
                            "Invalid Decaying Model IDs provided in "
                            "configuration parameters. Valid values should"
                            " be a string containing integers separated "
                            "by commas."
                        )
                        self.logger.error(f"{self.log_prefix}: {err_msg}")
                        return ValidationResult(success=False, message=err_msg)

            except Exception as exp:
                err_msg = (
                    "Invalid Decaying Model IDs found in configuration"
                    " parameters."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}."
                        f" {err_msg} Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(success=False, message=err_msg)

        to_ids = configuration.get("to_ids", [])
        if to_ids and not all(x in ["enabled", "disabled"] for x in to_ids):
            err_msg = (
                "Invalid Filter on IDS flag selected in configuration "
                "parameters. Allowed values are Enabled and Disabled."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        enforce_warning_list = configuration.get(
            "enforce_warning_list", "no"
        ).strip()
        if enforce_warning_list and enforce_warning_list not in ["yes", "no"]:
            err_msg = (
                "Invalid Enforce Warning List IoCs selected "
                "in configuration parameters. Allowed values are Yes and No."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        enable_tagging = configuration.get("enable_tagging", "").strip()
        if not enable_tagging:
            err_msg = "Enable Tagging is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif enable_tagging not in ["yes", "no"]:
            err_msg = (
                "Invalid value provided in Enable Polling configuration"
                " parameter. Allowed values are Yes and No."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        try:
            pulling_mechanism = configuration.get(
                "pulling_mechanism", "incremental"
            )
            look_back = configuration.get("look_back", 24)
            if not pulling_mechanism:
                err_msg = (
                    "Pulling Mechanism is a required configuration parameter."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

            elif pulling_mechanism not in ["incremental", "look_back"]:
                err_msg = (
                    "Invalid value for Pulling Mechanism provided in"
                    " configuration parameter. Allowed values are Incremental"
                    " and Look Back."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
            elif pulling_mechanism == "look_back" and not look_back:
                err_msg = (
                    "Look Back is a required configuration "
                    'parameter when "Look Back" is selected as '
                    "Pulling Mechanism."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif pulling_mechanism == "look_back" and (
                not isinstance(look_back, int)
                or look_back <= 0
                or look_back > MAX_LOOK_BACK
            ):
                err_msg = (
                    "Invalid value for Look Back provided in"
                    " configuration parameters. Valid value should be "
                    "an integer in range 1-8760 i.e. 1 year."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

        except Exception as exp:
            err_msg = (
                "Invalid value for Look Back found in configuration"
                " parameters."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg}."
                    f" {err_msg} Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=err_msg)

        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(days, int):
            err_msg = (
                "Invalid Initial Range provided in configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif days < 0 or days > INTEGER_THRESHOLD:
            err_msg = (
                "Invalid Initial Range provided in configuration"
                " parameters. Valid value should be in range 0 to 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        self.logger.debug(
            f"{self.log_prefix}: Successfully validated credentials "
            f"for {PLATFORM_NAME} plugin."
        )
        return ValidationResult(success=True, message="Validation successful.")

    def _validate_auth(
        self,
        base_url: str,
        api_key: str,
    ) -> ValidationResult:
        """Validate Authentication Key by making REST API call.

        Args:
            base_url (str): Base URL.
            api_key (str): MISP Authentication Key.

        Returns:
            ValidationResult: Validation result containing success
            flag and message.
        """
        try:
            body = {"returnFormat": "json", "limit": 1, "page": 1}
            self.misp_helper.api_helper(
                method="POST",
                url=f"{base_url}/attributes/restSearch",
                headers=self.misp_helper.get_header(api_key),
                json=body,
                logger_msg=f"validating authentication with {PLATFORM_NAME}",
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=True,
            )
            return True
        except MISPPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = (
                "Unexpected validation error occurred while authenticating."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
        return ValidationResult(
            success=False,
            message=f"{err_msg} Check logs for more details.",
        )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add to event", value="event"),
        ]

    def validate_action(self, action: Action):
        """Validate Misp configuration."""
        if action.value not in ["event"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        event_name = action.parameters.get("event_name", "")
        if event_name is None:
            err_msg = "Event Name is a required action parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(event_name, str):
            err_msg = "Invalid Event Name provided in action parameters."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        self.logger.info(
            f"{self.log_prefix}: Successfully saved Action configuration."
        )
        return ValidationResult(
            success=True, message="Successfully saved Action configuration."
        )

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value == "event":
            return [
                {
                    "label": "Event Name",
                    "key": "event_name",
                    "type": "text",
                    "mandatory": True,
                    "default": "",
                    "description": (
                        "Name of the MISP Event in which the "
                        "attributes/indicators are to be pushed."
                    ),
                }
            ]
