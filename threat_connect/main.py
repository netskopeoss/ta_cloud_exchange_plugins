"""
BSD 3-Clause License.

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

ThreatConnect Plugin implementation to pull the data from
ThreatConnect Platform.
"""

import datetime
import time
import hmac
import hashlib
import base64
import traceback
import requests
import urllib.parse
import os
import json
import copy
import re
import ipaddress
from ipaddress import ip_address, IPv4Address
from typing import Dict, List
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    TagIn,
)
from netskope.common.utils import add_user_agent
from netskope.integrations.cte.models.business_rule import (
    ActionWithoutParams,
    Action,
)

from .threat_connect_constants import (
    INDICATOR_TYPES,
    RATING_TO_SEVERITY,
    SEVERITY_TO_RATING,
    LIMIT,
    PAGE_LIMIT,
    MAX_RETRY,
    TAG_NAME,
    PLATFORM_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
)

class ThreatConnectException(Exception):
    """ThreatConnect exception class."""
    pass


class ThreatConnectPlugin(PluginBase):
    """ThreatConnect Plugin Base Class.

    Args:
        PluginBase (PluginBase): Inherit PluginBase Class from Cloud
        Threat Exchange Integration.
    """

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

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_name = manifest_json.get("name", PLATFORM_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
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

    def _add_user_agent(self, headers: Dict = None) -> Dict:
        """Add User-Agent in the headers of any request.

        Returns:
            Dict: Dictionary after adding User-Agent.
        """
        headers = add_user_agent(headers)
        plugin_name = self.plugin_name.lower().replace(" ", "-")
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent, MODULE_NAME.lower(), plugin_name, self.plugin_version
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def parse_response(self, response: requests.models.Response):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = f"Invalid JSON response received from API. Error: {err}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=response.text,
            )
            raise ThreatConnectException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                " json response. Error: {}".format(exp)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=response.text,
            )
            raise ThreatConnectException(err_msg)

    def check_url_domain_ip(self, ioc_value):
        """Categorize URL as Domain, IP or URL."""
        regex_domain = (
            "^((?!-)[A-Za-z0-9-]" +
            "{1,63}(?<!-)\\.)" +
            "+[A-Za-z]{2,6}"
        )
        try:
            ipaddress.ip_address(ioc_value)
            return "Address"
        except Exception:
            if re.search(regex_domain, ioc_value):
                return "Host"
            else:
                return "URL"

    def handle_error(self, resp) -> Dict:
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API.
        Returns:
            dict: Returns the dictionary of response JSON when response is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return self.parse_response(resp)
            except ThreatConnectException as err:
                raise ThreatConnectException(err)
        elif resp.status_code == 401:
            err_msg = "User is not authorized, check the Access ID provided."
            self.logger.error(
                f"{self.log_prefix}: Received exit code 401. Authentication Error. {err_msg}",
                details=resp.text,
            )
            raise ThreatConnectException(err_msg)
        elif resp.status_code == 403:
            err_msg = "The user does not have the required roles. Check the roles assigned."
            self.logger.error(
                f"{self.log_prefix}: Received exit code 403, Forbidden User. {err_msg}",
                details=resp.text,
            )
            raise ThreatConnectException(err_msg)
        elif resp.status_code >= 400 and resp.status_code < 500:
            err_msg = f"Received exit code {resp.status_code}, HTTP Client Error."
            self.logger.error(
                f"{self.log_prefix}: "
                f"{err_msg}",
                details=resp.text,
            )
            raise ThreatConnectException(err_msg)
        elif resp.status_code >= 500 and resp.status_code < 600:
            f"Received exit code {resp.status_code}, Internal Server Error."
            self.logger.error(
                f"{self.log_prefix}: "
                f"{err_msg}",
                details=resp.text,
            )
            raise ThreatConnectException(err_msg)
        else:
            err_msg = f"Received exit code {resp.status_code}, HTTP Error."
            self.logger.error(
                f"{self.log_prefix}: "
                f"{err_msg}",
                details=resp.text,
            )
            raise ThreatConnectException(err_msg)

    def _get_headers_for_auth(
        self, api_path: str, access_id: str, secret_key: str, request_type: str
    ) -> Dict:
        """Return header for authentication.

        Args:
            api_path (str): API path string.
            access_id(str): ThreatConnect API Access ID.
            secret_key(str): ThreatConnect API Secret Key.
            request_type (str): Request Type like GET, POST, PUT, etc.

        Returns:
            header (dict) : Header for authentication.
        """
        unix_epoch_time = int(time.time())
        api_path = f"{api_path}:{request_type}:{unix_epoch_time}"
        bytes_api_path = bytes(api_path, "utf-8")
        bytes_secret_key = bytes(secret_key, "utf-8")

        # HMAC-SHA256
        dig = hmac.new(
            bytes_secret_key, msg=bytes_api_path, digestmod=hashlib.sha256
        ).digest()

        # BASE64 ENCODE
        hmac_sha256 = base64.b64encode(dig).decode()
        signature = f"TC {access_id}:{hmac_sha256}"
        header = {
            "Authorization": str(signature),
            "Timestamp": str(unix_epoch_time),
        }
        return header

    def get_reputation(self, ioc_response_json) -> int:
        """Get reputation value based on confidence score.

        Args:
            ioc_response_json (json): Single response JSON object.

        Returns:
            int: Reputation score ( >= 1 and <= 10).
        """
        # confidence is in between 0 and 100
        # reputation is in between 1 and 10.
        if "confidence" in ioc_response_json:
            reputation = ioc_response_json["confidence"]
            if reputation and reputation > 10:
                return round(reputation / 10)
            else:
                return 1
        else:
            return 5 # default value

    def get_api_url(self, api_path, threat_type):
        """Get API url.

        Args:
            api_path (str): API endpoint.
            threat_type (str): Type of data to pull.

        Returns:
            str: return API url endpoint.
        """
        result_start = 0
        if self.last_run_at:
            last_run_time = self.last_run_at
            last_run_time = last_run_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            last_run_time = datetime.datetime.now() - datetime.timedelta(
                days=self.configuration.get("days")
            )
            last_run_time = last_run_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        query = f"typeName IN {tuple(threat_type)}"
        query += f" AND lastModified >= '{last_run_time}'"

        filtered_string = "tql=" + urllib.parse.quote(query)
        api_url = f"{api_path}?sorting=lastModified%20asc&fields=tags&{filtered_string}"
        api_url += f"&resultStart={result_start}&resultLimit={LIMIT}"
        return api_url

    def get_pull_request(self, api_url):
        """Make pull request to get data from ThreatConnect.

        Args:
            api_url (str): API url endpoint.

        Returns:
            Response: Return API response.
        """
        headers = self._get_headers_for_auth(
            api_url,
            self.configuration.get("access_id", "").strip(),
            self.configuration.get("secret_key", ""),
            "GET",
        )
        query_endpoint = self.configuration.get("base_url", "").strip() + api_url
        ioc_response = self._api_calls(
            "get",
            query_endpoint,
            headers
        )
        return ioc_response

    def make_indicators(self, ioc_response_json, indicator_list):
        """Add received data to Netskope.

        Args:
            ioc_response_json (_type_): _description_
            tagging (_type_): _description_
            indicator_list (_type_): _description_
        """
        md5, sha256, url_ioc, file_count, address, host = 0, 0, 0, 0, 0, 0
        (
            skipped_md5,
            skipped_sha256,
            skipped_url,
            skipped_ioc,
            skipped_address,
            skipped_host,
        ) = (0, 0, 0, 0, 0, 0)
        skipped_tags = set()
        skipped_tags_due_to_val_err = set()
        tag_utils = TagUtils()
        for ioc_json in ioc_response_json["data"]:
            skipped_tag_val_err, skipped = [], []
            if (
                "tags" in ioc_json
                and "data" in ioc_json["tags"]
                and TAG_NAME
                in [
                    tag_info["name"]
                    for tag_info in ioc_json["tags"]["data"]
                    if "name" in tag_info
                ]
            ):
                skipped_ioc += 1
                continue
            tag_list, tags = [], []
            if (
                self.configuration.get("enable_tagging", "No") == "Yes"
                and "tags" in ioc_json
                and ioc_json["tags"] != {}
            ):
                for tag_json in ioc_json.get("tags", {}).get("data", []):
                    if tag_json.get("name"):
                        tag_list.append(tag_json["name"])

                tags, skipped_tag_val_err, skipped = self._create_tags(
                    tag_utils,
                    tag_list,
                    self.configuration,
                )

            if ioc_json["type"] == "File":
                file_count += 1
                if "md5" in ioc_json:
                    try:
                        type_tags, skipped_type_tag_val_err, skipped_type_tag = self._create_tags(
                            tag_utils,
                            ["ThreatConnect-File-MD5"],
                            self.configuration,
                        )
                        skipped_tag_val_err = skipped_tag_val_err + skipped_type_tag_val_err
                        skipped = skipped + skipped_type_tag
                        indicator_list.append(
                            Indicator(
                                value=ioc_json["md5"].lower(),
                                type=IndicatorType.MD5,
                                active=ioc_json.get("active", True),
                                severity=RATING_TO_SEVERITY[ioc_json.get("rating", 0)],
                                reputation=self.get_reputation(ioc_json),
                                comments=ioc_json.get("description", ""),
                                firstSeen=ioc_json.get("dateAdded"),
                                lastSeen=ioc_json.get("lastModified"),
                                tags=tags+type_tags if type_tags else tags,
                            )
                        )
                        md5 += 1
                    except Exception:
                        skipped_md5 += 1

                if "sha256" in ioc_json:
                    try:
                        type_tags, skipped_type_tag_val_err, skipped_type_tag = self._create_tags(
                            tag_utils,
                            ["ThreatConnect-File-SHA256"],
                            self.configuration,
                        )
                        skipped_tag_val_err = skipped_tag_val_err + skipped_type_tag_val_err
                        skipped = skipped + skipped_type_tag
                        indicator_list.append(
                            Indicator(
                                value=ioc_json["sha256"].lower(),
                                type=IndicatorType.SHA256,
                                active=ioc_json.get("active", True),
                                severity=RATING_TO_SEVERITY[ioc_json.get("rating", 0)],
                                reputation=self.get_reputation(ioc_json),
                                comments=ioc_json.get("description", ""),
                                firstSeen=ioc_json.get("dateAdded"),
                                lastSeen=ioc_json.get("lastModified"),
                                tags=tags+type_tags if type_tags else tags,
                            )
                        )
                        sha256 += 1
                    except Exception:
                        skipped_sha256 += 1
            elif ioc_json.get("type", "") == "Address":
                try:
                    tag_type = ["ThreatConnect-Address-IPV4"] if type(ip_address(ioc_json.get("ip", ""))) is IPv4Address else ["ThreatConnect-Address-IPV6"]
                    type_tags, skipped_type_tag_val_err, skipped_type_tag = self._create_tags(
                        tag_utils,
                        tag_type,
                        self.configuration,
                    )
                    skipped_tag_val_err = skipped_tag_val_err + skipped_type_tag_val_err
                    skipped = skipped + skipped_type_tag
                    indicator_list.append(
                        Indicator(
                            value=ioc_json.get("ip"),
                            type=IndicatorType.URL,
                            active=ioc_json.get("active", True),
                            severity=RATING_TO_SEVERITY[ioc_json.get("rating", 0)],
                            reputation=self.get_reputation(ioc_json),
                            comments=ioc_json.get("description", ""),
                            firstSeen=ioc_json.get("dateAdded"),
                            lastSeen=ioc_json.get("lastModified"),
                            tags=tags+type_tags if type_tags else tags,
                        )
                    )
                    address += 1
                except Exception:
                    skipped_address += 1
            elif ioc_json.get("type", "") == "Host":
                try:
                    type_tags, skipped_type_tag_val_err, skipped_type_tag = self._create_tags(
                        tag_utils,
                        ["ThreatConnect-Host"],
                        self.configuration,
                    )
                    skipped_tag_val_err = skipped_tag_val_err + skipped_type_tag_val_err
                    skipped = skipped + skipped_type_tag
                    indicator_list.append(
                        Indicator(
                            value=ioc_json.get("hostName"),
                            type=IndicatorType.URL,
                            active=ioc_json.get("active", True),
                            severity=RATING_TO_SEVERITY[ioc_json.get("rating", 0)],
                            reputation=self.get_reputation(ioc_json),
                            comments=ioc_json.get("description", ""),
                            firstSeen=ioc_json.get("dateAdded"),
                            lastSeen=ioc_json.get("lastModified"),
                            tags=tags+type_tags if type_tags else tags,
                        )
                    )
                    host += 1
                except Exception:
                    skipped_host += 1
            else:
                for url in ioc_json["text"].split(","):
                    try:
                        type_tags, skipped_type_tag_val_err, skipped_type_tag = self._create_tags(
                            tag_utils,
                            ["ThreatConnect-URL"],
                            self.configuration,
                        )
                        skipped_tag_val_err = skipped_tag_val_err + skipped_type_tag_val_err
                        skipped = skipped + skipped_type_tag
                        indicator_list.append(
                            Indicator(
                                value=url,
                                type=IndicatorType.URL,
                                active=ioc_json.get("active", True),
                                severity=RATING_TO_SEVERITY[ioc_json.get("rating", 0)],
                                reputation=self.get_reputation(ioc_json),
                                comments=ioc_json.get("description", ""),
                                firstSeen=ioc_json.get("dateAdded"),
                                lastSeen=ioc_json.get("lastModified"),
                                tags=tags+type_tags if type_tags else tags,
                            )
                        )
                        url_ioc += 1
                    except Exception:
                        skipped_url += 1
            skipped_tags_due_to_val_err.update(skipped_tag_val_err)
            skipped_tags.update(skipped)

        if len(skipped_tags_due_to_val_err) > 0:
            self.logger.info(
                f"{self.log_prefix}: {len(skipped_tags_due_to_val_err)} tag(s) skipped as they were longer than expected size: ({', '.join(skipped_tags_due_to_val_err)})."
            )
        if len(skipped_tags) > 0:
            self.logger.info(
                f"{self.log_prefix}: {len(skipped_tags)} tag(s) skipped as some failure occurred while creating these tags: ({', '.join(skipped_tags)})."
            )
        self.logger.debug(
            f"{self.log_prefix}: Pull Stats - File: {file_count}(MD5: {md5}, SHA256: {sha256}), URL: {url_ioc}, Address: {address}, Host: {host}. Skipped IOC(s) as they were previously shared by Netskope CE: {skipped_ioc}. "
            "Skipped IOC(s) as some error occurred while creating these IOC(s): "
            f"MD5({skipped_md5}), SHA256({skipped_sha256}), URL({skipped_url}), Address({skipped_address}), Host({skipped_host})."
        )
        total_ioc_count = md5 + sha256 + url_ioc + address + host
        total_skipped_count = skipped_md5 + skipped_sha256 + skipped_url + skipped_address + skipped_host + skipped_ioc
        total_skipped_tags = len(skipped_tags) + len(skipped_tags_due_to_val_err)
        return total_ioc_count, total_skipped_count, total_skipped_tags

    def pull_data_from_threatconnect(
        self, api_path: str, threat_type: str
    ) -> List[Indicator]:
        """Fetch Data from ThreatConnect API.

        Args:
            api_path (str): API endpoint.
            threat_type (str): Type of threat data.
            tagging (bool): Enable or disable tagging.

        Returns:
            List[Indicator]: List of Indicator Models.
        """
        indicator_list = []
        total_ioc_fetched, total_ioc_skipped, total_tag_skipped = 0, 0, 0
        page_count = 0
        api_url = None
        if self.storage is not None:
            storage = self.storage
        else:
            storage = {}
        display_storage = copy.deepcopy(storage)
        configuration_details = {}
        next_uri = ""
        if (
            display_storage
            and display_storage.get("configuration_details", {}).get("access_id", "").strip()
            and display_storage.get("configuration_details", {}).get("secret_key", "")
        ):
            del display_storage["configuration_details"]["access_id"]
            del display_storage["configuration_details"]["secret_key"]
            next_uri = display_storage.get("next_uri", "")
            configuration_details = display_storage.get("configuration_details", {})
        debug_msg = (
            f"{self.log_prefix}: Pulling the indicators, configuration_details from storage: {configuration_details}"
        )
        if next_uri:
            debug_msg += f", next_uri from storage: {next_uri}."
        self.logger.debug(debug_msg)
        api_url = storage.get("next_uri")
        prev_configuration = storage.get("configuration_details", {})
        prev_base_url = prev_configuration.get("base_url", "").strip()
        prev_access_id = prev_configuration.get("access_id", "").strip()
        prev_secret_key = prev_configuration.get("secret_key", "")
        prev_threat_type = prev_configuration.get("threat_type", [])
        base_url = self.configuration.get("base_url", "").strip()
        access_id = self.configuration.get("access_id", "").strip()
        secret_key = self.configuration.get("secret_key", "")

        configuration_match = (
            prev_base_url.strip("/") == base_url.strip("/")
            and prev_access_id == access_id
            and prev_secret_key == secret_key
            and prev_threat_type == threat_type
        )
        self.logger.debug(
            f"{self.log_prefix}: Previous configuration's comparison with current configuration. Match result: {configuration_match}."
        )
        if not (api_url and configuration_match):
            api_url = self.get_api_url(api_path, threat_type)

        while True:
            self.logger.debug(
                f"{self.log_prefix}: API URL to fetch the indicators for page {page_count + 1}: {api_url}."
            )
            try:
                ioc_response = self.get_pull_request(
                    api_url,
                )
                self.logger.debug(
                    f"{self.log_prefix}: Pull API Response code for page {page_count + 1}: {ioc_response.status_code}."
                )
                ioc_response_json = self.handle_error(ioc_response)
            except ThreatConnectException:
                storage.clear()
                storage["next_uri"] = api_url
                storage["configuration_details"] = self.configuration
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"Total indicator(s) fetched {total_ioc_fetched}, skipped {total_ioc_skipped} indicator(s), total {total_tag_skipped} tag(s) skipped."
                )
                return indicator_list
            except Exception as ex:
                storage.clear()
                storage["next_uri"] = api_url
                storage["configuration_details"] = self.configuration
                err_msg = (
                    f"{self.log_prefix}: Error occurred while executing the pull cycle. "
                    "The pulling of the indicators will be resumed in the next pull cycle. "
                    f"Error: {ex}."
                )
                self.logger.error(message=err_msg, details=traceback.format_exc())
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"Total indicator(s) fetched {total_ioc_fetched}, skipped {total_ioc_skipped} indicator(s), total {total_tag_skipped} tag(s) skipped."
                )
                return indicator_list
            if ioc_response_json.get("status", "") != "Success":
                raise requests.exceptions.HTTPError(
                    f"{self.log_prefix}: Unable to fetch Indicator. "
                    f"Error: {ioc_response_json.get('message', '')}."
                )
            elif ioc_response_json.get("data", None):
                ioc_count_per_page, ioc_skipped_per_page, tag_skipped_per_page = self.make_indicators(
                    ioc_response_json, indicator_list
                )
                total_ioc_fetched += ioc_count_per_page
                total_ioc_skipped += ioc_skipped_per_page
                total_tag_skipped += tag_skipped_per_page
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched {ioc_count_per_page} indicator(s) for page {page_count + 1}. "
                    f"Total Indicators fetched - {total_ioc_fetched}."
                )
                # Handling Result Limit Of API
                if ioc_response_json.get("next", None):
                    api_url = ioc_response_json["next"].replace(
                        self.configuration.get("base_url", "").strip("/"), ""
                    )
                else:
                    storage.clear()
                    storage["configuration_details"] = self.configuration
                    self.logger.info(
                        f"{self.log_prefix}: Completed fetching indicators for the plugin. "
                        f"Total indicator(s) fetched {total_ioc_fetched}, skipped {total_ioc_skipped} indicator(s), total {total_tag_skipped} tag(s) skipped."
                    )
                    return indicator_list
            else:
                # case: status -> Success, return -> []
                storage.clear()
                storage["configuration_details"] = self.configuration
                self.logger.info(
                    f"{self.log_prefix}: Completed fetching indicators for the plugin. "
                    f"Total indicator(s) fetched {total_ioc_fetched}, skipped {total_ioc_skipped} indicator(s), total {total_tag_skipped} tag(s) skipped."
                )
                return indicator_list

            page_count += 1
            if page_count >= PAGE_LIMIT:
                storage["next_uri"] = api_url
                storage["configuration_details"] = self.configuration
                self.logger.info(
                    f"{self.log_prefix}: Page limit of {PAGE_LIMIT} has reached. Returning {len(indicator_list)} indicator(s). "
                    "The pulling of the indicators will be resumed in the next pull cycle."
                )
                self.logger.info(
                    f"{self.log_prefix}: Completed fetching indicators for the plugin. "
                    f"Total indicator(s) fetched {total_ioc_fetched}, skipped {total_ioc_skipped} indicator(s), total {total_tag_skipped} tag(s) skipped."
                )
                return indicator_list

    def _create_tags(
        self, utils: TagUtils, tags: List[dict], configuration: dict
    ) -> (List[str], List[str]):
        """Create new tag(s) in database if required."""

        tag_names, skipped_tags_val_err, skipped_tags = [], [], []
        for tag in tags:
            try:
                if tag is not None and not utils.exists(tag.strip()):
                    utils.create_tag(TagIn(name=tag.strip(), color="#ED3347"))
            except ValueError:
                skipped_tags_val_err.append(tag)
            except Exception:
                skipped_tags.append(tag)
            else:
                tag_names.append(tag)
        return tag_names, skipped_tags_val_err, skipped_tags

    def _api_calls(self, method, url_endpoint, headers, params={}, json={}):
        try:
            req = getattr(requests, method)
            headers = self._add_user_agent(headers)
            for retry_count in range(MAX_RETRY):
                response = req(
                    url_endpoint,
                    headers=headers,
                    params=params,
                    json=json,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                )
                if response.status_code in [500, 503] or (response.status_code == 400 and "TQL Parse Error" in response.text):
                    retry_after = (retry_count + 1) * 30
                    if response.status_code == 400:
                        error_code = "TQL Parse Error"
                    else:
                        error_code = "Server Error"
                    msg = (
                            f"{self.log_prefix}: Received Error Code {response.status_code}, "
                            f"{error_code}: "
                            f"Retrying after {retry_after} seconds."
                        )
                    self.logger.error(message=msg, details=response.text)
                    time.sleep(retry_after)
                    continue
                else:
                    break
            return response
        except requests.exceptions.ProxyError as err:
            err_msg = (
                "Invalid proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise ThreatConnectException(err_msg)
        except requests.exceptions.ConnectionError as err:
            err_msg = (
                "Connection Error occurred. Check the Base URL provided."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise ThreatConnectException(err_msg)
        except requests.exceptions.RequestException as err:
            err_msg = "Request Exception occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise ThreatConnectException(err)
        except Exception as err:
            raise Exception(err)

    def _is_valid_credentials(
        self, base_url: str, access_id: str, secret_key: str
    ) -> bool:
        """Validate credentials.

        Args:
            access_id (str): Access ID for ThreatConnect.
            secret_key (str): Secret Key for ThreatConnect.

        Returns:
            bool: True for valid credentials and false for not valid.
        """
        api_path = "/api/v3/security/owners"
        query_endpoint = base_url + api_path
        headers = self._get_headers_for_auth(
            api_path,
            access_id,
            secret_key,
            "GET",
        )
        response = self._api_calls(
                "get",
                query_endpoint,
                headers
            )
        if response.status_code == 400:
            err_msg = "Validation Failed. Check the provided Secret Key."
            self.logger.error(
                f"{self.log_prefix}: "
                f"{err_msg}",
                details=response.text,
            )
            raise ThreatConnectException(f"{err_msg} Check logs for more details.")
        self.handle_error(response)
        if response.status_code == 200 or response.status_code == 201:
            return True
        else:
            self.logger.error(
                message=f"{self.log_prefix}: Invalid Access ID or Secret Key Provided.",
                details=response.text,
            )
            return False

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urllib.parse.urlparse(url.strip())
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the configuration.

        Args:
            configuration(dict): Configuration from manifest.json.

        Returns:
            ValidationResult: Valid configuration fields or not.
        """
        # Base URL
        base_url = configuration.get("base_url", "").strip()
        if "base_url" not in configuration or not base_url:
            err_msg = "Base URL is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif (
            not isinstance(base_url, str)
            or not self._validate_url(base_url)
            or "threatconnect" not in base_url
        ):
            err_msg = "Invalid Base URL Provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Access_ID
        access_id = configuration.get("access_id", "").strip()
        if "access_id" not in configuration or not access_id:
            err_msg = "Access ID is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(access_id, str):
            err_msg = "Invalid Access ID provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Secret Key
        secret_key = configuration.get("secret_key", "")
        if "secret_key" not in configuration or not secret_key:
            err_msg = "Secret Key is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(secret_key, str):
            err_msg = "Invalid Secret Key provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Type of Indicator
        threat_ioc_type = configuration.get("threat_type", [])
        if "threat_type" not in configuration or not threat_ioc_type:
            err_msg = "Threat Indicator Type is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(threat_ioc_type, list):
            err_msg = "Invalid Threat Indicator Type provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not (set(threat_ioc_type).issubset(INDICATOR_TYPES)):
            available_types = ", ".join(INDICATOR_TYPES)
            err_msg = (
                "Invalid value for Threat Indicator Type provided. "
                f"Available values are: {available_types}."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Enable Tagging
        enable_tagging = configuration.get("enable_tagging", "No").strip()
        if "enable_tagging" not in configuration or not enable_tagging:
            err_msg = "Enable Tagging is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif enable_tagging not in ["Yes", "No"]:
            err_msg = "Invalid value for Enable Tagging provided. Avialable values are 'Yes' or 'No'."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Enable Polling
        enable_polling = configuration.get("is_pull_required", "Yes").strip()
        if "is_pull_required" not in configuration or not enable_polling:
            err_msg = "Enable Polling is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif enable_polling not in ["Yes", "No"]:
            err_msg = "Invalid value for Enable Polling provided. Avialable values are 'Yes' or 'No'."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Initial Range
        initial_range = configuration.get("days", 0)
        if "days" not in configuration or initial_range is None:
            err_msg = "Initial Range (in days) is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(initial_range, int):
            err_msg = (
                "Invalid value for Initial Range (in days) provided. "
                "Must be an integer."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif int(initial_range) <= 0 or int(initial_range) > 365:
            err_msg = (
                "Invalid value for Initial Range (in days) provided. "
                "Select a value between 1 - 365."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        try:
            if not self._is_valid_credentials(
                base_url,
                access_id,
                secret_key,
            ):
                err_msg = "Invalid Access ID or Secret Key Provided."
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )
        except ThreatConnectException as err:
            return ValidationResult(
                success=False,
                message=f"{err}",
            )
        except Exception as err:
            err_msg = f"Invalid Base URL, Access ID or Secret Key provided."
            self.logger.error(
                message=f"{self.log_prefix}:  {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def pull(self) -> List[Indicator]:
        """Pull Indicators data from ThreatConnect API.

        Returns:
            List[Indicator] : Return List of Indicators Models.
        """
        if self.configuration.get("is_pull_required", "Yes") == "Yes":
            api_path = "/api/v3/indicators"
            return self.pull_data_from_threatconnect(
                api_path, self.configuration["threat_type"]
            )
        else:
            self.logger.info(f"{self.log_prefix}: Polling is disabled, indicators will not be fetched.")
            return []

    def get_group_id(self, action_dict):
        """Return group id based on condition.

        Args:
            action_dict (Dict): Aciton dictionary.

        Returns:
            str: Return group id.
        """
        group_names = self.get_group_names()
        if action_dict.get("parameters", {}).get("group_name", "") != "create_group":
            if (
                action_dict.get("parameters", {}).get("group_name", "")
                not in group_names.values()
            ):
                err_msg = (
                    "The group selected in the sharing configuration "
                    f"no longer exists on {PLATFORM_NAME}, sharing will be skipped."
                )
                self.logger.error(
                    f"{self.log_prefix}: {err_msg}"
                )
                raise ThreatConnectException(err_msg)
            return action_dict.get("parameters")["group_name"]
        # Creating  New Group
        api_path = "/api/v3/groups/"
        create_group_api = self.configuration.get("base_url", "").strip() + api_path
        headers = self._get_headers_for_auth(
            api_path,
            self.configuration.get("access_id", "").strip(),
            self.configuration.get("secret_key", ""),
            "POST",
        )
        if (
            action_dict.get("parameters", {}).get("new_group_name", "").strip()
            not in group_names
        ):
            data = {
                "name": action_dict.get("parameters", {}).get("new_group_name", "").strip(),
                "type": action_dict.get("parameters", {}).get("new_group_type", "").strip(),
                "tags": {
                    "data": [
                        {"name": TAG_NAME},
                    ]
                },
            }
            response = self._api_calls(
                "post",
                create_group_api,
                headers,
                params={},
                json=data
            )
            response_json = self.parse_response(response)
            if (
                response_json.get("status", "") == "Success"
                and "data" in response_json
                and "name" in response_json.get("data", [])
                and "id" in response_json.get("data", [])
            ):
                action_dict["parameters"]["group_name"] = response_json["data"][
                    "name"
                ]
                return response_json["data"]["id"]
            else:
                err_msg = (
                    f"{self.log_prefix}: Error while creating a group."
                )
                self.logger.error(
                    message=err_msg,
                    details=f"Error: {response_json.get('message', 'Error message not available.')}"
                )
        else:
            return group_names[action_dict.get("parameters", {})["new_group_name"]]

    def prepare_payload(self, indicator, existing_group_id):
        """Prepare payload for request.

        Args:
            indicator (Indicator): given indicators.
            existing_group_id (_type_): group id.

        Returns:
            Dict: return dictionary of data.
        """
        data = {}
        if indicator.type == IndicatorType.URL and 1 <= len(indicator.value) <= 500:
            url_subtype = self.check_url_domain_ip(indicator.value)
            if url_subtype == "Address":
                data["ip"] = indicator.value
            elif url_subtype == "Host":
                data["hostName"] = indicator.value
            else:
                data["text"] = indicator.value
            data["type"] = url_subtype
        elif indicator.type == IndicatorType.MD5:
            data["md5"] = indicator.value
            data["type"] = "File"
        elif indicator.type == IndicatorType.SHA256:
            data["sha256"] = indicator.value
            data["type"] = "File"
        data["associatedGroups"] = {
            "data": [
                {
                    "id": existing_group_id,
                }
            ]
        }
        data["tags"] = {"data": [{"name": TAG_NAME}]}
        data["rating"] = SEVERITY_TO_RATING[indicator.severity]
        data["confidence"] = indicator.reputation * 10
        return data

    def update_ioc(self, value, group_id):
        """Update IoCs metadata for mutiple groups.

        Args:
            value (str): value of IoC
            group_id (str): group id

        Returns:
            Response: return Response object.
        """
        api_path = f"/api/v3/indicators/{value}"
        url = self.configuration.get("base_url", "").strip() + api_path
        headers = self._get_headers_for_auth(
            api_path,
            self.configuration.get("access_id", "").strip(),
            self.configuration.get("secret_key", ""),
            "PUT",
        )
        update_data = {
            "associatedGroups": {
                "data": [
                    {"id": group_id},
                ],
                "mode": "append",
            },
        }
        response = self._api_calls(
            "put",
            url,
            headers,
            params={},
            json=update_data,
        )
        return response

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push Indicators to ThreatConnect Platform.

        Args:
            indicators (List[Indicator]): List of Indicators to push.
            action_dict (Dict): action dictionary for performing actions.

        Returns:
            PushResult: return PushResult object with success and message
            parameters.
        """
        try:
            existing_group_id = self.get_group_id(action_dict)
            api_path = "/api/v3/indicators"
            query_endpoint = self.configuration.get("base_url", "").strip() + api_path
            invalid_ioc, indicator_pushed = 0, 0
            already_exists = 0
            self.logger.debug(
                f"{self.log_prefix}: API URL to share the indicators: {query_endpoint}."
            )
            total_ioc_received = 0
            try:
                for indicator in indicators:
                    total_ioc_received += 1
                    if indicator.type == IndicatorType.URL and len(indicator.value) > 500:
                        invalid_ioc += 1
                        continue
                    data = self.prepare_payload(indicator, existing_group_id)
                    headers = self._get_headers_for_auth(
                        api_path,
                        self.configuration.get("access_id", "").strip(),
                        self.configuration.get("secret_key", ""),
                        "POST",
                    )
                    response = self._api_calls(
                        "post",
                        query_endpoint,
                        headers,
                        params={},
                        json=data
                    )
                    response_json = self.parse_response(response)
                    debug_message = f"{self.log_prefix}: Push response status code for indicator for {indicator.value} : {response.status_code}."
                    if response.status_code not in [200, 201]:
                        debug_message += f" Response: {response.text}"
                    self.logger.debug(debug_message)
                    if (
                        response_json.get("status", "") == "Success"
                        and response_json.get("message", "") == "Created"
                    ):
                        indicator_pushed += 1
                        continue
                    elif response_json.get("message", "").endswith("already exists"):
                        response = self.update_ioc(
                            indicator.value.upper(),
                            data["associatedGroups"]["data"][0]["id"],
                        )
                        if response_json.get("status", "") == "Success":
                            already_exists += 1
                        else:
                            err_msg = (
                                f"{self.log_prefix}: Error while updating indicator - {indicator.value} metadata."
                            )
                            self.logger.error(
                                message=err_msg,
                                details=response_json.get('message', 'Error message not available.')
                            )
                            invalid_ioc += 1
                    elif (
                        response_json.get("message", "").startswith("Please enter a valid")
                        or response_json.get("message", "") == "This Indicator is contained on a "
                        "system-wide exclusion list."
                    ):
                        err_msg = f"{self.log_prefix}: Failed to push indicator - {indicator.value} to {PLATFORM_NAME}."
                        self.logger.error(
                            message=err_msg,
                            details=f"Failed to push indicator. Error: {response_json.get('message')}"
                        )
                        invalid_ioc += 1
                    else:
                        err_msg = (
                            f"{self.log_prefix}: Failed to push indicator - {indicator.value} to {PLATFORM_NAME}."
                        )
                        self.logger.error(
                            message=err_msg,
                            details=response_json.get('message', 'No error message available.')
                        )
                        invalid_ioc += 1
                self.logger.info(
                    f"{self.log_prefix}: Push Stats: "
                    f"indicator(s) received - {total_ioc_received}, "
                    f"indicator(s) sucessfully pushed - {indicator_pushed}, "
                    f"indicator(s) already exists(modified) - {already_exists}, "
                    f"indicator(s) failed to share: {invalid_ioc}."
                )
                return PushResult(
                    success=True,
                    message=f"Indicators pushed successfully to {PLATFORM_NAME}.",
                )
            except ThreatConnectException as error_msg:
                return PushResult(
                        success=False,
                        message=f"{error_msg}",
                    )
            except Exception as err:
                error_msg = (
                    f"{self.log_prefix}: Error Ocurred while ingesting indicators to {PLATFORM_NAME}. "
                    f"Error: {err}"
                )
                self.logger.error(message=error_msg, details=traceback.format_exc())
                return PushResult(
                    success=False,
                    message=error_msg,
                )
        except ThreatConnectException as error_msg:
            return PushResult(
                    success=False,
                    message=f"{error_msg}",
                )
        except Exception as err:
            error_msg = (
                f"{self.log_prefix}: Error Occurred while fetching group IDs. "
                f"Error: {err}"
            )
            self.logger.error(message=error_msg, details=traceback.format_exc())
            return PushResult(
                success=False,
                message=error_msg,
            )

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available Actions.

        Returns:
            List[ActionWithoutParams]: Return list of actions.
        """
        return [ActionWithoutParams(label="Add to Group", value="add_to_group")]

    def get_owner(self):
        """Get owner information from given API credentials.

        Returns:
            str: Name of owner.
        """
        api_path = "/api/v2/owners/mine"
        headers = self._get_headers_for_auth(
            api_path,
            self.configuration.get("access_id", "").strip(),
            self.configuration.get("secret_key", ""),
            "GET",
        )
        endpoint = self.configuration.get("base_url", "").strip() + api_path
        # Fetching owner_name
        try:
            response = self._api_calls(
                "get",
                endpoint,
                headers
            )
            response_json = self.parse_response(response)
            if (
                response_json.get("status", "") == "Success"
                and "data" in response_json
                and "owner" in response_json.get("data", [])
                and "name" in response_json.get("data", []).get("owner", "")
            ):
                return response_json.get("data").get("owner").get("name")

            # Not able to fetch Owner.
            err_msg = (
                f"{self.log_prefix}: Error while fetching owner information."
            )
            self.logger.error(
                message=err_msg,
                details=f"Error: {response_json.get('message', 'Error message not available.')}"
            )
            return None
        except ThreatConnectException:
            return None
        except Exception as err:
            err_msg = (
                f"{self.log_prefix}: Error while fetching owner information. "
                f"Error: {err}"
            )
            self.logger.error(message=err_msg, details=traceback.format_exc())
            return None

    def get_group_names(self) -> Dict:
        """Get names of available group along with id.

        Returns:
            Dict: dictionary of group name as key and group id as value.
        """
        owner_name = self.get_owner()
        if owner_name:
            query = urllib.parse.quote(f"ownerName == '{owner_name}'")
            api_path = f"/api/v3/groups?tql={query}&resultLimit={LIMIT}"
            url = self.configuration.get("base_url", "").strip() + api_path
            group_names = {}

            while True:
                headers = self._get_headers_for_auth(
                    api_path,
                    self.configuration.get("access_id", "").strip(),
                    self.configuration.get("secret_key", ""),
                    "GET",
                )
                # Fetching group Name based on owner name.
                try:
                    response = self._api_calls(
                        "get",
                        url,
                        headers
                    )
                    response_json = self.parse_response(response)
                    if response_json.get("status", "") == "Success":
                        for group_info in response_json.get("data", []):
                            if (
                                "name" in group_info
                                and "id" in group_info
                                and group_info.get("name", "") not in group_names
                            ):
                                group_names[group_info["name"]] = str(group_info.get("id", ""))

                        if response_json.get("next", None):
                            api_path = (
                                response_json
                                .get("next")
                                .replace(self.configuration.get("base_url", "").strip(), "")
                            )
                            url = response_json.get("next", None)
                        else:
                            return group_names
                    else:
                        # Not able to fetch Groups.
                        err_msg = (
                            f"{self.log_prefix}: Error while fetching group details."
                        )
                        self.logger.error(
                            message=err_msg,
                            details=f"Error: {response_json.get('message', 'Error message not available.')}"
                        )
                        break
                except ThreatConnectException:
                    break
                except Exception as err:
                    err_msg = (
                        f"{self.log_prefix}: Error while fetching group details. "
                        f"Error: {err}"
                    )
                    self.logger.error(message=err_msg, details=traceback.format_exc())
                    break

    def get_action_fields(self, action: Action) -> List[Dict]:
        """Get action fields for a given action.

        Args:
            action (Action): Given action.

        Returns:
            List[Dict]: List of configuration parameters for a given action.
        """
        if action.value == "add_to_group":
            group_names = dict(sorted(self.get_group_names().items()))
            group_types = [
                "Adversary",
                "Attack Pattern",
                "Campaign",
                "Course of Action",
                "Email",
                "Event",
                "Incident",
                "Intrusion Set",
                "Malware",
                "Tactic",
                "Task",
                "Threat",
                "Tool",
                "Vulnerability",
            ]  # Document, Report, Signature not supported.
            return [
                {
                    "label": "Add to Existing Group",
                    "key": "group_name",
                    "type": "choice",
                    "choices": [
                        {"key": group_name, "value": group_id}
                        for group_name, group_id in group_names.items()
                    ]
                    + [{"key": "Create New Group", "value": "create_group"}],
                    "mandatory": True,
                    "description": f"Available groups on {PLATFORM_NAME}.",
                },
                {
                    "label": "Name of New Group (only applicable for Create "
                    "New Group)",
                    "key": "new_group_name",
                    "type": "text",
                    "mandatory": False,
                    "default": "",
                    "description": "Name of new group in which you want to "
                    "add all your IoCs.",
                },
                {
                    "label": "Type of New Group (only applicable for Create "
                    "New Group)",
                    "key": "new_group_type",
                    "type": "choice",
                    "choices": [
                        {"key": group_type, "value": group_type}
                        for group_type in group_types
                    ],
                    "mandatory": False,
                    "default": "Incident",
                    "description": "Select group type for new group.",
                },
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate action configuration.

        Returns:
            ValidationResult: Valid configuration or not for action.
        """
        if action.value not in ["add_to_group"]:
            return ValidationResult(success=False, message="Invalid Action Provided.")
        if (
            action.value in ["add_to_group"]
            and action.parameters["group_name"] == "create_group"
            and action.parameters["new_group_name"].strip() == ""
        ):
            return ValidationResult(
                success=False,
                message="'Name of New Group' is a required field when 'Create New Group' is selected in the 'Add to Existing Group' parameter.",
            )
        if (
            action.value in ["add_to_group"]
            and action.parameters["group_name"] == "create_group"
            and action.parameters["new_group_type"].strip() == ""
        ):
            return ValidationResult(
                success=False,
                message="'Type of New Group' is a required field when 'Create New Group' is selected in the 'Add to Existing Group' parameter.",
            )
        return ValidationResult(
            success=True,
            message="Action configuration validated.",
        )
