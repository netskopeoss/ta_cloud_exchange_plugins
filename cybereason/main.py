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

"""Cybereason Plugin implementation to push and pull the data from Cybereason Platform."""


import os
import csv
import json
import math
import tempfile
import requests
import traceback
from datetime import datetime
from typing import List, Tuple, Dict
from pydantic import ValidationError
from urllib.parse import urlparse
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models.business_rule import (
    ActionWithoutParams,
    Action,
)
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
)
from .utils.cybereason_helper import (
    CybereasonPluginHelper,
    CybereasonPluginException,
)
from netskope.common.utils import add_user_agent
from .utils.cybereason_constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PLATFORM_NAME,
    IOC_DESCRIPTION,
    DATE_FORMAT_FOR_IOCS,
    INTERNAL_TYPES_TO_CYBEREASON,
)


class CybereasonPlugin(PluginBase):
    """CybereasonPlugin class having concrete implementation for pulling and pushing threat information."""

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
        self.cybereason_helper = CybereasonPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = CybereasonPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            err_msg = f"Error occurred while getting plugin details. Error"
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}:{exp}."
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _get_credentials(self, configuration: Dict):
        """Get API Credentials.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            Tuple: Tuple containing Base URL, API Username, API Password and is_pull_required.
        """
        return (
            configuration.get("base_url", "").strip().strip("/"),
            configuration.get("username", "").strip(),
            configuration.get("password", ""),
            configuration.get("is_pull_required").strip(),
        )

    def get_headers(self) -> Dict:
        """Get headers required for the API call."""
        return self.cybereason_helper._add_user_agent(
            {
                "Content-Type": "application/json",
            }
        )

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        (base_url, username, password, is_pull_required) = (
            self._get_credentials(configuration)
        )
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(base_url, str):
            err_msg = "Invalid Base URL, Type of Base URL should be String."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not self._validate_url(base_url):
            err_msg = (
                "Invalid Base URL provided in the configuration parameter."
            )
            self.logger.error(
                f"{validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if not username:
            err_msg = "Username is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(username, str):
            err_msg = "Invalid Username provided."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not password:
            err_msg = "Password is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(password, str):
            err_msg = (
                "Invalid Password provided, Type of Password should be String."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not is_pull_required:
            err_msg = "Enable Polling is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif is_pull_required not in ["Yes", "No"]:
            err_msg = (
                "Invalid value provided in Enable Polling configuration"
                " parameter. Allowed values are Yes and No."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self.validate_auth_params(configuration, validation_err_msg)

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )
        
    def validate_auth_params(
        self, configuration, validation_err_msg
    ) -> ValidationResult:
        """Validate the authentication params with Cybereason platform.

        Args:
            username (str): API Username required to login to Cybereason console.
            password (str): API Password required to login to Cybereason console.
            base_url (str): Base url of Cybereason console.
        Returns:
            ValidationResult: ValidationResult object having validation results after making
            an API call.
        """

        (base_url, username, password, is_pull_required) = (
            self._get_credentials(configuration)
        )
        
        try:
            session = self.get_session(username, password, base_url)

            if not session.cookies.get_dict().get("JSESSIONID"):
                err_msg = "Error in validating Credentials"
                self.logger.error(f"{validation_err_msg} {err_msg}.")
                return ValidationResult(
                    success=False,
                    message=(
                        f"Validation Error, {err_msg}. "
                        "Please use the correct credentials."
                    ),
                )
            indicator_endpoint = (
                f"{base_url}/rest/classification/reputations/list"
            )
            headers = self.get_headers()
            json_payload = {
                "page": 0,
                "size": 1,
                "filter": {"includeExpired": False},
            }
            ioc_resp = self.cybereason_helper.api_helper(
                logger_msg="Validating Authentication parameters",
                method="POST",
                url=indicator_endpoint,
                headers=headers,
                data=json.dumps(json_payload),
                session=session,
                is_validation=True,
            )

            if ioc_resp.get("outcome", "") == "success":
                self.logger.debug(
                    f"{self.log_prefix}: Successfully Validated Authentication parameters."
                )
                msg = "Validation successful"
                return ValidationResult(
                    success=True,
                    message=msg,
                )
            else:
                err_msg = "Validation Error, Error in validating Credentials. Please verify the API Username and API Password."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=(err_msg),
                )
        except CybereasonPluginException as err:
            return ValidationResult(
                success=False,
                message=(str(err)),
            )
        except Exception as err:
            err_msg = "Validation Error, Error in validating Credentials. Please verify the API Username and API Password."
            self.logger.error(
                f"{self.log_prefix}: {err_msg} " 
                f"Error: {err}"
            )
            return ValidationResult(
                success=False,
                message=(err_msg),
            )

    def format_time(self, time_in_milliseconds):
        seconds = time_in_milliseconds / 1000
        formatted_time = datetime.fromtimestamp(seconds).strftime("%Y-%m-%dT%H:%M:%SZ")
        return formatted_time
    
    def get_indicators(self, session, headers):
        """Get detailed information by Detection IDs.

        Args:
            headers (dict): Header dict needed for the Cybereason API call.
        Returns:
            List[cte.models.Indicators]: List of indicator objects received from the Cybereason platform.
        """

        (base_url, _, _, _) = self._get_credentials(self.configuration)
        indicator_endpoint = f"{base_url}/rest/classification/reputations/list"
        headers = self.get_headers()

        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if sub_checkpoint:
            checkpoint = sub_checkpoint.get("checkpoint")
        else:
            checkpoint = self._get_cybereason_last_seen()

        self.logger.info(
            f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME}"
            f" platform using checkpoint {checkpoint}."
        )
        
        indicator_checkpoint = checkpoint

        next_page = True
        page_count = 0
        total_indicators = 0
        indicator_fetched_till_now = 0
        batch_size = 50000
        max_pages = 0
        try:
            while next_page:

                resp_json = self.cybereason_helper.api_helper(
                    logger_msg=f"Pulling data for page {page_count+1}",
                    url=indicator_endpoint,
                    method="POST",
                    data=json.dumps(
                        {
                            "page": page_count,
                            "size": batch_size,
                            "filter": {"includeExpired": False},
                        }
                    ),
                    headers=headers,
                    session=session,
                )
                if resp_json.get("outcome") == "success":
                    data = {}
                    indicators_json_list = []
                    data = resp_json.get("data", {})
                    if data and (not isinstance(data, str)):
                        indicators_json_list = data.get("reputations", [])
                        total_indicators = data.get("total", 0)
                        max_pages = math.ceil(total_indicators / batch_size)
                    else: 
                        err_msg = str(resp_json.get("data")) if resp_json.get("data") else f"Not able to fetch data from {PLATFORM_NAME}."
                        raise CybereasonPluginException(err_msg)
                else:     
                    err_msg = str(resp_json.get("data")) if resp_json.get("data") else f"Not able to fetch data from {PLATFORM_NAME}."
                    raise CybereasonPluginException(err_msg)
                
                indicator_list = []
                indicators_per_page = {
                    "total": 0,
                    "skipped": 0,
                    "ipv4": 0,
                    "ipv6": 0,
                    "md5": 0,
                    "sha256": 0,
                    "domain": 0,
                }

                for indicator in indicators_json_list:
                    indicator_checkpoint = indicator.get(
                        "lastUpdated",
                        str(datetime.now().strftime(DATE_FORMAT_FOR_IOCS)),
                    )

                    if indicator.get("maliciousType", "") == "blacklist":
                        ioc_type, ioc_category = self.get_indicator_type(
                            indicator.get("lookupKeyType")
                        )
                        indicator_comment = str(indicator.get("comment"))
                        if (
                            ioc_type
                            and IOC_DESCRIPTION.lower()
                            not in indicator_comment
                        ):
                            try:
                                firstseen_timestamp = indicator.get("firstSeen")
                                firstseen = (
                                    self.format_time(firstseen_timestamp) 
                                    if firstseen_timestamp 
                                    else None
                                )
                                    
                                lastseen_timestamp = indicator.get("lastUpdated")
                                lastseen = (
                                    self.format_time(lastseen_timestamp) 
                                    if lastseen_timestamp 
                                    else None
                                )
                                indicator_value = indicator.get("key")
                                indicator_list.append(
                                    Indicator(
                                        value=indicator_value,
                                        type=ioc_type,
                                        comments=(
                                            ""
                                            if str(indicator.get("comment"))
                                            .lower()
                                            .strip()
                                            == "null"
                                            else str(indicator.get("comment"))
                                        ),
                                        firstSeen=firstseen,
                                        lastSeen=lastseen,
                                    )
                                )
                                if ioc_category:
                                    indicators_per_page[ioc_category] += 1
                            except ValidationError:
                                indicators_per_page["skipped"] += 1
                        else:
                            indicators_per_page["skipped"] += 1
                        indicators_per_page["total"] += 1

                    else:
                        indicators_per_page["skipped"] += 1

                indicator_fetched_till_now += len(indicator_list)
                count_per_page_msg = (
                    "Successfully fetched {total} indicator(s) and skipped "
                    "{skipped} indicator(s) in page {page}. Pull Stats: "
                    "SHA256={SHA256}, Domain={domain}, md5={md5}, ipv4={ipv4}, ipv6={ipv6},"
                    " Total indicator(s) fetched: {indicator_fetched_till_now}".format(
                        total=len(indicator_list),
                        skipped=indicators_per_page["skipped"],
                        page=page_count + 1,
                        SHA256=indicators_per_page["sha256"],
                        domain=indicators_per_page["domain"],
                        md5=indicators_per_page["md5"],
                        ipv4=indicators_per_page["ipv4"],
                        ipv6=indicators_per_page["ipv6"],
                        indicator_fetched_till_now=indicator_fetched_till_now,
                    )
                )

                indicators_per_page_count = len(indicator_list)
                self.logger.info(
                    f"{self.log_prefix}: Fetched {indicators_per_page_count} indicators in page {page_count+1}"
                    f", Total indicators fetched till now {indicator_fetched_till_now}."
                )
                self.logger.debug(f"{self.log_prefix}: {count_per_page_msg}.")
                page_count += 1
                if page_count >= max_pages:
                    next_page = False

                if hasattr(self, "sub_checkpoint"):
                    yield indicator_list, {"checkpoint": indicator_checkpoint}
                else:
                    yield indicator_list

        except CybereasonPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error Occurred while pulling "
                    f"indicators from {PLATFORM_NAME}. Error: {err}."
                ),
                details=traceback.format_exc(),
            )
            raise CybereasonPluginException(str(err))
        except Exception as exp:
            err_msg = f"Error occurred while pulling indicators from {PLATFORM_NAME}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}.",
                details=traceback.format_exc(),
            )
            raise CybereasonPluginException(err_msg)
        
    def get_indicator_type(self, ioc_key):
        """Get indicator type from given IOC key."""
        ioc_type = None
        ioc_category = None
        if ioc_key == "DOMAIN":
            # URL
            ioc_type = IndicatorType.URL
            ioc_category = "domain"
        elif ioc_key == "IPV4":
            # URL
            ioc_type = IndicatorType.URL
            ioc_category = "ipv4"
        elif ioc_key == "IPV6":
            # URL
            ioc_type = IndicatorType.URL
            ioc_category = "ipv6"
        elif ioc_key == "FILE_HASH_MD5":
            # MD5
            ioc_type = IndicatorType.MD5
            ioc_category = "md5"
        elif ioc_key == "FILE_HASH_SHA256":
            # SHA256
            ioc_type = IndicatorType.SHA256
            ioc_category = "sha256"
        return ioc_type, ioc_category

    def _get_cybereason_last_seen(self) -> str:
        """Get Cybereason LastSeen Or DateChanged parameter.
        Returns:
            LastSeen/DateChanged (str):
                A datetime object as string representation.
        """
        if not self.last_run_at:
            start_time = datetime.now()
        else:
            start_time = self.last_run_at
        return start_time.strftime(DATE_FORMAT_FOR_IOCS)

    def pull(self):
        """Pull the Threat information from Cybereason platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects received from the Cybereason platform.
        """
        (base_url, username, password, is_pull_required) = (
            self._get_credentials(self.configuration)
        )
        try:
            if is_pull_required == "No":
                self.logger.info(
                    f"{self.log_prefix}: Polling is disabled in configuration "
                    "parameter hence skipping pulling of indicators from "
                    f"{PLATFORM_NAME}."
                )
                return []

            session = self.get_session(
                username,
                password,
                base_url,
            )

            headers = self.get_headers()

            if not session.cookies.get_dict().get("JSESSIONID"):
                err_msg = f"Unable to establish session with the {PLATFORM_NAME} console."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
            else:
                if hasattr(self, "sub_checkpoint"):

                    def wrapper(self):
                        yield from self.get_indicators(session, headers)

                    return wrapper(self)

                else:
                    indicators = []
                    for batch in self.get_indicators(session, headers):
                        indicators.extend(batch)

                    total_counts_msg = (
                        f"Successfully fetched {len(indicators)} indicator(s) "
                        f"from {PLATFORM_NAME}."
                    )
                    self.logger.info(f"{self.log_prefix}: {total_counts_msg}")
                    return indicators

        except CybereasonPluginException as err:
            raise err
        except Exception as exp:
            err_msg = "Error occurred while pulling indicator(s)."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}"
                    f" indicators. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise CybereasonPluginException(str(err_msg))

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to Cybereason.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator objects to be pushed.
        Returns:
            cte.plugin_base.PushResult: PushResult object with success flag and Push result message.
        """

        (base_url, username, password, _) = self._get_credentials(
            self.configuration
        )
        session = self.get_session(
            username,
            password,
            base_url,
        )
        total_push_count = 0
        batch_count = 0
        total_skip_count = 0
        if not session.cookies.get_dict().get("JSESSIONID"):
            err_msg = "Error: Unable to establish session with the Cybereason console."
            self.logger.error(f"{self.log_prefix: {err_msg}}")
            raise CybereasonPluginException(err_msg)
        else:
            try:
                with tempfile.TemporaryDirectory() as temp_dir:

                    csv_file = tempfile.NamedTemporaryFile(
                        suffix=".csv", dir=temp_dir, delete=False
                    ).name
                    indicators_list = list(indicators)
                    for chunk in self.divide_in_chunks(indicators_list, 1000):
                        batch_count += 1
                        indicator_count = self.prepare_payload(
                            chunk, csv_file
                        )

                        response = self.push_indicators_to_cybereason(
                            session, csv_file
                        )

                        if response:
                            outcome = response.get("outcome")
                            data = response.get("data")
                            if outcome == "success" and data:
                                total_push_count += indicator_count
                                msg = f"For Batch {batch_count}, Pushed {indicator_count} Indicators to {PLATFORM_NAME}."
                                self.logger.info(f"{self.log_prefix}: {msg}")
                            else:
                                total_skip_count += indicator_count
                                self.logger.error(f"{self.log_prefix}: Batch {batch_count} with {indicator_count} Indicators is not pushed , Error: {str(response)}")
                        else:
                            total_skip_count += indicator_count
                            self.logger.error(f"{self.log_prefix}: Batch {batch_count} with {indicator_count} Indicators is not pushed due to some unexpected error.")

                    msg = f"Successfully Pushed {total_push_count} indicators to Cybereason. Skipped sharing {total_skip_count} indicator(s)."
                    self.logger.info(f"{self.log_prefix}: {msg}")
                    return PushResult(
                        success=True,
                        message=msg,
                    )
            except CybereasonPluginException as exp:
                err_msg = "Error occurred while sharing indicator(s)."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=str(traceback.format_exc()),
                )
                return PushResult(
                    success=False,
                    message=err_msg,
                )                
            except Exception as exp:
                err_msg = "Error occurred while sharing indicator(s)."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=str(traceback.format_exc()),
                )
                return PushResult(
                    success=False,
                    message=err_msg,
                )

    def divide_in_chunks(self, indicators, chunk_size):
            """Divide the json payload into chunks of size less than 1MB."""
            for i in range(0, len(indicators), chunk_size):
                yield indicators[i : i + chunk_size]
                
    def push_indicators_to_cybereason(self, session, csv_file):
        """Push the indicator to the Cybereason endpoint.

        Args:
            session: Request session object
            headers (dict): Header dict object needed to make the Cybereason API call
            json_payload (List[dict]): List of python dict object of JSON reputation model as per Cybereason API.)
        Returns:
            dict: JSON response dict received after successfull Push.
        """
        (base_url, _, _, _) = self._get_credentials(self.configuration)
        push_endpoint = f"{base_url}/rest/classification/upload"
        try:
            post_resp = self.cybereason_helper.api_helper(
                logger_msg=f"Pushing indicators to {PLATFORM_NAME}",
                method="POST",
                url=push_endpoint,
                session=session,
                files=[
                    (
                        "classification_file",
                        (
                            os.path.basename(csv_file),
                            open(csv_file, "rb"),
                            "text/csv",
                        ),
                    )
                ],
            )
            outcome = post_resp.get("outcome")

            if outcome == "failed":
                err_msg = post_resp.get("data", "")
                self.logger.error(
                    f"{PLATFORM_NAME} Unable to Push Indicators,"
                    f"Error: {err_msg}."
                )
                error_message = post_resp

                if "data" in error_message:
                    with open(csv_file, "r") as csv_file:
                        for line_number, error_code in error_message[
                            "data"
                        ].items():

                            # Find the corresponding line in the CSV file
                            csv_file.seek(0)
                            reader = csv.reader(csv_file)
                            line_count = 0
                            for row in reader:
                                line_count += 1
                                if line_count == int(line_number):
                                    self.logger.error(
                                        message=f"{self.log_prefix}: Error occurred while sharing indicator(s). Error Code: {error_code}.",
                                        details=f"Payload details: {row}.",
                                    )
                                    break

                raise CybereasonPluginException(
                    f"{PLUGIN_NAME} Unable to Push Indicators, "
                    f"Error: {err_msg}."
                )
            return post_resp
        except CybereasonPluginException:
            pass
        except Exception as exp:
            err_msg = "Error occurred while sharing indicator(s)."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise CybereasonPluginException(str(exp))


    def prepare_payload(self, indicators, csv_file):
        """Prepare the JSON payload for Push.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator objects to be pushed.
        Returns:
            List[dict]: List of python dict object of JSON reputation model as per Cybereason API.
        """
        indicator_headers = [
            "key",
            "reputation",
            "prevent execution",
            "comment",
            "remove",
        ]
        
        indicator_types = {
            "skipped":0,
            "domain":0,
            "md5":0,
            "sha256":0,
        }

        indicator_count = 0
        try:
            with open(csv_file, "w", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=indicator_headers)
                writer.writeheader()
                for indicator in indicators:
                    filtered_row = {
                        "remove": "false",
                        "prevent execution": "false",
                        "reputation": "blacklist",
                    }

                    filtered_row["key"] = str(indicator.value)
                    filtered_row["comment"] = (
                        str(indicator.comments) + IOC_DESCRIPTION
                    )
                    writer.writerow(filtered_row)
                    indicator_types[INTERNAL_TYPES_TO_CYBEREASON.get(str(indicator.type), "skipped")]+=1
                    indicator_count += 1
                    
        except Exception as err:
            err_msg = "Error occurred while sharing indicator(s)."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise CybereasonPluginException(str(err))
        
        log_msg = (
            "Successfully created payload for {total}"
            " indicator(s) and skipped {skipped} indicator(s) for sharing in which {md5} "
            " MD5 indicator(s). {sha256} SHA256, {domain} "
            "URL(s), will be shared. ".format(
                total=indicator_count,
                skipped=indicator_types["skipped"],
                md5=indicator_types["md5"],
                sha256=indicator_types["sha256"],
                domain=indicator_types["domain"],
            )
        )
        self.logger.info(f"{self.log_prefix}: {log_msg}")
        
        return indicator_count

    def get_session(self, username, password, base_url):
        """Get the session object after authentication from Cybereason platform.

        Args:
            username (str): API Username required to login to Cybereason console.
            password (str): API Password required to login to Cybereason console.
            base_url (str): Base url of Cybereason console.
        Returns:
            session: session object in case of Success.
        """
        auth_endpoint = f"{base_url}/login.html"
        session = requests.Session()
        auth_params = {
            "username": username,
            "password": password,
        }
        
        self.cybereason_helper.api_helper(
            logger_msg=f"Getting session object after authentication from {PLATFORM_NAME}",
            method="POST",
            url=auth_endpoint,
            data=auth_params,
            session=session,
            headers=add_user_agent(),
            get_session=True,
        )
        return session

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Share Indicators", value="share"),
        ]

    def validate_action(self, action: Action):
        """Validate Cybereason configuration."""
        if action.value not in ["share"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []


