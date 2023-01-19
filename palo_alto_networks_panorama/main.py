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
import json
import time
from datetime import datetime, timedelta
from typing import List, Union
from urllib.parse import urlparse

import pytz
import requests
from .lib import xmltodict
from netskope.integrations.cte.models.indicator import (
    Indicator,
    IndicatorType,
    SeverityType,
)
from netskope.integrations.cte.models.tags import TagIn
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.utils.tag_utils import TagUtils
from pydantic import ValidationError

PLUGIN_NAME = "Palo Alto Networks Panorama CTE Plugin"
tag_utils = TagUtils()
LOG_TYPE_TO_TAG_MAPPING = {
    "wildfire": "wildfire",
    "url": "url-filtering",
}
LOG_LIMIT = 5000
DATE_FORMAT = r"%Y/%m/%d %H:%M:%S"


class PaloAltoNetworksPanoramaException(Exception):
    """PaloAltoNetworks exception class."""

    pass


class PaloAltoNetworksPanoramaPlugin(PluginBase):
    """PaloAltoNetworksPanoramaPlugin class."""

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
        except ValueError:
            return False

    def handle_error(self, resp: requests.models.Response) -> dict:
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API
            call.
        Returns:
            dict: Returns the dictionary of response JSON when the response
            code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code == 200 or resp.status_code == 201:
            return self.xml_to_dict(resp.text)

        elif resp.status_code == 401:
            raise PaloAltoNetworksPanoramaException(
                f"{PLUGIN_NAME}: "
                "Received exit code 401, Authentication Error"
            )

        elif resp.status_code == 403:
            raise PaloAltoNetworksPanoramaException(
                f"{PLUGIN_NAME}: Received exit code 403, Forbidden User"
            )
        elif resp.status_code >= 400 and resp.status_code < 500:

            raise PaloAltoNetworksPanoramaException(
                f"{PLUGIN_NAME}: "
                f"Received exit code {resp.status_code}, HTTP client Error"
            )

        elif resp.status_code >= 500 and resp.status_code < 600:
            raise PaloAltoNetworksPanoramaException(
                f"{PLUGIN_NAME}: "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )

        else:
            raise PaloAltoNetworksPanoramaException(
                f"{PLUGIN_NAME}: "
                f"Received exit code {resp.status_code}, HTTP Error."
            )

    def _request(self, params: dict) -> dict:
        """Request Panorama API and get response.

        Args:
            params (dict): Parameters to pass to API.

        Returns:
            dict: Response JSON.
        """
        url = f"{self.configuration.get('base_url')}/api/"

        resp = requests.get(
            url=url,
            params=params,
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        resp_json = self.handle_error(resp=resp)
        if resp_json.get("response", {}).get("@status") == "success":
            return resp_json
        else:
            msg = (
                resp_json.get("response", {}).get("result", {}).get("msg", "")
            )
            err_msg = (
                f"{PLUGIN_NAME}: Error occured while fetching indicators."
            )
            self.logger.error(message=err_msg, details=msg)
            raise PaloAltoNetworksPanoramaException(err_msg)

    def _get_job_id(
        self, log_type: str, time_generated: Union[None, datetime]
    ) -> str:
        """Get job id to fetch the logs from.

        Args:
            log_type (str): Log type.
            time_generated (Union[None, datetime]): Time the log was generated
            on the dataplane.

        Raises:
            PaloAltoNetworksPanoramaException: Raise exception if any error
            occurred while getting job id.

        Returns:
            str: Job id.
        """
        last_run_time = None
        if time_generated:
            last_run_time = time_generated.strftime(DATE_FORMAT)
        elif self.last_run_at and (time_generated is None):
            last_run_time = self.last_run_at.strftime(DATE_FORMAT)
        else:
            last_run_time = datetime.now() - timedelta(
                days=self.configuration["days"]
            )
            last_run_time = last_run_time.strftime(DATE_FORMAT)
        params = {
            "key": self.configuration.get("api_key"),
            "type": "log",
            "log-type": log_type,
            "query": f"(time_generated geq '{last_run_time}')",
            "nlogs": LOG_LIMIT,
            "dir": "forward",
        }
        resp_json = self._request(params=params)
        return resp_json.get("response", {}).get("result", {}).get("job")

    def _get_iocs(
        self, log_type: str, time_generated: Union[None, datetime]
    ) -> list:
        """Get IOCs from the wildfire and urls.

        Args:
            log_type (str): Log type.
            time_generated (Union[None, datetime]): Time the log was generated
            on the dataplane.

        Returns:
            list: List of IOCs.
        """
        iocs = []
        while True:

            job_id = self._get_job_id(
                log_type=log_type,
                time_generated=time_generated,
            )
            self.logger.info(f"{PLUGIN_NAME}: Got Job ID: {job_id}")
            params = {
                "key": self.configuration.get("api_key"),
                "type": "log",
                "action": "get",
                "job-id": job_id,
            }

            resp_json = self._request(params=params)

            status = (
                resp_json.get("response", {})
                .get("result", {})
                .get("job", {})
                .get("status")
            )

            self.logger.info(
                f"{PLUGIN_NAME}: Getting details for job {job_id}."
            )
            start_time = time.time()
            while status != "FIN":
                time.sleep(2)
                current_time = time.time()
                if current_time - start_time >= 300:
                    err_msg = (
                        "Fetching job details time limit of 5 mins exceeded."
                    )
                    self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
                    raise PaloAltoNetworksPanoramaException(err_msg)

                resp_json = self._request(params=params)
                status = (
                    resp_json.get("response", {})
                    .get("result", {})
                    .get("job", {})
                    .get("status")
                )

            self.logger.info(
                f"{PLUGIN_NAME}: Successfully fetched details for job_id \
                    {job_id}."
            )
            num_logs = int(
                resp_json.get("response", {})
                .get("result", {})
                .get("log", {})
                .get("logs", {})
                .get("@count")
            )

            response_data = (
                resp_json.get("response", {})
                .get("result", {})
                .get("log", {})
                .get("logs", {})
                .get("entry")
            )

            if response_data and log_type == "wildfire":
                self.logger.info(
                    f"{PLUGIN_NAME} Fetching filehashes from \
                    details of job {job_id}"
                )
                for data in response_data:
                    try:
                        ioc = self._get_hashes(
                            data, LOG_TYPE_TO_TAG_MAPPING.get(log_type)
                        )
                        iocs.append(ioc)
                    except ValidationError as error:
                        self.logger.error(
                            f"{PLUGIN_NAME}: Error occured while fetching \
                                filehashes.",
                            details=error,
                        )

            elif response_data and log_type == "url":
                self.logger.info(
                    f"{PLUGIN_NAME} Fetching URLs from details of job {job_id}"
                )
                for data in response_data:
                    try:
                        ioc = self._get_urls(
                            data, LOG_TYPE_TO_TAG_MAPPING.get(log_type)
                        )
                        iocs.append(ioc)
                    except ValidationError as error:
                        self.logger.error(
                            f"{PLUGIN_NAME}: Error occured while fetching \
                                URLs.",
                            details=error,
                        )

            if num_logs < LOG_LIMIT:
                return iocs
            self.logger.info(
                f"{PLUGIN_NAME}: No of IOCs fetched so far are {len(iocs)}"
            )
            time_generated = datetime.strptime(
                response_data[-1].get("time_generated"), DATE_FORMAT
            )

    def _get_urls(self, data: dict, tag: str) -> Indicator:
        """Get URLs from logs.

        Args:
            data (dict): Log Data.
            tag (str): Tag for the log type.

        Returns:
            Indicator: Fetched indicator.
        """
        date = datetime.strptime(data.get("time_generated"), DATE_FORMAT)
        date = pytz.timezone("UTC").localize(date)
        tags = self._generate_tags(tags=[tag])
        return Indicator(
            value=data.get("misc"),
            type=IndicatorType.URL,
            firstSeen=date,
            lastSeen=date,
            severity=data.get("severity")
            if data.get("severity") != "informational"
            else SeverityType.UNKNOWN,
            tags=tags,
        )

    def _generate_tags(self, tags: list) -> list:
        """Generate Tags.

        Args:
            tags (list): List of tags to generate.

        Returns:
            list: List of tags that are generated.
        """
        generated_tags = []
        for tag in tags:
            tag = tag.strip()
            try:
                if not tag_utils.exists(tag):
                    self.logger.info(f"{PLUGIN_NAME}: Generating tag {tag}")
                    tag_utils.create_tag(TagIn(name=f"{tag}", color="#ED3347"))
                    self.logger.info(
                        f"{PLUGIN_NAME}: Successfully generated tag {tag}"
                    )
            except ValueError:
                self.logger.warn(
                    f"{PLUGIN_NAME}: Invalid Tag found. Skipping {tag}."
                )
            else:
                generated_tags.append(tag)
        return generated_tags

    def _get_hashes(self, data: dict, tag: str) -> Indicator:
        """Get Sha256 hashes from wildire logs.

        Args:
            data (dict): Fetched log data.
            tag (str): Tag to be added to indicator.

        Returns:
            Indicator: Fetched indicator from wildire log.
        """
        date = datetime.strptime(data.get("time_generated"), DATE_FORMAT)
        date = pytz.timezone("UTC").localize(date)
        category_tag = data.get("category")
        tags = self._generate_tags(tags=[tag, category_tag])

        return Indicator(
            value=data.get("filedigest"),
            type=IndicatorType.SHA256,
            firstSeen=date,
            lastSeen=date,
            severity=data.get("severity")
            if data.get("severity") != "informational"
            else SeverityType.UNKNOWN,
            tags=tags,
            comments=f"Filename: {data.get('misc')}",
        )

    def pull(self) -> List[Indicator]:
        """Pull the Threat information from Palo Alto Networks platform.

        Returns : List of indicators.
        """
        self.logger.info(f"{PLUGIN_NAME}: Pulling indicators from panorama.")
        iocs = []
        if self.configuration.get("threat_data_type") in ["Both", "Malware"]:
            iocs.extend(
                self._get_iocs(log_type="wildfire", time_generated=None)
            )

        if self.configuration.get("threat_data_type") in ["Both", "URL"]:
            iocs.extend(self._get_iocs(log_type="url", time_generated=None))

        self.logger.info(
            f"{PLUGIN_NAME}: Successfully fetched {len(iocs)} indicators \
                from panorama."
        )
        return iocs

    def xml_to_dict(self, xml_data: str):
        """Convert XML data to python dictionary.

        Args:
            xml_data (str): Response data in xml format.

        Returns:
            dict: Dictionary containing converted data.
        """
        try:
            return json.loads(json.dumps(xmltodict.parse(xml_data)))
        except Exception as exp:
            err_msg = (
                f"{PLUGIN_NAME}: Error occurred while parsing xml to json."
            )
            self.logger.error(
                err_msg,
                details=exp,
            )
            raise PaloAltoNetworksPanoramaException(err_msg)

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object
            with success flag and message.
        """
        if "base_url" not in configuration or not configuration.get(
            "base_url"
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred."
                "Error: Base URL should not be empty."
            )
            return ValidationResult(
                success=False,
                message="Base URL is a Required Field.",
            )
        elif type(configuration.get("base_url")) != str:
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred. Error "
                "Type of API Key Token should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Base URL is a required field.",
            )
        if "threat_data_type" not in configuration or configuration.get(
            "threat_data_type"
        ) not in [
            "Both",
            "Malware",
            "URL",
        ]:
            self.logger.error(
                f"{PLUGIN_NAME}: Netskope Invalid value for \
                    'Type of Threat data to pull' provided. "
                "Allowed values are Both, Malware, or URL.",
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Type of Threat data to pull' "
                "provided. Allowed values are 'Both', 'Malware', or 'URL'.",
            )
        if "api_key" not in configuration or not configuration.get("api_key"):
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred. Error "
                "API Key should not be empty."
            )
            return ValidationResult(
                success=False,
                message="API Key is a required field.",
            )
        elif type(configuration.get("api_key")) != str:
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred. Error "
                "Type of API Key Token should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid API Key provided.",
            )

        base_url = configuration.get("base_url").strip()
        is_url = self.is_url(base_url)
        if not is_url:
            err_msg = """Invalid Base URL provided.
                URL should contain device IP address or domain name.
                e.g. https://<panorama_instance>"""
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        return self.validate_auth_params(
            base_url=base_url,
            api_key=configuration.get("api_key"),
        )

    def validate_auth_params(self, base_url, api_key):
        """Validate the authentication params with Palo Alto Networks platform.

        Args:
            configuration(dict): Dict object having all the Plugin
        Returns:
            ValidationResult: ValidationResult object having validation
            results after making
            an API call.
        """
        try:
            query_endpoint = "".join([base_url, "/api/"])
            params = {
                "key": api_key,
                "type": "config",
                "action": "get",
            }
            response = requests.get(
                query_endpoint,
                params=params,
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            if response.status_code == 200:
                return ValidationResult(
                    success=True,
                    message=f"Validation successfull for {PLUGIN_NAME}.",
                )
            elif response.status_code == 429:
                err_resp = response.json()
                err_msg = " ".join(
                    [
                        f"{PLUGIN_NAME}: Received exit",
                        "code 429, Too Many Requests.",
                        f"Cause: {err_resp.get('error').get('message')}",
                    ]
                )
                self.notifier.error(err_msg)
                self.logger.error(err_msg)
                return ValidationResult(
                    success=False,
                    message="Received exit code 429, Too Many Requests.",
                )
            else:
                self.logger.error(
                    f"{PLUGIN_NAME}: Invalid API Key or Base URL provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid API Key or Base URL provided.",
                )

        except requests.exceptions.ProxyError:
            self.logger.error(
                f"{PLUGIN_NAME}: Validation Error, "
                "Invalid proxy configuration."
            )
            return ValidationResult(
                success=False,
                message="Validation Error, Invalid proxy configuration.",
            )
        except requests.exceptions.ConnectionError:
            err_msg = " ".join(
                [
                    "Validation Error, Unable to establish",
                    "connection with Palo Alto platform API",
                ]
            )
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        except requests.HTTPError as err:
            err_msg = (
                "Validation error occurred. Invalid Credentials provided."
            )
            self.logger.error(
                message=f"{PLUGIN_NAME}: {err_msg}",
                details=str(err),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg}: {str(err)}",
            )
        except Exception as exp:
            err_msg = (
                "Validation error occurred. Invalid Credentials provided."
            )
            self.logger.error(message=err_msg, details=f"{exp}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
