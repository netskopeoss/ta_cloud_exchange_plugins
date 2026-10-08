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

CTE Plugin's main file which contains the implementation of all the
plugin's methods.
"""

import json
import traceback
import base64
from urllib.parse import urlparse
from datetime import datetime, timedelta
from pydantic import ValidationError
from typing import List, Tuple, Dict

from netskope.integrations.cte.models import (
    Indicator,
    SeverityType
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)
from .utils.symantec_edr_constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    SYMANTEC_EDR_TO_INDICATOR_TYPE_MAPPING,
    DISPOSITION_TO_SEVERITY_MAPPING,
    FILE_HEALTH_TO_SEVERITY_MAPPING,
    DATE_FORMAT_FOR_IOCS,
)
from .utils.symantec_edr_helper import (
    SymantecEDRPluginException,
    SymantecEDRPluginHelper,
)


class SymantecEDRPlugin(PluginBase):
    """Symantec EDR plugin class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Plugin initializer.

        Args:
            name (str): Plugin configuration name.
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

        self.symantec_edr_helper = SymantecEDRPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version.

        Returns:
            Tuple: Plugin name and version.
        """
        try:
            manifest_json = SymantecEDRPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _str_to_datetime(self, string: str) -> datetime:
        """Convert ISO formatted string to datetime object.

        Args:
            string(str): ISO formatted string.

        Returns:
            datetime: Converted datetime object.
        """
        try:
            return datetime.strptime(string.replace(".", ""), DATE_FORMAT_FOR_IOCS)
        except Exception:
            return datetime.now()

    def _get_credentials(self, configuration: Dict):
        """Get Symantec EDR credentials.

        Args:
            configuration (dict): Plugin configuration dictionary.

        Returns:
            Tuple: server_url, client_id, client_secret.
        """
        return (
            configuration.get("server_url", "").strip().rstrip("/"),
            configuration.get("client_id", "").strip(),
            configuration.get("client_secret", ""),
        )

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

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with
            success flag and message.
        """
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        server_url = configuration.get("server_url", "").strip().rstrip("/")
        if not server_url:
            err_msg = "Server URL is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(server_url, str) or not self._validate_url(server_url):
            err_msg = "Invalid Server URL provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        client_id = configuration.get("client_id", "").strip()
        if not client_id:
            err_msg = "Client ID is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = "Invalid Client ID provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        client_secret = configuration.get("client_secret", "")
        if not client_secret:
            err_msg = "Client Secret is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_secret, str):
            err_msg = "Invalid Client Secret provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range (in days) is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(days, int):
            err_msg = (
                "Invalid Initial Range (in days) provided in configuration parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif (days <= 0) or (days > 365):
            err_msg = "Invalid Initial Range (in days) provided in configuration parameters. Must be between 1 and 365."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self.validate_auth_params(configuration)

    def validate_auth_params(self, configuration):
        """
        A method to validate authentication parameters.

        Parameters:
            configuration (dict): A dictionary containing the configuration parameters.

        Returns:
            ValidationResult: A ValidationResult object containing the validation result.
        """
        validation_err_msg = f"{self.log_prefix}: Validation error occurred. "

        try:
            (server_url, client_id, client_secret) = self._get_credentials(
                configuration
            )
            access_token = self.generate_auth_token(
                server_url,
                client_id,
                client_secret,
                is_validation=True,
            )

            payload = {"limit": 1, "verb": "query"}
            self.symantec_edr_helper.api_helper(
                logger_msg="validating authentication parameters",
                url=f"{server_url}/atpapi/v2/entities",
                method="POST",
                data=json.dumps(payload),
                headers=self.get_headers(access_token),
                is_validation=True,
            )
            return ValidationResult(success=True, message="Validation successful.")

        except SymantecEDRPluginException as err:
            self.logger.error(
                message=f"{validation_err_msg} {err}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as e:
            err_msg = "Unexpected error occurred while validating authentication parameters. Check logs for more details."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {e}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def generate_auth_token(
        self, server_url, clientid, clientsecret, is_validation=False
    ):
        try:
            url = f"{server_url}/atpapi/oauth2/tokens"
            body = {
                "client_id": clientid,
                "client_secret": clientsecret,
                "grant_type": "client_credentials",
            }
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Authorization": "Basic "
                + base64.b64encode(
                    (f"{clientid}:{clientsecret}").encode("utf-8")
                ).decode("ascii"),
            }
            response = self.symantec_edr_helper.api_helper(
                "generating the access token",
                url,
                "POST",
                headers=self.symantec_edr_helper._add_user_agent(headers),
                data=body,
                is_validation=is_validation,
            )
            if response and "access_token" in response:
                return response.get("access_token")
            else:
                raise SymantecEDRPluginException(
                    "No access token found in the response. Check the provided Client ID and Client Secret."
                )
        except SymantecEDRPluginException as err:
            raise SymantecEDRPluginException(str(err))
        except Exception as e:
            err_msg = "Error occurred while generating access token."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {e}",
                details=str(traceback.format_exc()),
            )
            raise SymantecEDRPluginException(err_msg)

    def get_headers(self, access_token):
        """
        A method to get headers for API requests. It adds user agent information to the headers.

        Parameters:
            access_token (str): The access token used for authorization.

        Returns:
            dict: A dictionary containing the headers for the API request.
        """
        return self.symantec_edr_helper._add_user_agent(
            {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def pull(self) -> List[Indicator]:
        """Pull the Threat IoCs from platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects fetched
            from the platform.
        """

        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self.get_indicators()

            return wrapper(self)

        else:
            indicators = []
            for batch in self.get_indicators():
                indicators.extend(batch)

            self.logger.info(
                f"{self.log_prefix}: Total {len(indicators)} indicator(s) fetched."
            )
            return indicators

    def get_indicators(self):
        """
        A method to get indicators from Symantec EDR.

        Parameters:
            access_token (str): The access token used for authorization.

        Returns:
            list: A list of dictionaries containing the indicators.
        """
        indicators = []
        (server_url, client_id, client_secret) = self._get_credentials(
            self.configuration
        )
        url = f"{server_url}/atpapi/v2/entities"
        access_token = self.generate_auth_token(
            server_url,
            client_id,
            client_secret,
        )
        headers = self.get_headers(access_token)
        end_time = datetime.now()
        end_time = end_time.strftime(DATE_FORMAT_FOR_IOCS)
        checkpoint = None
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if sub_checkpoint and sub_checkpoint.get("checkpoint"):
            checkpoint = sub_checkpoint.get("checkpoint")
        elif not (self.last_run_at or sub_checkpoint):
            # Initial Run
            days = self.configuration["days"]
            checkpoint = datetime.now() - timedelta(days=days)
            checkpoint = checkpoint.strftime(DATE_FORMAT_FOR_IOCS)
            self.logger.info(
                f"{self.log_prefix}: This is initial ran of plugin hence"
                f" pulling indicators from last {days} days."
            )
        else:
            checkpoint = self.last_run_at
            checkpoint = checkpoint.strftime(DATE_FORMAT_FOR_IOCS)

        query_params = {
            "verb": "query",
            "limit": 1000,
            "query": f"last_seen: [{checkpoint} TO {end_time}]",
        }

        is_next_page = True
        total_indicators = 0
        page_count = 0
        while is_next_page:
            current_extracted_indicators = []
            page_count += 1
            current_page_skip_count = 0
            indicator_type_count = {
                "ip": 0,
                "domain": 0,
                "sha256": 0,
            }
            try:
                response = self.symantec_edr_helper.api_helper(
                    "pulling indicators for page {}".format(page_count),
                    url,
                    "POST",
                    data=json.dumps(query_params),
                    headers=headers,
                )

                if not response.get("result"):
                    self.logger.info(
                        f"{self.log_prefix}: No indicators found for the page {page_count}."
                    )
                    break

                for data in response["result"]:
                    try:
                        last_indicator_timestamp = data.get("last_seen")
                        indicator_value = ""
                        severity = ""
                        if data.get("type"):
                            if data.get("type") == "file_latest" and data.get("sha2"):
                                indicator_type_count["sha256"] += 1
                                indicator_value = data.get("sha2")
                                severity = (
                                    FILE_HEALTH_TO_SEVERITY_MAPPING.get(
                                        data.get("file_health")
                                    )
                                    if data.get("file_health")
                                    else ""
                                )
                            elif data.get(
                                "type"
                            ) == "external_domain_latest" and data.get(
                                "data_source_url_domain"
                            ):
                                indicator_type_count["domain"] += 1
                                indicator_value = data.get("data_source_url_domain")
                                severity = (
                                    DISPOSITION_TO_SEVERITY_MAPPING.get(
                                        data.get("disposition")
                                    )
                                    if data.get("disposition")
                                    else ""
                                )
                            elif data.get("type") == "endpoint_latest" and data.get(
                                "device_ip"
                            ):
                                indicator_type_count["ip"] += 1
                                indicator_value = data.get("device_ip")
                                severity = (
                                    DISPOSITION_TO_SEVERITY_MAPPING.get(
                                        data.get("disposition")
                                    )
                                    if data.get("disposition")
                                    else ""
                                )
                            if indicator_value:
                                current_extracted_indicators.append(
                                    Indicator(
                                        value=indicator_value,
                                        type=SYMANTEC_EDR_TO_INDICATOR_TYPE_MAPPING.get(
                                            data.get("type")
                                        ),
                                        firstSeen=self._str_to_datetime(
                                            data.get("first_seen")
                                        ),
                                        lastSeen=self._str_to_datetime(
                                            data.get("last_seen")
                                        ),
                                        severity=severity if severity else SeverityType.UNKNOWN,
                                    )
                                )
                            else:
                                current_page_skip_count += 1

                        else:
                            current_page_skip_count += 1
                    except (ValidationError, Exception) as error:
                        current_page_skip_count += 1
                        error_message = (
                            "Validation error occurred"
                            if isinstance(error, ValidationError)
                            else "Unexpected error occurred"
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {error_message} while"
                                " creating indicator. This record will be"
                                f" skipped. Error: {error}."
                            ),
                            details=str(traceback.format_exc()),
                        )
                total_indicators += len(current_extracted_indicators)
                indicators.extend(current_extracted_indicators)
                self.logger.debug(
                    f"{self.log_prefix}: Pull Stat: SHA256:"
                    f" {indicator_type_count['sha256']}, Domain:"
                    f" {indicator_type_count['domain']}, "
                    f"IP: {indicator_type_count['ip']} "
                    f" were fetched in page {page_count}."
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{len(current_extracted_indicators)} indicator(s) "
                    f"in page {page_count}. Total indicator(s) "
                    f"fetched - {total_indicators}."
                )

                if response.get("next"):
                    query_params["next"] = response["next"]
                else:
                    is_next_page = False

                if hasattr(self, "sub_checkpoint"):
                    yield current_extracted_indicators, {
                        "checkpoint": last_indicator_timestamp
                    }
                else:
                    yield current_extracted_indicators

            except (SymantecEDRPluginException, Exception) as ex:
                err_msg = (
                    f"{self.log_prefix}: Error occurred while pulling the indicators"
                    f". Error: {ex}."
                )
                self.logger.error(
                    message=err_msg, details=(str(traceback.format_exc()))
                )
                raise ex
