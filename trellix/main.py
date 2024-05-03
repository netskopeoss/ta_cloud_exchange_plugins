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

Trellix CTE Plugin's main file which contains the implementation of all the
plugin's methods.
"""

import traceback
import datetime
import json
import hashlib


from typing import Dict, List, Tuple
from base64 import b64encode
from urllib.parse import urlparse


from netskope.integrations.cte.models import (
    Indicator,
    SeverityType,
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)


from .utils.trellix_helper import TrellixPluginHelper, TrellixPluginException
from .utils.trellix_constants import (
    DEFAULT_BATCH_SIZE,
    TRELLIX_URLS,
    DATE_FORMAT_FOR_IOCS,
    NETSKOPE_DATE_FORMAT_FOR_IOCS,
    MODULE_NAME,
    PLUGIN_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    THREAT_TYPES_TO_INTERNAL_TYPES,
    INTEGER_THRESHOLD,
    TRELLIX_GRANT_TYPE,
    TRELLIX_API_SCOPES,
    TRELLIX_AUDIENCE,
    MAX_PAGE_COUNT,
)


class TrellixPlugin(PluginBase):
    """Trellix class having implementation all
    plugin's methods."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Trellix Plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

        self.trellix_helper = TrellixPluginHelper(
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
            manifest_json = TrellixPlugin.metadata
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

    def _get_credentials(self, configuration: Dict) -> Tuple:
        """Get API Credentials.
        Args:
            configuration (Dict): Configuration Dictionary.
        Returns:
            Tuple: Tuple containing Base URL, Client ID, Client Secret, API Key.
        """
        return (
            configuration.get("base_url", "").strip().strip("/"),
            configuration.get("client_id").strip(),
            configuration.get("client_secret"),
            configuration.get("api_key", ""),
        )

    def _get_headers(self, access_token: str, api_key: str) -> Dict:
        """Prepares headers dictionary for Trellix APIs.
        Args:
            - access_token (str): Trellix API Access Token.
            - api_key (str): Trellix api key.
        """
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": access_token,
            "x-api-key": api_key,
        }

    def _generate_access_token(
        self,
        client_id: str,
        client_secret: str,
        api_key: str,
        is_validation: bool = False,
    ) -> str:
        """Generate Access Token via Trellix Authorization API.
        Args:
            - client_id (str): Trellix Client ID.
            - client_secret (str): Trellix Client Secret
            - api_key (str): Trellix API Key.
            - is_validation (bool): Used for the Trellix api_helper method.
        Returns:
            - Access Token (str): Access Token for Trellix APIs.
        """
        authorization_url = TRELLIX_URLS["AUTHORIZATION"]

        auth = f"{client_id}:{client_secret}"
        encoded_token = "Basic {token}".format(
            token=b64encode(auth.encode()).decode()
        )
        headers = self._get_headers(encoded_token, api_key)
        auth_data_payload = {
            "grant_type": TRELLIX_GRANT_TYPE,
            "scope": TRELLIX_API_SCOPES,
            # Audience header typically used to define
            # intended consumer of the resource/API.
            "audience": TRELLIX_AUDIENCE,
        }

        auth_resp = self.trellix_helper.api_helper(
            logger_msg=f"Generating access token for {PLATFORM_NAME} using given configuration parameters",  # noqa
            url=authorization_url,
            method="POST",
            headers=headers,
            data=auth_data_payload,
            is_handle_error_required=False,
            is_validation=True,
        )

        if auth_resp.status_code == 200:
            resp_json = self.trellix_helper.parse_response(
                auth_resp, is_validation
            )
            access_token = resp_json.get("access_token")
            if not access_token:
                err_msg = (
                    "No access token or OAuth2 token found in"
                    " the API Response."
                )
            else:
                self.logger.debug(
                    f"{self.log_prefix}: Successfully pulled OAuth2 "
                    f"token from {PLATFORM_NAME}."
                )
                if self.storage is not None:
                    self.storage[
                        "token_expiry"
                    ] = datetime.datetime.now() + datetime.timedelta(
                        seconds=int(resp_json.get("expires_in", 600))
                    )
                return f"Bearer {access_token}"
        elif auth_resp.status_code == 400:
            err_msg = "Received exit code 400, Verify configuration parameters."
        elif auth_resp.status_code == 401:
            err_msg = (
                "Received exit code 401, Unauthorized access. "
                "Verify Client ID or Client Secret provided in the"
                " configuration parameters."
            )
        elif auth_resp.status_code == 403:
            err_msg = (
                "Received exit code 403, Forbidden access. "
                "Verify API Scope assigned to the user "
                "or API Key provided in the configuration parameters."
            )
        elif auth_resp.status_code == 404:
            err_msg = (
                "Received exit code 400, Verify Base URL "
                "provided in the configuration parameters."
            )
        else:
            err_msg = (
                f"Received exit code {str(auth_resp.status_code)} "
                f"Error occurred while pulling OAuth2 token."
            )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=(
                f"{PLATFORM_NAME} Authentication API Response:"
                f" {auth_resp.text}"
            ),
        )
        raise TrellixPluginException(err_msg)

    def _reload_access_token(self, headers: Dict) -> Dict:
        """Reload the access token after expiry.
        Args:
            - headers (Dict): Headers
        Returns:
            - Dict: Dictionary containing access token.
        """
        if self.storage is None or self.storage.get("token_expiry") < (
            datetime.datetime.now() + datetime.timedelta(seconds=10)
        ):
            (_, client_id, client_secret, api_key) = self._get_credentials(
                self.configuration
            )

            # Reload access token.
            access_token = self._generate_access_token(
                client_id, client_secret, api_key
            )
            headers.update({"Authorization": access_token})
        return headers

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the Plugin configuration parameters.
        Args:
            configuration (Dict): Dict object having all plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidationResult: ValidationResult object with
            success flag and message.
        """
        (base_url, client_id, client_secret, api_key) = self._get_credentials(
            configuration
        )

        # Default to 1 if not present in the config params.
        initial_range = configuration.get("initial_range", 1)

        threat_types = configuration.get("threat_types", [])
        validation_err_message = "Validation error occurred."

        # Validate base_url
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not self._validate_url(base_url):
            err_msg = (
                "Invalid Base URL provided in the configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate client_id
        if not client_id:
            err_msg = "Client ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(client_id, str):
            err_msg = (
                "Invalid Client ID provided in the configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate client_secret
        if not client_secret:
            err_msg = "Client Secret is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(client_secret, str):
            err_msg = "Invalid Client Secret provided in the configuration parameter."  # noqa
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate api_key
        if not api_key:
            err_msg = "API Key is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(api_key, str):
            err_msg = (
                "Invalid API Key is provided in the configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate initial_range
        if initial_range is None:
            err_msg = "Initial Range is a required configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(initial_range, int):
            err_msg = (
                "Invalid Initial Range provided in the "
                "configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif initial_range < 0 or initial_range > INTEGER_THRESHOLD:
            err_msg = (
                "Invalid Initial Range provided in configuration"
                " parameters. Valid value should be in range 0 to 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate threat_types
        allowed_threat_types = set(THREAT_TYPES_TO_INTERNAL_TYPES.keys())
        if not threat_types:
            err_msg = (
                "Type of Threat data to pull is a required configuration "
                "parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not (
            set(threat_types).issubset(allowed_threat_types)
            and isinstance(threat_types, list)
        ):
            err_msg = (
                "Invalid value provided in the Type of Threat data to "
                "pull configuration parameter. Allowed values are MD5, SHA256"
                " Domain, URL, IP."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return self._validate_auth_params(
            base_url, client_id, client_secret, api_key
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

    def _validate_trellix_api_key(
        self, base_url: str, access_token: str, api_key: str
    ) -> bool:
        """Validate Trellix API Key.
        Args:
            - base_url (str): Trellix API domain.
            - access_token (str): Trellix API access token.
            - api_key (str): Trellix API Key.
        Returns:
            - is_valid_api_key (bool): Return True if valid API Key else False.
        """
        try:
            url = TRELLIX_URLS["GET_IOCS"].format(base_url=base_url)
            headers = self._get_headers(access_token, api_key)
            query_params = {"page[limit]": 1, "page[offset]": 0}
            resp = self.trellix_helper.api_helper(
                logger_msg=f"Validating {PLATFORM_NAME} API Key configuration Parameter",  # noqa
                url=url,
                method="GET",
                headers=headers,
                params=query_params,
                is_handle_error_required=False,
                is_validation=True,
            )
            resp_json = self.trellix_helper.parse_response(resp)
            if resp.status_code == 200:
                msg = (
                    "Successfully validated configuration for "
                    f"{PLUGIN_NAME} plugin."
                )
                return True, msg
            elif resp.status_code == 401:
                err_msg = (
                    "Received exit code 401, Unauthorized access."
                    "Verify Trellix API Key provided in the configuration parameters."
                )

                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"{str(resp_json)}",
                )
                return False, (
                    "Invalid Trellix API Key provided in the configuration parameter."
                )
            else:
                err_msg = f"Received exit code {str(resp.status_code)}, Please check logs for more details."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"{str(resp_json)}",
                )
                return False, err_msg
        except TrellixPluginException as trellix_err:
            self.logger.error(
                message=f"{self.log_prefix}: Error occurred while validating Trellix API Key.",
                details=str(traceback.format_exc()),
            )
            return False, str(trellix_err)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred. Please check logs for more details."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                details=str(traceback.format_exc()),
            )
            return False, "Unexpected validation error occurred."

    def _validate_auth_params(
        self, base_url, client_id, client_secret, api_key
    ) -> ValidationResult:
        """Validate Trellix Authentication Parameters.
        Args:
            - base_url (str): Trellix API Domain
            - client_id (str): Trellix Client ID
            - client_secret (str): Trellix Client Secret
            - api_key (str): Trellix API Key
        Returns:
           cte.plugin_base.ValidationResult: ValidationResult object with
           success flag and message.
        """
        try:
            access_token = self._generate_access_token(
                client_id, client_secret, api_key
            )
            if access_token:
                is_api_key_valid, message = self._validate_trellix_api_key(
                    base_url, access_token, api_key
                )

                return ValidationResult(
                    success=is_api_key_valid, message=message
                )
        except TrellixPluginException as trellix_err:
            return ValidationResult(success=False, message=str(trellix_err))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg}, Check logs for more details.",
            )

    def _get_trellix_severity(self, severity: int) -> SeverityType:
        """Get Netskope Severity level from Trellix Lethality
        Args:
            - severity (int): Trellix lethality from Get IoCs API Response.
        Returns:
            - A SeverityType object.
        Severity Levels:
            - Unknown: (null)
            - Low: 1 to 30
            - Medium: 31 to 50
            - High: 51 to 70
            - Critical: above 70
        """
        if not severity:  # Unconfirmed
            return SeverityType.UNKNOWN
        elif 0 < severity <= 15:  # Dual Use
            return SeverityType.LOW
        elif 15 < severity <= 30:  # Probable Malicious
            return SeverityType.LOW
        elif 30 < severity <= 50:  # Malicious Enabler
            return SeverityType.MEDIUM
        elif 50 < severity <= 70:  # Malicious
            return SeverityType.HIGH
        elif severity > 70:  # Destruction
            return SeverityType.CRITICAL
        else:
            return SeverityType.UNKNOWN

    def _get_trellix_last_seen(self) -> str:
        """Get last_seen/created_on date to pull IoCs from Trellix.
        Returns:
            - LastSeen/CreatedOn (str): A datetime object as string representation.
        """
        if not self.last_run_at:
            self.last_run_at = datetime.datetime.now() - datetime.timedelta(
                days=int(self.configuration.get("initial_range"))
            )
        return self.last_run_at.strftime(DATE_FORMAT_FOR_IOCS)

    def pull(self) -> List[Indicator]:
        """Pull indicators from Trellix.

        Returns:
            List[Indicator]: List of indictors fetched from Trellix.
        """
        current_config_digest = self._create_configuration_digest()
        config_digest = self.storage.get("config_digest", "")
        is_config_modified = bool(current_config_digest == config_digest)
        if is_config_modified:
            self.storage["config_digest"] = current_config_digest

        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._pull(is_config_modified)

            return wrapper(self)

        else:
            indicators = []
            for batch in self._pull(is_config_modified):
                indicators.extend(batch)
            return indicators

    def _pull(self, is_config_modified: bool) -> List[Indicator]:
        """Retrieves all the IoCs that were triggered since the specified
        time, with pagination options.
        Every listing includes IoCs properties.
        - Args:
            - is_config_modified (bool): A boolean flag indicates weather
                configuration is modified or not.
        - Returns:
            List[cte.models.Indicators]: List of indicator objects fetched
            from the platform.
        """
        (base_url, client_id, client_secret, api_key) = self._get_credentials(
            self.configuration
        )
        limit = DEFAULT_BATCH_SIZE
        get_iocs_url = TRELLIX_URLS["GET_IOCS"].format(base_url=base_url)

        threat_types = self.configuration.get("threat_types")

        # Get a last_seen datetime as string representations.
        # For retrieving indicators
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if sub_checkpoint and not is_config_modified:
            checkpoint = sub_checkpoint.get("checkpoint")
        elif (
            self.storage
            and self.storage.get("checkpoint")
            and not is_config_modified
        ):
            checkpoint = self.storage.get("checkpoint")
        else:
            checkpoint = {
                "offset": 0,
                "created_on": self._get_trellix_last_seen(),
            }

        # Get Access Token
        access_token = self._generate_access_token(
            client_id, client_secret, api_key
        )

        self.logger.info(
            f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME}"
            f" platform using checkpoint {checkpoint}"
        )

        headers = self._get_headers(access_token, api_key)
        now = str(datetime.datetime.now().strftime(DATE_FORMAT_FOR_IOCS))
        query_params = {
            "page[limit]": limit,
            "filter[created_on][gte]": checkpoint.get("created_on", now),
            "page[offset]": checkpoint.get("offset", 0),
        }

        next_page = True
        page_count = 1
        total_indicators = 0
        parsed_indicators = []

        try:
            while next_page:
                logger_msg = (
                    f"pulling IoCs for page {page_count} from {PLATFORM_NAME}"
                )
                indicator_resp = self.trellix_helper.api_helper(
                    logger_msg=logger_msg,
                    url=get_iocs_url,
                    method="GET",
                    params=query_params,
                    headers=self._reload_access_token(headers),
                    is_handle_error_required=True,
                )
                indicators = indicator_resp.get("data", [])

                (parsed_indicators, indicators_per_page) = (
                    self._parse_trellix_indicators_response(
                        indicators, threat_types
                    )
                )

                total_indicators += indicators_per_page["total"]

                per_page_msg = (
                    "Successfully fetched {total} indicator(s) and skipped "
                    "{skipped} indicators(s) in the page {page}."
                    "Total indicator(s) {total_indicators} fetched.".format(
                        total=indicators_per_page["total"],
                        skipped=indicators_per_page["skipped"],
                        page=page_count,
                        total_indicators=total_indicators,
                    )
                )
                self.logger.info(f"{self.log_prefix}: {per_page_msg}")

                pull_stat_msg = (
                    "Pull Stats: MD5={md5}, SHA256={sha256}, Domain={domain},"
                    " IP={ip}, URL={url} in page {page}.".format(
                        md5=indicators_per_page["md5"],
                        sha256=indicators_per_page["sha256"],
                        domain=indicators_per_page["domain"],
                        ip=indicators_per_page["ip"],
                        url=indicators_per_page["url"],
                        page=page_count,
                    )
                )
                self.logger.debug(f"{self.log_prefix}: {pull_stat_msg}")

                # Set offset += limit
                query_params["page[offset]"] += limit

                if len(indicators) < limit:
                    next_page = False
                    self.storage.clear()

                if page_count == MAX_PAGE_COUNT:
                    self.storage["checkpoint"] = {
                        "created_on": query_params["filter[created_on][gte]"],
                        "offset": query_params["page[offset]"],
                    }
                    next_page = False

                # Set the page_count
                page_count += 1

                if hasattr(self, "sub_checkpoint"):
                    yield parsed_indicators, {
                        "checkpoint": self.storage.get("checkpoint", {})
                    }
                else:
                    yield parsed_indicators
        except TrellixPluginException as trellix_err:
            self.storage["checkpoint"] = {
                "created_on": query_params["filter[created_on][gte]"],
                "offset": query_params["page[offset]"],
            }

            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error Occurred while pulling "
                    f"indicators from {PLATFORM_NAME} using checkpoint "
                    f"{self.storage['checkpoint']}. Error: {trellix_err}"
                ),
                details=traceback.format_exc(),
            )

            if not hasattr(self, "sub_checkpoint"):
                yield parsed_indicators
        except Exception as exp:
            self.storage["checkpoint"] = {
                "created_on": query_params["filter[created_on][gte]"],
                "offset": query_params["page[offset]"],
            }
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred while "
                    f"pulling/parsing indicators from {PLATFORM_NAME} using "
                    f"checkpoint {self.storage['checkpoint']}. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )

            if not hasattr(self, "sub_checkpoint"):
                yield parsed_indicators

    def _parse_trellix_indicators_response(
        self, indicators: List[Dict], indicator_types: List[str]
    ) -> Tuple[List[Indicator], Dict]:
        """Parse Trellix IoCs with pagination API response.
        and, create an objects of Indicator class.
        Alone with that return the pulling stats of Iocs types.
        Args:
            - indicators (List[Dict]): A nested structure containing list of IoCs.
            - indicator_types (Set[str]): A list of allowed type of indicator(s).
        Returns:
            - List[cte.models.Indicators]: List of indicator objects pulled
            from the Trellix platform.
            - indicators_per_page (Dict): Containing the pull stats of counts.
        """
        parsed_indicators = []
        indicators_per_page = {
            "total": 0,
            "md5": 0,
            "sha256": 0,
            "domain": 0,
            "url": 0,
            "ip": 0,
            "skipped": 0,
        }

        for indicator in indicators:
            try:
                attributes = indicator.get("attributes", {})

                # Get Indicator Type.
                ioc_type = str(attributes.get("type"))

                if ioc_type not in indicator_types:
                    indicators_per_page["skipped"] += 1
                    continue

                parsed_ioc_type = THREAT_TYPES_TO_INTERNAL_TYPES.get(ioc_type)
                if not parsed_ioc_type:
                    # indicator type are not supported by Netskope.
                    indicators_per_page["skipped"] += 1
                    continue

                created_on = attributes.get(
                    "created-on",
                    str(
                        datetime.datetime.now().strftime(
                            NETSKOPE_DATE_FORMAT_FOR_IOCS
                        )
                    ),
                )

                # Get comment
                comment = attributes.get("comment", "")
                if not comment:
                    # Indicator class does not support None as value, Hence Empty string.
                    comment = ""

                # Create an instance of Indicator class.
                parsed_indicators.append(
                    Indicator(
                        type=parsed_ioc_type,
                        value=attributes.get("value"),
                        firstSeen=created_on,
                        severity=self._get_trellix_severity(
                            attributes.get("lethality")
                        ),
                        comments=comment,
                    )
                )
                indicators_per_page[ioc_type] += 1
                indicators_per_page["total"] += 1
            except Exception as exp:
                err_msg = "Error occurred while creating the indicator from "
                f"alert having alert Id {indicator.get('id')} hence this "
                "record will be skipped."

                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                indicators_per_page["skipped"] += 1
                continue
        return parsed_indicators, indicators_per_page

    def _create_configuration_digest(self) -> str:
        """Creates a MD5 digest of configurations.
        Returns:
            - A string representation of MD5 hexdigest of configuration.
        """
        (base_url, client_id, client_secret, api_key) = self._get_credentials(
            self.configuration
        )

        initial_range = self.configuration.get("initial_range")
        threat_types = self.configuration.get("threat_types")

        config_dict = {
            "client_id": client_id,
            "client_secret": client_secret,
            "api_key": api_key,
            "base_url": base_url,
            "initial_range": initial_range,
            "threat_types": threat_types,
        }
        return hashlib.md5(
            json.dumps(config_dict, sort_keys=True).encode("utf-8")
        ).hexdigest()
