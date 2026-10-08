import json
import time
import traceback
import requests
from typing import Dict, Union

from netskope.common.utils import add_user_agent

from .microsoft_defender_threat_intelligence_constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
)

from .microsoft_defender_threat_intelligence_constants import (
    OAUTH_URL,
    OAUTH_TOKEN_ENDPOINT,
    SCOPE,
)


class MicrosoftDefenderThreatIntelligencePluginException(Exception):
    """Microsoft Defender Threat Intelligence plugin custom exception class."""

    pass


class MicrosoftDefenderThreatIntelligencePluginHelper(object):
    """MicrosoftDefenderThreatIntelligencePluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
            self,
            logger,
            configuration,
            log_prefix: str,
            plugin_name: str,
            plugin_version: str,
            ssl_validation,
            proxy
            ):
        """MicrosoftDefenderThreatIntelligencePluginHelper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.configuration = configuration
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.verify = ssl_validation
        self.proxies = proxy

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers for third-party requests.

        Args:
            headers (Dict): Dictionary containing headers for any request.
        Returns:
            Dict: Dictionary after adding User-Agent.
        """
        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def api_helper(
        self,
        logger_msg: str,
        url,
        method,
        params=None,
        data=None,
        headers=None,
        json_params=None,
        is_handle_error_required=True,
        is_validation=False,
        regenerate_auth_token=True,

    ):
        """API Helper perform API request to ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            request (request): Requests object.
            logger_msg (str): Logger string.
            is_handle_error_required (bool, optional): Is handling status
            code is required?. Defaults to True.

        Returns:
            dict: Response dictionary.
        """
        try:
            display_headers = {
                k: v for k, v in headers.items() if k not in {"Authorization"}
            }
            debug_log_msg = (
                f"{self.log_prefix} : API Request for {logger_msg} - "
                f"Method={method},  URL={url},  headers={display_headers}, "
            )
            if params:
                debug_log_msg += f"params={params}"

            self.logger.debug(debug_log_msg)
            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=self.verify,
                    proxies=self.proxies,
                    json=json_params,
                )
                debug_msg = (
                    f"API response for {logger_msg} - {response.status_code}."
                )
                self.logger.debug(f"{self.log_prefix}: {debug_msg}")
                if (
                    regenerate_auth_token
                    and (
                        response.status_code == 401
                        or response.text.find("Unauthorized") != -1
                    )
                ):
                    self.logger.info(
                        f"{self.log_prefix}: Received response code 401 - Unauthorized. "
                        f"while {logger_msg}. "
                        "The Access token might be expired. "
                        "Trying to regenerate the Authentication token"
                    )

                    token = self.generate_token(
                        is_validation,
                        logger_msg
                    )
                    headers["Authorization"] = f"Bearer {token}"
                    return self.api_helper(
                        logger_msg=logger_msg,
                        url=url,
                        method=method,
                        params=params,
                        data=data,
                        headers=headers,
                        json_params=json_params,
                        is_handle_error_required=is_handle_error_required,
                        regenerate_auth_token=False,
                    )

                if (
                    response.status_code == 429
                    or 500 <= response.status_code <= 600
                ) and not is_validation:
                    api_err_msg = str(response.text)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            "Received exit code {}, API rate limit "
                            "exceeded while {}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            " code {}.".format(
                                response.status_code,
                                logger_msg,
                                response.status_code,
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, API rate limit"
                            " exceeded while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                DEFAULT_WAIT_TIME,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the provided "
                "proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                "Unable to establish connection with {} "
                "platform while {}. Proxy server or {}"
                " server is not reachable.".format(
                    self.plugin_name, logger_msg, self.plugin_name
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)
        except MicrosoftDefenderThreatIntelligencePluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting "
                f"to {self.plugin_name} server while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)

    def generate_token(self, logger_msg, is_from_validation=False, configuration: Dict = None):
        """
        Generates a token for authentication.

        Parameters:
            is_from_validation (bool): A flag indicating whether the request is from a validation process.

        Returns:
            str: The generated token.
        """
        if configuration:
            self.configuration = configuration
        headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            }
        tenant_id = self.configuration.get("tenant_id", "").strip()
        auth_body = {
            "scope": SCOPE,
            "client_id": self.configuration.get("client_id", "").strip(),
            "client_secret": self.configuration.get("client_secret", ""),
            "grant_type": "client_credentials",
        }
        oath_url = f"{OAUTH_URL}/{tenant_id}{OAUTH_TOKEN_ENDPOINT}"
        try:
            response = self.api_helper(
                logger_msg=logger_msg,
                url=oath_url,
                method="post",
                headers=headers,
                data=auth_body,
                is_validation=is_from_validation,
                regenerate_auth_token=False,
            )
            if response.get("access_token", ""):
                return response.get("access_token")
            else:
                if is_from_validation:
                    err_msg = "Verify Tenant ID, Client ID and Client Secret provided in configuration parameters."
                else:
                    err_msg = f"Error while generating token. Error: {response.text}."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                )
                raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)
        except MicrosoftDefenderThreatIntelligencePluginException:
            raise
        except Exception as err:
            error_message = (
                f"Unexpected error occurred while {logger_msg}."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_message} Error: {err}",
                details=traceback.format_exc(),
            )
            raise MicrosoftDefenderThreatIntelligencePluginException(
                f"{error_message} Check logs for more details."
            )

    def parse_response(
        self, response: requests.models.Response, is_validation: bool
    ):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                f"Invalid JSON response received from API. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify the Base URL "
                    "provided in the configuration parameters."
                    " Check logs for more details."
                )
            raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify the Base URL "
                    "provided in the configuration parameters. Check "
                    "logs for more details."
                )
            raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation=False,
    ) -> Dict:
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned
                from API call.
            logger_msg: logger message.
        Returns:
            dict: Returns the dictionary of response JSON when the
                response code is 200.
        Raises:
            MicrosoftDefenderThreatIntelligencePluginException: When the response code is
            not in 200 range.
        """
        error_msg = "Received exit code {} while {}.".format(
            resp.status_code, logger_msg
        )
        api_err_msg = str(resp.text)
        if resp.status_code in [200, 201, 202]:
            return self.parse_response(
                response=resp, is_validation=is_validation
            )
        elif resp.status_code == 204:
            return {}
        elif resp.status_code == 401:
            err_msg = error_msg + (
                " Unauthorized access, verify the Tenant ID, Client ID and "
                "Client Secret provided in the configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=api_err_msg
            )
            raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)
        elif resp.status_code == 403:
            err_msg = error_msg + (
                " Access is denied to the requested resource. "
                "Verify that the application has required permission and "
                "the account has required license."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=api_err_msg
            )
            raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)
        elif resp.status_code == 404:
            err_msg = (
                "Received exit code 404, Resource not found while {}.".format(
                    logger_msg
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=api_err_msg
            )
            raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)
        elif resp.status_code >= 400 and resp.status_code < 500:
            err_msg = (
                "Received exit code {}, HTTP client error while {}".format(
                    resp.status_code, logger_msg
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=api_err_msg
            )
            raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)
        elif resp.status_code >= 500 and resp.status_code < 600:
            err_msg = (
                "Received exit code {}. HTTP Server Error while {}.".format(
                    resp.status_code, logger_msg
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=api_err_msg
            )
            raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)
        else:
            err_msg = "Received exit code {}. HTTP Error while {}.".format(
                resp.status_code, logger_msg
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=api_err_msg,
            )
            raise MicrosoftDefenderThreatIntelligencePluginException(err_msg)
