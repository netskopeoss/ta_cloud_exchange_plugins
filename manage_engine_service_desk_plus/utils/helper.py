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

CTO Manage Engine Service Desk Plugin helper module.
"""

import functools
import hashlib
import json
import time
import traceback
import tempfile
from copy import deepcopy
from tempfile import _TemporaryFileWrapper
from typing import Dict, Literal, Tuple, Union

import requests
from netskope.common.utils import add_user_agent

from .constants import (
    API_RATE_LIMIT_ERROR_MESSAGE_ON_PREMISE,
    CLOUD,
    CLOUD_API_AND_AUTH_URLS,
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    ON_PREMISE,
    PLATFORM_NAME,
)


class ServiceDeskPluginException(Exception):
    """Service Desk plugin custom exception class."""

    pass


def api_ssl_wrapper(func):
    """
    Decorator to wrap a function to add the SSL verification.

    Adds the SSL verification for the API calls based on the deployment
    type and the configuration.
    If the deployment type is not provided, it will use the configuration
    from the instance.
    If the configuration is not provided, it will use the default
    configuration.

    Args:
        func (function): The function to wrap.

    Returns:
        function: The wrapped function.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            self = args[0]
            if kwargs.get("configuration"):
                configuration = kwargs["configuration"]
            else:
                configuration = self.configuration
            ssl_cert = self.servicedesk_helper._get_ssl_certificate_path(
                configuration=configuration,
                deployment_type=kwargs["deployment_type"],
            )
            kwargs.update({"verify": ssl_cert})
            return func(*args, **kwargs)
        except ServiceDeskPluginException:
            raise
        except Exception as e:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error occurred."
                    f" Error: {str(e)}"
                ),
                details=traceback.format_exc()
            )
            raise ServiceDeskPluginException(str(e))
        finally:
            if not isinstance(ssl_cert, bool):
                ssl_cert.close()

    return wrapper


class ServiceDeskPluginHelper(object):
    """Service Desk plugin helper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """Service Now Plugin Helper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers for ServiceNow requests.

        Args:
            headers (Dict): Dictionary containing headers for any request.
        Returns:
            Dict: Dictionary after adding User-Agent.
        """
        if headers and "User-Agent" in headers:
            return headers
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
        url: str,
        method: str = "GET",
        params: Dict = {},
        data=None,
        files=None,
        headers: Dict = {},
        json_body=None,
        verify=True,
        proxies=None,
        is_handle_error_required=True,
        is_validation=False,
        deployment_type: Literal["cloud", "onpremise"] = CLOUD,
        storage: Dict = {},
        configuration: Dict = {},
        regenerate_auth_token: bool = True,
    ):
        """API helper to perform API request on ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            logger_msg (str): Logger message.
            url (str): API endpoint.
            method (str, optional): API method. Defaults to GET.
            params (Dict, optional): Query parameters. Defaults to {}.
            data (Dict, optional): Data to be sent in the request. Defaults
                to None.
            files (Dict, optional): Files to be sent in the request. Defaults
                to None.
            headers (Dict, optional): Headers to be sent in the request.
                Defaults to {}.
            json_body (Dict, optional): JSON body to be sent in the request.
                Defaults to None.
            verify (bool, optional): Verify SSL certificate. Defaults to True.
            proxies (Dict, optional): Proxies to be used for the request.
                Defaults to None.
            is_handle_error_required (bool, optional): Whether to handle
                error. Defaults to True.
            is_validation (bool, optional): Whether the request is for
                validation. Defaults to False.
            deployment_type (Literal["cloud", "onpremise"], optional):
                Deployment type. Defaults to CLOUD.
            storage (Dict, optional): Storage dictionary. Defaults to {}.
            configuration (Dict, optional): Configuration dictionary. Defaults
                to {}.
            regenerate_auth_token (bool, optional): Whether to regenerate auth
                token. Defaults to True.

        Returns:
            dict: Response dictionary.
        """
        try:
            # For deployment type cloud verify will be of type bool
            # When the plugin regenerates access token it will call
            # api_helper recursively but this time the verify parameter will
            # be of type str
            # Hence will only go inside the if only when verify is of type
            # _TemporaryFileWrapper
            if not isinstance(verify, (bool, str)):
                verify = verify.name
            # The API expects the input_data query and body parameter in
            # string format
            query_params = deepcopy(params)
            if params and params.get("input_data"):
                query_params["input_data"] = json.dumps(
                    query_params["input_data"]
                )
            request_body = deepcopy(data)
            if data and data.get("input_data"):
                request_body["input_data"] = json.dumps(
                    request_body["input_data"]
                )
            headers = self._add_user_agent(headers)

            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}. "
                f"Endpoint: {method} {url}"
            )
            if params:
                debug_log_msg += f", params: {params}."

            self.logger.debug(f"{self.log_prefix}: {debug_log_msg}")
            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=query_params,
                    data=request_body,
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                    json=json_body,
                    files=files,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )
                # Token Regeneration Logic
                if status_code == 401 and regenerate_auth_token:
                    new_access_token = self._regenerate_access_token_and_update_storage(
                        deployment_type=deployment_type,
                        storage=storage,
                        configuration=configuration,
                        verify=verify,
                        proxy=proxies,
                        is_validation=is_validation,
                    )
                    new_headers = self.get_auth_headers(
                        token=new_access_token,
                        deployment_type=deployment_type
                    )
                    headers.update(new_headers)
                    return self.api_helper(
                        logger_msg=logger_msg,
                        url=url,
                        method=method,
                        params=params,
                        data=data,
                        files=files,
                        headers=headers,
                        json_body=json_body,
                        verify=verify,
                        proxies=proxies,
                        is_handle_error_required=is_handle_error_required,
                        is_validation=is_validation,
                        deployment_type=deployment_type,
                        storage=storage,
                        configuration=configuration,
                        regenerate_auth_token=False
                    )
                # Handle Rate Limit Error for On Premise
                if status_code == 400 and (
                    API_RATE_LIMIT_ERROR_MESSAGE_ON_PREMISE in response.text
                ):
                    status_code = 429
                if (
                    status_code == 429 or 500 <= status_code <= 600
                ) and not is_validation:
                    api_err_msg = str(response.text)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}, API rate limit"
                            f" exceeded while {logger_msg}. Max retries for"
                            "rate limit handler exceeded hence returning"
                            f" status code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise ServiceDeskPluginException(err_msg)
                    if status_code == 429:
                        log_err_msg = "API rate limit exceeded"
                    else:
                        log_err_msg = "HTTP server error occurred"
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code"
                            f" {status_code}, {log_err_msg} while {logger_msg}"
                            f". Retrying after {DEFAULT_WAIT_TIME} seconds. "
                            f"{MAX_API_CALLS - 1 - retry_counter} retries"
                            " remaining."
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return (
                        self.handle_error(
                            resp=response,
                            logger_msg=logger_msg,
                            is_validation=is_validation,
                            deployment_type=deployment_type
                        ) if is_handle_error_required else response
                    )
        except ServiceDeskPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read Timeout error occurred."

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ServiceDeskPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the "
                "proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy configuration"
                    " provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ServiceDeskPluginException(err_msg)
        except requests.exceptions.SSLError as error:
            err_msg = (
                f"SSL error occurred while {logger_msg}. Verify the "
                " SSL Certificate provided in configuration."
            )
            if is_validation:
                err_msg = (
                    "SSL error occurred. Verify the SSL Certificate"
                    " provided in configuration."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ServiceDeskPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    f"platform. Proxy server or {PLATFORM_NAME} "
                    "server is not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ServiceDeskPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify configuration parameters"
                    " provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise ServiceDeskPluginException(err_msg)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing API call to"
                    f" {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                raise ServiceDeskPluginException(err_msg)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg,
        is_validation: bool = False,
    ):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.
            logger_msg (str): Logger message
            is_validation: (bool): Check for validation

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received from API while"
                f" {logger_msg}. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify authentication parameters provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise ServiceDeskPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing "
                f"json response while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify authentication parameters provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise ServiceDeskPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
        deployment_type: Literal["cloud", "onpremise"] = None,
    ):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object
            returned from API call.
            logger_msg: logger message.
            is_validation : API call from validation method or not
            deployment_type : cloud or onpremise
        Returns:
            dict: Returns the dictionary of response JSON
            when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        status_code = resp.status_code
        validation_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, Bad Request",
            403: "Received exit code 403, Forbidden",
            401: "Received exit code 401, Unauthorized access",
            404: "Received exit code 404, Resource not found",
        }
        if deployment_type == CLOUD:
            error_401 = "Verify the Client ID, Client Secret and Auth Code"
            error_403 = "Verify permission for Auth Code"
        elif deployment_type == ON_PREMISE:
            error_401 = "Verify the Auth Token"
            error_403 = "Verify permission for Auth Token"
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request, "
                    "Verify the Service Desk instance URL provided in "
                    f"the configuration parameters. {logger_msg}"
                ),
                401: (
                    "Received exit code 401, Unauthorized, "
                    f"{error_401} provided in the configuration"
                    " parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, "
                    f"{error_403} provided in the configuration"
                    " parameters."
                ),
                404: (
                    "Received exit code 404, Resource not found, "
                    "Verify the Service Desk instance URL provided in "
                    "the configuration parameters."
                ),
            }

        if status_code in [200, 201]:
            return self.parse_response(
                response=resp,
                logger_msg=logger_msg,
                is_validation=is_validation
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise ServiceDeskPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                if status_code == 401:
                    err_msg = (
                        f"{err_msg} {error_401} provided "
                        "in configuration parameters."
                    )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise ServiceDeskPluginException(err_msg)

        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{validation_msg+err_msg} while {logger_msg}."
                ),
                details=f"API response: {resp.text}",
            )
            raise ServiceDeskPluginException(err_msg)

    def get_configuration_params(
        self,
        configuration: Dict,
        deployment_type: Literal["cloud", "onpremise"]
    ) -> Union[Tuple[str, str, str, str, str], Tuple[str, str, str, str]]:
        """
        Get Configuration params.

        Args:
            configuration (Dict): Configuration parameter dictionary.
            deployment_type (Literal["cloud", "onpremise"]): Deployment type
                of the Service Desk Plus.

        Returns:
            Tuple: Tuple containing API Base URL and API Token.
        """
        auth_params = configuration.get("auth", {})
        base_url = auth_params.get("sdp_api_url", "").strip().strip("/")
        portal_url = auth_params.get("portal_url").strip()
        if deployment_type == CLOUD:
            client_id = auth_params.get("client_id")
            client_secret = auth_params.get("client_secret")
            auth_code = auth_params.get("auth_code")
            return (
                base_url, client_id, client_secret, auth_code, portal_url
            )
        elif deployment_type == ON_PREMISE:
            return (
                base_url,
                auth_params.get("auth_token"),
                auth_params.get("ssl_certificate"),
                portal_url,
            )
        else:
            err_msg = f"Invalid deployment type: {deployment_type}."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ServiceDeskPluginException(err_msg)

    def access_token_operation(
        self,
        base_url: str,
        auth_code: str,
        refresh_token: str,
        client_id: str,
        client_secret: str,
        verify,
        proxies,
        is_validation: bool,
        operation: Literal["generate", "regenerate"] = "generate",
    ) -> Tuple[str, Union[str, None]]:
        """
        Generates a new access token for authentication or regenerates an
        existing one.

        Args:
            base_url (str): The base URL of the Service Desk Plus API.
            auth_code (str): The authorization code received after
                authorization.
            refresh_token (str): The refresh token received after
                authorization.
            client_id (str): The client ID for authentication.
            client_secret (str): The client secret for authentication.
            verify (bool): Whether to verify the SSL certificate.
            proxies (dict): The proxy server to use for the API call.
            is_validation (bool): Whether the operation is for validation.
            operation (Literal["generate", "regenerate"]): The operation
                to perform.
                Defaults to "generate".

        Returns:
            Tuple[str, Union[str, None]]: The access token and refresh token.
        """
        try:
            if operation == "generate":
                data = {
                    "code": auth_code,
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "client_secret": client_secret,
                }
                logger_msg = "generating access token"
            elif operation == "regenerate":
                data = {
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "client_secret": client_secret,
                }
                logger_msg = "regenerating access token"
            url = CLOUD_API_AND_AUTH_URLS.get(base_url)
            response = self.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                verify=verify,
                proxies=proxies,
                deployment_type=CLOUD,
                regenerate_auth_token=False,
                is_validation=is_validation,
            )
            return response.get("access_token"), response.get("refresh_token")
        except ServiceDeskPluginException:
            raise
        except Exception as error:
            error_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}. Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise ServiceDeskPluginException(error_msg)

    def _regenerate_access_token_and_update_storage(
        self,
        deployment_type: Literal["cloud", "onpremise"],
        storage: Dict,
        configuration: Dict,
        verify,
        proxy,
        is_validation: bool,
    ) -> str:
        """
        Regenerate the access token using the refresh token and update the
        storage.

        Args:
            deployment_type (Literal["cloud", "onpremise"]): Deployment type
                of the Service Desk Plus.
            storage (Dict): Storage dictionary containing the refresh token.
            configuration (Dict): Configuration parameter dictionary.
            verify (bool): SSL verification flag.
            proxy (Dict): Proxy configuration dictionary.
            is_validation (bool): Whether the regeneration is done for
                validation
                or not.

        Returns:
            str: The regenerated access token.

        Raises:
            ServiceDeskPluginException: If any error occurs during
                regeneration.
        """
        if deployment_type == ON_PREMISE:
            err_msg = (
                "Unauthorized error occurred. Please check whether"
                " your Auth token has the proper permissions. If it has"
                " expired, generate a new Auth Token from the 'Profile >"
                " Generate Authtoken' page and update the plugin"
                " configuration."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ServiceDeskPluginException(err_msg)
        elif deployment_type == CLOUD:
            base_url, client_id, client_secret, *_ = (
                self.get_configuration_params(
                    configuration=configuration, deployment_type=CLOUD
                )
            )
            try:
                access_token, _ = self.access_token_operation(
                    base_url=base_url,
                    client_id=client_id,
                    client_secret=client_secret,
                    refresh_token=storage.get("refresh_token"),
                    auth_code=None,
                    verify=verify,
                    proxies=proxy,
                    is_validation=is_validation,
                    operation="regenerate",
                )
                storage.update({"access_token": access_token})
                return access_token
            except ServiceDeskPluginException:
                raise
            except Exception as err:
                err_msg = (
                    "Unexpected error occurred while regenerating"
                    " access token."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=str(traceback.format_exc()),
                )
                raise ServiceDeskPluginException(err_msg)

    def get_auth_headers(
        self, token: str, deployment_type: Literal["cloud", "onpremise"]
    ):
        """
        This method returns the authorization headers for the given instance
        type.

        Args:
            token (str): The access token obtained after authentication.
            deployment_type (str): The type of instance, either cloud or
                onpremise.

        Returns:
            dict: A dictionary containing the authorization headers.
        """
        if deployment_type == CLOUD:
            return {
                "Accept": "application/vnd.manageengine.sdp.v3+json",
                "Authorization": f"Zoho-oauthtoken {token}",
                "Content-Type": "application/x-www-form-urlencoded",
            }
        elif deployment_type == ON_PREMISE:
            return {
                "Accept": "application/vnd.manageengine.sdp.v3+json",
                "authtoken": token,
                "Content-Type": "application/x-www-form-urlencoded",
            }
        else:
            err_msg = (
                f"Invalid instance type {deployment_type} provided"
                " while getting auth headers."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ServiceDeskPluginException(err_msg)

    def get_deployment_type(
        self, configuration: Dict
    ) -> Literal["cloud", "onpremise"]:
        """
        This method returns the deployment type of the given configuration.

        Args:
            configuration (Dict): The configuration dictionary containing the
                deployment type.

        Returns:
            Literal["cloud", "onpremise"]: The deployment type of the given
                configuration.
        """
        return configuration.get(
            "sdp_deployment_type", {}
        ).get("deployment_type", "")

    def generate_auth_param_hash(
        self, auth_param_string: str
    ) -> str:
        """
        This method generates a SHA256 hash of the given auth parameter string.

        Args:
            auth_param_string (str): The auth parameter string to be hashed.

        Returns:
            str: The SHA256 hash of the given auth parameter string.
        """
        return hashlib.sha256(auth_param_string.encode()).hexdigest()

    def _get_ssl_certificate_path(
        self,
        configuration: Dict,
        deployment_type: Literal["cloud", "onpremise"],
    ) -> Union[_TemporaryFileWrapper, bool]:
        """
        This method returns the path to the ssl certificate.

        Args:
            configuration (Dict): The configuration dictionary containing the
                ssl certificate.
            deployment_type (Literal["cloud", "onpremise"]): The deployment
                type of the given configuration.

        Returns:
            Union[_TemporaryFileWrapper, bool]: The path to the ssl certificate
                if the deployment type is onpremise, otherwise True.
        """
        if deployment_type == ON_PREMISE:
            ssl_cert = configuration.get("auth", {}).get("ssl_certificate")
            if not ssl_cert:
                return True
            cert_file = tempfile.NamedTemporaryFile(delete=True, suffix=".crt")
            cert_file.write(ssl_cert.encode())
            cert_file.flush()
            return cert_file
        elif deployment_type == CLOUD:
            return True
