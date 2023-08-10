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

URE Crowdstrike plugin.
"""

import datetime
import json
import os
import time
import traceback
from typing import Dict, Tuple, List

import requests
from netskope.common.utils import add_user_agent
from netskope.integrations.cre.models import (
    Action,
    ActionWithoutParams,
    Record,
    RecordType,
)
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult


PAGE_SIZE = 5000
BATCH_SIZE = 1000
MAC_PUT_DIR = "/Users"
PLUGIN_NAME = "CrowdStrike"
PLUGIN_VERSION = "1.2.0"
MODULE_NAME = "URE"
MAX_API_CALLS = 3
CROWDSTRIKE_DATE_FORMAT = r"%Y-%m-%dT%H:%M:%SZ"
COMMAND_TIMEOUT = 60
COMMAND_WAIT = 6
SCORE_TO_FILE_MAPPING = {
    "1_25": "crwd_zta_1_25.txt",
    "26_50": "crwd_zta_26_50.txt",
    "51_75": "crwd_zta_51_75.txt",
    "76_100": "crwd_zta_76_100.txt",
}


class CrowdstrikeException(Exception):
    """Crowdstrike exception class."""

    pass


class CrowdstrikePlugin(PluginBase):
    """Crowdstrike plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """CrowdStrike plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"

    def _get_plugin_info(self) -> Tuple:
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
                plugin_name = manifest_json.get("name", PLUGIN_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLUGIN_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _get_credentials(self, configuration: Dict) -> Tuple:
        """Get API Credentials.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            Tuple: Tuple containing Base URL, Client ID and Client Secret.
        """
        return (
            configuration.get("base_url", "").strip(),
            configuration.get("client_id", "").strip(),
            configuration.get("client_secret"),
        )

    def _add_user_agent(self, headers: Dict = None) -> Dict:
        """Add User-Agent in the headers of any request.

        Returns:
            Dict: Dictionary after adding User-Agent.
        """
        headers = add_user_agent(headers)
        plugin_name = self.plugin_name.lower()
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-ure-{}/{}".format(
            ce_added_agent, plugin_name, self.plugin_version
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
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise CrowdstrikeException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                " json response. Error: {}".format(exp)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise CrowdstrikeException(err_msg)

    def handle_error(
        self, resp: requests.models.Response, logger_msg: str
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
            CrowdstrikeException: When the response code is
            not 200,201 and 204.
        """
        if resp.status_code in [200, 201]:
            return self.parse_response(response=resp)
        elif resp.status_code == 204:
            return {}
        elif resp.status_code == 403:
            err_msg = "Received exit code 403, Forbidden while {}.".format(
                logger_msg
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json.get("errors")),
            )
            raise CrowdstrikeException(err_msg)
        elif resp.status_code == 404:
            err_msg = (
                "Received exit code 404, Resource not found while {}.".format(
                    logger_msg
                )
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(
                    resp_json.get(
                        "errors", "No error details found from API Response."
                    )
                ),
            )
            raise CrowdstrikeException(err_msg)
        elif resp.status_code >= 400 and resp.status_code < 500:
            err_msg = (
                "Received exit code {}, HTTP client error while {}.".format(
                    resp.status_code, logger_msg
                )
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(
                    resp_json.get(
                        "errors", "No error details found from API Response."
                    )
                ),
            )
            raise CrowdstrikeException(err_msg)
        elif resp.status_code >= 500 and resp.status_code < 600:
            err_msg = (
                "Received exit code {}. HTTP Server Error while {}.".format(
                    resp.status_code, logger_msg
                )
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(
                    resp_json.get(
                        "errors", "No error details found from API Response."
                    )
                ),
            )
            raise CrowdstrikeException(err_msg)
        else:
            err_msg = "Received exit code {}. HTTP Error while {}.".format(
                resp.status_code, logger_msg
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(
                    resp_json.get(
                        "errors", "No error details found from API Response."
                    )
                ),
            )
            raise CrowdstrikeException(err_msg)

    def _api_helper(
        self, request, logger_msg: str, is_handle_error_required=True
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
            for retry_counter in range(MAX_API_CALLS):
                response = request()
                if response.status_code == 429:
                    resp_json = self.parse_response(response=response)
                    api_err_msg = str(
                        resp_json.get(
                            "errors",
                            "No error details found in API response.",
                        )
                    )
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            "Received exit code 429, API rate limit "
                            "exceeded while {}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            " code 429.".format(logger_msg)
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise CrowdstrikeException(err_msg)
                    retry_after = response.headers.get(
                        "X-Ratelimit-Retryafter"
                    )
                    if retry_after is None:
                        self.logger.info(
                            "{}: No X-Ratelimit-Retryafter value received from"
                            "API hence plugin will retry after 60 "
                            "seconds.".format(self.log_prefix)
                        )
                        time.sleep(60)
                        continue
                    retry_after = int(retry_after)
                    diff_retry_after = abs(retry_after - time.time())
                    if diff_retry_after > 300:
                        err_msg = (
                            "'X-Ratelimit-Retryafter' value received from "
                            "response headers while {} is greater than 5  "
                            "minutes hence returning status code 429.".format(
                                logger_msg
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}"
                        )
                        raise CrowdstrikeException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code 429, API rate limit"
                            " exceeded while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                logger_msg,
                                diff_retry_after,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(diff_retry_after)
                else:
                    return (
                        self.handle_error(response, logger_msg)
                        if is_handle_error_required
                        else response
                    )
        except requests.exceptions.ProxyError as error:
            err_msg = (
                "Proxy error occurred. Verify the provided "
                "proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise CrowdstrikeException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                "Unable to establish connection with {} "
                "platform. Proxy server or {}"
                " server is not reachable.".format(
                    self.plugin_name, self.plugin_name
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise CrowdstrikeException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc()
            )
            raise CrowdstrikeException(err_msg)
        except CrowdstrikeException as exp:
            self.logger.error(
                message=f"{self.log_prefix}: {exp}",
                details=traceback.format_exc(),
            )
            raise CrowdstrikeException(exp)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting "
                "to {} server. Error: {}".format(self.plugin_name, exp)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise CrowdstrikeException(err_msg)

    def get_agent_ids(self, headers: Dict, device_id: str = None) -> List[str]:
        """Get the all the Agent ID list from the Query Endpoint.

        Args:
            headers (Dict): Header dict object having OAUTH2 access token.
            device_id (str): Device id. Default None.

        Returns:
            dict: List of agent ids received from CrowdStrike platform.
        """
        base_url = self.configuration.get("base_url", "").strip()
        query_endpoint = f"{base_url}/devices/queries/devices-scroll/v1"
        self.logger.debug(
            "{}: Pulling the host ids from {} "
            "using endpoint {}.".format(
                self.log_prefix, self.plugin_name, query_endpoint
            )
        )
        api_filter = None
        if self.last_run_at and (device_id is None):
            # This filter is for fetching only the updated hosts.
            formatted_date = self.last_run_at.strftime(CROWDSTRIKE_DATE_FORMAT)
            api_filter = f"first_seen: > '{formatted_date}'"
            self.logger.debug(
                "{}: Plugin will be pulling host id(s) from {} using "
                'checkpoint "{}".'.format(
                    self.log_prefix, self.plugin_name, api_filter
                )
            )

        elif device_id:
            # This filter is to fetch the hosts on the bases of provided
            # device id. This filter is utilized in execute_action
            api_filter = f"device_id: '{device_id}'"
            self.logger.debug(
                '{}: Pulling the Host with ID "{}" from {}.'.format(
                    self.log_prefix, device_id, self.plugin_name
                )
            )
        elif self.last_run_at is None:
            self.logger.info(
                "{}: This is an initial pull of the plugin hence pulling all"
                " the host id(s) present on the {} Host Management"
                " page.".format(self.log_prefix, self.plugin_name)
            )

        agent_ids = []
        offset = ""
        while True:
            headers = self.reload_auth_token(headers)
            params = {"limit": PAGE_SIZE, "offset": offset}
            if api_filter is not None:
                # Adding filter only when api_filter is not None.
                params.update({"filter": api_filter})

            self.logger.debug(
                "{}: Pulling the host id(s) from {} using filter"
                " parameters {}".format(
                    self.log_prefix, self.plugin_name, params
                )
            )
            all_agent_resp = self._api_helper(
                request=lambda: requests.get(
                    query_endpoint,
                    headers=self._add_user_agent(headers),
                    params=params,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                ),
                logger_msg="pulling the host id(s) from {} platform".format(
                    self.plugin_name
                ),
                is_handle_error_required=True,
            )
            resources = all_agent_resp.get("resources", [])
            offset = (
                all_agent_resp.get("meta", {})
                .get("pagination", {})
                .get("offset", "")
            )
            agent_ids.extend(resources)
            self.logger.info(
                "{}: Successfully pulled {} host id(s) from {} in "
                "current page. Total {} host id(s) fetched so far in the "
                "current pull cycle.".format(
                    self.log_prefix,
                    len(resources),
                    self.plugin_name,
                    len(agent_ids),
                )
            )
            if not offset.strip():
                break
        self.logger.info(
            "{}: Successfully pulled {} host id(s) from {} platform.".format(
                self.log_prefix, len(agent_ids), self.plugin_name
            )
        )
        return agent_ids

    def _put_files_on_rtr_cloud(self):
        """Put files on RTR cloud."""
        base_url, client_id, client_secret = self._get_credentials(
            configuration=self.configuration
        )
        put_files_url = f"{base_url}/real-time-response/entities/put-files/v1"
        auth_json = self.get_auth_json(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
        )
        auth_token = auth_json.get("access_token")
        headers = {"Authorization": f"Bearer {auth_token}"}
        self.logger.debug(
            "{}: Creating files for all the scores on the RTR Cloud using"
            " endpoint {}. Files: {}".format(
                self.log_prefix,
                put_files_url,
                list(SCORE_TO_FILE_MAPPING.values()),
            )
        )
        for score, file in SCORE_TO_FILE_MAPPING.items():
            headers = self.reload_auth_token(headers=headers)
            PAYLOAD = {
                "description": f"file representing a ZTA score of {score}",
                "name": file,
                "comments_for_audit_log": (
                    "uploaded file representing a ZTA "
                    "score of {} for Netskope ZTA-RTR integration".format(
                        score
                    )
                ),
            }

            file_upload = [("file", "Netskope ZTA-RTR Integration")]
            self.logger.debug(
                "{}: Creating file for score {} and name {} on "
                "RTR cloud. File object: {}, Payload: {}".format(
                    self.log_prefix, score, file, file_upload, PAYLOAD
                )
            )
            logger_msg = f"putting file {file} on RTR cloud"
            response = self._api_helper(
                request=lambda: requests.post(
                    url=put_files_url,
                    files=file_upload,
                    data=PAYLOAD,
                    headers=self._add_user_agent(headers),
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                ),
                logger_msg=logger_msg,
                is_handle_error_required=False,
            )
            if response.status_code in [200, 201]:
                self.logger.info(
                    "{}: {} file successfully uploaded on RTR cloud.".format(
                        self.log_prefix, file
                    )
                )

            elif response.status_code == 409:
                resp_json = self.parse_response(response=response)
                errors = resp_json.get("errors", [])
                if errors:
                    for error in errors:
                        if (
                            error.get("message", "")
                            != "file with given name already exists"
                        ):
                            err_msg = (
                                "Received exit code {}, while {}.".format(
                                    response.status_code, logger_msg
                                )
                            )
                            self.logger.error(
                                message=f"{self.log_prefix}: {logger_msg}",
                                details=str(errors),
                            )
                            raise CrowdstrikeException(err_msg)
                    self.logger.debug(
                        "{}: File with given name {} already exist on "
                        "RTR Cloud. API Response: {}".format(
                            self.log_prefix, file, errors
                        )
                    )
            else:
                self.handle_error(resp=response, logger_msg=logger_msg)

    def _get_session_id(self, device_id: str) -> str:
        """Get session id of the connection made to the device.

        Args:
            device_id (str): Id of device that plugin will make session with.

        Returns:
            str: Session id of the connection.
        """
        base_url, client_id, client_secret = self._get_credentials(
            configuration=self.configuration
        )
        query_endpoint = f"{base_url}/real-time-response/entities/sessions/v1"
        auth_json = self.get_auth_json(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
        )
        auth_token = auth_json.get("access_token")
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        }
        body = {
            "device_id": device_id,
            "origin": "Netskope",
            "queue_offline": True,
        }
        self.logger.debug(
            '{}: Creating session with host "{}" using endpoint {}. '
            "API payload: {}".format(
                self.log_prefix, device_id, query_endpoint, body
            )
        )
        resp_json = self._api_helper(
            lambda: requests.post(
                query_endpoint,
                headers=self._add_user_agent(headers),
                data=json.dumps(body),
                verify=self.ssl_validation,
                proxies=self.proxy,
            ),
            logger_msg=f'creating session with host ID "{device_id}"',
            is_handle_error_required=True,
        )
        session_id = ""
        resources = resp_json.get("resources", [])
        if resources:
            session_id = resources[0].get("session_id", "")
            self.logger.debug(
                '{}: Successfully created session with host "{}".'.format(
                    self.log_prefix, device_id
                )
            )
            return session_id
        else:
            self.logger.debug(
                "{}: Unable to get the session id from the response json for"
                ' the host "{}". Response json: {}'.format(
                    self.log_prefix, device_id, resp_json
                )
            )

    def _remove_files_from_device(
        self, session_id: str, device_id: str, platform_name: str
    ):
        """Remove files from the remote host.

        Args:
            session_id (str): Session Id to remove files against.
            device_id (str): Id of the remote host.
            platform_name (str): platform name of host.
        """
        score_files = list(SCORE_TO_FILE_MAPPING.values())
        self.logger.debug(
            '{}: Removing files present on the host with ID "{}". Files '
            "to be removed are {}".format(
                self.log_prefix, device_id, score_files
            )
        )
        base_url, client_id, client_secret = self._get_credentials(
            configuration=self.configuration
        )
        auth_json = self.get_auth_json(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
        )
        auth_token = auth_json.get("access_token")
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        }
        for file in score_files:
            cmd = f"rm '{file}'"
            if platform_name == "Mac":
                cmd = f"rm '{MAC_PUT_DIR}/{file}'"
            self.logger.debug(
                '{}: Command "{}" will be executed on host'
                ' with ID "{}".'.format(self.log_prefix, cmd, device_id)
            )
            headers = self.reload_auth_token(headers=headers)
            cloud_request_id, is_queued = self._execute_command(
                "rm", cmd, session_id, device_id, headers
            )
            headers = self.reload_auth_token(headers=headers)
            status = self._check_command_status(
                cloud_request_id=cloud_request_id,
                device_id=device_id,
                cmd=cmd,
                headers=headers,
            )
            if status is False and is_queued is True:
                self.logger.info(
                    '{}: Execution of command "{}" on host with ID "{}" '
                    "is in RTR queue.".format(self.log_prefix, cmd, device_id)
                )
            if status is False and is_queued is False:
                self._block_until_completed(
                    status=status,
                    cloud_request_id=cloud_request_id,
                    device_id=device_id,
                    cmd=cmd,
                    headers=headers,
                )

    def _block_until_completed(
        self,
        status: bool,
        cloud_request_id: str,
        device_id: str,
        cmd: str,
        headers: Dict,
    ):
        """Block execution until command successfully executed.

        Args:
            status (bool): Status of command.
            cloud_request_id (str): Cloud request Id of the request.
            device_id (str): Device ID.
            cmd (str): Command to be executed.
        """
        start_time = time.time()
        while status is False:
            # Run the look until status is True
            headers = self.reload_auth_token(headers=headers)
            status = self._check_command_status(
                cloud_request_id=cloud_request_id,
                device_id=device_id,
                cmd=cmd,
                headers=headers,
            )
            curr_time = time.time()
            if status:
                # If status is true then return.
                return
            elif curr_time - start_time > COMMAND_TIMEOUT:
                # Raise timeout if status is False and time is 60 seconds.
                err_msg = (
                    "Timeout exceeded for executing "
                    "command {} on host ID {}".format(cmd, device_id)
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise CrowdstrikeException(err_msg)

            # Adding delay of command wait after which API call
            # for status will be done
            time.sleep(COMMAND_WAIT)

    def _put_file_on_device(
        self, session_id: str, score: int, device_id: str, platform_name: str
    ) -> str:
        """Put file on the remote host.

        Args:
            session_id (str): Session id to put files against.
            score (int): score to determine which file is to be put.
            device_id (str): Id of the remote host.
            platform_name (str): Platform name of the host.
        """
        file = None
        score = int(score / 10)
        if score <= 25:
            file = SCORE_TO_FILE_MAPPING["1_25"]
        elif score >= 26 and score <= 50:
            file = SCORE_TO_FILE_MAPPING["26_50"]
        elif score >= 51 and score <= 75:
            file = SCORE_TO_FILE_MAPPING["51_75"]
        elif score > 75:
            file = SCORE_TO_FILE_MAPPING["76_100"]
        else:
            err_msg = (
                "Invalid score value received for putting file on device."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise CrowdstrikeException()
        base_url, client_id, client_secret = self._get_credentials(
            configuration=self.configuration
        )
        auth_json = self.get_auth_json(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
        )
        auth_token = auth_json.get("access_token")
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        }
        if platform_name == "Mac":
            cmd = f"cd '{MAC_PUT_DIR}'"
            cloud_request_id, is_queued = self._execute_command(
                "cd", cmd, session_id, device_id, headers
            )
            status = self._check_command_status(
                cloud_request_id=cloud_request_id,
                device_id=device_id,
                cmd=cmd,
                headers=headers,
            )
            if status is False and is_queued is False:
                self._block_until_completed(
                    status=status,
                    cloud_request_id=cloud_request_id,
                    device_id=device_id,
                    cmd=cmd,
                    headers=headers,
                )

        cloud_request_id, is_queued = self._execute_command(
            "put", f"put '{file}'", session_id, device_id, headers
        )
        status = self._check_command_status(
            cloud_request_id, device_id, f"put {file}", headers
        )
        if status is False and is_queued is False:
            self._block_until_completed(
                status=status,
                cloud_request_id=cloud_request_id,
                device_id=device_id,
                cmd=f"put {file}",
                headers=headers,
            )

    def _execute_command(
        self,
        base_command: str,
        command_string: str,
        session_id: str,
        device_id: str,
        headers: Dict,
    ) -> str:
        """Execute the specified command on the remote host.

        Args:
            base_command (str): Base command to perform.
            command_string (str): Full command line of the command to execute.
            session_id (str): Session id to execute the command against.
            device_id (str): Id of the remote host.
            headers (Dict): Headers dictionary containing auth token
            and Content-Type

        Returns:
            str: Cloud request id to check status of the command.
        """
        base_url = self.configuration.get("base_url")
        query_endpoint = (
            f"{base_url}/real-time-response/entities/admin-command/v1"
        )
        body = {
            "base_command": base_command,
            "command_string": command_string,
            "persist": True,
            "session_id": session_id,
        }
        resp_json = self._api_helper(
            lambda: requests.post(
                query_endpoint,
                headers=self._add_user_agent(headers),
                data=json.dumps(body),
                verify=self.ssl_validation,
                proxies=self.proxy,
            ),
            logger_msg='executing "{}" command on host ID {}'.format(
                command_string, device_id
            ),
            is_handle_error_required=True,
        )
        cloud_request_id, is_queued = "", False
        resources = resp_json.get("resources", [])
        if resources:
            cloud_request_id = resources[0].get("cloud_request_id", "")
            is_queued = resources[0].get("queued_command_offline")
        return cloud_request_id, is_queued

    def _check_command_status(
        self, cloud_request_id: str, device_id: str, cmd: str, headers: Dict
    ):
        """Check the status of the executed command.

        Args:
            cloud_request_id (str): Cloud request id generated from execute
            command.
            device_id (str): Device id on which the command was executed.
            cmd (str): Command that was
            headers (Dict): Headers dictionary containing auth token
            and Content-Type
        """
        base_url = self.configuration.get("base_url", "").strip()
        query_endpoint = (
            f"{base_url}/real-time-response/entities/admin-command/v1"
        )
        params = {
            "cloud_request_id": cloud_request_id,
            "sequence_id": 0,
        }

        resp_json = self._api_helper(
            lambda: requests.get(
                query_endpoint,
                headers=self._add_user_agent(headers),
                params=params,
                verify=self.ssl_validation,
                proxies=self.proxy,
            ),
            logger_msg=(
                'checking status of command "{}" on host'
                ' ID "{}"'.format(cmd, device_id)
            ),
            is_handle_error_required=True,
        )
        resources = resp_json.get("resources", [])
        if resources:
            stderr = resources[0].get("stderr", "")
            if resources[0].get("complete") is False and stderr != "":
                err_msg = (
                    'Unable to execute the "{}" command on '
                    'host ID "{}".'.format(cmd, device_id)
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(resources),
                )
                raise CrowdstrikeException(err_msg)

            elif resources[0].get("complete") is False and stderr == "":
                self.logger.info(
                    '{}: Execution of "{}" on host ID "{}" is still '
                    "in progress. API Response: {}".format(
                        self.log_prefix, cmd, device_id, resources
                    )
                )
                return False
            elif resources[0].get("complete") is True:
                self.logger.info(
                    '{}: Successfully executed command "{}" on host ID'
                    ' "{}".'.format(self.log_prefix, cmd, device_id)
                )
                return True

            if stderr and "already exists" not in stderr:
                err_msg = (
                    'Unable to execute the "{}" command on the '
                    'host ID "{}". Error: {}'.format(cmd, device_id, stderr)
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(resources),
                )
                raise CrowdstrikeException(err_msg)
            self.logger.info(
                '{}: "{}" is successfully executed '
                'on host ID "{}".'.format(self.log_prefix, cmd, device_id)
            )

    def _delete_session(self, session_id: str, device_id: str):
        """Delete the created session with the remote host.

        Args:
            session_id (str): Session id to delete the session.
            device_id (str): Device id of the connected host.
        """
        base_url, client_id, client_secret = self._get_credentials(
            configuration=self.configuration
        )
        query_endpoint = (
            f"{base_url}/real-time-response/entities/sessions/v1"  # noqa
        )
        auth_json = self.get_auth_json(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
        )
        auth_token = auth_json.get("access_token")
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        }
        params = {"session_id": session_id}
        self.logger.debug(
            '{}: Deleting the session with host having ID "{}". '
            "API parameters: {}".format(self.log_prefix, device_id, params)
        )
        logger_msg = f"deleting session with host ID {device_id}"
        resp = self._api_helper(
            lambda: requests.delete(
                query_endpoint,
                headers=self._add_user_agent(headers),
                params=params,
                verify=self.ssl_validation,
                proxies=self.proxy,
            ),
            logger_msg=logger_msg,
            is_handle_error_required=False,
        )
        if resp.status_code == 204:
            self.logger.debug(
                "{}: Successfully deleted session with host "
                'having id "{}".'.format(self.log_prefix, device_id)
            )
        self.handle_error(resp=resp, logger_msg=logger_msg)

    def fetch_records(self) -> List[Record]:
        """Get the all the Agent ID list from the Query Endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token.

        Returns:
            List[Record]: List of hosts fetched from CrowdStrike.
        """
        self.logger.debug(
            "{}: Fetching records from {} platform.".format(
                self.log_prefix, self.plugin_name
            )
        )
        base_url, client_id, client_secret = self._get_credentials(
            configuration=self.configuration
        )
        auth_json = self.get_auth_json(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
        )
        auth_token = auth_json.get("access_token")
        headers = {"Authorization": f"Bearer {auth_token}"}
        agent_ids = self.get_agent_ids(headers)
        uids_names = []
        for ids in agent_ids:
            uids_names.append(Record(uid=ids, type=RecordType.HOST))
        self.logger.info(
            "{}: Successfully fetched {} host(s) from {} platform.".format(
                self.log_prefix, len(uids_names), self.plugin_name
            )
        )
        return uids_names

    def fetch_scores(self, agent_ids: List[Record]) -> List[Record]:
        """Fetch scores of hosts from CrowdStrike platform.

        Args:
            agent_ids (List[Record]): List of records containing host's
            agent ids.

        Returns:
            List[Record]: List of records with scores.
        """
        base_url, client_id, client_secret = self._get_credentials(
            configuration=self.configuration
        )
        zero_trust_assessment_url = (
            f"{base_url}/zero-trust-assessment/entities/assessments/v1"
        )
        self.logger.debug(
            "{}: Fetching the score(s) for record(s) from {} "
            'platform using "{}".'.format(
                self.log_prefix, self.plugin_name, zero_trust_assessment_url
            )
        )
        auth_json = self.get_auth_json(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
        )
        aids = [ids.uid for ids in agent_ids if ids.type == RecordType.HOST]
        self.logger.debug(
            "{}: {} plugin only supports the hosts hence it will only fetch "
            "scores for {} host(s) and will not fetch scores for remaining {} "
            "user(s).".format(
                self.log_prefix,
                self.plugin_name,
                len(aids),
                len(agent_ids) - len(aids),
            )
        )
        scores = {}
        for i in range(0, len(aids), BATCH_SIZE):
            aid_batch = aids[i : i + BATCH_SIZE]  # noqa
            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}"}
            payload = {"ids": aid_batch}
            headers = self.reload_auth_token(headers)
            logger_msg = f"pulling scores from {self.plugin_name} platform"
            resp = self._api_helper(
                request=lambda: requests.get(
                    zero_trust_assessment_url,
                    headers=self._add_user_agent(headers),
                    params=payload,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                ),
                logger_msg=logger_msg,
                is_handle_error_required=False,
            )
            resp_json = None
            if resp.status_code == 404:
                # If the assessment of the host is not found on
                # the CrowdStrike then the API returns 404 for the
                # response but it sends the valid response for
                # the other assessment ids.
                err_msg = (
                    "Received exit code {}, "
                    "Resource not found while {}.".format(
                        resp.status_code, logger_msg
                    )
                )
                resp_json = self.parse_response(response=resp)
                self.logger.error(
                    message=(
                        "{}: {} One or more assessment ids "
                        "are not found on {} platform.".format(
                            self.log_prefix, err_msg, self.plugin_name
                        )
                    ),
                    details=str(
                        resp_json.get(
                            "errors",
                            "No error details found from API Response.",
                        )
                    ),
                )
            else:
                resp_json = self.handle_error(resp=resp, logger_msg=logger_msg)

            if resp_json:
                for sub in resp_json.get("resources", []):
                    scores[sub.get("aid")] = (
                        sub.get("assessment", {}).get("overall") * 10
                    )
                self.logger.info(
                    "{}: Successfully pulled scores for {} host(s) "
                    "from {} platform in the current batch. The total score(s)"
                    " for {} host(s) have been fetched "
                    "so far in the current pull cycle.".format(
                        self.log_prefix,
                        len(resp_json.get("resources", [])),
                        self.plugin_name,
                        len(scores),
                    )
                )

        scored_uids = []
        count_host = 0
        maximum_score = int(self.configuration.get("maximum_score"))
        for aid, score in scores.items():
            if score <= maximum_score:
                scored_uids.append(
                    Record(uid=aid, type=RecordType.HOST, score=score)
                )
                count_host += 1
        self.logger.info(
            "{}: Successfully fetched scores for {} host(s) and"
            " skipped fetching scores for {} host(s) on the basis of Maximum "
            "Score i.e({}) provided in the plugin configuration.".format(
                self.log_prefix,
                count_host,
                len(aids) - count_host,
                maximum_score,
            )
        )
        return scored_uids

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Put RTR Script", value="rtr"),
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def validate_action(self, action: Action):
        """Validate Netskope configuration."""
        if action.value not in ["generate", "rtr"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []

    def _get_host_platform_name(self, host_id: str) -> str:
        """Get the host platform name.

        Args:
            host_id (str): Host ID.

        Returns:
            str: Platform Name. for e.g. Windows or mac.
        """
        url = f"{self.configuration['base_url']}/devices/entities/devices/v2"
        base_url, client_id, client_secret = self._get_credentials(
            configuration=self.configuration
        )
        auth_json = self.get_auth_json(
            base_url=base_url, client_id=client_id, client_secret=client_secret
        )

        auth_token = auth_json.get("access_token")
        headers = {"Authorization": f"Bearer {auth_token}"}
        headers = self.reload_auth_token(headers)
        params = {"ids": [host_id]}
        self.logger.debug(
            '{}: Getting platform name for host ID "{}" using '
            "endpoint {}. Parameters: {}".format(
                self.log_prefix, host_id, url, params
            )
        )
        resp_json = self._api_helper(
            lambda: requests.get(
                url,
                headers=self._add_user_agent(headers),
                params=params,
                verify=self.ssl_validation,
                proxies=self.proxy,
            ),
            logger_msg=f"getting platform details of host ID {host_id}",
            is_handle_error_required=True,
        )
        platform_name = resp_json.get("resources", [{}])[0].get(
            "platform_name", ""
        )
        self.logger.debug(
            '{}: Successfully fetched platform name for host ID "{}".'
            " Platform name: {}".format(
                self.log_prefix, host_id, platform_name
            )
        )
        return platform_name

    def _get_device_match(self, device_id: str) -> bool:
        """Get device match.

        Args:
            device_id (str): Device ID.

        Returns:
            bool: True if device is found else False.
        """
        base_url, client_id, client_secret = self._get_credentials(
            configuration=self.configuration
        )
        auth_json = self.get_auth_json(
            base_url=base_url, client_id=client_id, client_secret=client_secret
        )
        auth_token = auth_json.get("access_token")
        headers = {"Authorization": f"Bearer {auth_token}"}
        agent_ids = self.get_agent_ids(headers, device_id)
        return True if device_id in agent_ids else False

    def execute_action(self, record: Record, action: Action):
        """Execute action on the record.

        Args:
            record (Record): Record object containing record id and score
            action (Action): Actions object containing action label and value.
        """
        action_label = action.label
        self.logger.debug(
            "{}: Executing action {} on record {}.".format(
                self.log_prefix, action_label, record.uid
            )
        )
        if action.value == "generate":
            self.logger.debug(
                '{}: Successfully executed "{}" action on record "{}". '
                "Note: No processing will be done from plugin for "
                'the "{}" action.'.format(
                    self.log_prefix, action_label, record.uid, action_label
                )
            )
            return
        elif record.type != RecordType.HOST:
            self.logger.debug(
                "{}: CrowdStrike plugin only supports Hosts hence skipping"
                " execution of action {} on user {}.".format(
                    self.log_prefix,
                    action_label,
                    record.uid,
                )
            )
            return
        elif not record.scores:
            self.logger.debug(
                "{}: Score for host {} not found on cloud exchange"
                " hence {} action will not perform on it.".format(
                    self.log_prefix, record.uid, action_label
                )
            )
            return
        device = record.uid

        # Verify whether host is present on CrowdStrike platform or not.
        self.logger.debug(
            f"{self.log_prefix}: Verifying the existence of"
            " host on CrowdStrike platform."
        )
        match = self._get_device_match(record.uid)
        if not match:
            self.logger.warn(
                "{}: Host with ID {} was not "
                "found on {} platform. Hence {} action will not be executed on"
                " this it.".format(
                    self.log_prefix, device, action_label, self.plugin_name
                )
            )
            return
        self.logger.debug(
            '{}: Since the host with ID "{}" is present on the {} platform,'
            " the {} action will be executed on it.".format(
                self.log_prefix, device, self.plugin_name, action_label
            )
        )
        if action.value == "rtr":
            score_to_be_put = None
            for score in record.scores:
                if score.source == self.name:
                    score_to_be_put = score.current
                    self.logger.debug(
                        "{}: Current score for the host is {}. Hence "
                        "action will be performed on the basis of current"
                        " host's score.".format(
                            self.log_prefix, score_to_be_put
                        )
                    )
            # If score is None then skip the execution of action on host.
            if score_to_be_put is None:
                err_msg = (
                    "Could not find score for host ID {}. Hence "
                    "action will not be performed on this host.".format(
                        record.uid
                    )
                )
                self.logger.warn(f"{self.log_prefix}: {err_msg}")
                raise CrowdstrikeException(err_msg)

            # Step 1: Put the file on RTR cloud.
            self._put_files_on_rtr_cloud()

            # Step 2: Create session with host.
            session_id = self._get_session_id(device)

            # Step 3: Get platform name with host id.
            platform_name = self._get_host_platform_name(host_id=record.uid)

            # Step 4: Remove the present file from RTR cloud.
            self._remove_files_from_device(session_id, device, platform_name)

            # Step 5: Put file on device.
            self._put_file_on_device(
                session_id=session_id,
                score=score_to_be_put,
                device_id=device,
                platform_name=platform_name,
            )

            # Step 6: Delete the session with host.
            self._delete_session(session_id, device)
            self.logger.info(
                "{}: Successfully executed {} action on "
                'host with ID "{}".'.format(
                    self.log_prefix, action_label, device
                )
            )

    def reload_auth_token(self, headers: Dict) -> Dict:
        """Reload the OAUTH2 token after Expiry.

        Args:
            headers (Dict): Headers

        Returns:
            Dict: Dictionary containing auth token.
        """
        base_url, client_id, client_secret = self._get_credentials(
            configuration=self.configuration
        )
        if self.storage is None:
            # If storage is None then generate the auth token.
            auth_json = self.get_auth_json(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
            )
            auth_token = auth_json.get("access_token")
            headers.update({"Authorization": f"Bearer {auth_token}"})

        elif self.storage.get("token_expiry") < (
            datetime.datetime.now() + datetime.timedelta(seconds=5)
        ):
            # If token is expired then generate the new token.
            self.logger.info(
                f"{self.log_prefix}: OAUTH2 token expired generating"
                " new token."
            )
            auth_json = self.get_auth_json(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
            )
            auth_token = auth_json.get("access_token")
            headers.update({"Authorization": f"Bearer {auth_token}"})
        return headers

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin configuration
            parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success
            flag and message.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validation configuration parameters."
        )
        base_url = configuration.get("base_url", "").strip()
        if "base_url" not in configuration or base_url not in [
            "https://api.crowdstrike.com",
            "https://api.us-2.crowdstrike.com",
            "https://api.laggar.gcw.crowdstrike.com",
            "https://api.eu-1.crowdstrike.com",
        ]:
            err_msg = "Invalid Base URL provided in configuration parameters."
            self.logger.error(
                "{}: Validation error occurred. "
                "Error: {} Select the Base URL"
                " from available options.".format(self.log_prefix, err_msg)
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        client_id = configuration.get("client_id", "").strip()
        if "client_id" not in configuration or not client_id:
            err_msg = "Client ID is a required configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(configuration.get("client_id"), str):
            err_msg = "Invalid Client ID provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        client_secret = configuration.get("client_secret")
        if "client_secret" not in configuration or not client_secret:
            err_msg = "Client Secret is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_secret, str):
            err_msg = (
                "Invalid Client Secret provided in configuration parameters."
            )
            self.logger.error(
                "{}: Validation error occurred. {}"
                " Client Secret should be a string value.".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        maximum_score = configuration.get("maximum_score")
        if "maximum_score" not in configuration or maximum_score is None:
            err_msg = "Maximum Score is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif maximum_score < 1 or maximum_score > 1000:
            err_msg = (
                "Invalid Maximum Score provided in configuration parameters."
                " Maximum Score must be in range from 1 to 1000."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate the auth parameters.
        self.logger.debug(
            "{}: Successfully validated basic configuration parameter.".format(
                self.log_prefix
            )
        )

        return self.validate_auth_params(client_id, client_secret, base_url)

    def validate_auth_params(self, client_id, client_secret, base_url):
        """Validate the authentication params with CrowdStrike platform.

        Args:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2
            token.
            base_url (str): Base url of crowd strike
        Returns:
            ValidationResult: ValidationResult object having validation
            results after making
            an API call.
        """
        self.logger.debug(f"{self.log_prefix}: Validating auth credentials.")
        try:
            validation_result = self.check_url_valid(
                client_id, client_secret, base_url
            )
            if validation_result.success:
                self.logger.debug(f"{self.log_prefix}: Validation successful.")
            return validation_result
        except CrowdstrikeException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = f"Unexpected validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)

    def check_url_valid(self, client_id, client_secret, base_url):
        """
        Validate the authentication params with CrowdStrike platform.

        Args:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2
            token.
            base_url (str): Base url of crowd strike
        Returns:
            Raise error if valid base url is not selected.
        """
        auth_json = self.get_auth_json(client_id, client_secret, base_url)
        auth_token = auth_json.get("access_token")
        headers = {"Authorization": f"Bearer {auth_token}"}
        query_endpoint = f"{base_url}/devices/queries/devices/v1?limit=1"
        response = self._api_helper(
            lambda: requests.get(
                query_endpoint,
                headers=self._add_user_agent(headers),
                verify=self.ssl_validation,
                proxies=self.proxy,
            ),
            logger_msg="checking connectivity with {} platform".format(
                self.plugin_name
            ),
            is_handle_error_required=False,
        )
        if response.status_code == 200:
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif response.status_code == 403:
            err_msg = (
                "Received exit code {}, Forbidden. Verify the "
                "API scopes provided to Client ID and Client Secret.".format(
                    response.status_code
                )
            )
            resp_json = self.parse_response(response)
            api_errors = resp_json.get(
                "errors", "No error details received from API response."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(api_errors),
            )
            return ValidationResult(success=False, message=err_msg)

        return self.handle_error(response, "validating the auth credentials")

    def get_auth_json(self, client_id, client_secret, base_url):
        """Get the OAUTH2 Json object with access token from CrowdStrike
        platform.

        Args:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2
            token.
            base_url (str): Base URL of crowdstrike.
        Returns:
            json: JSON response data in case of Success.
        """
        auth_endpoint = f"{base_url}/oauth2/token"
        self.logger.debug(
            '{}: Fetching auth token from {} using endpoint "{}".'.format(
                self.log_prefix, self.plugin_name, auth_endpoint
            )
        )
        auth_params = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        response = self._api_helper(
            lambda: requests.post(
                auth_endpoint,
                data=auth_params,
                verify=self.ssl_validation,
                proxies=self.proxy,
                headers=self._add_user_agent(),
            ),
            logger_msg=f"getting auth token from {self.plugin_name}",
            is_handle_error_required=False,
        )
        if response.status_code == 201:
            resp_json = self.parse_response(response)
            if self.storage is not None:
                self.storage[
                    "token_expiry"
                ] = datetime.datetime.now() + datetime.timedelta(
                    seconds=int(resp_json.get("expires_in", 1799))
                )
            self.logger.debug(
                "{}: Successfully fetched auth token.".format(self.log_prefix)
            )
            return resp_json
        elif response.status_code == 400:
            resp_json = self.parse_response(response)
            api_errors = resp_json.get(
                "errors", "No error details received from API response."
            )
            err_msg = (
                "Received exit code {}, Invalid request. Verify the"
                " Base URL, Client ID and Client Secret provided in"
                " configuration parameters.".format(response.status_code)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(api_errors),
            )
            raise CrowdstrikeException(err_msg)
        elif response.status_code == 401:
            resp_json = self.parse_response(response)
            api_errors = resp_json.get(
                "errors", "No error details received from API response."
            )
            err_msg = (
                "Received exit code {}, Unauthorized. Verify the"
                " Client ID and Client Secret provided in"
                " configuration parameters.".format(response.status_code)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(api_errors),
            )
            raise CrowdstrikeException(err_msg)
        elif response.status_code == 403:
            resp_json = self.parse_response(response)
            api_errors = resp_json.get(
                "errors", "No error details received from API response."
            )
            err_msg = (
                "Received exit code {}, Forbidden. Verify the API"
                " scopes provided to the Client ID and Client Secret.".format(
                    response.status_code
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(api_errors),
            )
            raise CrowdstrikeException(err_msg)

        return self.handle_error(
            response, f"getting auth token from {self.plugin_name}"
        )
