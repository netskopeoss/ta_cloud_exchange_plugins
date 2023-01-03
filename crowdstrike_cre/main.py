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

"""Crowdstrike URE plugin."""
import datetime
import json
import time
from typing import List

import requests
from netskope.common.utils import add_user_agent
from netskope.integrations.cre.models import (
    Action,
    ActionWithoutParams,
    Record,
    RecordType,
)
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from requests.models import HTTPError

from .lib.falconpy.api_complete import APIHarness

PAGE_SIZE = 5000
BATCH_SIZE = 1000
MAC_PUT_DIR = "/Users"
PLATFORM_TO_SCRIPT_MAPPING = {
    "Windows": {
        "script_name": "windows_agent_restart_script.ps1",
        "description": "Windows Netskope restart agent script.",
    },
    "Mac": {"script_name": "mac_agent_restart_script"},
}

PLUGIN_NAME = "Crowdstrike URE Plugin"


class CrowdstrikeException(Exception):
    """Crowdstrike exception class."""

    pass


class CrowdstrikePlugin(PluginBase):
    """Crowdstrike plugin implementation."""

    def handle_error(self, resp):
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
            try:
                return resp.json()
            except ValueError:
                raise CrowdstrikeException(
                    f"{PLUGIN_NAME}: "
                    "Exception occurred while parsing JSON response."
                )

        elif resp.status_code == 401:
            raise CrowdstrikeException(
                f"{PLUGIN_NAME}: "
                "Received exit code 401, Authentication Error"
            )

        elif resp.status_code == 403:
            raise CrowdstrikeException(
                f"{PLUGIN_NAME}: Received exit code 403, Forbidden User"
            )
        elif resp.status_code == 404:

            try:
                resp = resp.json()
            except Exception as exp:
                self.logger.error(
                    message=f"{PLUGIN_NAME}: response code 404 "
                    "received. Error while parsing response in json.",
                    details=exp.with_traceback(),
                )
                return
            self.logger.error(
                message=f"{PLUGIN_NAME}: One or more assessment ids "
                "are not found in crowdstrike.",
                details=str(resp.get("errors", "")),
            )
            return resp
        elif resp.status_code >= 400 and resp.status_code < 500:
            raise CrowdstrikeException(
                f"{PLUGIN_NAME}: "
                f"Received exit code {resp.status_code}, HTTP client Error"
            )

        elif resp.status_code >= 500 and resp.status_code < 600:
            raise CrowdstrikeException(
                f"{PLUGIN_NAME}: "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )

        else:
            raise CrowdstrikeException(
                f"{PLUGIN_NAME}: "
                f"Received exit code {resp.status_code}, HTTP Error"
            )

    def get_agent_ids(self, headers, device_id=None):
        """Get the all the Agent ID list from the Query Endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token.
            device_id(Optional): Device id.

        Returns:
            dict: JSON response dict received from query endpoint.
        """
        base_url = self.configuration["base_url"].strip()
        query_endpoint = f"{base_url}/devices/queries/devices-scroll/v1"
        agent_ids = []
        offset = ""
        while True:
            headers = self.reload_auth_token(headers)
            params = {"limit": PAGE_SIZE, "offset": offset}
            if self.last_run_at and (device_id is None):
                formatted_date = self.last_run_at.strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                params.update({"filter": f"first_seen: > '{formatted_date}'"})
            elif device_id:
                params.update({"filter": f"device_id: '{device_id}'"})

            all_agent_resp = requests.get(
                query_endpoint,
                headers=add_user_agent(headers),
                params=params,
                proxies=self.proxy,
            )
            agent_resp_json = self.handle_error(all_agent_resp)
            errors = agent_resp_json.get("errors")
            if errors:
                err_msg = " ".join(
                    [
                        f"{PLUGIN_NAME}: Unable to Fetch agents",
                        f"Error: {errors[0].get('message', '')}",
                    ]
                )

                self.notifier.error(err_msg)
                self.logger.error(err_msg)
                raise requests.HTTPError(err_msg)
            resources = agent_resp_json.get("resources", [])
            offset = (
                agent_resp_json.get("meta", {})
                .get("pagination", {})
                .get("offset", "")
            )
            agent_ids.extend(resources)
            if offset.strip() == "" or len(offset) == 0:
                break
        return agent_ids

    def _get_falcon(self):
        """Get Falcon object to perform operations."""
        falcon = APIHarness(
            client_id=self.configuration["client_id"].strip(),
            client_secret=self.configuration["client_secret"].strip(),
        )
        return falcon

    def _put_files_on_rtr_cloud(self):
        """Put files on RTR cloud."""
        falcon = self._get_falcon()
        files = [
            "crwd_zta_1_25.txt",
            "crwd_zta_26_50.txt",
            "crwd_zta_51_75.txt",
            "crwd_zta_76_100.txt",
        ]
        scores = ["1_25", "26_50", "51_75", "76_100"]
        for i in range(4):
            PAYLOAD = {
                "description": f"file representing a zta score of {scores[i]}",
                "name": f"{files[i]}",
                "comments_for_audit_log": f"uploaded file representing a zta \
                    score of {scores[i]} for Netskope ZTA-RTR integration",
            }
            file_upload = [("file", "Netskope ZTA-RTR Integration")]
            response = falcon.command(
                "RTR_CreatePut_Files", data=PAYLOAD, files=file_upload
            )
            errors = response["body"].get("errors", [])
            if errors:
                for error in errors:
                    if (
                        error.get("message", "")
                        != "file with given name already exists"
                    ):
                        raise Exception(
                            f"{PLUGIN_NAME}: Error while uploading"
                            f" file {files[i]}to cloud: {error['message']}"
                        )
            else:
                self.logger.info(
                    f"{PLUGIN_NAME}: {files[i]} uploaded successfully on RTR cloud."
                )

    def _get_session_id(self, device_id: str) -> str:
        """Get session id of the connection made to the device.

        Args:
            device_id (str): Device of to which we want to connect.

        Returns:
            str: Session id of the connection.
        """
        try:
            base_url = self.configuration["base_url"].strip()
            auth_json = self.get_auth_json(
                self.configuration.get("client_id").strip(),
                self.configuration.get("client_secret").strip(),
                self.configuration.get("base_url").strip(),
            )
            auth_token = auth_json.get("access_token")
            headers = {
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            }
            query_endpoint = (
                f"{base_url}/real-time-response/entities/sessions/v1"
            )
            body = {
                "device_id": device_id,
                "origin": "Netskope",
                "queue_offline": True,
            }
            resp = requests.post(
                query_endpoint,
                headers=add_user_agent(headers),
                data=json.dumps(body),
                proxies=self.proxy,
            )
            resp.raise_for_status()
            response = resp.json()
            session_id = ""
            resources = response.get("resources", [])
            if resources:
                session_id = resources[0].get("session_id", "")
            return session_id

        except requests.exceptions.ProxyError:
            err_msg = " ".join(
                [
                    f"{PLUGIN_NAME}: CrowdStrike Invalid",
                    "proxy configuration.",
                ]
            )
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        except requests.exceptions.ConnectionError:
            err_msg = " ".join(
                [
                    f"{PLUGIN_NAME}: CrowdStrike Unable to establish",
                    "connection with CrowdStrike platform."
                    "Proxy server or CrowdStrike API is not reachable.",
                ]
            )
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        except Exception as e:
            self.logger.error(
                f"{PLUGIN_NAME}: Exception occurred while "
                f"creating session with device id {device_id}."
            )
            raise Exception(
                e.response.json().get(
                    "errors",
                    f"Unable to create session with device id {device_id}.",
                )
            )

    def _remove_files_from_device(
        self, session_id: str, device_id: str, platform_name: str
    ):
        """Remove files from the remote host.

        Args:
            session_id (str): Session Id to remove files against.
            device_id (str): Id of the remote host.
        """
        files = [
            "crwd_zta_1_25.txt",
            "crwd_zta_26_50.txt",
            "crwd_zta_51_75.txt",
            "crwd_zta_76_100.txt",
        ]

        for i in range(4):
            cmd = f"rm '{files[i]}'"
            if platform_name == "Mac":
                cmd = f"rm '{MAC_PUT_DIR}/{files[i]}'"
            self._execute_command("rm", cmd, session_id, device_id)

    def _block_until_completed(
        self, status: bool, cloud_request_id: str, device_id: str, cmd: str
    ):
        """Block execution until command successfully executed.

        Args:
            status (bool): Status of command.
            cloud_request_id (str): Cloud request Id of the request.
            device_id (str): Device ID.
            cmd (str): Command to be executed.
        """
        while status is False:
            status = self._check_command_status(
                cloud_request_id=cloud_request_id,
                device_id=device_id,
                cmd=cmd,
            )
            if status:
                return
            time.sleep(3)

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
            file = "crwd_zta_1_25.txt"
        elif score >= 26 and score <= 50:
            file = "crwd_zta_26_50.txt"
        elif score >= 51 and score <= 75:
            file = "crwd_zta_51_75.txt"
        else:
            file = "crwd_zta_76_100.txt"
        if platform_name == "Mac":
            cmd = f"cd '{MAC_PUT_DIR}'"
            cloud_request_id, is_queued = self._execute_command(
                "cd", cmd, session_id, device_id
            )
            status = self._check_command_status(
                cloud_request_id=cloud_request_id,
                device_id=device_id,
                cmd=cmd,
            )
            if status is False and is_queued is False:
                self._block_until_completed(
                    status=status,
                    cloud_request_id=cloud_request_id,
                    device_id=device_id,
                    cmd=cmd,
                )

        cloud_request_id, is_queued = self._execute_command(
            "put", f"put '{file}'", session_id, device_id
        )
        status = self._check_command_status(
            cloud_request_id, device_id, f"put {file}"
        )
        if status is False and is_queued is False:
            self._block_until_completed(
                status=status,
                cloud_request_id=cloud_request_id,
                device_id=device_id,
                cmd=f"put {file}",
            )

    def _execute_command(
        self,
        base_command: str,
        command_string: str,
        session_id: str,
        device_id: str,
    ) -> str:
        """Execute the specified command on the remote host.

        Args:
            base_command (str): Base command to perform.
            command_string (str): Full command line of the command to execute.
            session_id (str): Session id to execute the command against.
            device_id (str): Id of the remote host.

        Returns:
            str: Cloud request id to check status of the command.
        """
        try:
            base_url = self.configuration["base_url"].strip()
            auth_json = self.get_auth_json(
                self.configuration.get("client_id").strip(),
                self.configuration.get("client_secret").strip(),
                self.configuration.get("base_url").strip(),
            )
            auth_token = auth_json.get("access_token")
            headers = {
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            }

            query_endpoint = (
                f"{base_url}/real-time-response/entities/admin-command/v1"
            )
            body = {
                "base_command": base_command,
                "command_string": command_string,
                "persist": True,
                "session_id": session_id,
            }
            resp = requests.post(
                query_endpoint,
                headers=add_user_agent(headers),
                data=json.dumps(body),
                proxies=self.proxy,
            )
            resp.raise_for_status()
            response = resp.json()
            cloud_request_id, is_queued = "", False
            resources = response.get("resources", [])
            if resources:
                cloud_request_id = resources[0].get("cloud_request_id", "")
                is_queued = resources[0].get("queued_command_offline")
            return cloud_request_id, is_queued

        except requests.exceptions.ProxyError:
            err_msg = " ".join(
                [
                    f"{PLUGIN_NAME}: CrowdStrike Invalid",
                    "proxy configuration.",
                ]
            )
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        except requests.exceptions.ConnectionError:
            err_msg = " ".join(
                [
                    f"{PLUGIN_NAME}: Unable to establish connection ",
                    "with CrowdStrike platform.Proxy server or CrowdStrike"
                    "API is not reachable.",
                ]
            )
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        except Exception as e:
            self.logger.error(
                f"{PLUGIN_NAME}: CrowdStrike Exception occurred while "
                f"executing an command {command_string} on device {device_id}."
            )
            raise HTTPError(
                e.response.json().get(
                    "errors",
                    f"Unable to execute command on device {device_id}.",
                )
            )

    def _check_command_status(
        self, cloud_request_id: str, device_id: str, cmd: str
    ):
        """Check the status of the executed command.

        Args:
            cloud_request_id (str): Cloud request id generated from execute
            command.
            device_id (str): Device id on which the command was executed.
            cmd (str): Command that was
        """
        try:
            base_url = self.configuration["base_url"]
            auth_json = self.get_auth_json(
                self.configuration.get("client_id"),
                self.configuration.get("client_secret"),
                self.configuration.get("base_url"),
            )
            auth_token = auth_json.get("access_token")
            headers = {
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            }
            query_endpoint = (
                f"{base_url}/real-time-response/entities/admin-command/v1"
            )
            params = {"cloud_request_id": cloud_request_id, "sequence_id": 0}
            resp = requests.get(
                query_endpoint,
                headers=add_user_agent(headers),
                params=params,
                proxies=self.proxy,
            )
            resp.raise_for_status()
            response = resp.json()
            resources = response.get("resources", [])

            if resources:
                stderr = resources[0].get("stderr", "")
                if resources[0].get("complete") is False and stderr != "":
                    raise CrowdstrikeException(
                        f"Unable to execute the {cmd} command on the "
                        f"device {device_id}."
                    )

                elif resources[0].get("complete") is False and stderr == "":
                    self.logger.info(
                        f"{PLUGIN_NAME}: Execution of {cmd} is still "
                        "in progress."
                    )
                    return False
                elif resources[0].get("complete") is True:
                    self.logger.info(
                        f"{PLUGIN_NAME}: execution of {cmd} is completed."
                    )
                    return True

                if stderr and "already exists" not in stderr:
                    raise CrowdstrikeException(stderr)
                self.logger.info(
                    f"{PLUGIN_NAME}: {cmd} is successfully executed."
                    f"for device {device_id}"
                )

        except requests.exceptions.ProxyError:
            err_msg = f"{PLUGIN_NAME}: Invalid proxy configuration."
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        except requests.exceptions.ConnectionError:
            err_msg = " ".join(
                [
                    f"{PLUGIN_NAME}: Unable to establish connection",
                    "with CrowdStrike platform. Proxy server or ",
                    "CrowdStrike API is not reachable.",
                ]
            )
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        except CrowdstrikeException as e:
            self.logger.error(
                f"{PLUGIN_NAME}: Exception occurred "
                f"while uploading file to the device {device_id}."
            )
            raise Exception(str(e))
        except Exception as e:
            self.logger.error(
                f"{PLUGIN_NAME}: Exception occurred "
                f"while checking command status for device {device_id}."
            )
            raise HTTPError(
                e.response.json().get(
                    "errors",
                    f"Unable to check command status for device {device_id}.",
                )
            )

    def _delete_session(self, session_id: str, device_id: str):
        """Delete the created session with the remote host.

        Args:
            session_id (str): Session id to delete the session.
            device_id (str): Device id of the connected host.
        """
        try:
            auth_json = self.get_auth_json(
                self.configuration.get("client_id").strip(),
                self.configuration.get("client_secret").strip(),
                self.configuration.get("base_url").strip(),
            )
            auth_token = auth_json.get("access_token")
            headers = {
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            }
            query_endpoint = f"{self.configuration['base_url'].strip()}/real-time-response/entities/sessions/v1"  # noqa
            params = {"session_id": session_id}
            resp = requests.delete(
                query_endpoint,
                headers=add_user_agent(headers),
                params=params,
                proxies=self.proxy,
            )
            resp.raise_for_status()

        except requests.exceptions.ProxyError:
            err_msg = f"{PLUGIN_NAME}: Invalid proxy configuration."
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        except requests.exceptions.ConnectionError:
            err_msg = " ".join(
                [
                    f"{PLUGIN_NAME}: Unable to establish connection",
                    "with CrowdStrike platform. Proxy server or CrowdStrike",
                    "API is not reachable.",
                ]
            )
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        except Exception as e:
            self.logger.error(
                f"{PLUGIN_NAME}: Exception occurred "
                "while deleting session with session id "
                f"{session_id} and device id {device_id}."
            )
            raise Exception(
                e.response.json().get(
                    "errors Unable to delete session with session id ",
                    f"{session_id} and device id {device_id}.",
                )
            )

    def fetch_records(self):
        """Get the all the Agent ID list from the Query Endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token.
        Returns:
            dict: JSON response dict received from query endpoint.
        """
        self.configuration["client_id"] = self.configuration[
            "client_id"
        ].strip()
        self.configuration["client_secret"] = self.configuration[
            "client_secret"
        ].strip()
        try:
            auth_json = self.get_auth_json(
                self.configuration.get("client_id"),
                self.configuration.get("client_secret"),
                self.configuration.get("base_url"),
            )
            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}"}
            agent_ids = self.get_agent_ids(headers)
            uids_names = []
            for ids in agent_ids:
                uids_names.append(Record(uid=ids, type=RecordType.HOST))
            return uids_names

        except requests.exceptions.ProxyError:
            err_msg = f"{PLUGIN_NAME}: Invalid proxy configuration."
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        except requests.exceptions.ConnectionError:
            err_msg = " ".join(
                [
                    f"{PLUGIN_NAME}: Unable to establish connection",
                    "with CrowdStrike platform. Proxy server or CrowdStrike"
                    "API is not reachable.",
                ]
            )
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        except requests.exceptions.RequestException as e:
            self.logger.error(
                f"{PLUGIN_NAME}: Exception occurred while making "
                "an API call to CrowdStrike platform."
            )
            raise e

    def fetch_scores(self, agent_ids):
        """Fetch user scores."""
        self.configuration["client_id"] = self.configuration[
            "client_id"
        ].strip()
        self.configuration["client_secret"] = self.configuration[
            "client_secret"
        ].strip()
        try:
            auth_json = self.get_auth_json(
                self.configuration.get("client_id"),
                self.configuration.get("client_secret"),
                self.configuration.get("base_url"),
            )
            aids = []
            for ids in agent_ids:
                if ids.type == RecordType.HOST:
                    aids.append(ids.uid)

            scores = {}
            for i in range(0, len(aids), BATCH_SIZE):
                aid_batch = aids[i : i + BATCH_SIZE]
                auth_token = auth_json.get("access_token")
                headers = {"Authorization": f"Bearer {auth_token}"}
                query_endpoint = f"{self.configuration['base_url']}/zero-trust-assessment/entities/assessments/v1"  # noqa
                payload = {"ids": aid_batch}
                headers = self.reload_auth_token(headers)
                resp = requests.get(
                    query_endpoint,
                    headers=add_user_agent(headers),
                    params=payload,
                    proxies=self.proxy,
                )
                all_scores_json = self.handle_error(resp=resp)
                if all_scores_json:
                    for sub in all_scores_json.get("resources", []):

                        scores[sub["aid"]] = sub["assessment"]["overall"] * 10

            scored_uids = []
            count_host = 0
            for aid, score in scores.items():
                if score <= int(self.configuration["maximum_score"]):
                    scored_uids.append(
                        Record(uid=aid, type=RecordType.HOST, score=score)
                    )
                    count_host += 1
            self.logger.info(
                f"{PLUGIN_NAME}: Successfully fetched scores for "
                f"{count_host} Host(s) and skipped fetching scores for "
                f"{len(aids)-count_host} from CrowdStrike."
            )
            return scored_uids
        except requests.exceptions.ProxyError:
            err_msg = f"{PLUGIN_NAME}: Invalid proxy configuration."
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        except requests.exceptions.ConnectionError:
            err_msg = " ".join(
                [
                    f"{PLUGIN_NAME}: Unable to establish connection",
                    "with CrowdStrike platform. Proxy server or CrowdStrike",
                    "API is not reachable.",
                ]
            )
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        except requests.exceptions.RequestException as e:
            self.logger.error(
                f"{PLUGIN_NAME}: Exception occurred while "
                "making an API call to CrowdStrike platform."
            )
            raise e

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

    def _get_script_name(self, platform_name: str, falcon, device_id: str):
        """Get script name.

        Args:
            platform_name (str): Operation
            falcon: Falcon object
            device_id (str): Device ID
        """
        try:
            script_name = PLATFORM_TO_SCRIPT_MAPPING.get(
                platform_name, {}
            ).get("script_name")
            filter = f"platform:['{platform_name}']+name:'{script_name}'"

            response = falcon.command(
                "RTR_ListScripts",
                filter=filter,
            )
            if response.get("body", {}).get("resources", []):
                self._create_script(platform_name, device_id, falcon)

            return script_name
        except Exception as exp:
            self.logger.error(
                f"{PLUGIN_NAME}: "
                f"Error occurred while getting script for {device_id}."
                f"Cause {exp}"
            )

    def _create_script(self, platform_name: str, device_id: str, falcon):
        """Create Script for different platform.

        Args:
            platform_name (str): Platform name
            device_id (str): Device ID
            falcon: Falcon object
        """
        if platform_name not in PLATFORM_TO_SCRIPT_MAPPING.keys():
            self.logger.error(
                f"{PLUGIN_NAME}: {platform_name} is not supported by {PLUGIN_NAME}."
            )
            return
        cmd = None
        if platform_name == "Windows":
            cmd1 = r"cd 'C:\Program Files (x86)\Netskope\STAgent'"
            cmd2 = r".\stAgentSvc.exe -stop"
            cmd3 = r".\stAgentSvc.exe -start"
            cmd = "\n".join([cmd1, cmd2, cmd3])

        elif platform_name == "Mac":
            cmd1 = "sudo launchctl unload /Library/LaunchDaemons/com.netskope.client.auxsvc.plist"  # noqa
            cmd2 = "sudo launchctl load /Library/LaunchDaemons/com.netskope.client.auxsvc.plist"  # noqa
            cmd = "\n".join([cmd1, cmd2])

        script_name = PLATFORM_TO_SCRIPT_MAPPING.get(platform_name, {}).get(
            "script_name"
        )

        PAYLOAD = {
            "description": PLATFORM_TO_SCRIPT_MAPPING.get(
                platform_name, {}
            ).get("description"),
            "name": script_name,
            "permission_type": "public",
            "content": cmd,
            "platform": [platform_name.lower()],
        }

        file_upload = [
            (
                "file",
                (
                    script_name,
                    "application/script",
                ),
            )
        ]
        try:
            response = falcon.command(
                "RTR_CreateScripts", data=PAYLOAD, files=file_upload
            )
            if (
                response.get("status_code")
                and response.get("status_code") != 200
            ):
                self.logger.error(
                    f"{PLUGIN_NAME}: Error occurred while "
                    f"creating script for device id {device_id}."
                    f"Cause: {response.get('body',{}).get('errors')}"
                )
                return
        except Exception as exp:
            self.logger.error(
                f"{PLUGIN_NAME}: Error occurred while creating"
                f" script for {device_id}:  Cause {exp}"
            )

    def _get_host_platform_name(self, host_id):
        url = f"{self.configuration['base_url']}/devices/entities/devices/v2"
        auth_json = self.get_auth_json(
            self.configuration.get("client_id").strip(),
            self.configuration.get("client_secret").strip(),
            self.configuration.get("base_url").strip(),
        )
        auth_token = auth_json.get("access_token")
        headers = {"Authorization": f"Bearer {auth_token}"}
        headers = self.reload_auth_token(headers)
        params = {"ids": [host_id]}
        response = requests.get(
            url,
            headers=add_user_agent(headers),
            proxies=self.proxy,
            params=params,
        )
        resp_json = self.handle_error(response)

        platform_name = resp_json.get("resources", [])[0].get(
            "platform_name", ""
        )
        return platform_name

    def _restart_agent(
        self, session_id: str, host_id: str, platform_name: str
    ):
        """Restart Netskope Agent.

        Args:
            session_id (str): Session ID
            host_id (str): Host ID
            platform_name (str): Platform Name
        """
        falcon = self._get_falcon()
        script_name = self._get_script_name(platform_name, falcon, host_id)
        if script_name:
            script = f"runscript -CloudFile='{script_name}' -CommandLine="
            body = {
                "session_id": session_id,
                "command_string": script,
                "optional_hosts": [host_id],
                "persist_all": True,
            }
            try:
                response = falcon.command("RTR_ExecuteAdminCommand", body=body)
                if response.get("status_code") and response.get(
                    "status_code"
                ) in [
                    201,
                    200,
                ]:
                    self.logger.info(
                        f"{PLUGIN_NAME}: Successfully restarted "
                        f"Netskope agent for host {host_id}"
                    )
                else:
                    self.logger.error(
                        f"{PLUGIN_NAME}: Error occurred while "
                        f"executing script for device id {host_id}. "
                        f"Cause: {response.get('body',{}).get('errors')}"
                    )

                    return
            except Exception as exp:
                self.logger.error(
                    f"{PLUGIN_NAME}: Error occurred in while "
                    f"restarting host id {host_id}. Cause {exp}"
                )

    def _get_device_match(self, device_id: str) -> bool:
        """Get device match.

        Args:
            device_id (str): Device ID.

        Returns:
            bool: True if device is found else False.
        """
        auth_json = self.get_auth_json(
            self.configuration.get("client_id").strip(),
            self.configuration.get("client_secret").strip(),
            self.configuration.get("base_url").strip(),
        )
        auth_token = auth_json.get("access_token")
        headers = {"Authorization": f"Bearer {auth_token}"}
        agent_ids = self.get_agent_ids(headers, device_id)
        if device_id in agent_ids:
            return True
        else:
            return False

    def execute_action(self, record: Record, action: Action):
        """Execute action on the record."""
        if (
            action.value == "generate"
            or record.type != RecordType.HOST
            or record.scores
        ):
            pass
        device = record.uid
        match = self._get_device_match(record.uid)
        if not match:
            self.logger.warn(
                f"{PLUGIN_NAME}: Host with id {device} not "
                "found on CrowdStrike."
            )
            return
        if action.value == "rtr":
            score_to_be_put = None
            for score in record.scores:
                if score.source == self.name:
                    score_to_be_put = score.current
            if score_to_be_put is None:
                self.logger.error(
                    f"{PLUGIN_NAME}: Could not find user"
                    f" score for {record.uid}."
                )
                return
            self._put_files_on_rtr_cloud()
            session_id = self._get_session_id(device)
            platform_name = self._get_host_platform_name(host_id=record.uid)
            self._remove_files_from_device(session_id, device, platform_name)
            self._put_file_on_device(
                session_id=session_id,
                score=score_to_be_put,
                device_id=device,
                platform_name=platform_name,
            )
            self._restart_agent(
                session_id=session_id,
                host_id=record.uid,
                platform_name=platform_name,
            )
            self._delete_session(session_id, device)

    def reload_auth_token(self, headers):
        """Reload the OAUTH2 token after Expiry."""
        if self.storage is None:
            auth_json = self.get_auth_json(
                self.configuration.get("client_id"),
                self.configuration.get("client_secret"),
                self.configuration.get("base_url"),
            )
            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}"}
        elif self.storage["token_expiry"] < datetime.datetime.now():
            self.logger.info(
                f"{PLUGIN_NAME}: OAUTH2 token expired generating new token"
            )
            auth_json = self.get_auth_json(
                self.configuration.get("client_id"),
                self.configuration.get("client_secret"),
                self.configuration.get("base_url"),
            )
            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}"}
        return headers

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin configuration
            parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success
            flag and message.
        """

        if "base_url" not in data or data["base_url"].strip() not in [
            "https://api.crowdstrike.com",
            "https://api.us-2.crowdstrike.com",
            "https://api.laggar.gcw.crowdstrike.com",
            "https://api.eu-1.crowdstrike.com",
        ]:
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred "
                "Error: Type of Pulling configured should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid value base_url.",
            )

        if (
            "client_id" not in data
            or not data["client_id"].strip()
            or type(data["client_id"]) != str
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred"
                "Error: Type of Client ID should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Client ID provided.",
            )

        if (
            "maximum_score" not in data
            or not data["maximum_score"]
            or 1 > int(data["maximum_score"])
            or 1000 < int(data["maximum_score"])
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred"
                "Error: Type of Maximum Score should be non-empty integer."
            )
            return ValidationResult(
                success=False,
                message="Invalid Maximum Score provided. Range is from 1 to 1000.",
            )

        if (
            "client_secret" not in data
            or not data["client_secret"]
            or type(data["client_secret"]) != str
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred"
                "Error: Type of Client Secret should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Client Secret provided.",
            )

        return self.validate_auth_params(
            data["client_id"], data["client_secret"], data["base_url"]
        )

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
        try:
            self.check_url_valid(client_id, client_secret, base_url)
            return ValidationResult(
                success=True,
                message="Validation successfull for CrowdStrike Plugin",
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
                    "Validation Error, Unable to establish ",
                    "connection with CrowdStrike Platform API",
                ]
            )
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        except requests.HTTPError as err:
            err_msg = " ".join(
                [
                    "Validation Error, Error in ",
                    f"validating Credentials {repr(err)}",
                ]
            )
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
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
        all_agent_resp = requests.get(
            query_endpoint, headers=add_user_agent(headers), proxies=self.proxy
        )
        if all_agent_resp.status_code == 401:
            raise requests.HTTPError("Invalid base url.")

        agent_resp_json = self.handle_error(all_agent_resp)
        errors = agent_resp_json.get("errors")
        if errors:

            err_msg = " ".join(
                [
                    f"{PLUGIN_NAME}: Unable to Fetch agents,",
                    f"Error: {errors[0].get('message', '')}",
                ]
            )
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        return agent_resp_json

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
        client_id = client_id.strip()
        client_secret = client_secret.strip()
        auth_endpoint = f"{base_url}/oauth2/token"

        auth_params = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        resp = requests.post(
            auth_endpoint,
            data=auth_params,
            verify=self.ssl_validation,
            proxies=self.proxy,
            headers=add_user_agent(),
        )
        auth_json = self.handle_error(resp)
        auth_errors = auth_json.get("errors")
        if auth_errors:
            err_msg = " ".join(
                [
                    f"{PLUGIN_NAME}: Unable to generate Auth token. ",
                    f"Error: {auth_errors[0].get('message', '')}",
                ]
            )
            self.notifier.error(err_msg)
            self.logger.error(err_msg)
            raise requests.HTTPError(err_msg)
        if self.storage is not None:
            self.storage[
                "token_expiry"
            ] = datetime.datetime.now() + datetime.timedelta(
                seconds=int(auth_json.get("expires_in", 1799))
            )
        return auth_json
