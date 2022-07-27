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

"""Crowdstrike CRE plugin."""


import json
import datetime
import requests
from requests.models import HTTPError
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cre.models import (
    Record,
    RecordType,
    ActionWithoutParams,
    Action,
)
from netskope.common.utils import add_user_agent
from typing import List
from .lib.falconpy.api_complete import APIHarness

PAGE_SIZE = 1000


class CrowdstrikeException(Exception):
    """Crowdstrike exception class."""

    pass


class CrowdstrikePlugin(PluginBase):
    """Crowdstrike plugin implementation."""

    def handle_error(self, resp):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API call.
        Returns:
            dict: Returns the dictionary of response JSON when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                raise CrowdstrikeException(
                    "Plugin: CrowdStrike,"
                    "Exception occurred while parsing JSON response."
                )

        elif resp.status_code == 401:
            raise CrowdstrikeException(
                "Plugin: CrowdStrike, "
                "Received exit code 401, Authentication Error"
            )

        elif resp.status_code == 403:
            raise CrowdstrikeException(
                "Plugin: CrowdStrike, "
                "Received exit code 403, Forbidden User"
            )

        elif resp.status_code >= 400 and resp.status_code < 500:
            raise CrowdstrikeException(
                f"Plugin: CrowdStrike, "
                f"Received exit code {resp.status_code}, HTTP client Error"
            )

        elif resp.status_code >= 500 and resp.status_code < 600:
            raise CrowdstrikeException(
                f"Plugin: CrowdStrike, "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )

        else:
            raise CrowdstrikeException(
                f"Plugin: CrowdStrike, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )

    def get_all_devices(self) -> List:
        """Get list of all devices.

        Returns:
            List: List of all devices.
        """
        try:
            auth_json = self.get_auth_json(
                self.configuration.get("client_id").strip(),
                self.configuration.get("client_secret").strip(),
                self.configuration.get("base_url").strip(),
            )
            agent_ids = []
            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}"}
            agent_ids = self.get_agent_ids(headers)
            return agent_ids

        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin: CrowdStrike "
                "Exception occurred while making an API call to CrowdStrike platform"
            )
            raise e

    def _find_device_by_id(self, devices: List, device_id: str) -> str:
        """Find device by id.

        Args:
            devices (List): List of all devices
            device_id (str): id of the device to find

        Returns:
            str: Id of the device if found, None otherwise.
        """
        for device in devices:
            if device == device_id:
                return device
        return None

    def get_agent_ids(self, headers):
        """Get the all the Agent ID list from the Query Endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token.
        Returns:
            dict: JSON response dict received from query endpoint.
        """
        query_endpoint = f"{self.configuration['base_url'].strip()}/devices/queries/devices/v1"
        agent_ids = []
        offset = 0
        while True:
            headers = self.reload_auth_token(headers)
            all_agent_resp = requests.get(
                query_endpoint,
                headers=add_user_agent(headers),
                params={"limit": PAGE_SIZE, "offset": offset},
                proxies=self.proxy,
            )
            agent_resp_json = self.handle_error(all_agent_resp)
            errors = agent_resp_json.get("errors")
            if errors:
                err_msg = errors[0].get("message", "")
                self.notifier.error(
                    "Plugin: CrowdStrike Unable to Fetch agents, "
                    f"Error: {err_msg}"
                )
                self.logger.error(
                    "Plugin: CrowdStrike Unable to Fetch Agents, "
                    f"Error: {err_msg}"
                )
                raise requests.HTTPError(
                    f"Plugin: CrowdStrike Unable to Fetch Agents, "
                    f"Error: {err_msg}"
                )
            resources = agent_resp_json.get("resources", [])
            offset += PAGE_SIZE
            agent_ids.extend(resources)
            if len(resources) < PAGE_SIZE:
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
                "comments_for_audit_log": f"uploaded file representing a zta score \
                    of {scores[i]} for Netskope ZTA-RTR integration",
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
                            f"Error while uploading file {files[i]}\
                            to cloud: {error['message']}"
                        )
            else:
                self.logger.info(
                    f"{files[i]} uploaded successfully on RTR cloud."
                )

    def _get_session_id(self, device_id: str) -> str:
        """Get session id of the connection made to the device.

        Args:
            device_id (str): Device of to which we want to connect.

        Returns:
            str: Session id of the connection.
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
            query_endpoint = f"{self.configuration['base_url'].strip()}/real-time-response/entities/sessions/v1"
            body = {
                "device_id": device_id,
                "origin": "netskope",
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
            self.notifier.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
        except Exception as e:
            self.logger.error(
                "Plugin: CrowdStrike "
                f"Exception occurred while creating session with device id {device_id}."
            )
            raise Exception(
                e.response.json().get(
                    "errors",
                    f"Unable to create session with device id {device_id}.",
                )
            )

    def _remove_files_from_device(self, session_id: str, device_id: str):
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
            self._execute_command(
                "rm", f"rm '{files[i]}'", session_id, device_id
            )

    def _put_file_on_device(
        self, session_id: str, score: int, device_id: str
    ) -> str:
        """Put file on the remote host.

        Args:
            session_id (str): Session id to put files against.
            score (int): score to determine which file is to be put.
            device_id (str): Id of the remote host.

        Returns:
            str: cloud request id to check the status of put command.
        """
        score = int(score / 10)
        if score >= 1 and score <= 25:
            file = "crwd_zta_1_25.txt"
        elif score >= 26 and score <= 50:
            file = "crwd_zta_26_50.txt"
        elif score >= 51 and score <= 75:
            file = "crwd_zta_51_75.txt"
        elif score >= 76 and score <= 100:
            file = "crwd_zta_76_100.txt"
        id = self._execute_command(
            "put", f"put '{file}'", session_id, device_id
        )
        return id, file

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
            query_endpoint = f"{self.configuration['base_url'].strip()}/real-time-response/entities/admin-command/v1"
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
            cloud_request_id = ""
            resources = response.get("resources", [])
            if resources:
                cloud_request_id = resources[0].get("cloud_request_id", "")
            return cloud_request_id

        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
        except Exception as e:
            self.logger.error(
                "Plugin: CrowdStrike "
                f"Exception occurred while executing an command {command_string} on device {device_id}."
            )
            raise HTTPError(
                e.response.json().get(
                    "errors",
                    f"Unable to execute command on device {device_id}.",
                )
            )

    def _check_command_status(
        self, cloud_request_id: str, device_id: str, fileName: str
    ):
        """Check the status of the executed command.

        Args:
            cloud_request_id (str): Cloud request id generated from execute command.
            device_id (str): Device id on which the command was executed.
            fileName (str): File name to be put.
        """
        try:
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
            query_endpoint = f"{self.configuration['base_url']}/real-time-response/entities/admin-command/v1"
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
                if resources[0].get("complete") == False:
                    raise CrowdstrikeException(
                        f"Unable to execute the put command on the device {device_id}."
                    )
                if stderr and "already exists" not in stderr:
                    raise CrowdstrikeException(stderr)
                self.logger.info(
                    f"File {fileName} uploaded successfully on the device {device_id}."
                )

        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
        except CrowdstrikeException as e:
            self.logger.error(
                "Plugin: CrowdStrike "
                f"Exception occurred while uploading file to the device {device_id}."
            )
            raise Exception(str(e))
        except Exception as e:
            self.logger.error(
                "Plugin: CrowdStrike "
                f"Exception occurred while checking command status for device {device_id}."
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
            query_endpoint = f"{self.configuration['base_url'].strip()}/real-time-response/entities/sessions/v1"
            params = {"session_id": session_id}
            resp = requests.delete(
                query_endpoint,
                headers=add_user_agent(headers),
                params=params,
                proxies=self.proxy,
            )
            resp.raise_for_status()

        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
        except Exception as e:
            self.logger.error(
                "Plugin: CrowdStrike "
                f"Exception occurred while deleting session with session id "
                f"{session_id} and device id {device_id}."
            )
            raise Exception(
                e.response.json().get(
                    "errors",
                    f"Unable to delete session with session id {session_id} and device id {device_id}.",
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
            self.notifier.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin: CrowdStrike "
                "Exception occurred while making an API call to CrowdStrike platform."
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

            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}"}
            query_endpoint = f"{self.configuration['base_url']}/zero-trust-assessment/entities/assessments/v1"
            payload = {"ids": aids}
            headers = self.reload_auth_token(headers)
            resp = requests.get(
                query_endpoint,
                headers=add_user_agent(headers),
                params=payload,
                proxies=self.proxy,
            )
            all_scores_json = resp.json()
            scores = all_scores_json.get("resources", [])
            dict1 = {}
            for sub in scores:
                dict1[sub["aid"]] = sub["assessment"]["overall"] * 10
            scored_uids = []
            count_host = 0
            for ids, score in dict1.items():
                if score <= int(self.configuration["minimum_score"]):
                    count_host = count_host + 1
                    continue
                else:
                    scored_uids.append(
                        Record(uid=ids, type=RecordType.HOST, score=score)
                    )
            self.logger.info(
                "Plugin: CrowdStrike "
                f"Unable to store scores of {count_host} Hosts to CrowdStrike."
            )
            return scored_uids
        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin: CrowdStrike "
                "Exception occurred while making an API call to CrowdStrike platform."
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

    def execute_action(self, record: Record, action: Action):
        """Execute action on the record."""
        if (
            action.value == "generate"
            or record.type != RecordType.HOST
            or record.scores == None
        ):
            pass
        device = record.uid
        devices = self.get_all_devices()
        match = self._find_device_by_id(devices, device)
        if match is None:
            self.logger.warn(
                f"CrowdStrike CRE: Host with id {device} not found on CrowdStrike."
            )
            return
        if action.value == "rtr":
            score_to_be_put = None
            for score in record.scores:
                if score.source == self.name:
                    score_to_be_put = score.current
            if score_to_be_put is None:
                self.logger.error(
                    f"CrowdStrike CRE: Could not find user score for {record.uid}."
                )
                return
            self._put_files_on_rtr_cloud()
            session_id = self._get_session_id(device)
            self._remove_files_from_device(session_id, device)
            cloud_request_id, fileName = self._put_file_on_device(
                session_id, score_to_be_put, device
            )
            self._check_command_status(cloud_request_id, device, fileName)
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
                "Plugin: Crowdstrike OAUTH2 token expired generating new token"
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
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.info(
            "Plugin: CrowdStrike Executing validate method for CrowdStrike plugin"
        )

        if "base_url" not in data or data["base_url"].strip() not in [
            "https://api.crowdstrike.com",
            "https://api.us-2.crowdstrike.com",
            "https://api.laggar.gcw.crowdstrike.com",
            "https://api.eu-1.crowdstrike.com",
        ]:
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred "
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
                "Plugin: CrowdStrike Validation error occurred"
                "Error: Type of Client ID should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Client ID provided.",
            )

        if (
            "minimum_score" not in data
            or not data["minimum_score"]
            or 1 > int(data["minimum_score"])
            or 1000 < int(data["minimum_score"])
        ):
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred"
                "Error: Type of minimum_score should be non-empty integer."
            )
            return ValidationResult(
                success=False,
                message="Invalid minimum_score provided.Range is from 1 to 1000.",
            )

        if (
            "client_secret" not in data
            or not data["client_secret"]
            or type(data["client_secret"]) != str
        ):
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred"
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
            client_secret (str): Client Secret required to generate OAUTH2 token.
            base_url (str): Base url of crowd strike
        Returns:
            ValidationResult: ValidationResult object having validation results after making
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
                "Plugin: CrowdStrike Validation Error, "
                "Invalid proxy configuration."
            )
            return ValidationResult(
                success=False,
                message="Validation Error, Invalid proxy configuration.",
            )
        except requests.exceptions.ConnectionError:
            self.logger.error(
                "Plugin: CrowdStrike Validation Error, "
                "Unable to establish connection with CrowdStrike Platform API"
            )
            return ValidationResult(
                success=False,
                message="Validation Error, Unable to establish connection with CrowdStrike Platform API",
            )
        except requests.HTTPError as err:
            self.logger.error(
                f"Plugin: CrowdStrike Validation Error, "
                f"Error in validating Credentials {repr(err)}"
            )
            return ValidationResult(
                success=False,
                message=f"Validation Error, Error in validating Credentials {repr(err)}",
            )

    def check_url_valid(self, client_id, client_secret, base_url):
        """
        Validate the authentication params with CrowdStrike platform.

        Args:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2 token.
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
            err_msg = errors[0].get("message", "")
            self.notifier.error(
                "Plugin: CrowdStrike Unable to Fetch agents, "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to Fetch Agents, "
                f"Error: {err_msg}"
            )
            raise requests.HTTPError(
                f"Plugin: CrowdStrike Unable to Fetch Agents, "
                f"Error: {err_msg}"
            )
        return agent_resp_json

    def get_auth_json(self, client_id, client_secret, base_url):
        """Get the OAUTH2 Json object with access token from CrowdStrike platform.

        Args:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2 token.
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
            err_msg = auth_errors[0].get("message", "")
            self.notifier.error(
                "Plugin: CrowdStrike Unable to generate Auth token. "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to generate Auth token. "
                f"Error: {err_msg}"
            )
            raise requests.HTTPError(
                f"Plugin: CrowdStrike Unable to generate Auth token. "
                f"Error: {err_msg}"
            )
        if self.storage is not None:
            self.storage[
                "token_expiry"
            ] = datetime.datetime.now() + datetime.timedelta(
                seconds=int(auth_json.get("expires_in", 1799))
            )
        return auth_json
