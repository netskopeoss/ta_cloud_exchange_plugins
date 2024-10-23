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

import json
import os
import time
import traceback
from typing import Dict, Tuple, List

from netskope.integrations.cre.models import (
    Action,
    ActionWithoutParams,
    Record,
    RecordType,
)
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from .utils.constants import (
    BASE_URLS,
    BATCH_SIZE,
    CROWDSTRIKE_DATE_FORMAT,
    MAC_REMOVE_FILE_SCRIPT_NAME,
    MAC_PUT_DIR,
    COMMAND_TIMEOUT,
    COMMAND_WAIT,
    PLATFORM_NAME,
    MODULE_NAME,
    PAGE_SIZE,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    SCORE_NORMALIZE_MULTIPLIER,
    SCORE_TO_FILE_MAPPING,
    SCRIPT_PERMISSION_TYPE,
    WINDOWS_PUT_DIR,
    WINDOWS_REMOVE_FILE_SCRIPT_NAME,
)
from .utils.helper import CrowdstrikePluginException
from .utils.helper import CrowdstrikePluginHelper


class CrowdstrikePlugin(PluginBase):
    """CrowdStrike plugin Class."""

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
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.crowdstrike_helper = CrowdstrikePluginHelper(
            logger=self.logger,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            log_prefix=self.log_prefix,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
            configuration=self.configuration,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = CrowdstrikePlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
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

    def get_agent_ids(
        self, base_url: str, headers: Dict, device_id: str = None
    ) -> List[str]:
        """Get the all the Agent ID list from the Query Endpoint.

        Args:
            headers (Dict): Header dict object having OAUTH2 access token.
            device_id (str): Device id. Default None.

        Returns:
            dict: List of agent ids received from CrowdStrike platform.
        """
        query_endpoint = f"{base_url}/devices/queries/devices-scroll/v1"

        api_filter = None
        if self.last_run_at and (device_id is None):
            # This filter is for fetching only the updated hosts.
            formatted_date = self.last_run_at.strftime(CROWDSTRIKE_DATE_FORMAT)
            api_filter = f"first_seen: > '{formatted_date}'"
            self.logger.info(
                f"{self.log_prefix}: Plugin will be pulling host id(s)"
                f' from {PLATFORM_NAME} using checkpoint "{formatted_date}".'
            )

        elif device_id:
            # This filter is to fetch the hosts on the bases of provided
            # device id. This filter is utilized in execute_action
            api_filter = f"device_id: '{device_id}'"
        elif self.last_run_at is None:
            self.logger.debug(
                f"{self.log_prefix}: This is an initial pull of the plugin"
                " hence pulling all the host id(s) present on the "
                f"{PLATFORM_NAME} Host Management page."
            )

        agent_ids = []
        offset = ""
        page_count = 1
        while True:
            params = {"limit": PAGE_SIZE, "offset": offset}
            if api_filter is not None:
                # Adding filter only when api_filter is not None.
                params.update({"filter": api_filter})

            all_agent_resp = self.crowdstrike_helper.api_helper(
                method="GET",
                url=query_endpoint,
                headers=headers,
                params=params,
                logger_msg=(
                    f"pulling the host id(s) for page {page_count}"
                    f" from {PLATFORM_NAME} platform"
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
                f"{self.log_prefix}: Successfully pulled {len(resources)}"
                f" host id(s) from {PLATFORM_NAME} in page {page_count}."
                f" Total host id(s) fetched: {len(agent_ids)}"
            )
            if not offset.strip():
                break
            page_count += 1
        self.logger.debug(
            f"{self.log_prefix}: Successfully pulled {len(agent_ids)}"
            f" host id(s) from {PLATFORM_NAME} platform."
        )
        return agent_ids

    def _put_files_on_rtr_cloud(self, base_url: str, headers: Dict) -> None:
        """Put files on RTR cloud.

        Args:
            base_url (str): Base URL
            headers (Dict): Headers with auth token.
        """
        put_files_url = f"{base_url}/real-time-response/entities/put-files/v1"
        self.logger.debug(
            f"{self.log_prefix}: Creating files for all the scores on the RTR"
            f" Cloud. Files: {','.join(list(SCORE_TO_FILE_MAPPING.values()))}"
        )
        created_files, exist_files = [], []
        for score, file in SCORE_TO_FILE_MAPPING.items():
            PAYLOAD = {
                "description": f"file representing a ZTA score of {score}",
                "name": file,
                "comments_for_audit_log": (
                    "uploaded file representing a ZTA "
                    f"score of {score} for Netskope ZTA-RTR integration"
                ),
            }

            file_upload = [("file", "Netskope ZTA-RTR Integration")]
            logger_msg = f"creating file {file} on RTR cloud"
            response = self.crowdstrike_helper.api_helper(
                method="POST",
                url=put_files_url,
                headers=headers,
                files=file_upload,
                data=PAYLOAD,
                logger_msg=logger_msg,
                is_handle_error_required=False,
            )
            if response.status_code in [200, 201]:
                created_files.append(file)
                self.logger.info(
                    f"{self.log_prefix}: {file} file successfully "
                    "uploaded on RTR cloud."
                )

            elif response.status_code == 409:
                resp_json = self.crowdstrike_helper.parse_response(
                    response=response
                )
                errors = resp_json.get("errors", [])
                if errors:
                    for error in errors:
                        if (
                            error.get("message", "")
                            != "file with given name already exists"
                        ):
                            err_msg = (
                                f"Received exit code {response.status_code},"
                                f" while {logger_msg}."
                            )
                            self.logger.error(
                                message=f"{self.log_prefix}: {logger_msg}",
                                details=str(errors),
                            )
                            raise CrowdstrikePluginException(err_msg)
                    self.logger.debug(
                        f"{self.log_prefix}: File with given name {file} "
                        f"already exist on RTR Cloud. API Response: {errors}"
                    )
                    exist_files.append(file)
            else:
                self.crowdstrike_helper.handle_error(
                    resp=response, logger_msg=logger_msg
                )
        log_msg = ""
        if created_files and exist_files:
            log_msg = (
                f"Successfully created ({', '.join(created_files)}) files"
                f" on RTR cloud; however, {', '.join(exist_files)} files"
                " already exist."
            )
        elif created_files:
            log_msg = (
                f"Successfully created {', '.join(created_files)} files"
                " on RTR cloud."
            )
        elif exist_files:
            log_msg = (
                f"Files {', '.join(exist_files)} already exist on "
                "RTR cloud; hence, no new files were created."
            )
        else:
            log_msg = "No files were created or already existed on RTR cloud."

        self.logger.info(f"{self.log_prefix}: {log_msg}")
        return

    def _get_session_id(
        self, base_url: str, headers: Dict, device_id: str
    ) -> str:
        """Get session id of the connection made to the device.

        Args:
            base_url (str): Base URL.
            headers (Dict): Headers with auth token.
            device_id (str): Id of device that plugin will make session with.

        Returns:
            str: Session id of the connection.
        """
        query_endpoint = f"{base_url}/real-time-response/entities/sessions/v1"
        body = {
            "device_id": device_id,
            "origin": "Netskope",
            "queue_offline": True,
        }
        self.logger.debug(
            f'{self.log_prefix}: Creating session with host "{device_id}".'
        )
        resp_json = self.crowdstrike_helper.api_helper(
            method="POST",
            url=query_endpoint,
            headers=headers,
            data=json.dumps(body),
            logger_msg=f'creating session with host "{device_id}"',
            is_handle_error_required=True,
        )
        session_id = ""
        resources = resp_json.get("resources", [])
        if resources:
            session_id = resources[0].get("session_id", "")
            self.logger.info(
                f"{self.log_prefix}: Successfully created session with"
                f' host "{device_id}".'
            )
            return session_id
        else:
            err_msg = (
                "Unable to get session id from API Response "
                f'for host "{device_id}"'
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} ",
                details=f"API Response: {resp_json}",
            )
            raise CrowdstrikePluginException(err_msg)

    def _change_directory(
        self,
        headers: Dict,
        session_id: str,
        device_id: str,
        platform_name: str,
    ) -> None:
        """Change directory in the remote host.

        Args:
            headers (Dict): Headers with auth token.
            session_id (str): Session Id to change directory against.
            device_id (str): Id of the remote host.
            platform_name (str): platform name of host.

        Returns:
            None
        """
        self.logger.debug(
            f"{self.log_prefix}: Changing directory in the "
            f'host "{device_id}" having platform '
            f'"{platform_name}".'
        )

        if platform_name == "mac":
            cmd = f"cd '{MAC_PUT_DIR}'"
        elif platform_name == "windows":
            cmd = f"cd '{WINDOWS_PUT_DIR}'"
        else:
            err_msg = (
                f'Unsupported platform name "{platform_name}" received. Hence '
                f'skipped execution of the "Put RTR Script" action on '
                f'device "{device_id}".'
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise CrowdstrikePluginException(err_msg)

        cloud_request_id, is_queued = self._execute_command(
            "cd", cmd, session_id, device_id, headers
        )
        status = self._check_command_status(
            cloud_request_id=cloud_request_id,
            device_id=device_id,
            cmd=cmd,
            headers=headers,
        )
        if not (status or is_queued):
            self._block_until_completed(
                status=status,
                cloud_request_id=cloud_request_id,
                device_id=device_id,
                cmd=cmd,
                headers=headers,
            )

        return

    def _check_script_existence_on_rtr_cloud(
        self, base_url: str, headers: Dict, script_name: str
    ) -> bool:
        """Check if the script exists on RTR cloud.

        Args:
            base_url (str): Base URL
            headers (Dict): Headers with auth token.
            script_name (str): Script name.

        Returns:
            bool: True if script exists else False.
        """
        api_endpoint = f"{base_url}/real-time-response/queries/scripts/v1"
        params = {"filter": f"name: '{script_name}'"}
        self.logger.debug(
            f"{self.log_prefix}: Checking if the {script_name} "
            "script exists on RTR cloud."
        )
        resp_json = self.crowdstrike_helper.api_helper(
            method="GET",
            url=api_endpoint,
            headers=headers,
            params=params,
            logger_msg=(
                f"checking if the {script_name} script exists on RTR cloud."
            ),
            is_handle_error_required=True,
        )
        if resp_json.get("resources", []):
            self.logger.info(
                f"{self.log_prefix}: {script_name} script already "
                "exists on RTR cloud."
            )
            return True
        else:
            self.logger.error(
                f"{self.log_prefix}: {script_name} script does not exist"
                " on RTR cloud."
            )
            return False

    def _create_script_on_rtr_cloud(
        self, base_url: str, headers: Dict, platform_name: str
    ) -> None:
        """Create script on RTR cloud.

        Args:
            base_url (str): Base URL
            headers (Dict): Headers with auth token.
            platform_name (str): platform name of host.

        Returns:
            None
        """
        self.logger.info(
            f"{self.log_prefix}: Creating script"
            f" for {platform_name} on RTR cloud."
        )
        api_endpoint = f"{base_url}/real-time-response/entities/scripts/v1"
        payload = {}
        file = None
        if platform_name == "windows":
            cpath = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "utils",
                "windows_score_file_removal_script.ps1",
            )
            file = open(cpath, "rb")

            files = [
                (
                    "file",
                    (
                        "windows_score_file_removal_script.ps1",
                        file,
                        "application/octet-stream",
                    ),
                )
            ]
            payload = {
                "description": (
                    "This script will check whether the file "
                    f"exists in '{WINDOWS_PUT_DIR}' directory, "
                    "if it exists then script will delete it."
                ),
                "name": WINDOWS_REMOVE_FILE_SCRIPT_NAME,
                "permission_type": SCRIPT_PERMISSION_TYPE,
            }

        elif platform_name == "mac":
            cpath = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "utils",
                "mac_score_file_removal_script.zsh",
            )
            file = open(cpath, "rb")

            files = [
                (
                    "file",
                    (
                        "mac_score_file_removal_script.zsh",
                        file,
                        "application/octet-stream",
                    ),
                )
            ]
            payload = {
                "description": (
                    "This script will check whether the score files "
                    f"exists in '{MAC_PUT_DIR}' directory, "
                    "if it exists then script will delete it."
                ),
                "name": MAC_REMOVE_FILE_SCRIPT_NAME,
                "permission_type": SCRIPT_PERMISSION_TYPE,
            }
        self.crowdstrike_helper.api_helper(
            method="POST",
            url=api_endpoint,
            headers=headers,
            data=payload,
            files=files,
            logger_msg=(
                f"creating {payload.get('name')} script on "
                f"RTR cloud for {platform_name} platform"
            ),
            is_handle_error_required=True,
        )
        file.close()
        self.logger.info(
            f"{self.log_prefix}: Successfully created "
            f"{payload.get('name')} script on RTR cloud for "
            f"{platform_name} platform."
        )
        return

    def _remove_files_from_device(
        self,
        headers: Dict,
        session_id: str,
        device_id: str,
        script_name: str,
    ):
        """Remove files from the remote host.

        Args:
            headers (Dict): Headers with auth token.
            session_id (str): Session Id to remove files against.
            device_id (str): Id of the remote host.
            script_name (str): Script name for platform.
        """
        score_files = list(SCORE_TO_FILE_MAPPING.values())
        self.logger.debug(
            f"{self.log_prefix}: Removing files present on"
            f' the host "{device_id}". Files '
            f"to be removed are {score_files}"
        )
        cmd = f"runscript -CloudFile='{script_name}'"
        cloud_request_id, is_queued = self._execute_command(
            "runscript", cmd, session_id, device_id, headers
        )
        status = self._check_command_status(
            cloud_request_id=cloud_request_id,
            device_id=device_id,
            cmd=cmd,
            headers=headers,
        )
        if status is False and is_queued is True:
            self.logger.info(
                f"{self.log_prefix}: Execution of command"
                f' "{cmd}" on host "{device_id}" '
                "is in RTR queue."
            )
        if not (status or is_queued):
            self._block_until_completed(
                status=status,
                cloud_request_id=cloud_request_id,
                device_id=device_id,
                cmd=cmd,
                headers=headers,
            )
        return

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
            headers (Dict): Headers with auth token.
        """
        start_time = time.time()
        while status is False:
            # Run the look until status is True
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
                raise CrowdstrikePluginException(err_msg)

            # Adding delay of command wait after which API call
            # for status will be done
            time.sleep(COMMAND_WAIT)

    def _put_file_on_device(
        self,
        headers: Dict,
        session_id: str,
        score: int,
        device_id: str,
    ) -> None:
        """Put file on the remote host.

        Args:
            headers (Dict): Headers with auth token.
            session_id (str): Session id to put files against.
            score (int): score to determine which file is to be put.
            device_id (str): Id of the remote host.
            platform_name (str): Platform name of the host.

        Returns:
            None
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
            raise CrowdstrikePluginException(err_msg)
        self.logger.info(
            f"{self.log_prefix}: Putting {file} on host" f' "{device_id}".'
        )
        cloud_request_id, is_queued = self._execute_command(
            "put", f"put '{file}'", session_id, device_id, headers
        )
        status = self._check_command_status(
            cloud_request_id, device_id, f"put {file}", headers
        )
        if not (status or is_queued):
            self._block_until_completed(
                status=status,
                cloud_request_id=cloud_request_id,
                device_id=device_id,
                cmd=f"put {file}",
                headers=headers,
            )

        return

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
        resp_json = self.crowdstrike_helper.api_helper(
            method="POST",
            url=query_endpoint,
            headers=headers,
            data=json.dumps(body),
            logger_msg=(
                f"executing '{command_string}' command"
                f" on host ID {device_id}"
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
        self,
        cloud_request_id: str,
        device_id: str,
        cmd: str,
        headers: Dict,
    ) -> bool:
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
        resp_json = self.crowdstrike_helper.api_helper(
            method="GET",
            url=query_endpoint,
            headers=headers,
            params=params,
            logger_msg=(
                f'checking status of command "{cmd}" on host' f' "{device_id}"'
            ),
            is_handle_error_required=True,
        )
        resources = resp_json.get("resources", [])
        if resources:
            stderr = resources[0].get("stderr", "")
            # Check if the command is completed and stderr is empty.
            if resources[0].get("complete") is True and not stderr:
                self.logger.info(
                    f"{self.log_prefix}: Successfully executed "
                    f'command "{cmd}" on host ID "{device_id}".'
                )
                return True
            # Check if the command is completed and stderr is not empty.
            elif resources[0].get("complete") is False and not stderr:
                self.logger.debug(
                    f'{self.log_prefix}: Execution of "{cmd}" on '
                    f'host "{device_id}" is still in progress. '
                    f"API Response: {resources}"
                )
                return False

            # Check if the command is completed and stderr is not empty.
            elif resources[0].get("complete") is False and stderr:
                err_msg = (
                    f'Unable to execute the "{cmd}" command on '
                    f'host "{device_id}".'
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(resources),
                )
                raise CrowdstrikePluginException(err_msg)
            # Check if the command is completed and stderr is not empty.
            elif resources[0].get("complete") is True and stderr:

                err_msg = (
                    f'Unable to execute the "{cmd}" command on '
                    f'host "{device_id}". Error: {stderr}'
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(resources),
                )
                raise CrowdstrikePluginException(err_msg)
            elif resources[0].get("complete") is True and resources[0].get(
                "stdout"
            ):
                stdout = resources[0].get("stdout")
                self.logger.info(
                    f'{self.log_prefix}: "{cmd}" is successfully executed on '
                    f'host "{device_id}". Output from device '
                    f'terminal: "{stdout}"'
                )
                return True
            else:
                self.logger.error(
                    message=(
                        f'{self.log_prefix}: Unable to check status of "{cmd}"'
                        f' command for host "{device_id}".'
                    ),
                    details=f"API Response: {resp_json}",
                )
                return False

    def _delete_session(
        self, base_url: str, headers: Dict, session_id: str, device_id: str
    ) -> None:
        """Delete the created session with the remote host.

        Args:
            base_url (str): Base url of the API endpoint.
            headers (Dict): Headers dictionary containing auth token.
            session_id (str): Session id to delete the session.
            device_id (str): Device id of the connected host.
        """
        query_endpoint = f"{base_url}/real-time-response/entities/sessions/v1"
        params = {"session_id": session_id}
        self.logger.info(
            f"{self.log_prefix}: Deleting the session with "
            f'host "{device_id}".'
        )
        logger_msg = f'deleting session with host "{device_id}"'
        resp = self.crowdstrike_helper.api_helper(
            method="DELETE",
            url=query_endpoint,
            headers=headers,
            params=params,
            logger_msg=logger_msg,
            is_handle_error_required=False,
        )
        if resp.status_code == 204:
            self.logger.debug(
                f"{self.log_prefix}: Successfully deleted session "
                f' with host "{device_id}".'
            )
        self.crowdstrike_helper.handle_error(resp=resp, logger_msg=logger_msg)
        return

    def fetch_records(self) -> List[Record]:
        """Get the all the Agent ID list from the Query Endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token.

        Returns:
            List[Record]: List of hosts fetched from CrowdStrike.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching records from "
            f"{PLATFORM_NAME} platform."
        )
        base_url, client_id, client_secret = (
            self.crowdstrike_helper.get_credentials(
                configuration=self.configuration
            )
        )
        auth_header = self.crowdstrike_helper.get_auth_header(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
        )
        agent_ids = self.get_agent_ids(base_url, auth_header)
        uids_names = []
        for ids in agent_ids:
            uids_names.append(Record(uid=ids, type=RecordType.HOST))
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(uids_names)} "
            f"host(s) from {PLATFORM_NAME} platform."
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
        base_url, client_id, client_secret = (
            self.crowdstrike_helper.get_credentials(
                configuration=self.configuration
            )
        )
        zero_trust_assessment_url = (
            f"{base_url}/zero-trust-assessment/entities/assessments/v1"
        )
        self.logger.info(
            f"{self.log_prefix}: Fetching the score(s) for record(s) "
            f" from {PLATFORM_NAME} platform."
        )
        auth_header = self.crowdstrike_helper.get_auth_header(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
        )
        aids = [ids.uid for ids in agent_ids if ids.type == RecordType.HOST]
        self.logger.info(
            f"{self.log_prefix}: {self.plugin_name} plugin only supports the"
            f" hosts hence it will only fetch scores for {len(aids)} host(s)"
            " and will not fetch scores for remaining "
            f" {len(agent_ids) - len(aids)} user(s)."
        )
        page_count = 1
        scored_uids = []
        total_host_count = 0
        maximum_score = int(self.configuration.get("maximum_score"))

        for i in range(0, len(aids), BATCH_SIZE):
            page_host_count = 0
            try:
                aid_batch = aids[i : i + BATCH_SIZE]  # noqa
                payload = {"ids": aid_batch}
                logger_msg = (
                    f"pulling scores for host(s) of page {page_count}"
                    f" from {PLATFORM_NAME} platform"
                )
                resp = self.crowdstrike_helper.api_helper(
                    method="GET",
                    url=zero_trust_assessment_url,
                    headers=auth_header,
                    params=payload,
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
                        f"Received exit code {resp.status_code}, "
                        f"Resource not found while {logger_msg}."
                    )
                    resp_json = self.crowdstrike_helper.parse_response(
                        response=resp
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {err_msg} One or more "
                            " assessment ids are not found on "
                            f"{PLATFORM_NAME} platform."
                        ),
                        details=str(
                            resp_json.get(
                                "errors",
                                "No error details found from API Response.",
                            )
                        ),
                    )
                else:
                    resp_json = self.crowdstrike_helper.handle_error(
                        resp=resp, logger_msg=logger_msg
                    )

                if resp_json:
                    for sub in resp_json.get("resources", []):
                        aid = sub.get("aid")
                        score = sub.get("assessment", {}).get("overall")
                        if score is not None:
                            score = int(score) * SCORE_NORMALIZE_MULTIPLIER
                            if score <= maximum_score:
                                scored_uids.append(
                                    Record(
                                        uid=aid,
                                        type=RecordType.HOST,
                                        score=score,
                                    )
                                )
                                total_host_count += 1
                                page_host_count += 1

                    self.logger.info(
                        f"{self.log_prefix}: Successfully pulled scores for"
                        f" {page_host_count} host(s) in page {page_count} "
                        f"from {PLATFORM_NAME} platform. Total host(s) "
                        f"score pulled: {total_host_count}"
                    )

            except (CrowdstrikePluginException, Exception) as error:
                error_message = (
                    "Error occurred"
                    if isinstance(error, CrowdstrikePluginException)
                    else "Unexpected error occurred"
                )
                err_msg = (
                    f"{error_message} while fetching scores "
                    f"for page {page_count} hence skipping this batch."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=str(traceback.format_exc()),
                )
            finally:
                page_count += 1

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched scores for "
            f"{total_host_count} host(s) and skipped fetching scores for "
            f"{len(aids) - total_host_count} host(s) on the basis of Maximum"
            f" Score i.e({maximum_score}) provided in the plugin  "
            f"configuration or score might not available on {PLATFORM_NAME}."
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

    def _get_host_platform_name(
        self, base_url: str, headers: Dict, host_id: str
    ) -> str:
        """Get the host platform name.

        Args:
            base_url (str): Base URL.
            headers (Dict): Headers.
            host_id (str): Host ID.

        Returns:
            str: Platform Name. for e.g. Windows or mac.
        """
        self.logger.debug(
            f"{self.log_prefix}: Fetching platform name "
            f"for host {host_id}."
        )
        url = f"{base_url}/devices/entities/devices/v2"
        params = {"ids": [host_id]}
        resp_json = self.crowdstrike_helper.api_helper(
            method="GET",
            url=url,
            headers=headers,
            params=params,
            logger_msg=f"getting platform details of host {host_id}",
            is_handle_error_required=True,
        )
        platform_name = resp_json.get("resources", [{}])[0].get(
            "platform_name", ""
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched platform name "
            f'for host "{host_id}". Platform name: {platform_name}'
        )
        return platform_name.lower()

    def _get_device_match(
        self, base_url: str, headers: Dict, device_id: str
    ) -> bool:
        """Get device match.

        Args:
            base_url (str): Base URL.
            headers (Dict): Headers.
            device_id (str): Device ID.

        Returns:
            bool: True if device is found else False.
        """
        agent_ids = self.get_agent_ids(base_url, headers, device_id)
        return True if device_id in agent_ids else False

    def execute_action(self, record: Record, action: Action):
        """Execute action on the record.

        Args:
            record (Record): Record object containing record id and score
            action (Action): Actions object containing action label and value.
        """
        action_label = action.label
        self.logger.info(
            f"{self.log_prefix}: Executing action {action_label} on"
            f" record {record.uid}."
        )
        if action.value == "generate":
            self.logger.debug(
                f'{self.log_prefix}: Successfully executed "{action_label}"'
                f' action on record "{record.uid}". Note: No processing will'
                f' be done from plugin for the "{action_label}" action.'
            )
            return
        elif record.type != RecordType.HOST:
            self.logger.debug(
                f"{self.log_prefix}: CrowdStrike plugin only supports Hosts "
                f" hence skipping execution of action {action_label}"
                f" on user {record.uid}."
            )
            return
        elif not record.scores:
            self.logger.debug(
                f"{self.log_prefix}: Score for host {record.uid} not found"
                f" on cloud exchange hence {action_label} action will "
                "not perform on it."
            )
            return
        device = record.uid
        base_url, client_id, client_secret = (
            self.crowdstrike_helper.get_credentials(
                configuration=self.configuration
            )
        )
        headers = self.crowdstrike_helper.get_auth_header(
            base_url=base_url, client_id=client_id, client_secret=client_secret
        )

        # Verify whether host is present on CrowdStrike platform or not.
        self.logger.debug(
            f"{self.log_prefix}: Verifying the existence of"
            f' host "{device}" on {PLATFORM_NAME} platform.'
        )
        match = self._get_device_match(base_url, headers, record.uid)
        if not match:
            self.logger.info(
                f"{self.log_prefix}: Host with ID {device} was not "
                f"found on {PLATFORM_NAME} platform. Hence {action_label}"
                " action will not be executed on this it."
            )
            return
        self.logger.info(
            f'{self.log_prefix}: Since the host with ID "{device}" is '
            f"present on the {PLATFORM_NAME} platform, the "
            f'"{action_label}" action will be executed on it.'
        )
        if action.value == "rtr":
            score_to_be_put = None
            for score in record.scores:
                if score.source == self.name:
                    score_to_be_put = score.current
                    self.logger.debug(
                        f"{self.log_prefix}: Current score for the host"
                        f" is {score_to_be_put}. Hence action will be "
                        "performed on the basis of current host's score."
                    )
            # If score is None then skip the execution of action on host.
            if score_to_be_put is None:
                err_msg = (
                    f"Could not find score for host ID {record.uid}. Hence "
                    "action will not be performed on this host."
                )
                self.logger.warn(f"{self.log_prefix}: {err_msg}")
                raise CrowdstrikePluginException(err_msg)

            # Step 1: Put the file on RTR cloud.
            self._put_files_on_rtr_cloud(base_url, headers)

            # Step 2: Get platform name with host id.
            platform_name = self._get_host_platform_name(
                base_url=base_url, headers=headers, host_id=record.uid
            )
            script_name = None
            if platform_name == "windows":
                script_name = WINDOWS_REMOVE_FILE_SCRIPT_NAME
            elif platform_name == "mac":
                script_name = MAC_REMOVE_FILE_SCRIPT_NAME
            else:
                err_msg = (
                    f"{platform_name} platform is not supported"
                    " in Put RTR Script action."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise CrowdstrikePluginException(err_msg)

            # Step 3: Check Script Existence on RTR cloud.
            is_script_exists = self._check_script_existence_on_rtr_cloud(
                base_url, headers, script_name
            )
            if not is_script_exists:
                # Step 4: Create script on RTR cloud.
                self._create_script_on_rtr_cloud(
                    base_url, headers, platform_name
                )

            # Step 5: Create session with host.
            session_id = self._get_session_id(base_url, headers, device)

            # Step 6: Change directory in the host.
            self._change_directory(
                headers=headers,
                session_id=session_id,
                device_id=device,
                platform_name=platform_name,
            )

            # Step 8: Remove the present file from RTR cloud.
            self._remove_files_from_device(
                headers, session_id, device, script_name
            )

            # Step 9: Put file on device.
            self._put_file_on_device(
                headers=headers,
                session_id=session_id,
                score=score_to_be_put,
                device_id=device,
            )

            # Step 10: Delete the session with host.
            self._delete_session(base_url, headers, session_id, device)
            self.logger.info(
                f"{self.log_prefix}: Successfully executed {action_label} "
                f'action on host "{device}".'
            )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (Dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success
            flag and message.
        """
        validation_err_msg = "Validation error occurred."
        # Validate Base URL
        base_url = configuration.get("base_url", "").strip()
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif base_url not in BASE_URLS:
            err_msg = "Invalid Base URL provided in configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} "
                f"{err_msg} Select the Base URL from the available options."
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Client ID
        client_id = configuration.get("client_id", "").strip()
        if not client_id:
            err_msg = "Client ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = "Invalid Client ID provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Client Secret
        client_secret = configuration.get("client_secret")
        if not client_secret:
            err_msg = "Client Secret is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_secret, str):
            err_msg = (
                "Invalid Client Secret provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} "
                f"{err_msg} Client Secret should be an non-empty string."
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Maximum Score
        maximum_score = configuration.get("maximum_score")
        if maximum_score is None:
            err_msg = "Maximum Score is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif (
            not isinstance(maximum_score, int)
            or maximum_score < 1
            or maximum_score > 1000
        ):
            err_msg = (
                "Invalid Maximum Score provided in configuration parameters."
                " Maximum Score must be an integer in range from 1 to 1000."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Auth Credentials
        return self.validate_auth_params(client_id, client_secret, base_url)

    def validate_auth_params(
        self, client_id: str, client_secret: str, base_url: str
    ) -> ValidationResult:
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
            auth_token_header = self.crowdstrike_helper.get_auth_header(
                client_id, client_secret, base_url, True
            )
            query_endpoint = f"{base_url}/devices/queries/devices/v1?limit=1"
            response = self.crowdstrike_helper.api_helper(
                method="GET",
                url=query_endpoint,
                headers=auth_token_header,
                logger_msg=(
                    f"checking connectivity with {PLATFORM_NAME} platform"
                ),
                is_handle_error_required=False,
                is_validation=True,
                regenerate_auth_token=False,
            )
            if response.status_code in [200, 201]:
                log_msg = f"Validation successful for {PLUGIN_NAME} plugin."
                return ValidationResult(
                    success=True,
                    message=log_msg,
                )
            elif response.status_code == 403:
                err_msg = (
                    f"Received exit code {response.status_code}, Forbidden"
                    "access. Verify the API scopes provided to Client ID "
                    "and Client Secret."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation "
                        f"error occurred. {err_msg}"
                    ),
                    details=str(response.text),
                )
                return ValidationResult(success=False, message=err_msg)
            else:
                self.crowdstrike_helper.handle_error(
                    response, "validating auth credentials"
                )

        except CrowdstrikePluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )
