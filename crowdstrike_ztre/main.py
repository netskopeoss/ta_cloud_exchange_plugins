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

CRE Crowdstrike plugin.
"""

import json
import os
import time
import traceback
from typing import List, Dict, Union, Callable

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    BASE_URLS,
    BATCH_SIZE,
    COMMAND_TIMEOUT,
    COMMAND_WAIT,
    CROWDSTRIKE_DATE_FORMAT,
    HOST_ID,
    MAC_PUT_DIR,
    MAC_REMOVE_FILE_SCRIPT_NAME,
    MODULE_NAME,
    NETSKOPE_NORMALIZED_SCORE,
    OVERALL_ASSESSMENT_SCORE,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    SCORE_NORMALIZE_MULTIPLIER,
    SCORE_TO_FILE_MAPPING,
    SCRIPT_PERMISSION_TYPE,
    WINDOWS_PUT_DIR,
    WINDOWS_REMOVE_FILE_SCRIPT_NAME,
    HOST_ENTITY_MAPPING,
    HOST_MANAGEMENT_PAGE,
    ZERO_TRUST_ASSESSMENT_PAGE,
    HOST_FETCH_BATCH_SIZE,
)
from .utils.helper import (
    CrowdstrikePluginException,
    CrowdstrikePluginHelper,
)


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
        if self.crowdstrike_helper.partial_action_result_supported:
            self.provide_action_id = True

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
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

    def _add_falcon_prefix(self, tag_name):
        """Add FalconGroupingTags prefix if not already present.

        Args:
            tag_name: The tag name to process

        Returns:
            str: Tag name with FalconGroupingTags prefix
        """
        tag_name = str(tag_name).strip()
        if tag_name.startswith("FalconGroupingTags/"):
            return tag_name
        else:
            return f"FalconGroupingTags/{tag_name}"

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Agents",
                fields=[
                    EntityField(
                        name="Host ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="System Serial Number",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Overall Assessment Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Tags",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="CID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Agent Version",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="BIOS Manufacturer",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="BIOS Version",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Build Number",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="External IP",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Mac Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Hostname",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="First Seen",
                        type=EntityFieldType.DATETIME,
                    ),
                    EntityField(
                        name="Last Login User",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Last Login User SID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Last Seen",
                        type=EntityFieldType.DATETIME,
                    ),
                    EntityField(
                        name="Local IP",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="OS Version",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="OS Build",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Platform ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Platform Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="RTR State",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Groups",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Product Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Product Type Description",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Provision Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="System Manufacturer",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="System Product Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Modified Timestamp",
                        type=EntityFieldType.DATETIME,
                    ),
                    EntityField(
                        name="Kernel Version",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="OS Product Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Chassis Type",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Chassis Type Description",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Connection IP",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Default Gateway IP",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Connection Mac Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Filesystem Containment Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Applied Policies",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Applied Device Policies",
                        type=EntityFieldType.LIST,
                    ),
                ],
            ),
        ]

    def get_agent_ids(
        self,
        base_url: str,
        headers: dict,
        device_id: str = None,
    ) -> list[str]:
        """Get the all the Host ID list from the Query Endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token.
            device_id (str): Device id. Default None.

        Returns:
            dict: list of host ids received from CrowdStrike platform.
        """
        query_endpoint = f"{base_url}/devices/queries/devices-scroll/v1"

        api_filter = None
        if self.last_run_at and (device_id is None):
            # This filter is for fetching only the updated hosts.
            formatted_date = self.last_run_at.strftime(CROWDSTRIKE_DATE_FORMAT)
            api_filter = f"modified_timestamp: > '{formatted_date}'"
            self.logger.info(
                f"{self.log_prefix}: Plugin will be fetching"
                f" host id(s) from {PLATFORM_NAME} {HOST_MANAGEMENT_PAGE}"
                f' using checkpoint "{formatted_date}".'
            )
        elif device_id:
            # This filter is to fetch the hosts on the bases of provided
            # device id. This filter is utilized in execute_action
            api_filter = f"device_id: '{device_id}'"
        elif self.last_run_at is None:
            self.logger.debug(
                f"{self.log_prefix}: This is an initial pull of the plugin"
                " hence fetching all the host id(s) present on the "
                f"{PLATFORM_NAME} {HOST_MANAGEMENT_PAGE}."
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
                    f"fetching host id(s) for page {page_count}"
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
                f"{self.log_prefix}: Successfully fetched {len(resources)}"
                f" host id(s) from {PLATFORM_NAME} in page {page_count}."
                f" Total host id(s) fetched: {len(agent_ids)}."
            )
            if not offset.strip():
                break
            page_count += 1
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched {len(agent_ids)}"
            f" host id(s) from {PLATFORM_NAME} "
            f"{HOST_MANAGEMENT_PAGE}."
        )
        return agent_ids

    def _put_files_on_rtr_cloud(self, base_url: str, headers: dict) -> None:
        """Put files on RTR cloud.

        Args:
            base_url (str): Base URL
            headers (dict): Headers with auth token.
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
        self, base_url: str, headers: dict, device_id: str
    ) -> str:
        """Get session id of the connection made to the device.

        Args:
            base_url (str): Base URL.
            headers (dict): Headers with auth token.
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
        headers: dict,
        session_id: str,
        device_id: str,
        platform_name: str,
    ) -> None:
        """Change directory in the remote host.

        Args:
            headers (dict): Headers with auth token.
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
            resolution = (
                "Ensure that the platform name is either mac or windows."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
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
        self, base_url: str, headers: dict, script_name: str
    ) -> bool:
        """Check if the script exists on RTR cloud.

        Args:
            base_url (str): Base URL
            headers (dict): Headers with auth token.
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
            err_msg = f"{script_name} script does not exist" " on RTR cloud."
            resolution = (
                f"Ensure that the script name {script_name} exists on "
                "RTR cloud."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            return False

    def _create_script_on_rtr_cloud(
        self, base_url: str, headers: dict, platform_name: str
    ) -> None:
        """Create script on RTR cloud.

        Args:
            base_url (str): Base URL
            headers (dict): Headers with auth token.
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
        headers: dict,
        session_id: str,
        device_id: str,
        script_name: str,
    ):
        """Remove files from the remote host.

        Args:
            headers (dict): Headers with auth token.
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
        headers: dict,
    ):
        """Block execution until command successfully executed.

        Args:
            status (bool): Status of command.
            cloud_request_id (str): Cloud request Id of the request.
            device_id (str): Device ID.
            cmd (str): Command to be executed.
            headers (dict): Headers with auth token.
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
        headers: dict,
        session_id: str,
        score: int,
        device_id: str,
    ) -> None:
        """Put file on the remote host.

        Args:
            headers (dict): Headers with auth token.
            session_id (str): Session id to put files against.
            score (int): score to determine which file is to be put.
            device_id (str): Id of the remote host.
            platform_name (str): Platform name of the host.

        Returns:
            None
        """
        file = None
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
            resolution = (
                "Ensure that the score value is between 1 and 100 for "
                "putting file on device."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
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
        headers: dict,
    ) -> str:
        """Execute the specified command on the remote host.

        Args:
            base_command (str): Base command to perform.
            command_string (str): Full command line of the command to execute.
            session_id (str): Session id to execute the command against.
            device_id (str): Id of the remote host.
            headers (dict): Headers dictionary containing auth token
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
        headers: dict,
    ) -> bool:
        """Check the status of the executed command.

        Args:
            cloud_request_id (str): Cloud request id generated from execute
            command.
            device_id (str): Device id on which the command was executed.
            cmd (str): Command that was
            headers (dict): Headers dictionary containing auth token
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
        self, base_url: str, headers: dict, session_id: str, device_id: str
    ) -> None:
        """Delete the created session with the remote host.

        Args:
            base_url (str): Base url of the API endpoint.
            headers (dict): Headers dictionary containing auth token.
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

    def _get_scores_details(
        self,
        host_records: dict,
        base_url: str,
        auth_header: dict,
        host_id_list: list,
        update_records: bool = False,
    ) -> list:
        """Get the scores details of the hosts.

        Args:
            host_id_list (list): List of host ids.

        Returns:
            list: List of scores details.
        """
        log_pre = "Updating" if update_records else "Fetching"
        zero_trust_assessment_url = (
            f"{base_url}/zero-trust-assessment/entities/assessments/v1"
        )
        self.logger.info(
            f"{self.log_prefix}: {log_pre} score(s) for {len(host_id_list)}"
            f" host(s) from {PLATFORM_NAME} {ZERO_TRUST_ASSESSMENT_PAGE}."
        )

        page_count = 1
        total_host_count = 0
        total_skip_count = 0
        maximum_score = int(self.configuration.get("maximum_score"))
        records_list_with_scores = []
        for i in range(0, len(host_id_list), BATCH_SIZE):
            page_host_count = 0
            page_skip_count = 0
            try:
                aid_batch = host_id_list[i : i + BATCH_SIZE]  # noqa
                payload = {"ids": aid_batch}
                logger_msg = (
                    f"fetching scores for host(s) of page {page_count}"
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
                                "No error details found from API Response.",  # noqa
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
                        if score or (isinstance(score, int) and score == 0):
                            score = int(score)
                            record = None
                            if score <= maximum_score and aid in host_records:
                                record = host_records.get(aid)
                                if record:
                                    host_records[aid][
                                        OVERALL_ASSESSMENT_SCORE
                                    ] = score
                                    host_records[aid][
                                        NETSKOPE_NORMALIZED_SCORE
                                    ] = (score * SCORE_NORMALIZE_MULTIPLIER)
                                    total_host_count += 1
                                    page_host_count += 1
                    
                    page_skip_count = len(aid_batch) - page_host_count
                    total_skip_count += page_skip_count

                    log_msg = (
                        f"Successfully {'updated' if update_records else 'fetched'} " # noqa
                        f"score(s) for {page_host_count} host(s) in page "
                        f"{page_count}. Total host(s) score "
                        f"{'updated' if update_records else 'fetched'}: "
                        f"{total_host_count}."
                    )
                    if page_skip_count:
                        log_msg += (
                            f" Skipped {'fetching' if update_records else 'updating'} " # noqa
                            f"score(s) for {page_skip_count} "
                            f"host(s) in page {page_count} from "
                            f"{PLATFORM_NAME} platform."
                        )

                    self.logger.info(f"{self.log_prefix}: {log_msg}")

            except (CrowdstrikePluginException, Exception) as error:
                error_message = (
                    "Error occurred"
                    if isinstance(error, CrowdstrikePluginException)
                    else "Unexpected error occurred"
                )
                err_msg = (
                    f"{error_message} while {log_pre.lower()} scores "
                    f"for page {page_count} hence skipping this batch."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=str(traceback.format_exc()),
                )
            finally:
                page_count += 1

        self.logger.info(
            f"{self.log_prefix}: Successfully "
            f"{'updated' if update_records else 'fetched'} "
            f"scores for {total_host_count} host(s) and skipped "
            f"{'updating' if update_records else 'fetching'} scores for "
            f"{total_skip_count} host(s) on the basis "
            f"of Maximum Score i.e ({maximum_score}) provided in the plugin "
            "configuration or score might not"
            f" available on {PLATFORM_NAME} {ZERO_TRUST_ASSESSMENT_PAGE}."
        )
        for aid, record in host_records.items():
            records_list_with_scores.append(record)
        return records_list_with_scores

    def _get_host_details(
        self,
        base_url: str,
        auth_header: dict,
        host_id_list: list,
        update_records: bool = False,
    ) -> list:
        """Get the all the Host details from the Query Endpoint.

        Args:
            base_url (str): Base URL of the CrowdStrike platform.
            auth_header (dict): Authentication header.
            host_id_list (list): List of host IDs.

        Returns:
            list: List of host details.
        """
        log_pre = "Updated" if update_records else "Fetched"
        updated_records = {}
        page_count = 1
        total_fetch_count = 0
        total_skip_count = 0
        for i in range(0, len(host_id_list), HOST_FETCH_BATCH_SIZE):
            page_fetch_count = 0
            host_skip_count = 0
            host_id_batch = host_id_list[i : i + HOST_FETCH_BATCH_SIZE]  # noqa
            payload = {"ids": host_id_batch}
            logger_msg = (
                f"fetching host details for {len(host_id_batch)} "
                f"host(s) of page {page_count} from {PLATFORM_NAME} "
                f"{HOST_MANAGEMENT_PAGE}."
            )
            resp = self.crowdstrike_helper.api_helper(
                method="POST",
                url=f"{base_url}/devices/entities/devices/v2",
                headers=auth_header,
                data=json.dumps(payload),
                logger_msg=logger_msg,
                is_handle_error_required=False,
            )
            resp_json = None
            if resp.status_code == 404:
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
                        f"{PLATFORM_NAME} {HOST_MANAGEMENT_PAGE}."
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
                for host in resp_json.get("resources", []):
                    extracted_fields = (
                        self.crowdstrike_helper.extract_entity_fields(
                            host, HOST_ENTITY_MAPPING, update_records
                        )
                    )
                    if extracted_fields:
                        updated_records[host.get("device_id")] = (
                            extracted_fields
                        )
                        page_fetch_count += 1
                    else:
                        host_skip_count += 1

            total_skip_count += host_skip_count
            total_fetch_count += page_fetch_count
            msg = (
                f"Successfully {log_pre.lower()} details for "
                f"{page_fetch_count} host(s) for page {page_count}."
            )
            if host_skip_count > 0:
                msg += (
                    f" Skipped {host_skip_count} host(s) due to invalid data "
                    "or field could not be extracted from them."
                )
            self.logger.info(f"{self.log_prefix}: {msg}")
            page_count += 1

        final_msg = (
            f"Successfully {log_pre.lower()} details for "
            f"{total_fetch_count} host(s) from "
            f"{PLATFORM_NAME} {HOST_MANAGEMENT_PAGE}."
        )
        if total_skip_count > 0:
            final_msg += (
                f" Skipped total {total_skip_count} host(s) due to "
                "invalid data or field could not be extracted from them."
            )

        self.logger.info(f"{self.log_prefix}: {final_msg}")
        return updated_records

    def fetch_records(self, entity: str) -> list:
        """Get the all the Host ID list from the Query Endpoint.

        Args:
            entity (Entity): Entity object containing the entity type.

        Returns:
            list[Record]: list of hosts fetched from CrowdStrike.
        """
        combined_records = []
        host_records = {}
        entity_name = entity.lower()
        if entity_name != "agents":
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Agents' Entity."
            )
            resolution = "Ensure that the entity is 'Agents'."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            raise CrowdstrikePluginException(err_msg)
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
        host_id_list = []

        host_id_list = self.get_agent_ids(base_url, auth_header)

        # Fetch the host details
        host_records = self._get_host_details(
            base_url=base_url,
            auth_header=auth_header,
            host_id_list=host_id_list,
        )

        # Fetch the scores details
        combined_records = self._get_scores_details(
            host_records=host_records,
            base_url=base_url,
            auth_header=auth_header,
            host_id_list=host_id_list,
        )
        return combined_records
        
    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Fetch scores of hosts from CrowdStrike platform.

        Args:
            entity (str): Entity name.
            agent_ids (list[Record]): list of records containing host's
            host ids.

        Returns:
            list[Record]: list of records with scores.
        """
        if entity.lower() != "agents":
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Agents' Entity."
            )
            resolution = "Ensure that the entity is 'Agents'."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            raise CrowdstrikePluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} {entity.lower()}"
            f" records from {PLATFORM_NAME} platform."
        )
        host_id_list = []
        record_skip_count = 0
        for record in records:
            if record.get(HOST_ID):
                host_id_list.append(record[HOST_ID])
            else:
                record_skip_count += 1

        log_msg = (
            f"{len(host_id_list)} {entity.lower()} record(s) will be updated"
            f" out of {len(records)} record(s) from {PLATFORM_NAME}."
        )

        if record_skip_count > 0:
            log_msg += (
                f" Skipped {record_skip_count} {entity.lower()} record(s)"
                " as they do not have 'Host ID' field in them."
            )

        self.logger.info(f"{self.log_prefix}: {log_msg}")

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
        # Fetch the host details
        updated_records_with_tags = self._get_host_details(
            base_url=base_url,
            auth_header=auth_header,
            host_id_list=host_id_list,
            update_records=True,
        )
        # Fetch the scores details
        updated_records = self._get_scores_details(
            host_records=updated_records_with_tags,
            base_url=base_url,
            auth_header=auth_header,
            host_id_list=host_id_list,
            update_records=True,
        )
        return updated_records

    def _validate_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: Dict = None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
        validation_err_msg: str = "Validation error occurred. ",
        check_dollar: bool = False,
        is_source_field_allowed: bool = True,
    ) -> Union[ValidationResult, None]:
        """
        Validate the given configuration field value.

        Args:
            field_name (str): Name of the configuration field.
            field_value (str, List, bool, int): Value of the configuration
                field.
            field_type (type): Expected type of the configuration field.
            allowed_values (Dict, optional): Dictionary of allowed values for
                the configuration field. Defaults to None.
            custom_validation_func (Callable, optional): Custom validation
                function to be applied. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.
            validation_err_msg (str, optional): Error message to be logged in
                case of validation failure. Defaults to "Validation error
                occurred. ".

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """

        if not is_source_field_allowed and "$" in field_value:
            err_msg = f"'{field_name}' can only contain the Static Field."
            resolution = (
                "Ensure that Static is selected for the field "
                f"'{field_name}' in the action configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if field_type is str:
            field_value = field_value.strip()
        if check_dollar and "$" in field_value:
            err_msg = (
                f"'{field_name}' contains the Source Field"
                " hence validation for this field will be performed"
                " while executing the action."
            )
            self.logger.info(
                message=f"{self.log_prefix}: {err_msg}",
            )
            return
        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = f"'{field_name}' is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if (
            is_required
            and not isinstance(field_value, field_type)
            or (
                custom_validation_func
                and not custom_validation_func(field_value)
            )
        ):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if allowed_values:
            if len(allowed_values) <= 5:
                err_msg = (
                    f"Invalid value provided for the configuration"
                    f" parameter '{field_name}'. Allowed values are"
                    f" {', '.join(value for value in allowed_values)}."
                )
            else:
                err_msg = (
                    f"Invalid value for '{field_name}' provided "
                    f"in the configuration parameters."
                )
            if field_type is str and field_value not in allowed_values:
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Put RTR Script", value="rtr"),
            ActionWithoutParams(label="Add/Remove Tag(s)", value="tag_action"),
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def validate_action(self, action: Action):
        """Validate Netskope configuration.

        Args:
            action (Action): Action object.

        Returns:
            ValidationResult: Validation result.
        """
        action_value = action.value
        action_params = action.parameters
        if action_value not in ["generate", "rtr", "tag_action"]:
            err_msg = (
                "Unsupported action "
                f'{action_value}" provided in the action '
                "configuration. Supported Actions are - "
                "'Put RTR Script', 'Add/Remove Tag(s)' and 'No action'."
            )
            resolution = (
                "Ensure that the action is selected from the "
                "supported actions 'Put RTR Script', 'Add/Remove Tag(s)' "
                "and 'No action' in the action configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if action_value == "generate":
            log_msg = (
                "Successfully validated action configuration"
                f" for '{action.label}'."
            )
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(success=True, message=log_msg)
        elif action_value == "rtr":
            params = action.parameters
            aid = params.get("aid")
            if not aid:
                err_msg = (
                    f"{HOST_ID} is a required action parameter"
                    " for Put RTR Script action."
                )
                resolution = (
                    f"Ensure that {HOST_ID} is provided in the action "
                    "configuration for Put RTR Script action."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)
            elif not isinstance(aid, str):
                err_msg = f"Invalid {HOST_ID} provided in action parameters."
                resolution = (
                    "Ensure that the action is selected from the "
                    "supported actions 'Put RTR Script', 'Add/Remove Tag(s)' "
                    "and 'No action' in the action configuration."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)

            score = params.get("score")

            if score is None:
                err_msg = (
                    "Score is a required action parameter"
                    " for Put RTR Script action."
                )
                resolution = (
                    "Ensure that Score is provided in the action "
                    "configuration for Put RTR Script action."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                return ValidationResult(success=False, message=err_msg)

            if isinstance(score, str) and "$" in score:
                log_msg = (
                    "Score contains the Business Rule Record Field"
                    " hence validation for this field will be performed"
                    " while executing the Put RTR Script action."
                )
                self.logger.info(f"{self.log_prefix}: {log_msg}")
                return ValidationResult(
                    success=True, message="Validation successful."
                )

            try:
                score = int(score)
                if not isinstance(score, int) or (score < 1 or score > 100):
                    err_msg = (
                        "Invalid Score provided in action parameters. "
                        "Valid should be in range 1 to 100."
                    )
                    resolution = (
                        "Ensure that Score is an integer in range 1 to 100 "
                        "provided in the action configuration for"
                        " Put RTR Script action."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(resolution),
                    )
                    return ValidationResult(success=False, message=err_msg)
            except Exception:
                err_msg = (
                    "Invalid Score provided in action parameters. "
                    "Valid should be an integer in range 1 to 100."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(success=False, message=err_msg)
        elif action_value == "tag_action":
            # validate the tag action type
            tag_action_type = action_params.get("tag_action_type", "add")
            if validation_result := self._validate_parameters(
                field_name="Action Type",
                field_value=tag_action_type,
                field_type=str,
                is_required=True,
                is_source_field_allowed=False,
            ):
                return validation_result

            # validate the host id
            host_id = action_params.get("host_id")
            if validation_result := self._validate_parameters(
                field_name="Host ID",
                field_value=host_id,
                field_type=str,
                is_required=True,
                check_dollar=True,
            ):
                return validation_result

            # validate the tag name
            tags = action_params.get("tag")
            if validation_result := self._validate_parameters(
                field_name="Tag(s)",
                field_value=tags,
                field_type=str,
                is_required=True,
                check_dollar=True,
            ):
                return validation_result

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_params(self, action: Action):
        """Get action params.

        Args:
            action (Action): Action object.

        Returns:
            list: List of action parameters.
        """
        if action.value == "generate":
            return []
        if action.value == "rtr":
            return [
                {
                    "label": HOST_ID,
                    "key": "aid",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Agent ID/Host ID of the host to perform the action"
                        " on."
                    ),
                },
                {
                    "label": (
                        f"{OVERALL_ASSESSMENT_SCORE} "
                        "(in the range of 1-100)"
                    ),
                    "key": "score",
                    "type": "number",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        f"{OVERALL_ASSESSMENT_SCORE} to consider while"
                        " performing the action."
                    ),
                },
            ]
        if action.value == "tag_action":
            return [
                {
                    "label": "Action Type",
                    "key": "tag_action_type",
                    "type": "choice",
                    "choices": [
                        {"key": "Add Tag(s)", "value": "add"},
                        {"key": "Remove Tag(s)", "value": "remove"},
                    ],
                    "default": "add",
                    "mandatory": True,
                    "description": ("Choose action to perform on host(s)."),
                },
                {
                    "label": HOST_ID,
                    "key": "host_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Comma separated Device ID(s) of "
                        "the host to perform the action on."
                    ),
                },
                {
                    "label": "Tag(s)",
                    "key": "tag",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Comma separated Tag(s) to"
                        " add/remove from the host(s)."
                    ),
                },
            ]
        return []

    def _get_host_platform_name(
        self, base_url: str, headers: dict, host_id: str
    ) -> str:
        """Get the host platform name.

        Args:
            base_url (str): Base URL.
            headers (dict): Headers.
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
        self, base_url: str, headers: dict, device_id: str
    ) -> bool:
        """Get device match.

        Args:
            base_url (str): Base URL.
            headers (dict): Headers.
            device_id (str): Device ID.

        Returns:
            bool: True if device is found else False.
        """
        agent_ids = self.get_agent_ids(base_url, headers, device_id)
        return True if device_id in agent_ids else False

    def _execute_rtr_action(self, action: Action):
        """Execute RTR action on the record.

        Args:
            action (Action): Action object containing action label and value.
        """
        action_label = action.label
        device = action.parameters.get("aid")
        if not device:
            err_msg = (
                f"{HOST_ID} not found in the action parameters. "
                f"Hence skipped execution of {action_label} on "
                f"record {device}."
            )
            resolution = (
                f"Ensure that {HOST_ID} is provided in the action "
                "configuration for Put RTR Script action."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            return
        elif not isinstance(device, str):
            err_msg = (
                f"Invalid {HOST_ID} found in the action parameters. "
                f"Hence skipped execution of {action_label} on "
                f"record {device}."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return

        self.logger.info(
            f"{self.log_prefix}: Executing action {action_label} on"
            f" record {device}."
        )
        score = action.parameters.get("score")
        if score is None:
            self.logger.error(
                f"{self.log_prefix}: {OVERALL_ASSESSMENT_SCORE} for"
                f" host {device} not found in the record hence skipped "
                f"execution of {action_label} action on it."
            )
            return
        try:
            score = int(score)

            if not isinstance(score, int) or score < 1 or score > 100:
                err_msg = (
                    f"Invalid {OVERALL_ASSESSMENT_SCORE} for host {device}"
                    " found in the record hence skipped execution of"
                    f" {action_label} action on it. Valid value should be"
                    " in range of 1 to 100."
                )
                resolution = (
                    f"Ensure that {OVERALL_ASSESSMENT_SCORE} is an integer"
                    " in range 1 to 100 provided in the action"
                    " configuration for Put RTR Script action."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                return
        except Exception as exp:
            err_msg = (
                f"Invalid {OVERALL_ASSESSMENT_SCORE} for host {device}"
                " found in the record hence skipped execution of"
                f" {action_label} action on it. Valid value should be"
                " an integer in range of 1 to 100."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise CrowdstrikePluginException(f"{err_msg}.")

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
        match = self._get_device_match(base_url, headers, device)
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

        # Step 1: Put the file on RTR cloud.
        self._put_files_on_rtr_cloud(base_url, headers)

        # Step 2: Get platform name with host id.
        platform_name = self._get_host_platform_name(
            base_url=base_url,
            headers=headers,
            host_id=device,
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
            resolution = (
                "Ensure that the platform is supported "
                "in Put RTR Script action."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            raise CrowdstrikePluginException(err_msg)

        # Step 3: Check Script Existence on RTR cloud.
        is_script_exists = self._check_script_existence_on_rtr_cloud(
            base_url, headers, script_name
        )
        if not is_script_exists:
            # Step 4: Create script on RTR cloud.
            self._create_script_on_rtr_cloud(base_url, headers, platform_name)

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
            score=score,
            device_id=device,
        )

        # Step 10: Delete the session with host.
        self._delete_session(base_url, headers, session_id, device)
        self.logger.info(
            f"{self.log_prefix}: Successfully executed {action_label} "
            f'action on host "{device}".'
        )

    def _execute_tag_action(self, action: Action):
        """
        Execute tag action on the record.

        Args:
            action (Action): Action object containing action label and value.
        """
        action_parameter = action.parameters
        action_label = action.label
        action_type = action_parameter.get("tag_action_type", "add")
        host_id = action_parameter.get("host_id", "")
        tag = action_parameter.get("tag", "")

        log_prefix = "Adding" if action_type == "add" else "Removing"
        logger_msg = f"{log_prefix} tag(s) {tag} on host(s) {host_id}"
        self.logger.info(f"{self.log_prefix}: {logger_msg}.")
        base_url, client_id, client_secret = (
            self.crowdstrike_helper.get_credentials(
                configuration=self.configuration
            )
        )
        taging_endpoint = f"{base_url}/devices/entities/devices/tags/v1"
        headers = self.crowdstrike_helper.get_auth_header(
            base_url=base_url, client_id=client_id, client_secret=client_secret
        )
        headers.update(
            {
                "Content-Type": "application/json",
                "accept": "application/json",
            }
        )
        # Handle both string and list inputs for host_id
        if isinstance(host_id, list):
            device_ids = [str(id).strip() for id in host_id if str(id).strip()]
        elif isinstance(host_id, str):
            if host_id.strip():  # Check if string is not empty after stripping
                device_ids = (
                    [id.strip() for id in host_id.split(",") if id.strip()]
                    if "," in host_id
                    else [host_id.strip()]
                )
            else:
                device_ids = []
        else:
            device_ids = [str(host_id).strip()] if host_id else []

        # Handle both string and list inputs for tag
        if isinstance(tag, list):
            tags = [self._add_falcon_prefix(t) for t in tag if str(t).strip()]
        elif isinstance(tag, str):
            if tag.strip():  # Check if string is not empty after stripping
                tags = (
                    [
                        self._add_falcon_prefix(t)
                        for t in tag.split(",")
                        if t.strip()
                    ]
                    if "," in tag
                    else [self._add_falcon_prefix(tag)]
                )
            else:
                tags = []
        else:
            tags = [self._add_falcon_prefix(tag)] if tag else []

        payload = {
            "action": action_type,
            "device_ids": device_ids,
            "tags": tags,
        }
        _ = self.crowdstrike_helper.api_helper(
            url=taging_endpoint,
            headers=headers,
            method="PATCH",
            data=json.dumps(payload),
            logger_msg=logger_msg,
            is_handle_error_required=True,
        )

        self.logger.info(
            f"{self.log_prefix}: Successfully executed {action_label} "
            f'action on host(s) "{host_id}".'
        )

    def _bulk_execute_tag_action_with_batching(
        self,
        action_label: str,
        action_type: str,
        tag: str,
        host_ids: List[str],
        action_id_to_hosts: Dict[str, List[str]],
    ) -> List[str]:
        """Execute bulk tag action with batching and failure tracking.

        Args:
            action_label (str): Action label for logging
            action_type (str): Action type ('add' or 'remove')
            tag (str): Single tag to apply/remove
            host_ids (List[str]): List of unique host IDs
            action_id_to_hosts (Dict[str, List[str]]): Mapping of action_id
              to host_ids

        Returns:
            List[str]: List of failed action IDs
        """
        failed_action_ids = []

        log_prefix = "Adding" if action_type == "add" else "Removing"
        self.logger.info(
            f"{self.log_prefix}: {log_prefix} tag '{tag}' on {len(host_ids)}"
            f" host(s) in batches of {BATCH_SIZE}."
        )

        base_url, client_id, client_secret = (
            self.crowdstrike_helper.get_credentials(
                configuration=self.configuration
            )
        )
        tagging_endpoint = f"{base_url}/devices/entities/devices/tags/v1"
        headers = self.crowdstrike_helper.get_auth_header(
            base_url=base_url, client_id=client_id, client_secret=client_secret
        )
        headers.update(
            {
                "Content-Type": "application/json",
                "accept": "application/json",
            }
        )

        # Process in batches
        total_batches = (len(host_ids) + BATCH_SIZE - 1) // BATCH_SIZE
        failed_host_ids = set()  # Track failed host IDs
        successful_batches = 0

        for batch_num in range(total_batches):
            start_idx = batch_num * BATCH_SIZE
            end_idx = min(start_idx + BATCH_SIZE, len(host_ids))
            batch_host_ids = host_ids[start_idx:end_idx]

            batch_action_ids = []
            for action_id, action_host_ids in action_id_to_hosts.items():
                if any(
                    host_id in batch_host_ids for host_id in action_host_ids
                ):
                    batch_action_ids.append(action_id)

            try:
                payload = {
                    "action": action_type,
                    "device_ids": batch_host_ids,
                    "tags": [tag],
                }

                logger_msg = (
                    f"{log_prefix} tag '{tag}' on batch "
                    f"{batch_num + 1}/{total_batches} ({len(batch_host_ids)}"
                    " host(s))"
                )

                _ = self.crowdstrike_helper.api_helper(
                    url=tagging_endpoint,
                    headers=headers,
                    method="PATCH",
                    data=json.dumps(payload),
                    logger_msg=logger_msg,
                    is_handle_error_required=True,
                )

                successful_batches += 1
                self.logger.info(
                    f"{self.log_prefix}: Successfully {'added' if log_prefix.lower() == 'adding' else 'removed'} tag '{tag}' "  # noqa
                    f"on batch {batch_num + 1}/{total_batches} "
                    f"({len(batch_host_ids)} host(s))."
                )

            except Exception as e:
                # Track failed host IDs and action IDs
                failed_host_ids.update(batch_host_ids)
                failed_action_ids.extend(batch_action_ids)

                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to {'add' if log_prefix.lower() == 'adding' else 'remove'} tag '{tag}' "  # noqa
                        f"on batch {batch_num + 1}/{total_batches} "
                        f"({len(batch_host_ids)} host(s)). Error: {str(e)}"
                    ),
                    details=str(traceback.format_exc()),
                )

        successful_hosts = len(host_ids) - len(failed_host_ids)
        self.logger.info(
            f"{self.log_prefix}: Successfully {'added' if log_prefix.lower() == 'adding' else 'removed'} tag '{tag}' "  # noqa
            f"on {successful_hosts} host(s), "
            f"failed on {len(failed_host_ids)} host(s)."
        )

        return failed_action_ids

    def execute_action(self, action: Action):
        """Execute action on the record.

        Args:
            record (Record): Record object containing record id and score
            action (Action): Actions object containing action label and value.
        """
        action_label = action.label
        if action.value == "generate":
            self.logger.debug(
                f'{self.log_prefix}: Successfully executed "{action_label}"'
                f" action. Note: No processing will be done from plugin for "
                f'the "{action_label}" action.'
            )
            return
        elif action.value == "rtr":
            self._execute_rtr_action(action)
            return
        elif action.value == "tag_action":
            self._execute_tag_action(action)
            return

    def execute_actions(self, actions: List[Action]):
        """Execute actions on the record.

        Args:
            record (Record): Record object containing record id and score
            action (Action): Actions object containing action label and value.
        """

        first_action = (
            actions[0].get("params", {})
            if self.crowdstrike_helper.partial_action_result_supported
            else actions[0]
        )
        action_label = first_action.label
        action_value = first_action.value
        self.logger.info(
            f"{self.log_prefix}: Executing '{action_label}' action "
            f"for {len(actions)} records."
        )
        failed_action_ids = []
        if action_value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return
        elif action_value == "tag_action":
            failed_action_ids = []
            tag_groups = {}
            for action_dict in actions:
                if self.crowdstrike_helper.partial_action_result_supported:
                    action_params = action_dict.get("params", {}).parameters
                    action_id = action_dict.get("id")
                else:
                    action_params = action_dict.parameters
                    action_id = ""

                host_id = action_params.get("host_id", "")
                if not host_id:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipping action {action_id}"
                        " - no host_id provided"
                    )
                    failed_action_ids.append(action_id)
                    continue
                if isinstance(host_id, list):
                    host_id_list = [
                        str(id).strip() for id in host_id if str(id).strip()
                    ]
                elif isinstance(host_id, str):
                    if not host_id.strip():
                        self.logger.debug(
                            f"{self.log_prefix}: Skipping action {action_id}"
                            " - empty host_id provided"
                        )
                        failed_action_ids.append(action_id)
                        continue
                    host_id_list = (
                        [id.strip() for id in host_id.split(",") if id.strip()]
                        if "," in host_id
                        else [host_id.strip()]
                    )
                else:
                    host_id_list = [str(host_id).strip()] if host_id else []

                tag = action_params.get("tag", "")
                if not tag:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipping action {action_id}"
                        " - no tag provided"
                    )
                    failed_action_ids.append(action_id)
                    continue

                if isinstance(tag, list):
                    tag_list = [
                        self._add_falcon_prefix(t)
                        for t in tag
                        if str(t).strip()
                    ]
                elif isinstance(tag, str):
                    if not tag.strip():
                        self.logger.debug(
                            f"{self.log_prefix}: Skipping action {action_id}"
                            " - empty tag provided"
                        )
                        failed_action_ids.append(action_id)
                        continue
                    tag_list = (
                        [
                            self._add_falcon_prefix(t)
                            for t in tag.split(",")
                            if t.strip()
                        ]
                        if "," in tag
                        else [self._add_falcon_prefix(tag)]
                    )
                else:
                    tag_list = [self._add_falcon_prefix(tag)] if tag else []

                action_type = action_params.get("tag_action_type", "add")
                for single_tag in tag_list:
                    tag_key = (single_tag, action_type)

                    if tag_key not in tag_groups:
                        tag_groups[tag_key] = {
                            "host_ids": [],
                            "action_id_to_hosts": {},
                        }

                    tag_groups[tag_key]["host_ids"].extend(host_id_list)
                    tag_groups[tag_key]["action_id_to_hosts"][
                        action_id
                    ] = host_id_list

            for (tag, action_type), group_data in tag_groups.items():
                host_ids = group_data["host_ids"]
                action_id_to_hosts = group_data["action_id_to_hosts"]

                unique_host_ids = list(dict.fromkeys(host_ids))

                group_failed_action_ids = (
                    self._bulk_execute_tag_action_with_batching(
                        action_label=action_label,
                        action_type=action_type,
                        tag=tag,
                        host_ids=unique_host_ids,
                        action_id_to_hosts=action_id_to_hosts,
                    )
                )

                failed_action_ids.extend(group_failed_action_ids)

            # If CE supports partial action failure return ActionResult model
            if self.crowdstrike_helper.partial_action_result_supported:
                from netskope.integrations.crev2.plugin_base import (
                    ActionResult,
                )

                return ActionResult(
                    success=True,
                    message=f"Successfully executed {action_label} action.",
                    failed_action_ids=list(failed_action_ids),
                )
            return
        else:
            raise NotImplementedError

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): dict object having all the Plugin
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
            resolution = (
                "Ensure that Base URL is provided in the configuration "
                "parameter. Select the Base URL from the available options"
                " in the plugin configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}. {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)
        elif base_url not in BASE_URLS:
            err_msg = "Invalid Base URL provided in configuration parameter."
            resolution = (
                "Ensure that Base URL is provided in the configuration "
                "parameter. Select the Base URL from the available options"
                " in the plugin configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}. {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Client ID
        client_id = configuration.get("client_id", "").strip()
        if not client_id:
            err_msg = "Client ID is a required configuration parameter."
            resolution = (
                "Ensure that Client ID is provided in the configuration "
                "parameter. Client ID can be generated from the 'Support "
                "and resources > API clients and keys' page."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}. {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = "Invalid Client ID provided in configuration parameters."
            resolution = (
                "Ensure that Client ID is provided in the configuration "
                "parameter. Client ID should be an non-empty string."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}. {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Client Secret
        client_secret = configuration.get("client_secret")
        if not client_secret:
            err_msg = "Client Secret is a required configuration parameter."
            resolution = (
                "Ensure that Client Secret is provided in the configuration "
                "parameter. Client Secret can be generated from the 'Support "
                "and resources > API clients and keys' page."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}. {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_secret, str):
            err_msg = (
                "Invalid Client Secret provided in configuration parameters."
            )
            resolution = (
                "Ensure that Client Secret is provided in the configuration "
                "parameter. Client Secret should be an non-empty string."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}. {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Maximum Score
        maximum_score = configuration.get("maximum_score")
        if maximum_score is None:
            err_msg = "Maximum Score is a required configuration parameter."
            resolution = (
                "Ensure that Maximum Score is provided in the configuration "
                "parameter. Maximum Score should be an integer in range from "
                "1 to 100."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}. {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif (
            not isinstance(maximum_score, int)
            or maximum_score < 1
            or maximum_score > 100
        ):
            err_msg = (
                "Invalid Maximum Score provided in configuration parameters."
                " Maximum Score must be an integer in range from 1 to 100."
            )
            resolution = (
                "Ensure that Maximum Score is provided in the configuration "
                "parameter. Maximum Score should be an integer in range from "
                "1 to 100."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}. {err_msg}",
                resolution=resolution,
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
                    f"Received exit code {response.status_code}, Forbidden "
                    "access. Verify the API scopes provided to Client ID "
                    "and Client Secret."
                )
                resolution = (
                    "Ensure that the API scopes provided to Client ID "
                    "and Client Secret are correct."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                    resolution=resolution,
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
