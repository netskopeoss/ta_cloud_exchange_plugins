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

CRE HPE Central plugin.
"""

import hashlib
import json
import traceback
from typing import Dict, Generator, List, Literal, Tuple, Union

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)
from pydantic import ValidationError

from .utils.constants import (
    ACTION_BATCH_SIZE,
    BLACKLIST_API_URL,
    DISCONNECT_CLIENT_API_URL,
    FAILED,
    MODULE_NAME,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    SUCCESS,
    UNAUTHORIZED,
    WIRED_CLIENT_FIELD_MAPPING,
    WIRED_CLIENTS_API_URL,
    WIRELESS_CLIENT_FIELD_MAPPING,
    WIRELESS_CLIENTS_API_URL,
)
from .utils.helper import (
    HPECentralPluginException,
    HPECentralPluginHelper,
    HPECentralUnauthorizedException,
)


class HPECentralPlugin(PluginBase):
    """HPE Central plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """HPE Central plugin initializer.

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
        self.hpe_central_helper = HPECentralPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = HPECentralPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _regenerate_access_token_and_update_storage(
        self, is_validation: bool = False
    ) -> Union[ValidationResult, None]:
        """
        Regenerates the access token and updates the storage.

        Args:
            is_validation (bool, optional): Flag indicating if this call is for validation or not. Defaults to False.

        Raises:
            HPECentralPluginException: If any error occurs while regenerating the access token.

        Returns:
            Union[ValidationResult, None]: ValidationResult if this call is for validation, else None.
        """
        storage = self.storage if self.storage is not None else {}
        access_token = storage.get("access_token")
        refresh_token = storage.get("refresh_token")
        try:
            access_token, refresh_token, expires_at = (
                self.hpe_central_helper.regenerate_access_token(
                    access_token=access_token,
                    refresh_token=refresh_token,
                    base_url=self.configuration.get("base_url", "").strip().strip("/"),
                    client_id=self.configuration.get("client_id", ""),
                    client_secret=self.configuration.get("client_secret", ""),
                )
            )
            if access_token and refresh_token and expires_at:
                storage.clear()
                storage["access_token"] = access_token
                storage["refresh_token"] = refresh_token
                storage["expires_at"] = expires_at
                storage["config_hash"] = self._create_configuration_hash(
                    self.configuration
                )
            else:
                if is_validation:
                    return ValidationResult(
                        success=False,
                        message=f"Validation error occurred. Failed to regenerate access token for {PLATFORM_NAME}.",
                    )
                err_msg = f"Failed to regenerate access token for {PLATFORM_NAME}."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise HPECentralPluginException(err_msg)
        except HPECentralPluginException:
            if is_validation:
                return ValidationResult(
                    success=False,
                    message=f"Validation error occurred. Failed to regenerate access token for {PLATFORM_NAME}.",
                )
            raise
        except Exception as error:
            if is_validation:
                return ValidationResult(
                    success=False,
                    message=f"Validation error occurred. Failed to regenerate access token for {PLATFORM_NAME}.",
                )
            err_msg = (
                f"Unexpected error occurred while"
                f"regenerating access token for {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(error),
            )
            raise HPECentralPluginException(err_msg)

    def _create_configuration_hash(self, configuration: Dict) -> str:
        """
        Creates a MD5 digest of configurations.

        Args:
            configuration (Dict): A dictionary containing configuration parameters.

        Returns:
            str: A string representation of MD5 hexdigest of configuration.
        """
        base_url, username, password, client_id, client_secret, customer_id = (
            self.hpe_central_helper.get_configuration_parameters(configuration)
        )

        config = {
            "base_url": base_url,
            "username": username,
            "password": password,
            "client_id": client_id,
            "client_secret": client_secret,
            "customer_id": customer_id,
        }
        return hashlib.md5(
            json.dumps(config, sort_keys=True).encode("utf-8")
        ).hexdigest()

    def _create_batch_of_100(
        self, blacklist_dict: Dict[str, List[str]]
    ) -> Generator[Tuple[str, List[str], int], None, None]:
        """
        Divides a list of mac addresses into batches of 100.

        Args:
            blacklist_dict (Dict[str, List[str]]): A dictionary containing
                swarm IDs as keys and list of MAC addresses as values.

        Yields:
            Tuple[str, List[str], int]: A tuple containing swarm ID, list of
                MAC addresses and batch number.
        """
        batch_size = ACTION_BATCH_SIZE
        batch_number = 0
        for key, value_list in blacklist_dict.items():
            batch_number += 1
            if len(value_list) < batch_size:
                yield key, value_list, batch_number
            else:
                for i in range(0, len(value_list), batch_size):
                    yield key, value_list[i: i + batch_size], batch_number

    def _retry_action(
        self,
        url,
        method,
        json_data,
        logger_msg,
    ) -> Literal["success", "unauthorized", "failed"]:
        # Retry action api call
        """
        Retry the action API call to Aruba Central.

        Args:
            url (str): The URL of the action API.
            method (str): The HTTP method of the action API.
            json_data (Dict): The JSON data to be sent in the request body.
            logger_msg (str): The message to be used in the log.

        Returns:
            Literal['success', 'unauthorized', 'failed']: The result of the action.
        """
        storage = self.storage if self.storage is not None else {}
        access_token = storage.get("access_token")
        try:
            self.hpe_central_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method=method,
                headers=self.hpe_central_helper.get_auth_headers(access_token),
                json=json_data,
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_handle_error_required=True,
                regenerate_auth_token=True,
                is_validation=False,
            )
            return SUCCESS
        except HPECentralUnauthorizedException:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unauthorized error occurred while {logger_msg}."
                )
            )
            return UNAUTHORIZED
        except HPECentralPluginException as err:
            self.logger.error(
                message=(f"{self.log_prefix}: Error occurred while {logger_msg}."),
                details=str(err),
            )
            return FAILED
        except Exception as error:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(error),
            )
            return FAILED

    def _blacklist_client_action(
        self, blacklist_dict: Dict[str, List[str]], action_name: str
    ):
        """
        Adds or removes clients from blacklist.

        Args:
            blacklist_dict (Dict[str, List[str]]): A dictionary containing
                swarm IDs as keys and list of MAC addresses as values.
            action_name (str): A string indicating the action to be performed.
                Supported actions are 'add' and 'remove'.

        Returns:
            Tuple[int, int]: A tuple containing the counts of successful and skipped actions.
        """
        storage = self.storage if self.storage is not None else {}
        access_token = storage.get("access_token")
        if action_name == "add":
            logger_msg_base = (
                "adding {number_of_clients} client(s) to blacklist -"
                " batch {batch_number} and Swarm ID - {swarm_id}"
            )
            http_method = "POST"
        elif action_name == "remove":
            logger_msg_base = (
                "removing {number_of_clients} client(s) from blacklist -"
                " batch {batch_number} and Swarm ID - {swarm_id}"
            )
            http_method = "DELETE"
        else:
            self.logger.error(
                f"{self.log_prefix}: Unsupported action '{action_name}' provided."
            )
            return 0, 0
        action_success_count = 0
        action_skip_count = 0

        for swarm_id, client_list, batch_number in self._create_batch_of_100(
            blacklist_dict
        ):
            logger_msg = logger_msg_base.format(
                number_of_clients=len(client_list),
                batch_number=batch_number,
                swarm_id=swarm_id,
            )
            url = BLACKLIST_API_URL.format(
                base_url=self.configuration.get("base_url").strip().strip("/"),
                swarm_id=swarm_id,
            )
            try:
                self.hpe_central_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method=http_method,
                    headers=self.hpe_central_helper.get_auth_headers(access_token),
                    json={"blacklist": client_list},
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    is_handle_error_required=True,
                    regenerate_auth_token=True,
                    is_validation=False,
                )
                action_success_count += len(client_list)
            except HPECentralUnauthorizedException:
                self._regenerate_access_token_and_update_storage(is_validation=False)
                retry_action_result = self._retry_action(
                    url=url,
                    method=http_method,
                    json_data={"blacklist": client_list},
                    logger_msg=logger_msg,
                    action_success_count=action_success_count,
                    action_skip_count=action_skip_count,
                )
                if retry_action_result == SUCCESS:
                    action_success_count += len(client_list)
                elif retry_action_result == UNAUTHORIZED:
                    break
                elif retry_action_result == FAILED:
                    action_skip_count += len(client_list)
            except HPECentralPluginException as err:
                self.logger.error(
                    message=(f"{self.log_prefix}: Error occurred while {logger_msg}."),
                    details=str(err),
                )
                action_skip_count += len(client_list)
                continue
            except Exception as error:
                err_msg = (
                    f"Unexpected error occurred while "
                    f"removing client(s) {client_list} from blacklist."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(error),
                )
                action_skip_count += len(client_list)
                continue

        return action_success_count, action_skip_count

    def _disconnect_client(
        self,
        client_mac: str,
        device_serial: str,
    ) -> bool:
        """
        Disconnect a client from a device.

        Args:
            client_mac (str): The MAC address of the client to be disconnected.
            device_serial (str): The serial number of the device from which the client
                will be disconnected.

        Returns:
            bool: True if the client is successfully disconnected, False otherwise.
        """
        storage = self.storage if self.storage is not None else {}
        access_token = storage.get("access_token")
        logger_msg = f"disconnecting client {client_mac} from device {device_serial}"
        url = DISCONNECT_CLIENT_API_URL.format(
            base_url=self.configuration.get("base_url").strip().strip("/"),
            device_serial=device_serial,
        )
        try:
            self.hpe_central_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                headers=self.hpe_central_helper.get_auth_headers(access_token),
                json={"disconnect_user_mac": client_mac},
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_handle_error_required=True,
                regenerate_auth_token=True,
                is_validation=False,
            )
            return True
        except HPECentralUnauthorizedException:
            self._regenerate_access_token_and_update_storage(is_validation=False)
            retry_action_result = self._retry_action(
                url=url,
                method="POST",
                json_data={"disconnect_user_mac": client_mac},
                logger_msg=logger_msg,
                action_success_count=0,
                action_skip_count=0,
            )
            return True if retry_action_result == SUCCESS else False
        except HPECentralPluginException as err:
            self.logger.error(
                message=(f"{self.log_prefix}: Error occurred while {logger_msg}."),
                details=str(err),
            )
            return False
        except Exception as error:
            err_msg = (
                f"Unexpected error occurred while "
                f"disconnecting client {client_mac} from device {device_serial}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(error),
            )
            return False

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="No action", value="generate"),
            ActionWithoutParams(label="Add client to blacklist", value="add"),
            ActionWithoutParams(label="Remove client from blacklist", value="remove"),
            ActionWithoutParams(
                label="Disconnect client from networking device", value="disconnect"
            ),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        if action.value == "generate":
            return []
        if action.value == "add":
            return [
                {
                    "label": "Client MAC Address",
                    "key": "client_mac_address",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "MAC address of Client to be added to blacklist.",
                },
                {
                    "label": "Swarm ID",
                    "key": "swarm_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Swarm ID/Device id of virtual controller or C2C"
                        " access point from where client will be"
                        "blacklisted (i.e. Blocked)."
                    ),
                },
            ]
        if action.value == "remove":
            return [
                {
                    "label": "Client MAC Address",
                    "key": "client_mac_address",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "MAC address of Client to be removed from blacklist.",
                },
                {
                    "label": "Swarm ID",
                    "key": "swarm_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Swarm ID/Device id of virtual controller or C2C"
                        " access point from where client will be"
                        "un-blacklisted (i.e. Unblocked)."
                    ),
                },
            ]
        if action.value == "disconnect":
            return [
                {
                    "label": "Client MAC Address",
                    "key": "client_mac_address",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "MAC address of client to be disconnected"
                        " from networking device."
                    ),
                },
                {
                    "label": "Device Serial",
                    "key": "device_serial",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Serial number of networking device from where client"
                        " is to be disconnected."
                    ),
                },
            ]
        return []

    def execute_actions(self, action: Action):
        """Execute action on the clients.

        Args:
            action (Action): Action that needs to be perform on clients.

        Returns:
            None
        """
        first_action = action[0]
        action_label = first_action.label
        action_value = first_action.value

        action_success_count = 0
        action_skip_count = 0

        if action_value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return
        if action_value in ["add", "remove"]:
            clients_dict = {}
            skipped_clients = []
            for action_item in action:
                swarm_id = action_item.parameters.get("swarm_id", "")
                if swarm_id:
                    swarm_id.strip()
                client_mac_address = action_item.parameters.get("client_mac_address")
                if swarm_id in clients_dict:
                    clients_dict[swarm_id].append(client_mac_address)
                else:
                    clients_dict[swarm_id] = [client_mac_address]
            skipped_clients.extend(clients_dict.pop(None, []))
            skipped_clients.extend(clients_dict.pop("", []))
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Action {action_label} will not be"
                    f" performed on {len(skipped_clients)} clients as they"
                    " do not have any Swarm ID/Device ID associated."
                ),
                details=f"Skipped Client MAC Address: {', '.join(skipped_clients)}",
            )
        if action_value == "add":
            action_success_count, action_skip_count = self._blacklist_client_action(
                clients_dict, "add"
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully added"
                f" {action_success_count} clients to blacklist"
                f". Skipped {action_skip_count} clients."
            )
        if action_value == "remove":
            action_success_count, action_skip_count = self._blacklist_client_action(
                clients_dict, "remove"
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully removed "
                f" {action_success_count} clients from blacklist"
                f". Skipped {action_skip_count} clients."
            )
        if action_value == "disconnect":
            raise NotImplementedError()

    def execute_action(self, action: Action):
        """Execute action on the clients.

        Args:
            action (Action): Action that needs to be perform on clients.

        Returns:
            None
        """
        action_label = action.label
        action_params = action.parameters
        swarm_id = action_params.get("swarm_id", "")
        if swarm_id:
            swarm_id = swarm_id.strip()
        client_mac_address = action_params.get("client_mac_address")
        action_success_count = 0

        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return
        if action.value == "add":
            if not swarm_id:
                self.logger.info(
                    (
                        f"{self.log_prefix}: Skipping action '{action_label}'"
                        f" for client {client_mac_address} because Swarm ID is empty."
                    )
                )
                return
            action_success_count, _ = self._blacklist_client_action(
                blacklist_dict={swarm_id: [client_mac_address]}, action_name="add"
            )
            if action_success_count:
                self.logger.info(
                    f"{self.log_prefix}: Successfully added client"
                    f" '{client_mac_address}' to blacklist."
                )
            else:
                err_msg = f"Failed to add client '{client_mac_address}' to blacklist."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise HPECentralPluginException(err_msg)
        if action.value == "remove":
            if not swarm_id:
                self.logger.info(
                    (
                        f"{self.log_prefix}: Skipping action '{action_label}'"
                        f" for client {client_mac_address} because Swarm ID is empty."
                    )
                )
                return
            action_success_count, _ = self._blacklist_client_action(
                blacklist_dict={swarm_id: [client_mac_address]}, action_name="remove"
            )
            if action_success_count:
                self.logger.info(
                    f"{self.log_prefix}: Successfully removed client"
                    f" '{client_mac_address}' from blacklist."
                )
            else:
                err_msg = (
                    f"Failed to remove client '{client_mac_address}'" " from blacklist."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}.")
                raise HPECentralPluginException(err_msg)
        if action.value == "disconnect":
            device_serial = action_params.get("device_serial")
            success = self._disconnect_client(
                client_mac=client_mac_address, device_serial=device_serial
            )
            if success:
                self.logger.info(
                    f"{self.log_prefix}: Successfully disconnected"
                    f" client '{client_mac_address}' from device"
                    f" '{device_serial}'."
                )
            else:
                err_msg = (
                    f"Failed to disconnect client '{client_mac_address}'"
                    f"from device '{device_serial}'."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise HPECentralPluginException(err_msg)

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate HPE Central action configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_value = action.value
        if action_value == "generate":
            log_msg = (
                f"Successfully validated action configuration for '{action.label}'."
            )
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(success=True, message=log_msg)
        if action_value not in ["add", "remove", "disconnect"]:
            self.logger.error(
                f'{self.log_prefix}: Unsupported action "{action.label}" '
                "provided in the action configuration. Supported Actions are - "
                " 'Add client to blacklist', 'Remove client from blacklist',"
                " 'Disconnect client from networking device'."
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        client_mac_address = action.parameters.get("client_mac_address")
        if not client_mac_address:
            err_msg = "Client MAC address is a required action parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(client_mac_address, str):
            err_msg = "Invalid Client MAC address provided in the action parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if action_value in ["add", "remove"]:
            swarm_id = action.parameters.get("swarm_id", "").strip()

            if not swarm_id:
                err_msg = "Swarm ID is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            if not isinstance(swarm_id, str):
                err_msg = "Invalid Swarm ID provided in the action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        if action_value == "disconnect":
            device_serial = action.parameters.get("device_serial")
            client_mac_address = action.parameters.get("client_mac_address")
            if not device_serial:
                err_msg = (
                    f"Device Serial is a required action parameter for {action.label}"
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            if not isinstance(device_serial, str):
                err_msg = "Invalid Device serial provided in the action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        self.logger.debug(
            f"{self.log_prefix}: Successfully validated "
            f"action configuration for '{action.label}'."
        )
        return ValidationResult(success=True, message="Validation successful.")

    def _extract_field_from_event(
        self, key: str, event: dict, default, transformation=None
    ):
        """Extract field from event.

        Args:
            key (str): Key to fetch.
            event (dict): Event dictionary.
            default (str,None): Default value to set.
            transformation (str, None, optional): Transformation
                to perform on key. Defaults to None.

        Returns:
            Any: Value of the key from event.
        """
        keys = key.split(".")
        while keys:
            k = keys.pop(0)
            if k not in event and default is not None:
                return default
            event = event.get(k, {})
        if transformation and transformation == "string":
            return str(event)
        return event

    def add_field(self, fields_dict: dict, field_name: str, value):
        """Add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        if isinstance(value, int) or isinstance(value, float):
            fields_dict[field_name] = value
            return
        if value:
            if value == "--":
                value = None
            fields_dict[field_name] = value

    def _extract_entity_fields(self, event: dict, entity_name: str) -> dict:
        """Extract entity fields from event payload.

        Args:
            event (dict): Event Payload.
            entity_name (str): Entity name.

        Returns:
            dict: Dictionary containing required fields.
        """
        entity_field_mapping = {
            "Wired": WIRED_CLIENT_FIELD_MAPPING,
            "Wireless": WIRELESS_CLIENT_FIELD_MAPPING,
        }
        extracted_fields = {}
        for field_name, field_value in entity_field_mapping[entity_name].items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(key, event, default, transformation),
            )
        return extracted_fields

    def _fetch_wired_clients(self) -> List[Dict]:
        """
        Fetches the list of Wired clients from HPE Central.

        Args:
            None

        Returns:
            List[Dict]: A list of dictionaries containing the Wired clients information.
        """
        offset = 0
        base_url = self.configuration.get("base_url").strip().strip("/")
        total_wired_clients = 0
        page_number = 1

        wired_clients_list = []
        while True:
            try:
                storage = self.storage if self.storage is not None else {}
                access_token = storage.get("access_token")
                logger_msg = (
                    f"wired clients for page {page_number} from {PLATFORM_NAME}"
                )
                self.logger.debug(f"{self.log_prefix}: Fetching {logger_msg}.")
                response, _ = self.hpe_central_helper.api_helper(
                    logger_msg="fetching " + logger_msg,
                    url=WIRED_CLIENTS_API_URL.format(base_url=base_url),
                    method="GET",
                    headers=self.hpe_central_helper.get_auth_headers(access_token),
                    params={"offset": offset, "limit": PAGE_SIZE},
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_auth_token=True,
                )
                if not response.get("clients"):
                    break
                page_wired_clients_count = 0
                page_wired_clients_skip_count = 0
                for wired_client in response.get("clients", []):
                    extracted_data = self._extract_entity_fields(
                        wired_client, entity_name="Wired"
                    )
                    if extracted_data:
                        wired_clients_list.append(extracted_data)
                        page_wired_clients_count += 1
                    else:
                        page_wired_clients_skip_count += 1
                total_wired_clients += page_wired_clients_count
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_wired_clients_count} wired client record(s),"
                    f" Skipped {page_wired_clients_skip_count} wired"
                    f" client record(s) for page {page_number}. "
                    f"Total wired clients fetched: {total_wired_clients}."
                )
                if response.get("count") < PAGE_SIZE:
                    break
                offset += PAGE_SIZE
                page_number += 1
            except HPECentralUnauthorizedException:
                self._regenerate_access_token_and_update_storage(is_validation=False)
                continue
            except HPECentralPluginException:
                raise
            except Exception as error:
                error_message = (
                    "Error occurred"
                    if isinstance(error, ValidationError)
                    else "Unexpected error occurred"
                )
                error_message += f" while fetching {logger_msg}."
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_message} " f"Error: {error}"),
                    details=str(traceback.format_exc()),
                )
                raise HPECentralPluginException(error_message)
        return wired_clients_list

    def _fetch_wireless_clients(self) -> List[Dict]:
        """
        Fetch list of wireless clients.

        Args:
            None

        Returns:
            List of dictionaries containing wireless clients information.
        """
        offset = 0
        base_url = self.configuration.get("base_url", "").strip().strip("/")
        total_wireless_clients = 0
        page_number = 1

        wireless_clients_list = []
        while True:
            try:
                storage = self.storage if self.storage is not None else {}
                access_token = storage.get("access_token")
                logger_msg = (
                    f"wireless clients for page {page_number} from {PLATFORM_NAME}"
                )
                self.logger.debug(f"{self.log_prefix}: Fetching {logger_msg}.")
                response, _ = self.hpe_central_helper.api_helper(
                    logger_msg="fetching " + logger_msg,
                    url=WIRELESS_CLIENTS_API_URL.format(base_url=base_url),
                    method="GET",
                    headers=self.hpe_central_helper.get_auth_headers(access_token),
                    params={"offset": offset, "limit": PAGE_SIZE},
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_auth_token=True,
                )
                if not response.get("clients"):
                    break
                page_wireless_clients_count = 0
                page_wireless_clients_skip_count = 0
                for wireless_clients in response.get("clients", []):
                    extracted_data = self._extract_entity_fields(
                        wireless_clients, entity_name="Wireless"
                    )
                    if extracted_data:
                        wireless_clients_list.append(extracted_data)
                        page_wireless_clients_count += 1
                    else:
                        page_wireless_clients_skip_count += 1
                total_wireless_clients += page_wireless_clients_count
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_wireless_clients_count} wireless client record(s),"
                    f" Skipped {page_wireless_clients_skip_count} wireless"
                    f" client record(s) for page {page_number}."
                    f" Total wireless clients fetched: "
                    f"{total_wireless_clients}."
                )
                if response.get("count") < PAGE_SIZE:
                    break
                offset += PAGE_SIZE
                page_number += 1
            except HPECentralUnauthorizedException:
                self._regenerate_access_token_and_update_storage(is_validation=False)
                continue
            except HPECentralPluginException:
                raise
            except Exception as error:
                error_message = (
                    "Error occurred"
                    if isinstance(error, ValidationError)
                    else "Unexpected error occurred"
                )
                error_message += f" while fetching {logger_msg}."
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_message} " f"Error: {error}"),
                    details=str(traceback.format_exc()),
                )
                raise HPECentralPluginException(error_message)
        return wireless_clients_list

    def fetch_records(self, entity: str) -> List:
        """Fetch records from HPE Central.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        storage = self.storage if self.storage is not None else {}
        if not storage:
            base_url, username, password, client_id, client_secret, customer_id = (
                self.hpe_central_helper.get_configuration_parameters(self.configuration)
            )
            access_token, refresh_token, expires_at = (
                self.hpe_central_helper.generate_access_token(
                    base_url=base_url,
                    username=username,
                    password=password,
                    client_id=client_id,
                    client_secret=client_secret,
                    customer_id=customer_id,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=(
                        f"Generating access token for {PLATFORM_NAME} platform."
                    ),
                    is_validation=False,
                )
            )
            storage.update(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_at": expires_at,
                    "config_hash": self._create_configuration_hash(self.configuration),
                }
            )
        else:
            config_hash = storage.get("config_hash")
            current_config_hash = self._create_configuration_hash(self.configuration)
            if config_hash != current_config_hash:
                base_url, username, password, client_id, client_secret, customer_id = (
                    self.hpe_central_helper.get_configuration_parameters(
                        self.configuration
                    )
                )
                access_token, refresh_token, expires_at = (
                    self.hpe_central_helper.generate_access_token(
                        base_url=base_url,
                        username=username,
                        password=password,
                        client_id=client_id,
                        client_secret=client_secret,
                        customer_id=customer_id,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        logger_msg=(
                            f"Generating access token for {PLATFORM_NAME} platform."
                        ),
                        is_validation=False,
                    )
                )
                storage.update(
                    {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "expires_at": expires_at,
                        "config_hash": current_config_hash,
                    }
                )
            else:
                access_token = storage.get("access_token")
                refresh_token = storage.get("refresh_token")
                expires_at = storage.get("expires_at")

        records = []
        entity_name = entity.lower()
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )
        fetch_client_types = self.configuration.get("client_types", [])
        try:
            if entity == "Wired Clients" and "wired" in fetch_client_types:
                records.extend(self._fetch_wired_clients())
            elif entity == "Wireless Clients" and "wireless" in fetch_client_types:
                records.extend(self._fetch_wireless_clients())
            else:
                err_msg = (
                    f"Invalid entity found. {PLATFORM_NAME} plugin "
                    "only supports 'Wired Clients' and 'Wireless Clients' Entity."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise HPECentralPluginException(err_msg)
            return records
        except HPECentralPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while fetching client "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise HPECentralPluginException(err_msg)

    def update_records(self, entity: str, records: list[dict]) -> list:
        if entity == "Wired Clients" or entity == "Wireless Clients":
            return []
        else:
            raise HPECentralPluginException("Unsupported entity found.")

    def _check_configuration_field_empty_and_type(
        self, field_name: str, field_value: str, field_type: type
    ):
        """
        Checks if the given configuration field is not empty and is of the given type.

        Args:
            field_name (str): The name of the configuration field.
            field_value (str): The value of the configuration field.
            field_type (type): The expected type of the configuration field.

        Returns:
            ValidationResult: ValidationResult object indicating whether the validation
            was successful or not.
        """
        if isinstance(field_value, str):
            field_value = field_value.strip()
        validation_err_msg = "Validation error occurred."
        empty_err_msg = f"{field_name} is a required configuration parameter."
        type_err_msg = (
            f"Invalid value provided for the configuration parameter '{field_name}'"
        )
        if not field_value:
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {empty_err_msg}"
            )
            return ValidationResult(success=False, message=empty_err_msg)
        if not isinstance(field_value, field_type):
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {type_err_msg}",
                details=(
                    f"Configuration parameter {field_name} should be of type"
                    f"{field_type.__name__}"
                ),
            )
            return ValidationResult(success=False, message=type_err_msg)

    def _validate_connectivity(
        self,
        base_url: str,
        username: str,
        password: str,
        client_id: str,
        client_secret: str,
        customer_id: str,
    ) -> ValidationResult:
        """
        Validates the connectivity with the HPE Central server.

        Args:
            base_url (str): The base URL of the HPE Central API.
            username (str): The username for authentication.
            password (str): The password for authentication.
            client_id (str): The client ID for authentication.
            client_secret (str): The client secret for authentication.
            customer_id (str): The customer ID for authentication.

        Returns:
            Union[ValidationResult, None]: ValidationResult object with success flag and message.
        """
        try:
            access_token, _, _ = self.hpe_central_helper.generate_access_token(
                base_url=base_url,
                username=username,
                password=password,
                client_id=client_id,
                client_secret=client_secret,
                customer_id=customer_id,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(f"Generating access token for {PLATFORM_NAME} server."),
                is_validation=True,
            )
            headers = self.hpe_central_helper.get_auth_headers(
                access_token=access_token
            )
            self.hpe_central_helper.api_helper(
                logger_msg=f"validating connectivity with {PLATFORM_NAME} server",
                url=WIRELESS_CLIENTS_API_URL.format(base_url=base_url),
                method="GET",
                headers=headers,
                params={"limit": 1, "offset": 0},
                is_handle_error_required=True,
                is_validation=True,
                regenerate_auth_token=True,
            )
            success_msg = (
                "Successfully validated "
                f"connectivity with {PLATFORM_NAME} server "
                "and plugin configuration parameters."
            )
            self.logger.debug(f"{self.log_prefix}: {success_msg}")
            return ValidationResult(
                success=True,
                message=success_msg,
            )
        except HPECentralPluginException as error:
            return ValidationResult(success=False, message=str(error))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the Plugin configuration parameters."""
        base_url, username, password, client_id, client_secret, customer_id = (
            self.hpe_central_helper.get_configuration_parameters(configuration)
        )

        # BASE URL
        if validation_result := self._check_configuration_field_empty_and_type(
            "Base URL", base_url, str
        ):
            return validation_result

        # USERNAME
        if validation_result := self._check_configuration_field_empty_and_type(
            "Username", username, str
        ):
            return validation_result

        # PASSWORD
        if validation_result := self._check_configuration_field_empty_and_type(
            "Password", password, str
        ):
            return validation_result

        # CLIENT ID
        if validation_result := self._check_configuration_field_empty_and_type(
            "Client ID", client_id, str
        ):
            return validation_result

        # CLIENT SECRET
        if validation_result := self._check_configuration_field_empty_and_type(
            "Client Secret", client_secret, str
        ):
            return validation_result

        # CUSTOMER ID
        if validation_result := self._check_configuration_field_empty_and_type(
            "Customer ID", customer_id, str
        ):
            return validation_result

        # Validate client type
        fetch_client_type = configuration.get("client_types", [])
        if validation_result := self._check_configuration_field_empty_and_type(
            "Client Type", fetch_client_type, list
        ):
            return validation_result

        for client_type in fetch_client_type:
            if client_type not in ["wired", "wireless"]:
                err_msg = (
                    f"Invalid client type {client_type} provided."
                    "Valid client types are 'wired' and 'wireless'."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

        # Validate connectivity
        validate_connectivity_result = self._validate_connectivity(
            base_url=base_url,
            username=username,
            password=password,
            client_id=client_id,
            client_secret=client_secret,
            customer_id=customer_id,
        )
        if not validate_connectivity_result.success:
            return validate_connectivity_result

        return ValidationResult(success=True, message="Validation successful.")

    def get_entities(self) -> List[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Wired Clients",
                fields=[
                    EntityField(
                        name="MAC Address",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(name="Client Type", type=EntityFieldType.STRING),
                    EntityField(name="IPv4", type=EntityFieldType.STRING),
                    EntityField(name="Username", type=EntityFieldType.STRING),
                    EntityField(name="VLAN", type=EntityFieldType.STRING),
                    EntityField(
                        name="Associated Device MAC Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Associated Device Serial Number",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(name="Hostname", type=EntityFieldType.STRING),
                    EntityField(name="Name", type=EntityFieldType.STRING),
                    EntityField(name="Group Name", type=EntityFieldType.STRING),
                    EntityField(name="Swarm ID", type=EntityFieldType.STRING),
                ],
            ),
            Entity(
                name="Wireless Clients",
                fields=[
                    EntityField(
                        name="MAC Address",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(name="Client Type", type=EntityFieldType.STRING),
                    EntityField(name="IPv4", type=EntityFieldType.STRING),
                    EntityField(name="Username", type=EntityFieldType.STRING),
                    EntityField(name="VLAN", type=EntityFieldType.STRING),
                    EntityField(
                        name="Associated Device MAC Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Associated Device Serial Number",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Authentication Type", type=EntityFieldType.STRING
                    ),
                    EntityField(name="Encryption Method", type=EntityFieldType.STRING),
                    EntityField(name="Hostname", type=EntityFieldType.STRING),
                    EntityField(name="Name", type=EntityFieldType.STRING),
                    EntityField(
                        name="Connection Standard", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Operating System Type", type=EntityFieldType.STRING
                    ),
                    EntityField(name="Group Name", type=EntityFieldType.STRING),
                    EntityField(name="Swarm ID", type=EntityFieldType.STRING),
                ],
            ),
        ]
