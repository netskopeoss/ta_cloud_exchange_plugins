"""Netskope EDM Forwarder/Receiver Plugin."""
import json
import os
import traceback
import zipfile
from io import BytesIO
from typing import List

import requests

from netskope.integrations.edm.models import Action, ActionWithoutParams
from netskope.integrations.edm.plugin_base import PluginBase, ValidationResult, PushResult
from netskope.integrations.edm.utils.exceptions import (
    CustomException as NetskopeCEError,
)

from .utils.constants import NETSKOPE_CE_AUTH_TYPE_FIELDS

ERROR_MSG = (
    "Plugin: Netskope EDM Forwarder/Receiver - "
    + "Couldn't establish a connection to Netskope CE machine with the given parameters"
)
UPLOAD_ENDPOINT = "/api/edm/nce_upload/"
AUTH_ENDPOINT = "/api/auth"
EDM_CONFIGURATIONS_ENDPOINT = "/api/edm/plugins/configurations"
MODULE_NAME = "EDM"
PLUGIN_NAME = "Netskope EDM Forwarder/Receiver"
PLUGIN_VERSION = "1.0.0"


class NetskopeCE(PluginBase):
    """Netskope EDM Forwarder/Receiver plugin is used to push data to other Netskope CE machine."""

    def __init__(
        self,
        name,
        configuration,
        storage,
        last_run_at,
        logger,
        use_proxy=False,
        ssl_validation=True,
        plugin_type=None,
    ):
        """Init method."""
        super().__init__(
            name,
            configuration,
            storage,
            last_run_at,
            logger,
            use_proxy,
            ssl_validation,
            plugin_type=plugin_type,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.auth_methods = {
            "basic_auth": self._basic_auth,
            "secret_token_auth": self._secret_token_auth,
            "sso_auth": self._sso_auth,
        }

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = NetskopeCE.metadata
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

    @staticmethod
    def strip_args(data):
        """Strip arguments from left and right directions.

        Args:
            data (dict): Dict object having all the
            Plugin configuration parameters.
        """
        keys = data.keys()
        for key in keys:
            if isinstance(data[key], str):
                data[key] = data[key].strip()

    def _validate_configured_plugin(self, url, token, destination_config):
        """Validate configured destination plugin.

        Args:
            url (str): url provided by user
            token (str): user login token
            destination_config (str): name of destination configuration

        Returns:
            bool: true if destination configuration is valid and false otherwise.
        """
        headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        plugin_response = requests.get(
            url=url + EDM_CONFIGURATIONS_ENDPOINT,
            headers=headers,
            timeout=30,
            proxies=self.proxy,
            verify=self.ssl_validation,
        )

        configured_plugins = plugin_response.json()

        for plugin in configured_plugins:
            if (
                plugin.get("name") == destination_config
                and "netskope_edm_forwarder_receiver.main" in plugin.get("plugin", "")
                and plugin.get("pluginType", "") == "receiver"
                and plugin.get("active", False) is True
            ):
                return True
        return False

    def _basic_auth(self, user_config, url):
        """User authentication using basic auth method.

        Args:
            user_config (dict): dict containing user login parameters.
            url (str): url provided by user.

        Returns:
            requests.Response: response from api call
        """
        data = {
            "username": user_config.get("username", ""),
            "password": user_config.get("password", ""),
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        }
        auth_response = requests.post(
            url + AUTH_ENDPOINT,
            headers=headers,
            data=data,
            timeout=30,
            proxies=self.proxy,
            verify=self.ssl_validation,
        )

        return auth_response

    def _secret_token_auth(self, user_config, url):
        """Secret token auth with username and password.

        Args:
            user_config (dict): dict containing user login parameters.
            url (str): url provided by user.

        Returns:
            requests.Response: response from api call
        """
        data = {
            "grant_type": "client_credentials",
            "username": "",
            "password": "",
            "client_id": {user_config.get("client_id", "")},
            "client_secret": {user_config.get("client_secret", "")},
            "scope": "",
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        }

        auth_response = requests.post(
            url + AUTH_ENDPOINT,
            headers=headers,
            data=data,
            timeout=30,
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        return auth_response

    def _sso_auth(self):
        raise NotImplementedError

    def _validate_user_auth(self, auth_method, user_config, url):
        """Validate user with a auth method provided by user.

        Args:
            auth_method (str): auth_method selected by user.
            user_config (dict): dict containing user login parameters.
            url (str): url provided by user.

        Returns:
            json: response of auth api.
        """
        if auth_method in self.auth_methods:
            auth_response = self.auth_methods[auth_method](user_config, url)
        return auth_response.json()

    def _create_zip_obj(self, folder_path) -> BytesIO:
        """Create a zip obj from directory.

        Args:
            folder_path (str): path to folder of which zip to create.

        Returns:
            BytesIO: zip file object
        """
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_ref:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, folder_path)
                    zip_ref.write(file_path, arcname=arcname)
        return zip_buffer

    def _request_upload_endpoint(
        self,
        url,
        token,
        files,
        source_config_name,
        destination_config,
        ce_identifier="",
    ) -> requests.Response:
        """Make a request on upload endpoint.

        Args:
            url (str): url provided by user.
            token (str): user auth token
            files (file object): file object for upload
            destination_config (str): destination configuration name
            ce_identifier (str, optional): uuid provided from storage. Defaults to "".

        Returns:
            requests.Response: response provided by user.
        """
        headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        files = {"file": files}

        file_name = self.storage.get(source_config_name, {}).get("file_name", "")
        edm_hashes_cfg = os.path.basename(
            self.storage.get(source_config_name, {})["edm_hashes_cfg"]
        )
        params = {
            "destination": destination_config,
            "ce_identifier": ce_identifier,
            "file_name": file_name,
            "edm_hashes_cfg": edm_hashes_cfg,
        }

        upload_response = requests.post(
            url + UPLOAD_ENDPOINT,
            headers=headers,
            files=files,
            params=params,
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        return upload_response

    def pull(self):
        """Store Forwarder's Info in Storage."""
        raise NotImplementedError()

    def push(self, source_config_name="", action_dict={}):
        """Push Hash data to configured netskope CE machine."""
        try:
            self.logger.info(
                message=f"{self.log_prefix}"
                f" Executing push method for configuration '{self._name}'."
            )

            config = self.configuration.get("configuration", {})

            url = config.get("netskope_ce_host", "")
            url = url.strip("/")

            ce_identifier = self.storage.get(source_config_name, {}).get(
                "ce_identifier", ""
            )
            destination_config = config.get("destination_config", "")
            auth_method = self.configuration.get("authentication_type").get(
                "auth_method", ""
            )

            edm_hash_folder = (self.storage.get(source_config_name, {}) or {}).get("edm_hash_folder")
            if not edm_hash_folder or not os.path.exists(edm_hash_folder):
                self.logger.error(
                    f"{self.log_prefix} Skipping EDM hashes upload. "
                    "It might be cleaned up as per scheduled time or not generated yet "
                    f"for configuration Source: {source_config_name} and Destination: {self.name}."
                )
                raise NetskopeCEError(
                    message="Plugin: Netskope EDM Forwarder/Receiver - Skipping EDM hashes upload. "
                    "It might be cleaned up as per scheduled time or not generated yet "
                    f"for configuration Source: {source_config_name} and Destination: {self.name}."
                )

            validate_user_response = self._validate_user_auth(auth_method, config, url)

            token = validate_user_response.get("access_token", None)

            if "edm_write" not in validate_user_response.get("scopes", []) or not token:
                if not token:
                    self.logger.error(
                        message=f"{self.log_prefix}"
                        f"Error occurred while authenticating user for configuration {self.name} -"
                        " Invalid credentials provided."
                    )
                    self.notifier.error(
                        "Plugin: Netskope EDM Forwarder/Receiver - "
                        f"An unexpected error occurred for configuration '{self._name}' "
                        " Invalid credentials provided.",
                    )
                    raise NetskopeCEError(
                        message="Plugin: Netskope EDM Forwarder/Receiver -"
                        f"Error occurred while authenticating user for configuration {self.name} -"
                        " Invalid credentials provided.",
                    )

                if "edm_write" not in validate_user_response.get("scopes", []):
                    self.logger.error(
                        message=f"{self.log_prefix}"
                        f"Error occurred while authenticating user for configuration {self.name} -"
                        " Provided user doesn't have enough permission."
                    )
                    self.notifier.error(
                        "Plugin: Netskope EDM Forwarder/Receiver - "
                        f"An unexpected error occurred for configuration '{self._name}' "
                        " Provided user doesn't have enough permission."
                    )
                    raise NetskopeCEError(
                        message=f"Plugin: Netskope EDM Forwarder/Receiver -"
                        f"Error occurred while authenticating user for configuration {self.name} -"
                        " Provided user doesn't have enough permission.",
                    )

            zip_buffer_obj = self._create_zip_obj(edm_hash_folder)

            upload_response = self._request_upload_endpoint(
                url=url,
                token=token,
                files=zip_buffer_obj.getvalue(),
                ce_identifier=ce_identifier,
                source_config_name=source_config_name,
                destination_config=destination_config,
            )

            if upload_response.status_code != 200:
                self.storage[source_config_name]["status"] = False
                message = ""

                try:
                    message = json.loads(upload_response.json())
                    message = message["message"]
                except Exception:
                    message = upload_response.content

                self.storage[source_config_name]["reason"] = message
                self.storage[source_config_name][
                    "status_code"
                ] = upload_response.status_code
                self.notifier.error(
                    "Plugin: Netskope EDM Forwarder/Receiver - "
                    f"An unexpected error occurred for configuration '{self._name}' "
                    f"while running push method.",
                )
                self.logger.error(
                    f"{self.log_prefix} "
                    f"Error occurred while sharing edm hashes for configuration {self.name} "
                    f"Error : {message}"
                )
                return PushResult(
                    success=False,
                    message=message,
                )

            ce_identifier = upload_response.json().get("ce_identifier", "")
            self.storage[source_config_name]["status"] = True
            self.storage[source_config_name][
                "message"
            ] = "EDM hashes pushed successfully"
            self.storage[source_config_name]["reason"] = ""
            self.storage[source_config_name][
                "status_code"
            ] = upload_response.status_code
            self.storage[source_config_name]["ce_identifier"] = ce_identifier

            self.logger.info(
                message=f"{self.log_prefix}"
                f" Executed push method for configuration '{self._name}' successfully."
            )
            return PushResult(
                success=True,
                message="EDM hashes pushed successfully",
            )
        except Exception as error:
            self.notifier.error(
                "Plugin: Netskope EDM Forwarder/Receiver - "
                f"An unexpected error occurred for configuration '{self._name}' "
                f"while running push method.",
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix} "
                    + f"Error occurred while running push method for configuration {self.name}."
                ),
                details=traceback.format_exc(),
            )
            raise NetskopeCEError(
                value=error,
                message=f"Error occurred while running push method for configuration {self.name}.",
            ) from error

    def validate(self, configuration):
        """
        Validate the plugin configuration parameters.

        Args:

            configuration (dict): Dictionary containing
            the plugin configuration parameters.

        Returns:
            ValidationResult: ValidationResult
            object with success flag and message.
        """
        try:
            if not self.plugin_type:
                self.logger.error(
                    message=f"{self.log_prefix}"
                    "Error occurred while executing validate method -"
                    " Plugin type is not provided."
                )
                return ValidationResult(
                    success=False,
                    message="Plugin type is not provided.",
                )
            if self.plugin_type == "forwarder":
                self.logger.info(
                    message=f"{self.log_prefix} "
                    "Executing validate method for Netskope EDM Forwarder/Receiver plugin."
                )
                config = configuration.get("configuration", {})
                url = config.get("netskope_ce_host", "")
                url = url.strip("/")

                auth_method = configuration.get("authentication_type").get(
                    "auth_method"
                )
                validate_user_response = self._validate_user_auth(
                    auth_method, config, url
                )
                token = validate_user_response.get("access_token", None)

                if (
                    "edm_write" not in validate_user_response.get("scopes", [])
                    or not token
                ):
                    if not token:
                        self.logger.error(
                            message=f"{self.log_prefix}"
                            "Error occurred while executing validate method -"
                            " Invalid credentials provided."
                        )
                        return ValidationResult(
                            success=False,
                            message="Invalid credentials provided.",
                        )

                    if "edm_write" not in validate_user_response.get("scopes", []):
                        self.logger.error(
                            message=f"{self.log_prefix}"
                            "Error occurred while executing validate method -"
                            " Provided user doesn't have enough permission."
                        )
                        return ValidationResult(
                            success=False,
                            message="Provided user doesn't have enough permission.",
                        )

                configured_validation_result = self._validate_configured_plugin(
                    url, token, config.get("destination_config")
                )

                if not configured_validation_result:
                    self.logger.error(
                        message=f"{self.log_prefix}"
                        "Error occurred while executing validate method -"
                        " Provided destination plugin is not a valid Netskope EDM Forwarder/Receiver receiver plugin."
                    )
                    return ValidationResult(
                        success=False,
                        message="Provided destination plugin is not a valid"
                        " Netskope EDM Forwarder/Receiver receiver plugin.",
                    )

                self.logger.info(
                    message=f"{self.log_prefix}"
                    " Executed validate method for Netskope EDM Forwarder/Receiver plugin successfully."
                )

            return ValidationResult(success=True, message="Validation Successful")

        except Exception:
            self.logger.error(message=ERROR_MSG, details=traceback.format_exc())
            return ValidationResult(success=False, message=ERROR_MSG)

    def validate_step(self, step: dict):
        """Validate a step in the plugin configuration.

        Args:
            step (dict): The step to validate.

        Returns:
            ValidationResult: The result of the validation.
        """
        result = ValidationResult(
            success=False,
            message="Step validation failed.",
        )
        if step == "authentication_type":
            result = ValidationResult(
                success=True,
                message="Step validation successful.",
            )
        elif step == "configuration":
            result = self.validate(self.configuration)
        return result

    def get_fields(self, name: str, configuration: dict):
        """Get fields configuration based on the specified authentication method.

        Args:
            name (str): The name of the field configuration to retrieve
            configuration (dict): Configuration parameters dictionary.

        Raises:
            ValueError: If the specified authentication method in the configuration is not supported.
            NotImplementedError: If a field configuration with the specified name
                is not implemented.

        Returns:
            str: List of configuration parameters.
        """
        if name == "configuration":
            protocol_configuration = configuration.get("authentication_type", {})

            if "auth_method" in protocol_configuration and protocol_configuration[
                "auth_method"
            ] in NETSKOPE_CE_AUTH_TYPE_FIELDS[name]:
                return NETSKOPE_CE_AUTH_TYPE_FIELDS[name][
                    protocol_configuration["auth_method"]
                ]
            else:
                raise ValueError(
                    "Authentication Method is required field & It should be either 'basic_auth','sso_auth' or 'secret_token_auth'"
                )
        else:
            raise NotImplementedError()

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get list of supported actions.

        Raises:
            NotImplementedError: If the method is not implemented.
        Returns:
            List[Action]: List of actions.
        """
        return [
            ActionWithoutParams(label="Share EDM Hashes", value="share_edm_hash"),
        ]

    def get_action_fields(self, action: Action) -> List:
        """Get list of fields to be rendered in UI.

        Raises:
            NotImplementedError: If the method is not implemented.
        Returns:
            List: List of fields to be rendered.
        """
        return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate action parameters.

        Args:
            action (Action): Action object.
        Returns:
            ValidationResult: Validation result object.
        """
        if action.value not in ["share_edm_hash"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        return ValidationResult(success=True, message="Validation successful.")
