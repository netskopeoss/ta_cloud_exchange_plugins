"""Netskope EDM Plugin."""
from copy import deepcopy
import os
import traceback
from typing import List

from netskope.common.utils.plugin_provider_helper import PluginProviderHelper
from netskope.common.utils import (
    AlertsHelper,
    resolve_secret,
)
from netskope.integrations.edm.models import ActionWithoutParams, Action
from netskope.integrations.edm.plugin_base import PluginBase, ValidationResult, PushResult
from netskope.integrations.edm.utils.exceptions import (
    CustomException as NetskopeEDMError
)
from netskope.integrations.edm.utils.edm.edm_uploader import (
    EDM_UPLOADER_CONFIG_TEMPLATE,
)
from netskope.integrations.edm.utils.edm.edm_uploader import EDMHashUploader

PLUGIN_NAME = "Netskope Exact Data Match"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "EDM"
plugin_provider_helper = PluginProviderHelper()


class NetskopeEDMPlugin(PluginBase):
    """Netskope EDM plugin class with methods required to push generated hashes on Netskope Tenant."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Netskope EDM plugin initializer.

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

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = NetskopeEDMPlugin.metadata
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

    def push(self, source_config_name="", action_dict={}):
        """Push the edm hashes to netskope tenant."""
        self.logger.info(
            f"{self.log_prefix} Executing plugin push method for configuration {self.name}."
        )
        helper = AlertsHelper()
        try:
            work_dir = self.storage.get(source_config_name, {}).get("edm_hash_folder", "")
            hash_upload_cfg = self.storage.get(source_config_name, {}).get("edm_hashes_cfg", "")
            source_name = source_config_name
            dest_name = self.name
            self.tenant = helper.get_tenant_edm(self.name)
            token = resolve_secret(self.tenant.parameters["v2token"])
            tenant_name = (
                self.tenant.parameters["tenantName"]
                .strip()
                .removeprefix("https://")
            )

            config = self.configuration.get("configuration", {})
            self.strip_args(config)

            edm_config = deepcopy(EDM_UPLOADER_CONFIG_TEMPLATE)
            edm_config.update(
                {
                    "hash_dir": work_dir,
                    "work_dir": work_dir,
                    "hash_upload_cfg": hash_upload_cfg,
                    "token": token,
                    "port": 0,
                    "servername": tenant_name,
                    "hostname": "netskope-ce-user",
                    "source_name": source_name,
                    "dest_name": dest_name
                }
            )

            edm_dir = self.storage.get(source_config_name, {}).get("edm_hash_folder", "")
            upload_status_dir = os.path.dirname(edm_dir)
            if not edm_dir or not os.path.exists(edm_dir):
                self.logger.error(
                    f"{self.log_prefix} - Skipping EDM hashes upload. "
                    "It might be cleaned up as per scheduled time or not generated yet "
                    f"for configuration Source: {source_name} and Destination: {dest_name}."
                )
                raise NetskopeEDMError(
                    message="Plugin: Netskope EDM - Skipping EDM hashes upload. "
                    "It might be cleaned up as per scheduled time or not generated yet "
                    f"for configuration Source: {source_name} and Destination: {dest_name}."
                )
            upload_status_file = f"{upload_status_dir}/edm_upload_status.log"
            edm_upload = EDMHashUploader(edm_config, upload_status_file)

            upload_status, msg, context = edm_upload.execute(config=edm_config, status_file=upload_status_file)
            file_id = context.get("file_id")
            upload_id = context.get("upload_id")
            apply_status = context.get("apply_status", False)
            apply_message = context.get("apply_message")

            if upload_status is True:
                self.storage[source_config_name]["status"] = True
                # upload hashes on netskope tenant
                self.logger.info(
                    f"{self.log_prefix} Successfully Executed plugin push "
                    f"method for configuration {self.name}."
                )
            else:
                self.logger.error(
                    f"{self.log_prefix} Error occurred while uploading "
                    f"edm hashes of configuration {source_config_name} "
                    f"to the configuration {self.name}.",
                    details=msg
                )
            message = msg if not upload_status else apply_message
            return PushResult(
                success=upload_status,
                apply_success=apply_status,
                message=message or "",
                upload_id=upload_id,
                file_id=file_id,
            )
        except Exception as error:
            self.logger.error(
                message=f"{self.log_prefix} Error occurred while "
                f"executing push method for configuration {self.name}.",
                details=traceback.format_exc(),
            )
            raise NetskopeEDMError(
                message="Error while uploading edm hashes to netskope tenant."
            ) from error

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            edm.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.info(
            f"{self.log_prefix} executing validate method for Netskope EDM plugin."
        )
        try:
            return ValidationResult(
                success=True,
                message="Validation Successful for Netskope EDM plugin",
            )
        except Exception:
            self.logger.error(
                message=f"{self.log_prefix} Error occurred while validating plugin.",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message="Error occurred while validating plugin.",
            )

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
