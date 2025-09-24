"""Netskope Plugin implementation to push the image hashes to Netskope Tenant."""
import traceback
import os
import shutil

from requests.exceptions import HTTPError
from tempfile import gettempdir, mkstemp
from typing import Dict
from uuid import uuid4


from netskope.common.utils import AlertsHelper, resolve_secret
from netskope.common.utils.exceptions import ForbiddenError
from netskope.integrations.cfc.models import ActionWithoutParams, Action, TrainingType
from netskope.integrations.cfc.plugin_base import PluginBase, ValidationResult, PushResult
from netskope.integrations.cfc.utils import NetskopeClientCFC

PLUGIN_NAME = "Netskope Custom File Classification"
MODULE_NAME = "CFC"
PLUGIN_VERSION = "1.0.0"
BATCH_SIZE = 500


class NetskopeCFCPlugin(PluginBase):
    """Netskope CFC Plugin Class with the methods required to push the image hashes to the Netskope Tenant."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Netskope CFC plugin initializer.

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
            manifest_json = NetskopeCFCPlugin.metadata
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

    def get_netskope_client(self, tenant=None):
        """Get netskope cline from the configuration name with validated token."""
        if tenant:
            self.tenant = tenant
        else:
            helper = AlertsHelper()
            self.tenant = helper.get_tenant_cfc(self.name)

        netskope_client = NetskopeClientCFC(
            tenant_base_url=self.tenant.parameters.get("tenantName"),
            api_token_v2=resolve_secret(self.tenant.parameters.get("v2token")),
            plugin=PLUGIN_NAME
        )
        return netskope_client

    def push(
        self,
        action_dict: Dict,
        hash_file_path: str,
        mapping: Dict
    ):
        """Push the CFC Hashes to Netskope Tenant.

        Args:
            action_dict (Dict): Action dictionary to be used while pushing CFC hashes.
            hash_file_path: (str): Hash file path
            mapping: (Dict): Mapping dictionary of a sharing for which CFC hashes to be shared. \
            contains Business Rule name, Classifier Name, Classifier ID and training type

        Raises:
            ForbiddenError: If no sufficient permissions are provided to the linked tenant v2 token.
        """
        mapping = mapping.copy()
        success = True
        message = "Sharing Success"
        if action_dict["value"] == "share_cfc_hash":
            try:
                netskope_client = self.get_netskope_client()
                # Changes when we need to use predefined classifier
                # class_id = (
                #     mapping["preDefinedClassifierID"]
                #     if mapping["classifierType"] == ClassifierType.PREDEFINED
                #     else mapping["classifierID"]
                # )
                class_id = mapping["classifierID"]
                classifier = netskope_client.classifier_by_id(class_id)
                if not classifier:
                    message = (
                        f"{self.log_prefix} "
                        f"Error occurred while uploading CFC hashes to the "
                        f"plugin configuration: '{self.name}' as Classifier: "
                        f"'{mapping['classifierName']}' deleted from the tenant."
                    )
                    mapping["classifierID"] = None
                    # mapping["preDefinedClassifierID"] = None
                    mapping["classifierName"] = None
                    self.logger.error(
                        message=message
                    )
                    success = False
                    return PushResult(
                        success=False,
                        message=message,
                        mapping=mapping,
                        invalid_files=None
                    )
                if self.storage and mapping["classifierID"] in (self.storage.get("max_limit_reached") or []):
                    overall_status = classifier[netskope_client.OVER_ALL_STATUS_KEY]
                    if (
                        overall_status[netskope_client.VALID_FILES_KEY]
                        >= netskope_client.MAXIMUM_NUMBER_OF_FILES_PER_CLASSIFIER
                    ):
                        message = (
                            f"{self.log_prefix} Classifier: '{mapping['classifierName']}' has "
                            "already reached its limit for the training files. Please "
                            "delete some files from the classifier to train it with "
                            "new files."
                        )
                        self.logger.error(
                            message=message
                        )
                        success = False
                        return PushResult(
                            success=False,
                            message=message,
                            mapping=mapping,
                            invalid_files=None
                        )
                    else:
                        self.storage["max_limit_reached"].remove(mapping["classifierID"])
                hash_file_dir = os.path.dirname(hash_file_path)
                temp_upload_dir = os.path.join(hash_file_dir, "tmp_hash")
                if os.path.exists(temp_upload_dir):
                    shutil.rmtree(temp_upload_dir)
                os.mkdir(temp_upload_dir)
                invalid_files = []
                tmp_file_num = 0
                try:
                    with open(hash_file_path, "r") as f:
                        line_num = 0
                        tmp_file_lines = []
                        for line in f:
                            if line_num == BATCH_SIZE:
                                line_num = 0
                                with open(f"{temp_upload_dir}/tmp_file_{tmp_file_num}.json", "w") as tmp_file:
                                    tmp_file.writelines(tmp_file_lines)
                                tmp_file_num += 1
                                tmp_file_lines = []
                            tmp_file_lines.append(line)
                            line_num += 1
                        else:
                            with open(f"{temp_upload_dir}/tmp_file_{tmp_file_num}.json", "w") as tmp_file:
                                tmp_file.writelines(tmp_file_lines)

                    ssid = str(uuid4())
                    for file_num in range(0, tmp_file_num + 1):
                        response = netskope_client.upload_hash(
                            class_id=mapping["classifierID"],
                            file_path=f"{temp_upload_dir}/tmp_file_{file_num}.json",
                            negative=mapping["trainingType"] == TrainingType.NEGATIVE,
                            sessionend=True if file_num == tmp_file_num else False,
                            ssid=ssid
                        )
                        if response["max_limit_reached"]:
                            success = False
                            self.storage["max_limit_reached"] = list(
                                set(
                                    (self.storage.get("max_limit_reached") or [])
                                    + [mapping["classifierID"]]
                                )
                            )
                            message = (
                                f"Classifier: '{mapping['classifierName']}' with ID:"
                                f" '{mapping['classifierID']}' has "
                                "reached its limit for the training files. Please "
                                "delete some files from the classifier to train it with "
                                "new files."
                            )
                            self.logger.error(
                                message=f"{self.log_prefix} {message}"
                            )
                        if response["invalid_files"]:
                            invalid_files.extend(response["invalid_files"])
                    if invalid_files:
                        same_hash_removed_files = list(filter(
                            lambda file: file["status"] != NetskopeClientCFC.SAME_HASH_STATUS,
                            invalid_files
                        ))
                        success = not bool(same_hash_removed_files)
                        if success:
                            message = (
                                f"{self.log_prefix} Hash upload is completed."
                            )
                        else:
                            message = (
                                "Hash upload failed for "
                                f"{len(same_hash_removed_files)} "
                                "files."
                            )
                except HTTPError as error:
                    success = False
                    invalid_files = None
                    message = (
                        f"{self.log_prefix} Error occurred while uploading CFC hashes"
                        f" to the plugin configuration: '{self.name}' with error: '{str(error)}'."
                    )
                    self.logger.error(
                        message=message
                    )
                if success:
                    mapping["classifierName"] = classifier["name"]
                    if mapping.get("isManual"):
                        self.logger.info(
                            message=f"{self.log_prefix} Sharing with Classifier: '{mapping['classifierName']}' "
                            "using manual upload "
                            f"for the plugin configuration: '{self.name}' is completed."
                        )
                    else:
                        self.logger.info(
                            message=f"{self.log_prefix} Sharing with Business Rule: "
                            f"'{mapping['businessRule']}' and Classifier: '{mapping['classifierName']}' "
                            f"for the plugin configuration: '{self.name}' is completed."
                        )
                if os.path.exists(temp_upload_dir):
                    shutil.rmtree(temp_upload_dir)
                return PushResult(
                    success=success,
                    message=message,
                    mapping=mapping,
                    invalid_files=invalid_files
                )
            except ForbiddenError as error:
                message = (
                    f"{self.log_prefix} Unable to access classifier endpoints "
                    f"for plugin configuration: '{self.name}'."
                    " Please add permissions for classifiers to the v2 token. "
                    f"{str(error)}"
                )
                success = False
                self.logger.error(
                    message=message
                )
                raise ForbiddenError(message=message) from error
        message = f"{self.log_prefix} Invalid Action provided for plugin configuration: '{self.name}'."
        self.logger.error(
            message=message
        )
        return PushResult(
            success=False,
            message=message,
            mapping=mapping,
            invalid_files=None
        )

    def validate_configuration_parameters(self, tenant = None):
        """Validate the Plugin configuration parameters.

        Returns:
            cfc.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.debug(
            f"{self.log_prefix} Validating configuration parameters for '{self.name}' plugin."
        )
        try:
            netskope_client = self.get_netskope_client(tenant)
            # # Validating for get predefined classifiers api access
            # predefined_classifiers = netskope_client.all_predefined_classifiers()
            # if predefined_classifiers["predefinedClassifiers"]["classifiers"]:
            #     # Validating for get predefined classifiers api access
            #     netskope_client.create_overlay_classifier(
            #         predefined_classifiers["predefinedClassifiers"]["classifiers"][0]["id"]
            #     )
            # else:
            #     self.logger.info(
            #         f"{self.log_prefix} Validation for the predefined classifier write access is skipped as, "
            #         f"no predefined classifier found on the tenant: '{self.tenant}' for configuration: '{self.name}'."
            #     )

            # Validating for get custom classifiers api access
            custom_classifiers = netskope_client.all_custom_classifiers(
                customOnly=True,
                limit=10
            )
            if custom_classifiers["customClassifiers"]:
                # Validating get custom classifier by id api access
                netskope_client.classifier_by_id(custom_classifiers["customClassifiers"][0]["id"])
                _, temp_file_name = mkstemp(dir=gettempdir(), suffix=".json")
                netskope_client.upload_hash(
                    class_id=custom_classifiers["customClassifiers"][0]["id"],
                    file_path=temp_file_name,
                    ssid=str(uuid4()),
                    sessionend=True
                )
            else:
                self.logger.info(
                    f"{self.log_prefix} Validation for the upload hash endpoint is skipped as, "
                    f"no custom classifier found on the tenant: '{self.tenant}' for configuration: '{self.name}'."
                )
        except ForbiddenError:
            message = (
                f"{self.log_prefix} Unable to access classifier endpoints "
                f"for plugin configuration: '{self.name}'."
                " Please add permissions for classifiers to the v2 token."
            )
            self.logger.error(message)
            return ValidationResult(
                success=False,
                message=message
            )
        except Exception as error:
            message = (
                f"{self.log_prefix} Error occurred while validating the configuration: '{self.name}'. "
                f"{str(error)}"
            )
            self.logger.error(
                message=message,
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=str(error)
            )
        self.logger.debug(
            f"{self.log_prefix} Configuration parameter validated for '{self.name}' plugin."
        )
        return ValidationResult(
            success=True,
            message="Validation Successful for Netskope CFC plugin",
        )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Share CFC Hashes", value="share_cfc_hash"),
        ]

    def validate_action(self, action: Action):
        """Validate Netskope configuration."""
        if action.value not in ["share_cfc_hash"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
