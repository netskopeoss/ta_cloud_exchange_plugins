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

Netskope Plugin implementation to push the image hashes to Netskope Tenant.
"""

import traceback
import os
import shutil

from requests.exceptions import HTTPError
from typing import Dict
from uuid import uuid4


from netskope.common.utils.exceptions import ForbiddenError
from netskope.integrations.cfc.models import (
    ActionWithoutParams,
    Action,
    TrainingType,
)
from netskope.integrations.cfc.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cfc.utils import NetskopeClientCFC
from .utils.constants import (
    PLUGIN_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    BATCH_SIZE,
)
from .utils.helper import NetskopeCFCPluginHelper


class NetskopeCFCPlugin(PluginBase):
    """
    Netskope CFC Plugin class with methods to push image hashes to the tenant.

    This class implements the required methods to process and transmit image
    hashes to the Netskope tenant.
    """

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
        self.helper = NetskopeCFCPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            name=self.name
        )

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

    def push(self, action_dict: Dict, hash_file_path: str, mapping: Dict):
        """Push the CFC Hashes to Netskope Tenant.

        Args:
            action_dict (Dict): Action dictionary to be used
                while pushing CFC hashes.
            hash_file_path: (str): Hash file path
            mapping: (Dict): Mapping dictionary of a sharing for
                which CFC hashes to be shared. \
            contains Business Rule name, Classifier Name,
                Classifier ID and training type

        Raises:
            ForbiddenError: If no sufficient permissions are
            provided to the linked tenant RBAC V3 token.
        """
        mapping = mapping.copy()
        success = True
        message = "Sharing Success"
        if action_dict["value"] == "share_cfc_hash":
            try:
                netskope_client = self.helper.get_netskope_client()
                # Changes when we need to use predefined classifier
                # class_id = (
                #     mapping["preDefinedClassifierID"]
                #     if mapping["classifierType"] == ClassifierType.PREDEFINED
                #     else mapping["classifierID"]
                # )
                class_id = mapping.get("classifierID")
                classifier = netskope_client.classifier_by_id(class_id)
                if not classifier:
                    message = (
                        f"{self.log_prefix}: "
                        "Error occurred while uploading CFC hashes "
                        f"as Classifier: '{mapping.get('classifierName')}' "
                        "deleted from the tenant."
                    )
                    mapping["classifierID"] = None
                    # mapping["preDefinedClassifierID"] = None
                    mapping["classifierName"] = None
                    self.logger.error(message=message)
                    success = False
                    return PushResult(
                        success=False,
                        message=message,
                        mapping=mapping,
                        invalid_files=None,
                    )
                if self.storage and mapping.get("classifierID") in (
                    self.storage.get("max_limit_reached") or []
                ):
                    overall_status = classifier[
                        netskope_client.OVER_ALL_STATUS_KEY
                    ]
                    if (
                        overall_status[netskope_client.VALID_FILES_KEY]
                        >=
                        netskope_client.MAXIMUM_NUMBER_OF_FILES_PER_CLASSIFIER
                    ):
                        message = (
                            f"{self.log_prefix}: Classifier: "
                            f"'{mapping.get('classifierName')}' has "
                            "already reached its limit for the training files."
                            " Delete some files from the classifier to "
                            "train it with new files."
                        )
                        self.logger.error(
                            message=message,
                            resolution=(
                                "Delete some files from the classifier to "
                                "train it with new files."
                            )
                        )
                        success = False
                        return PushResult(
                            success=False,
                            message=message,
                            mapping=mapping,
                            invalid_files=None,
                        )
                    else:
                        self.storage.get("max_limit_reached").remove(
                            mapping.get("classifierID")
                        )
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
                                with open(
                                    f"{temp_upload_dir}/tmp_file_{tmp_file_num}.json",  # noqa: E501
                                    "w",
                                ) as tmp_file:
                                    tmp_file.writelines(tmp_file_lines)
                                tmp_file_num += 1
                                tmp_file_lines = []
                            tmp_file_lines.append(line)
                            line_num += 1
                        else:
                            with open(
                                f"{temp_upload_dir}/tmp_file_{tmp_file_num}.json",  # noqa: E501
                                "w",
                            ) as tmp_file:
                                tmp_file.writelines(tmp_file_lines)

                    ssid = str(uuid4())
                    for file_num in range(0, tmp_file_num + 1):
                        response = netskope_client.upload_hash(
                            class_id=mapping.get("classifierID"),
                            file_path=(
                                f"{temp_upload_dir}/tmp_file_{file_num}.json"
                            ),
                            negative=(
                                mapping.get("trainingType")
                                ==
                                TrainingType.NEGATIVE
                            ),
                            sessionend=(
                                True if file_num == tmp_file_num else False
                            ),
                            ssid=ssid,
                        )
                        if response.get("max_limit_reached"):
                            success = False
                            self.storage["max_limit_reached"] = list(
                                set(
                                    (
                                        self.storage.get("max_limit_reached")
                                        or []
                                    )
                                    + [mapping.get("classifierID")]
                                )
                            )
                            message = (
                                "Classifier: "
                                f"'{mapping.get('classifierName')}' "
                                f"with ID: '{mapping.get('classifierID')}' "
                                "has reached its limit for the training files."
                                " Delete some files from the classifier"
                                " to train it with new files."
                            )
                            self.logger.error(
                                message=f"{self.log_prefix}: {message}"
                            )
                        if response.get("invalid_files"):
                            invalid_files.extend(response.get("invalid_files"))

                    # --- Start of Archive Filtering Logic ---
                    if invalid_files:
                        all_fingerprints_from_api = []
                        if hasattr(response, "get") and response.get(
                            "fingerprints"
                        ):
                            all_fingerprints_from_api.extend(
                                response.get("fingerprints")
                            )

                        archive_suffixes = (
                            ".zip",
                            ".tgz",
                            ".tar",
                            ".tar.gz",
                            ".tar.bz2",
                            ".tar.xz",
                        )

                        containers_with_children = set()
                        for fp in all_fingerprints_from_api:
                            filename = fp.get("filename", "") or ""
                            parts = filename.split(":")
                            if len(parts) < 2:
                                continue
                            for i in range(1, len(parts)):
                                container = ":".join(parts[:i])
                                if container.lower().endswith(
                                    archive_suffixes
                                ):
                                    containers_with_children.add(container)

                        filtered_invalid_files = []
                        for fp in invalid_files:
                            filename = fp.get("filename", "") or ""
                            status = fp.get("status")
                            final_segment = filename.split(":")[-1]
                            is_archive = final_segment.lower().endswith(
                                archive_suffixes
                            )

                            skip_archive = (
                                status == netskope_client.INVALID_FILE_STATUS
                                and is_archive
                                and (
                                    filename in containers_with_children
                                    or final_segment
                                    != filename  # nested archive segment
                                )
                            )

                            if skip_archive:
                                continue

                            filtered_invalid_files.append(fp)

                        # Update invalid_files with filtered list
                        invalid_files = filtered_invalid_files

                        same_hash_removed_files = list(
                            filter(
                                lambda file: file["status"]
                                != NetskopeClientCFC.SAME_HASH_STATUS,
                                invalid_files,
                            )
                        )
                        success = not bool(same_hash_removed_files)
                        if success:
                            message = (
                                "Hash upload is completed."
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
                        f"{self.log_prefix}: Error occurred while uploading "
                        f"CFC hashes with error: '{str(error)}'."
                    )
                    self.logger.error(
                        message=message,
                        details=traceback.format_exc(),
                    )
                if success:
                    mapping["classifierName"] = classifier["name"]
                    if mapping.get("isManual"):
                        self.logger.info(
                            message=(
                                f"{self.log_prefix}: Sharing with Classifier: "
                                f"'{mapping.get('classifierName')}' using "
                                f"manual upload is completed."
                            )
                        )
                    else:
                        self.logger.info(
                            message=(
                                f"{self.log_prefix}: Sharing with Business "
                                f"Rule: '{mapping.get('businessRule')}' "
                                "and Classifier: "
                                f"'{mapping.get('classifierName')}' "
                                "is completed."
                            )
                        )
                if os.path.exists(temp_upload_dir):
                    shutil.rmtree(temp_upload_dir)
                return PushResult(
                    success=success,
                    message=message,
                    mapping=mapping,
                    invalid_files=invalid_files,
                )
            except ForbiddenError as error:
                message = (
                    f"{self.log_prefix}: Unable to access classifier "
                    "endpoints. Add permissions for classifiers "
                    f"to the RBAC V3 token. Error: {str(error)}"
                )
                success = False
                self.logger.error(
                    message=message,
                    resolution=(
                        "Ensure that the RBAC V3 token has permission to "
                        "access the classifier endpoints."
                    ),
                    details=traceback.format_exc(),
                )
                raise ForbiddenError(message=message) from error
            except Exception:
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while "
                    "uploading Hashes."
                )

        message = "Invalid Action provided."
        self.logger.error(
            message=f"{self.log_prefix}: {message}"
        )
        return PushResult(
            success=False, message=message, mapping=mapping, invalid_files=None
        )

    def validate_configuration_parameters(self, tenant=None):
        """Validate the Plugin configuration parameters.

        Returns:
            cfc.plugin_base.ValidateResult: ValidateResult object with
            success flag and message.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration parameters."
        )
        try:
            result = self.helper.validate_configuration_parameters(tenant)
            if not result.success:
                return result
            message = (
                "Successfully validated the configuration parameters."
            )
            self.logger.debug(
                message=f"{self.log_prefix}: {message}"
            )
            return ValidationResult(
                success=True,
                message=message,
            )
        except Exception as error:
            message = (
                f"{self.log_prefix}: Error occurred while validating "
                f"configuration parameters. Error: {str(error)}"
            )
            self.logger.error(
                message=message,
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(error))

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Share CFC Hashes", value="share_cfc_hash"
            ),
        ]

    def validate_action(self, action: Action):
        """Validate Netskope configuration."""
        if action.value not in ["share_cfc_hash"]:
            message = "Unsupported action provided."
            self.logger.error(
                f"{self.log_prefix}: {message}"
            )
            return ValidationResult(
                success=False,
                message=message
            )
        message = "Successfully validated action."
        self.logger.debug(
            f"{self.log_prefix}: {message}"
        )
        return ValidationResult(
            success=True,
            message=message
        )

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
