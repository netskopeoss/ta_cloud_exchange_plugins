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

"""Google Cloud SCC Plugin."""


import datetime
import json
import re
import traceback
import uuid

from netskope.common.utils import add_user_agent
from netskope.integrations.cls.plugin_base import PluginBase, ValidationResult

from .utils.cscc_constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RESOURCE_NAME_URL
)
from .utils.cscc_exceptions import CSCCPluginException
from .utils.cscc_helper import (
    DataTypes,
    get_cscc_mappings,
    get_external_url,
    handle_data,
    map_cscc_data
)
from .utils.cscc_validator import CSCCValidator
from .utils.gcp_client import GCPClient


class CSCCPlugin(PluginBase):
    """The CSCC plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init method.

        Args:
            name (str): Configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = CSCCPlugin.metadata
            plugin_name = metadata_json.get("name", PLUGIN_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _add_user_agent(self, headers={}) -> str:
        """Add User-Agent in the headers of any request.

        Returns:
            str: String containing the User-Agent.
        """
        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.replace(" ", "-").lower(),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def push(self, transformed_data, data_type, subtype):
        """Tngests the transformed_data to GCP by creating a authenticated session with GCP.

        Args:
            transformed_data (list): The transformed data to be ingested.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested \
            (DLP, anomaly etc. in case of alerts)

        """
        try:
            gcp_client = GCPClient(
                self.configuration,
                self.logger,
                self.log_prefix,
                self.plugin_name,
                self.proxy
            )
            headers = self._add_user_agent()

            skipped_count = 0
            total_count = 0
            log_msg = (
                f"[{data_type}]:[{subtype}] Ingesting {len(transformed_data)} data "
                f"to {self.plugin_name}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            # Ingest the given data
            for data in transformed_data:
                try:
                    gcp_client.ingest(
                        fid=data["fid"],
                        finding=data["finding"],
                        headers=headers,
                        data_type=data_type,
                        subtype=subtype
                    )
                    total_count += 1
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}]:[{subtype}] "
                            f"Error occurred while ingesting data. Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skipped_count += 1
                    continue
            if skipped_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skipped_count} records "
                    "due to some unexpected error occurred."
                )

            log_msg = (
                f"[{data_type}]:[{subtype}] Successfully ingested "
                f"{total_count} {data_type} to {self.plugin_name}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
        except CSCCPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while ingesting "
                    f"[{data_type}]:[{subtype}]. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise err
        except Exception as err:
            err_msg = (
                f"Error occurred while ingesting "
                f"[{data_type}]:[{subtype}] data to {PLUGIN_NAME}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}"
                    f" Error: {str(err)}"
                ),
                details=str(traceback.format_exc())
            )
            raise err

    def get_subtype_mapping(self, mappings, subtype):
        """Retrieve subtype mappings (mappings for subtypes of alerts/events) case insensitively.

        Args:
            mappings: Mapping JSON from which subtypes are to be retrieved
            subtype: Subtype (e.g. DLP for alerts) for which the mapping is
            to be fetched

        Returns:
            Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def _normalize_key(self, key, transform_map):
        """Normalize the given key by removing any special characters.

        Args:
            key: The key string to be normalized

        Returns:
            normalized key
        """
        # Check if it contains characters other than alphanumeric and underscores
        if not re.match(r"^[a-zA-Z0-9_]+$", key):
            # Replace characters other than underscores and alphanumeric
            transform_map[key] = re.sub(r"[^0-9a-zA-Z_]+", "_", key)
            key = transform_map[key]
        return key

    def _get_category(self, data, data_type, subtype):
        """Fetch the alert/event category from the Netskope data.

        Returns:
            category of alert/event
        """
        return (
            subtype.lower()
            if data_type == DataTypes.EVENT.value
            else data.get("alert_type")
        )

    def transform(self, raw_data, data_type, subtype):
        """Transform a Netskope alerts/incident into a Google Cloud Security Command Center Finding.

        Args:
            raw_data (list): Raw data retrieved from Netskope which is supposed to be transformed
            data_type (str): Type of data to be transformed: Currently alerts and events
            subtype (str): The subtype of data being transformed
            (DLP, anomaly etc. in case of alerts)

        Returns:
            List: List of tuples containing the GCP SCC Finding ID and the Finding document (transformed data into
                required format)
        """
        """
        Different cases related mapping file:

            1. If mapping file is not found or contains invalid JSON, all the data will be ingested
            2. If the file contains few valid fields, only that fields with mandatory fields
               (['timestamp', 'url', 'alert_type']) will be ingested.
            3. If file is in valid format, but contains no fields, only the mandatory fields will be ingested.
            4. Fields which are not in Netskope response, but are present in mappings file will be ignored with logs.
        """
        skip_count = 0
        try:
            gcp_client = GCPClient(
                self.configuration,
                self.logger,
                self.log_prefix,
                self.plugin_name,
                self.proxy
            )
            headers = self._add_user_agent()
            resource_name = gcp_client.set_resource_name(headers=headers)
        except CSCCPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while getting "
                    f"project number. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise err
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while getting "
                    f"project number. Error: {err}"
                ),
                details=str(traceback.format_exc())
            )
            raise err

        try:
            mappings = get_cscc_mappings(self.mappings, data_type)
        except Exception as err:
            self.logger.error(
                message=f"An error occurred while mapping data using given json mapping. Error: {str(err)}",
                details=str(traceback.format_exc())
            )
            raise

        transformed_data_list = []

        for data in raw_data:
            transformed_data = {"fid": "", "finding": {}}
            transform_map = {}
            try:
                subtype_mappings = self.get_subtype_mapping(mappings, subtype)
                # If subtype mappings are provided, use only those fields, otherwise map all the fields
                if subtype_mappings:
                    try:
                        data = map_cscc_data(
                            subtype_mappings, data, self.logger, data_type, subtype
                        )
                    except Exception as err:
                        err_msg = (
                            f"[{data_type}][{subtype}]: An error occurred "
                            f"while filtering data. Error: {str(err)}."
                            " Transformation of the current record will be skipped."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        skip_count += 1

                # Add tenant name to raw data
                data["tenant_name"] = self.source

                fid = uuid.uuid1().hex

                now = datetime.datetime.utcnow()
                now = str(now).replace(" ", "T") + "Z"
                date = now
                if "timestamp" in data:
                    date = datetime.datetime.utcfromtimestamp(
                        int(data["timestamp"])
                    )
                    date = str(date).replace(" ", "T") + "Z"

                # Normalize the data keys in order to make data keys
                # only contain the letters, numbers and underscores
                normalized_data = {}
                for key, value in data.items():
                    # Now check if it contains characters other than alphanumeric and underscores
                    key = self._normalize_key(key, transform_map)
                    normalized_data[key] = value
                data = normalized_data

                try:
                    data = handle_data(data, self.logger, self.log_prefix)
                except Exception as err:
                    err_msg = (
                        f"[{data_type}][{subtype}]: Error occurred while "
                        f"handling unexpected values in data: {str(err)}."
                        " Transformation of the current record will be skipped."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {err_msg}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1

                external_url = ""
                if "url" in data:
                    try:
                        external_url = get_external_url(data)
                    except Exception as err:
                        err_msg = (
                            f"[{data_type}][{subtype}]: Error occurred while "
                            f"retrieving external URL: {str(err)}."
                            f" Transformation of the current record will be skipped."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        skip_count += 1

                finding = {
                    "name": "{}/findings/{}".format(
                        self.configuration["source_id"], fid
                    ),
                    "parent": str(self.configuration["source_id"]),
                    "resourceName": "{}/{}".format(
                        RESOURCE_NAME_URL, resource_name
                    ),
                    "state": "ACTIVE",
                    "externalUri": external_url,
                    # Because of incorrect response from Netskope API,
                    # category needs to be handled separately for alert
                    # and events otherwise this can be handled by just "subtype"
                    "category": self._get_category(data, data_type, subtype),
                    "sourceProperties": data,
                    "eventTime": date,
                    "createTime": now,
                }
                transformed_data["fid"] = fid
                transformed_data["finding"] = finding
                transformed_data_list.append(transformed_data)
            except Exception as err:
                err_msg = (
                    f"[{data_type}][{subtype}]: An error occurred "
                    f"during transformation. Error: {str(err)}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skip_count += 1
        if skip_count > 0:
            self.logger.debug(
                "{}: [{}][{}] Plugin couldn't process {} records because they "
                "either had no data or contained invalid/missing "
                "fields according to the configured JSON mapping. "
                "Therefore, the transformation and ingestion for those "
                "records were skipped.".format(
                    self.log_prefix, data_type, subtype, skip_count
                )
            )

        return transformed_data_list

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration of cscc plugin.

        Args:
            configuration (dict): dictionary containing all parameters to be validated

        Returns:
            ValidationResult: class that contains the success status of the configurations
        """
        cscc_validator = CSCCValidator(self.logger, self.log_prefix)
        validation_msg = f"{self.log_prefix}: Validation error occurred."

        # validating transformData is disabled
        transformData = configuration.get("transformData", False)
        if transformData:
            error_message = (
                "This plugin only supports sending JSON formatted data to Google Cloud SCC. "
                "Please disable 'Transformation Toggle' from basic information."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )

        # validate organization id
        organization_id = configuration.get("organization_id", "").strip()
        if not organization_id:
            error_message = (
                "Organization ID is a required configuration parameter."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )
        elif not isinstance(organization_id, str):
            error_message = "Invalid Organization ID provided."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )

        # validate source id
        source_id = configuration.get("source_id", "").strip()
        if not source_id:
            error_message = (
                "Source ID is a required configuration parameter."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )
        elif not isinstance(source_id, str):
            error_message = "Invalid Source ID provided."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )

        # validate service account key
        key_file = configuration.get("key_file", "").strip()
        if not key_file:
            error_message = (
                "Key File is a required configuration parameter."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )
        elif not isinstance(key_file, str):
            error_message = "Invalid Key File provided."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )

        # validating mapping file
        mappings = self.mappings.get("jsonData", None)
        try:
            mappings = json.loads(mappings)
        except json.decoder.JSONDecodeError as err:
            error_message = f"Invalid CSCC attribute mapping provided. {str(err)}"
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False,
                message=error_message,
            )

        if not isinstance(mappings, dict) or not cscc_validator.validate_cscc_map(
            mappings
        ):
            error_message = "Invalid CSCC attribute mapping provided."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False,
                message=error_message,
            )

        try:
            gcp_client = GCPClient(
                configuration,
                self.logger,
                self.log_prefix,
                self.plugin_name,
                self.proxy
            )
            headers = self._add_user_agent()

            result = gcp_client.validate_credentials(headers=headers)
            if not result:
                error_message = "Invalid Organization ID or Source ID."
                self.logger.error(f"{validation_msg} {error_message}")
                return ValidationResult(
                    success=False,
                    message=error_message,
                )
        except CSCCPluginException as err:
            self.logger.error(
                message=(
                    f"{validation_msg} Error: {str(err)}"
                ),
                details=str(traceback.format_exc())
            )
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as err:
            error_message = f"Error occurred while validating credentials. {str(err)}"
            self.logger.error(
                message=(
                    f"{validation_msg} {error_message}"
                ),
                details=str(traceback.format_exc())
            )
            return ValidationResult(
                success=False,
                message=f"{error_message} Check logs for more details.",
            )

        return ValidationResult(success=True, message="Validation successful")
