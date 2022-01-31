"""CSCC Plugin."""
import json
import uuid
import re
import datetime
from netskope.integrations.cls.plugin_base import PluginBase, ValidationResult
from .utils.cscc_constants import (
    GCP_URL,
    RESOURCE_NAME_URL,
)
from .utils.cscc_helper import (
    get_cscc_mappings,
    map_cscc_data,
    handle_data,
    get_external_url,
    DataTypes,
)
from .utils.cscc_exceptions import (
    MaxRetriesExceededError,
)
from .utils.gcp_client import GCPClient
from .utils.cscc_validator import CSCCValidator


class CSCCPlugin(PluginBase):
    """The CSCC plugin implementation class."""

    def create_gcp_client(self):
        """Create GCP client."""
        self.resource_name = None
        org_id = self.configuration.get("organization_id", None)
        src_id = self.configuration.get("source_id", None)
        self.gcp_post_url = "{}/{}/sources/{}/findings".format(
            GCP_URL, org_id, src_id
        )
        key_file = self.configuration.get("key_file", """{}""")
        key_file = json.loads(key_file)

        self.gcp_client = GCPClient(
            self.gcp_post_url, key_file, self.logger, self.proxy
        )
        if key_file != {}:
            self.resource_name = self.gcp_client.set_resource_name()

    def push(self, transformed_data, data_type, subtype):
        """Transform and ingests the given data chunks to GCP by creating a authenticated session with GCP.

        :param data_type: The type of data being pushed. Current possible values: alerts and events
        :param transformed_data: Transformed data to be ingested to GCP in chunks of 1
        :param subtype: The subtype of data being pushed. E.g. subtypes of alert is "dlp", "policy" etc.
        """
        self.create_gcp_client()

        self.gcp_client.set_gcp_session()
        try:
            # Ingest the given data
            for data in transformed_data:
                self.gcp_client.ingest(
                    data["fid"], data["finding"], data_type, subtype
                )
        except MaxRetriesExceededError as err:
            self.logger.error(f"Error while pushing data: {err}")
            raise err

    @staticmethod
    def chunk_size():
        """Get chunk_size would be 1 in this case.

        :return: data chunk size
        """
        return 1

    def get_subtype_mapping(self, mappings, subtype):
        """Retrieve subtype mappings (mappings for subtypes of alerts/events) case insensitively.

        :param mappings: Mapping JSON from which subtypes are to be retrieved
        :param subtype: Subtype (e.g. DLP for alerts) for which the mapping is to be fetched
        :return: Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def _normalize_key(self, key, transform_map):
        """Normalize the given key by removing any special characters.

        :param key: The key string to be normalized
        :return: normalized key
        """
        # Check if it contains characters other than alphanumeric and underscores
        if not re.match(r"^[a-zA-Z0-9_]+$", key):
            # Replace characters other than underscores and alphanumeric
            transform_map[key] = re.sub(r"[^0-9a-zA-Z_]+", "_", key)
            key = transform_map[key]
        return key

    def _get_category(self, data, data_type, subtype):
        """Fetch the alert/event category from the Netskope data.

        :return: category of alert/event
        """
        return (
            subtype.lower()
            if data_type == DataTypes.EVENT.value
            else data.get("alert_type")
        )

    def transform(self, raw_data, data_type, subtype):
        """Transform a Netskope alerts into a Google Cloud Security Command Center Finding.

        :param data_type: Type of data to be transformed: Currently alerts and events
        :param raw_data: Raw data retrieved from Netskope which is supposed to be transformed
        :param subtype: The subtype of data being transformed

        :return List of tuples containing the GCP SCC Finding ID and the Finding document (transformed data into
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
        self.create_gcp_client()

        try:
            mappings = get_cscc_mappings(self.mappings, data_type)
        except Exception as err:
            self.logger.error(
                f"An error occurred while mapping data using given json mapping.Error: {str(err)}"
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
                    data = map_cscc_data(
                        subtype_mappings, data, self.logger, data_type, subtype
                    )

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

                # Normalize the data keys in order to make data keys only contain the letters, numbers and underscores
                normalized_data = {}
                for key, value in data.items():
                    # Now check if it contains characters other than alphanumeric and underscores
                    key = self._normalize_key(key, transform_map)
                    normalized_data[key] = value
                data = normalized_data

                data = handle_data(data, self.logger)
                external_url = ""
                if "url" in data:
                    external_url = get_external_url(data)
                finding = {
                    "name": "{}/findings/{}".format(
                        self.configuration["source_id"], fid
                    ),
                    "parent": str(self.configuration["source_id"]),
                    "resourceName": "{}/{}".format(
                        RESOURCE_NAME_URL, self.resource_name
                    ),
                    "state": "ACTIVE",
                    "externalUri": external_url,
                    # Because of incorrect response from Netskope API, category needs to be handled separately for alert
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
                self.logger.error(
                    "Could not transform data \n{}.\n Error:{}".format(
                        data, err
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
        cscc_validator = CSCCValidator(self.logger)

        if (
            "organization_id" not in configuration
            or type(configuration["organization_id"]) != str
            or not configuration["organization_id"].strip()
        ):
            self.logger.error(
                "CSCC Plugin: Validation error occurred. Error: "
                "Invalid organization_id found in the configuration parameter"
            )
            return ValidationResult(
                success=False, message="Invalid organization id provided."
            )

        if (
            "source_id" not in configuration
            or type(configuration["source_id"]) != str
            or not configuration["source_id"].strip()
        ):
            self.logger.error(
                "CSCC Plugin: Validation error occurred. Error: "
                "Invalid source id found in the configuration parameter."
            )
            return ValidationResult(
                success=False, message="Invalid source id provided"
            )

        if (
            "key_file" not in configuration
            or type(configuration["key_file"]) != str
            or not configuration["key_file"].strip()
        ):
            self.logger.error(
                "CSCC Plugin: Validation error occurred. Error: "
                "Invalid key file found in configuration parameter."
            )
            return ValidationResult(
                success=False, message="Invalid key file provided"
            )

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if type(mappings) != dict or not cscc_validator.validate_cscc_map(
            mappings
        ):
            self.logger.error(
                "CSCC Plugin: Validation Error occurred. Error: "
                "Invalid cscc mapping attribute found in configuration"
            )
            return ValidationResult(
                success=False,
                message="Invalid cscc attribute mapping provided",
            )

        try:
            org_id = configuration.get("organization_id", None)
            src_id = configuration.get("source_id", None)
            gcp_post_url = "{}/{}/sources/{}/findings".format(
                GCP_URL, org_id, src_id
            )
            key_file = configuration.get("key_file", """{}""")
            key_file = json.loads(key_file)

            gcp_client = GCPClient(
                gcp_post_url, key_file, self.logger, self.proxy
            )

            gcp_client.set_gcp_session()
        except Exception as e:
            self.logger.error(
                f"CSCC Plugin: Validation Error occurred. Error: "
                f"Connection to GCP is not established. {e}"
            )
            return ValidationResult(
                success=False,
                message="Connection to GCP is not established. "
                "Make sure you have provided correct Key file.",
            )

        return ValidationResult(success=True, message="Validation successful")
