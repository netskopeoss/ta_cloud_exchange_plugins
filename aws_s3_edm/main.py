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

AWS S3 EDM Plugin is used to pull a CSV or TXT file from an AWS S3 bucket and
to perform sanitization on the pulled data before generating EDM hashes. The
file can be uncompressed or compressed as .gz or .zip.
"""

# Built-in libraries
import csv
import os
import shutil
import sys
import traceback
from copy import deepcopy
from typing import List

# Local imports
from .utils.client import AWSS3EDMClient
from .utils.constants import (
    AWS_S3_EDM_FIELDS,
    MAX_COLUMNS,
    MODULE_NAME,
    NO_STRIP_FIELDS,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    SAMPLE_CSV_FILE_NAME,
    SAMPLE_DATA_RECORD_COUNT,
    USER_AGENT,
)
from .utils.exception import AWSS3EDMException
from .utils.helper import build_error_message, remove_local_file
from .utils.validator import AWSS3EDMValidator
from netskope.integrations.edm.models import Action, ActionWithoutParams
from netskope.integrations.edm.plugin_base import PluginBase, ValidationResult
from netskope.integrations.edm.utils import CONFIG_TEMPLATE, FILE_PATH
from netskope.integrations.edm.utils import run_sanitizer
from netskope.integrations.edm.utils.constants import EDM_HASH_CONFIG
from netskope.integrations.edm.utils.edm.hash_generator.edm_hash_generator import (  # noqa: E501
    generate_edm_hash,
)


class AWSS3EDMPlugin(PluginBase):
    """AWS S3 EDM Plugin Class.

    This plugin is used to pull a CSV/TXT file from an AWS S3 bucket and
    perform sanitization on the pulled data.
    """

    def __init__(
        self,
        name: str,
        *args,
        **kwargs,
    ) -> None:
        """AWS S3 EDM plugin initializer.

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
        self.config_name = name
        self._client = None
        self._validator = None

    @property
    def client(self) -> AWSS3EDMClient:
        """Get the S3 client, created on first use.

        The client is created lazily because Cloud Exchange also builds the
        plugin only to render or redact fields (name and storage may be
        None) and reading ``self.proxy`` queries the database.

        Returns:
            AWSS3EDMClient: The client sharing the plugin storage dict.
        """
        if self._client is None:
            self._client = AWSS3EDMClient(
                self.logger,
                self.log_prefix,
                self.proxy,
                self.storage,
                USER_AGENT,
                lambda: self.ssl_validation,
            )
        return self._client

    @property
    def validator(self) -> AWSS3EDMValidator:
        """Get the parameter validator, created on first use.

        Returns:
            AWSS3EDMValidator: The validator (no network, no proxy).
        """
        if self._validator is None:
            self._validator = AWSS3EDMValidator(
                self.logger, self.log_prefix
            )
        return self._validator

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = AWSS3EDMPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the manifest.json of the plugin is valid."
                ),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _build_error(
        self, err_msg: str, resolution: str, action: str
    ) -> AWSS3EDMException:
        """Log an error and build the exception to raise.

        Args:
            err_msg (str): The specific reason (without log prefix).
            resolution (str): Actionable resolution ("Ensure that ...").
            action (str): What was being done ("Error occurred while
                <action>." leads the message).

        Returns:
            AWSS3EDMException: Exception carrying the logged message.
        """
        err_msg = build_error_message(action, err_msg)
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=(
                traceback.format_exc() if sys.exc_info()[0] else err_msg
            ),
            resolution=resolution,
        )
        return AWSS3EDMException(message=err_msg)

    def strip_string_values(self, configuration: dict) -> None:
        """Strip leading and trailing whitespace from string values.

        Password Phrase and Delimiter are never stripped as whitespace can
        be a part of their value.

        Args:
            configuration (dict): A dictionary containing key-value pairs.
        """
        for parameter, value in configuration.items():
            if parameter in NO_STRIP_FIELDS:
                continue
            if isinstance(value, str):
                configuration[parameter] = value.strip()

    @staticmethod
    def _copy_step(configuration, step_name: str) -> dict:
        """Copy one saved step into a plain dict, reading with ``get``.

        Values are read with ``get`` so secrets are resolved by SecretDict.

        Args:
            configuration: Full plugin configuration (dict or SecretDict).
            step_name (str): Name of the saved step.

        Returns:
            dict: The step values, empty when the step is missing.
        """
        source = (
            configuration.get(step_name)
            if hasattr(configuration, "get")
            else None
        )
        if not hasattr(source, "keys"):
            return {}
        return {key: source.get(key) for key in source.keys()}

    def _get_step1_config(self, configuration=None) -> dict:
        """Build the step 1 configuration used by the validator and client.

        It is a trimmed copy of ``configuration["configuration"]`` (string
        values are trimmed except the pass phrase and the delimiter).
        ``self.configuration`` is never modified.

        Args:
            configuration (dict, optional): Full plugin configuration.
                Defaults to ``self.configuration``.

        Returns:
            dict: Step 1 parameters (a new dict on every call).
        """
        if configuration is None:
            configuration = self.configuration
        step_configuration = self._copy_step(configuration, "configuration")
        self.strip_string_values(step_configuration)
        return step_configuration

    def _get_step_value(self, key: str, default=None):
        """Read one value of the ``configuration`` step only.

        Unlike ``_get_step1_config`` this reads only the requested key, so
        it never reads (and so never resolves) a secret value.

        Args:
            key (str): Parameter key.
            default: Value returned when the key is missing.

        Returns:
            The value of the parameter.
        """
        step = (
            self.configuration.get("configuration")
            if hasattr(self.configuration, "get")
            else None
        )
        if not hasattr(step, "get"):
            return default
        return step.get(key, default)

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration and access to the file in the S3 bucket.

        Args:
            configuration (dict): A dictionary containing
                configuration parameters.

        Returns:
            ValidationResult: Success with a message if the configuration,
                the connection and the file are valid, else a failure
                with an error message.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration parameters."
        )
        try:
            step_configuration = self._get_step1_config(configuration)

            validation_result = (
                self.validator.validate_configuration_parameters(
                    step_configuration
                )
            )
            if not validation_result.success:
                return validation_result

            # Always generate fresh temporary credentials on validation.
            self.client.clear_credentials()
            # Steps 1-10 of the network validation: credentials, bucket,
            # region, object checks, sample pull and CSV validation.
            self.pull_sample_data()

            self.logger.debug(
                f"{self.log_prefix}: Successfully validated configuration "
                "parameters and the file path in the AWS S3 bucket."
            )
            return ValidationResult(
                success=True,
                message=(
                    "Successfully validated configuration parameters and "
                    "the file path in the AWS S3 bucket."
                ),
            )
        except AWSS3EDMException as error:
            # Already logged with details and resolution where it was raised.
            return ValidationResult(success=False, message=str(error))
        except Exception:
            err_msg = "Error occurred while connecting to AWS S3."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the authentication method, bucket, region "
                    "and file path are correct and AWS S3 is reachable."
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)

    @staticmethod
    def create_csv_directory(csv_file_path: str) -> None:
        """Create the directory for a CSV file.

        Args:
            csv_file_path (str): The file path to the CSV file.
        """
        if os.path.isfile(csv_file_path):
            os.remove(csv_file_path)
        else:
            directory_path = os.path.dirname(csv_file_path)
            if not os.path.exists(directory_path):
                os.makedirs(directory_path)

    def get_delimiter(self) -> str:
        """Get the delimiter from the configuration.

        Raises:
            AWSS3EDMException: If the delimiter is empty or not a single
                character.

        Returns:
            str: The delimiter.
        """
        delimiter = self._get_step_value("delimiter", ",")
        if not delimiter:
            raise self._build_error(
                "A valid Delimiter is not provided.",
                "Ensure that a single character Delimiter is provided in "
                "the configuration.",
                "validating the configuration parameters",
            )
        if len(delimiter) > 1:
            raise self._build_error(
                "Delimiter should be a single character.",
                "Ensure that a single character Delimiter is provided in "
                "the configuration.",
                "validating the configuration parameters",
            )
        return delimiter

    def _get_quoting(self) -> int:
        """Get the csv quoting mode from the Remove Quotes parameter.

        Returns:
            int: ``csv.QUOTE_ALL`` if Remove Quotes is enabled, else
                ``csv.QUOTE_NONE``.
        """
        if self._get_step_value("remove_quotes", False):
            return csv.QUOTE_ALL
        return csv.QUOTE_NONE

    def _get_column_names_only(
        self, csv_file_path: str, delimiter: str = ","
    ) -> dict:
        """Extract column names from the header of a CSV file.

        Args:
            csv_file_path (str): Path to the CSV file.
            delimiter (str): CSV delimiter (default: ",").

        Returns:
            dict: Dictionary containing column names. The list is empty
                when the header cannot be read.
        """
        try:
            with open(csv_file_path, "rb") as csv_file_object:
                hdr_raw = csv_file_object.readline()
                if not hdr_raw:
                    return {"columns": []}
                header = next(
                    csv.reader(
                        [hdr_raw.decode("UTF-8")],
                        delimiter=delimiter,
                        quoting=self._get_quoting(),
                    )
                )
                return {"columns": header}
        except FileNotFoundError:
            self.logger.debug(
                f"{self.log_prefix}: The sample file is not available yet, "
                "no column names to read."
            )
            return {"columns": []}
        except Exception as error:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while "
                    f"extracting column names. Error: {str(error)}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the file is a valid UTF-8 encoded "
                    "delimited file with a header row."
                ),
            )
            return {"columns": []}

    def _validate_column_count(self, columns: list) -> None:
        """Ensure the number of columns does not exceed the maximum.

        Args:
            columns (list): Column names of the file.

        Raises:
            AWSS3EDMException: If more than ``MAX_COLUMNS`` columns exist.
        """
        if len(columns) > MAX_COLUMNS:
            raise self._build_error(
                f"Maximum {MAX_COLUMNS} columns allowed. Reduce columns "
                "from the source file.",
                f"Ensure that the number of columns in the source file is "
                f"reduced, as it contains {len(columns)} columns which "
                f"exceeds the maximum allowed limit of {MAX_COLUMNS} "
                "columns.",
                "validating the file",
            )

    def validate_csv_file_records(
        self, csv_file_path: str, record_count: int = 0, delimiter: str = ","
    ) -> dict:
        """Validate the content of a CSV/TXT file.

        Opens the file in binary mode (rb/wb) so the write-back of the
        truncated sample is never re-quoted or modified by a csv.writer.

        Args:
            csv_file_path (str): The file path to the CSV/TXT file.
            record_count (int, optional): The maximum number of records to
                validate. If set to a positive value, only the first
                'record_count' records are validated and the file is
                truncated to them. If 0 (default), all records are
                validated.
            delimiter (str): CSV delimiter.

        Raises:
            AWSS3EDMException: If validation fails due to incorrect data
                or missing data.

        Returns:
            dict: A dictionary containing the header columns of the
                CSV/TXT file as a list.
        """
        encoding = "UTF-8"
        row_count = 0
        header = None
        # Stores raw bytes lines for the sample write-back.
        sample_raw_lines = []
        cur_line_box = [None]
        remove_quotes = self._get_quoting()

        def _char_encoder(binary_file):
            while True:
                line = binary_file.readline()
                if not line:
                    return
                cur_line_box[0] = line  # raw bytes for lossless write-back
                yield line.decode(encoding)

        try:
            with open(csv_file_path, "rb") as csv_file_object:
                hdr_raw = csv_file_object.readline()
                if not hdr_raw:
                    raise ValueError(
                        "At least 1 record must be present in the CSV/TXT "
                        "file in addition to header row."
                    )

                header = next(
                    csv.reader(
                        [hdr_raw.decode(encoding)],
                        delimiter=delimiter,
                        quoting=remove_quotes,
                    )
                )
                if any(cell.strip() == "" for cell in header):
                    raise ValueError(
                        "Column name in provided file should not "
                        "have an empty value."
                    )

                row_count = 1  # header counted
                csv_reader = csv.reader(
                    _char_encoder(csv_file_object),
                    delimiter=delimiter,
                    quoting=remove_quotes,
                )

                for row in csv_reader:
                    row_count += 1
                    if record_count and row_count > record_count + 1:
                        break
                    if record_count:
                        sample_raw_lines.append(cur_line_box[0])
                    if len(row) != len(header):
                        raise ValueError(
                            f"Row '{row_count}' does not contain the "
                            "correct number of columns."
                        )

                if row_count < 2:
                    raise ValueError(
                        "At least 1 record must be present in the CSV/TXT "
                        "file in addition to header row."
                    )

            # Write back only the validated sample rows (header + data).
            # Raw bytes are used so quoting is never altered.
            if record_count:
                with open(csv_file_path, "wb") as csv_file_object:
                    csv_file_object.write(hdr_raw)
                    for raw_line in sample_raw_lines:
                        csv_file_object.write(raw_line)

            return {"columns": header}
        except UnicodeDecodeError as error:
            raise self._csv_error(
                "The file is not valid UTF-8 encoded text.", error
            ) from error
        except (ValueError, csv.Error) as error:
            raise self._csv_error(str(error), error) from error

    def _csv_error(
        self, err_msg: str, error: Exception
    ) -> AWSS3EDMException:
        """Log a CSV validation failure and build the exception.

        Args:
            err_msg (str): Error message shown to the user.
            error (Exception): The original exception.

        Returns:
            AWSS3EDMException: Exception to raise.
        """
        err_msg = build_error_message("validating the file", err_msg)
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            resolution=(
                "Ensure that the CSV file provided in the configuration "
                "is valid. "
                "\n• The file should be UTF-8 encoded and contain at least "
                "1 record in addition to header row."
                "\n• Column name in provided file should not "
                "have an empty value."
                "\n• Each row should contain the correct number of "
                "columns as the header row."
                f"\n• Maximum {MAX_COLUMNS} columns allowed."
            ),
            details=traceback.format_exc(),
        )
        return AWSS3EDMException(value=error, message=err_msg)

    def validate_step(self, step: str) -> ValidationResult:
        """Validate the step for the plugin.

        Args:
            step (str): The step to validate.

        Returns:
            ValidationResult: The validation result.
        """
        result = ValidationResult(
            success=False,
            message="Validation failed.",
        )
        if step == "configuration":
            result = self.validate(self.configuration)
        elif step == "sanity_inputs":
            result = self._validate_sanity_inputs()
        elif step == "sanity_results":
            message = "Successfully validated preview sanitization results."
            self.logger.debug(f"{self.log_prefix}: {message}")
            result = ValidationResult(success=True, message=message)
        return result

    def _validate_sanity_inputs(self) -> ValidationResult:
        """Validate the sanitization step by sanitizing the sample.

        Returns:
            ValidationResult: The validation result.
        """
        message = (
            "Successfully validated hash generation and "
            "sanitization parameters."
        )
        self.logger.debug(f"{self.log_prefix}: {message}")
        input_path = f"{FILE_PATH}/{self.name}/{SAMPLE_CSV_FILE_NAME}"
        output_path = f"{FILE_PATH}/{self.name}"
        try:
            self.storage.update(
                {
                    "csv_path": input_path,
                    "sanitization_data_path": output_path,
                }
            )
            self.sanitize(file_name="sample", sample_data=True)
        except Exception:
            err_msg = "Error occurred while sanitizing the sample data."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution="Ensure that the sample data is valid.",
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)
        return ValidationResult(success=True, message=message)

    def pull_sample_data(self) -> dict:
        """Pull sample data from the file and validate it.

        Raises:
            AWSS3EDMException: If any error occurs during the sample data
                retrieval or validation.

        Returns:
            dict: contains csv validate result
        """
        self.logger.debug(f"{self.log_prefix}: Pulling sample data.")
        csv_file_path = f"{FILE_PATH}/{self.name}/{SAMPLE_CSV_FILE_NAME}"
        try:
            step_configuration = self._get_step1_config()
            self.storage["csv_path"] = csv_file_path
            self.create_csv_directory(csv_file_path)
            delimiter = self.get_delimiter()

            info = self.client.validate_object(step_configuration)
            self.client.pull_sample(step_configuration, info, csv_file_path)

            columns_data = self._validate_sample(csv_file_path, delimiter)
            self.logger.debug(
                f"{self.log_prefix}: Successfully pulled sample data."
            )
            return columns_data
        except AWSS3EDMException:
            remove_local_file(csv_file_path)
            raise
        except Exception as error:
            remove_local_file(csv_file_path)
            error_message = "Error occurred while pulling the sample data."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the file path is accessible in the AWS S3 "
                    "bucket and the Cloud Exchange host has enough disk "
                    "space."
                ),
            )
            raise AWSS3EDMException(
                value=error, message=error_message
            ) from error

    def _validate_sample(self, csv_file_path: str, delimiter: str) -> dict:
        """Validate the sample file and its number of columns.

        Args:
            csv_file_path (str): Local sample file path.
            delimiter (str): CSV delimiter.

        Returns:
            dict: Header columns of the sample.
        """
        columns_data = self.validate_csv_file_records(
            csv_file_path, SAMPLE_DATA_RECORD_COUNT, delimiter=delimiter
        )
        self._validate_column_count(columns_data.get("columns", []))
        return columns_data

    def _normalize_file_name(self) -> str:
        """Build the local file name (without extension) for the pull.

        Returns:
            str: ``{name}_data`` with spaces, tabs and dashes replaced.
        """
        return (
            f"{self.name}_data".replace(" ", "_")
            .replace("\t", "_")
            .replace("-", "_")
        )

    def _cleanup_files(self, output_dir: str) -> None:
        """Remove temporary local files, ignoring cleanup failures.

        The ``edm_hashes`` directory is preserved.

        Args:
            output_dir (str): Local working directory of the plugin.
        """
        if not os.path.isdir(output_dir):
            return
        try:
            self.remove_files(
                temp_edm_hash_dir_path=f"{output_dir}/temp_edm_hashes",
                input_file_dir=f"{output_dir}/input",
                output_path=output_dir,
            )
        except Exception:
            # remove_files has already logged the failure with details.
            self.logger.debug(
                f"{self.log_prefix}: Unable to remove the temporary files "
                f"of '{output_dir}'. Files may remain on disk until the "
                "next pull."
            )

    def _validate_pulled_file(
        self, csv_file_path: str, delimiter: str
    ) -> None:
        """Validate the full pulled file (header, rows and columns).

        Args:
            csv_file_path (str): Local file path.
            delimiter (str): CSV delimiter.
        """
        self.logger.info(f"{self.log_prefix}: Validating the file.")
        # Fail fast on the header before scanning the whole file.
        header = self._get_column_names_only(csv_file_path, delimiter)
        self._validate_column_count(header.get("columns", []))
        columns_data = self.validate_csv_file_records(
            csv_file_path, delimiter=delimiter
        )
        self._validate_column_count(columns_data.get("columns", []))
        self.logger.info(f"{self.log_prefix}: Successfully validated file.")

    def _prepare_hash_input(
        self,
        csv_file_path: str,
        output_dir: str,
        csv_file_name: str,
        is_unsanitized_data: bool,
    ) -> None:
        """Sanitize the file, or skip sanitization when configured.

        Args:
            csv_file_path (str): Local file path.
            output_dir (str): Local working directory.
            csv_file_name (str): Local file name without extension.
            is_unsanitized_data (bool): Proceed without sanitization.
        """
        if is_unsanitized_data:
            if not os.path.exists(csv_file_path):
                raise self._build_error(
                    f"Data file doesn't exist at {csv_file_path}.",
                    "Ensure that a valid CSV/TXT file is provided in the "
                    "configuration.",
                    "pulling the data",
                )
            os.rename(csv_file_path, f"{output_dir}/{csv_file_name}.good")
            self.logger.debug(
                f"{self.log_prefix}: Sanitization skipped for file "
                f"'{csv_file_name}' as Proceed Without Sanitization is "
                "enabled."
            )
            return
        self.logger.info(f"{self.log_prefix}: Sanitizing the data.")
        self.sanitize(csv_file_name)
        self.logger.info(f"{self.log_prefix}: Successfully sanitized data.")

    def _pull_and_hash(self, output_dir: str) -> dict:
        """Pull the file, validate it, sanitize it and hash it.

        Args:
            output_dir (str): Local working directory of the plugin.

        Returns:
            dict: Success message of the pull.
        """
        step_configuration = self._get_step1_config()
        is_unsanitized_data = self.configuration.get("sanity_results", {}).get(
            "is_unsanitized_data", True
        )
        if not step_configuration.get("filepath"):
            raise self._build_error(
                "A valid File Path is not provided.",
                "Ensure that the File Path of the file is provided in the "
                "configuration.",
                "pulling the data",
            )
        csv_file_name = self._normalize_file_name()
        self.storage["sanitization_data_path"] = output_dir
        self.create_directory(output_dir)
        # Delete stale local files of a previous (failed) run.
        self._cleanup_files(output_dir)

        delimiter = self.get_delimiter()
        bucket = step_configuration.get("bucket_name")
        key = step_configuration.get("filepath")
        self.logger.info(
            f"{self.log_prefix}: Pulling the file '{key}' from the AWS S3 "
            f"bucket '{bucket}'."
        )
        info = self.client.validate_object(step_configuration)
        csv_file_path = self.client.fetch_object(
            step_configuration, info, output_dir, csv_file_name
        )
        self.storage["csv_path"] = csv_file_path
        self.storage["file_name"] = os.path.basename(csv_file_path)
        self.logger.info(
            f"{self.log_prefix}: Successfully pulled the file '{key}' from "
            f"the AWS S3 bucket '{bucket}'."
        )

        self._validate_pulled_file(csv_file_path, delimiter)
        self._prepare_hash_input(
            csv_file_path, output_dir, csv_file_name, is_unsanitized_data
        )
        self.generate_csv_edm_hash(csv_file=csv_file_name)
        return {
            "message": "File pulled and EDM Hash generated successfully."
        }

    def pull(self) -> dict:
        """Pull and sanitize the CSV/TXT file from AWS S3.

        Temporary local files are removed even when the pull fails.

        Raises:
            AWSS3EDMException: If any error occurs during the data
                retrieval, validation, sanitization or hash generation.

        Returns:
            dict: Success message.
        """
        output_dir = f"{FILE_PATH}/{self.name}"
        try:
            return self._pull_and_hash(output_dir)
        except AWSS3EDMException:
            self._cleanup_files(output_dir)
            raise
        except Exception as error:
            self._cleanup_files(output_dir)
            error_message = "Error occurred while pulling the data."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the file path is accessible in the AWS S3 "
                    "bucket and the Cloud Exchange host has enough disk "
                    "space."
                ),
            )
            raise AWSS3EDMException(
                value=error, message=error_message
            ) from error

    def push(self):
        """Plugin is not push supported.

        Raises:
            NotImplementedError: Always.
        """
        self.logger.info(
            f"{self.log_prefix}: Push is not supported for this plugin."
        )
        raise NotImplementedError("Push is not supported for this plugin.")

    def sanitize(self, file_name: str = "", sample_data: bool = False) -> None:
        """Sanitize the data from a CSV/TXT file and store good & bad files.

        Args:
            file_name (str): The name of the output file.
            sample_data (bool): True to keep the input and bad files.

        Raises:
            AWSS3EDMException: If an error occurs during the
                sanitization process.
        """
        csv_file_path = self.storage.get("csv_path")
        try:
            delimiter = self.get_delimiter()
            sanitization_input = self.configuration.get(
                "sanity_inputs", {}
            ).get("sanitization_input", {})

            exclude_stopwords = self.configuration.get(
                "sanity_inputs", {}
            ).get("exclude_stopwords", False)

            # Prepare EDM input configuration based on sanitization input.
            edm_input_configuration = deepcopy(CONFIG_TEMPLATE)
            edm_input_configuration.update(
                {
                    "names": [
                        field_input.get("field", "")
                        for field_input in sanitization_input
                        if field_input.get("nameColumn", False)
                    ]
                }
            )
            edm_input_configuration.update({"delimiter": delimiter})
            if (
                "stopwords" in edm_input_configuration
                and not exclude_stopwords
            ):
                del edm_input_configuration["stopwords"]

            sanitization_output_path = self.storage.get(
                "sanitization_data_path"
            )
            sanitization_output_file = (
                f"{sanitization_output_path}/{file_name}"
            )

            if not csv_file_path or not os.path.isfile(csv_file_path):
                raise self._build_error(
                    f"Data file doesn't exist at {csv_file_path} "
                    "for sanitization.",
                    "Ensure that a valid CSV/TXT file is provided in the "
                    "configuration.",
                    "sanitizing the data",
                )

            for file_extension in ["good", "bad"]:
                file_path = f"{sanitization_output_file}.{file_extension}"
                if os.path.isfile(file_path):
                    os.remove(file_path)

            if not os.path.exists(sanitization_output_path):
                os.makedirs(sanitization_output_path)
            edm_input_configuration["remove-quotes"] = (
                self._get_step_value("remove_quotes", False)
            )
            run_sanitizer(
                csv_file_path,
                sanitization_output_file,
                edm_input_configuration,
            )
            if not sample_data:
                if os.path.exists(csv_file_path):
                    os.remove(csv_file_path)
                if os.path.exists(f"{sanitization_output_file}.bad"):
                    os.remove(f"{sanitization_output_file}.bad")
        except AWSS3EDMException:
            raise
        except Exception as error:
            error_message = (
                "Error occurred while sanitizing "
                f"the data at {csv_file_path}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the sanitization parameters and the "
                    "data file are valid."
                ),
            )
            raise AWSS3EDMException(
                value=error, message=error_message
            ) from error

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get list of supported actions.

        Returns:
            List[ActionWithoutParams]: List of actions.
        """
        return []

    def get_action_fields(self, action: Action) -> List:
        """Get list of fields to be rendered in UI.

        Args:
            action (Action): Action object

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
        return ValidationResult(success=True, message="Validation successful.")

    def create_directory(self, dir_path: str) -> None:
        """Create a directory including all necessary parent directories.

        Args:
            dir_path (str): The path of the directory to be created.

        Raises:
            AWSS3EDMException: If there's an issue creating the directory.
        """
        try:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
        except Exception as error:
            err_msg = (
                "Error occurred while creating nested directories to "
                "store sanitized data or EDM hashes."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Cloud Exchange host has permission to "
                    "create directories."
                ),
            )
            raise AWSS3EDMException(
                value=error, message=err_msg
            ) from error

    def get_field_indices(self, sanity_inputs: dict) -> tuple:
        """Get the indices of fields based on normalization and sensitivity.

        Args:
            sanity_inputs (dict): Sanitization inputs with field info.

        Returns:
            tuple: Four comma separated index strings:
                 - case sensitive indices
                 - case insensitive indices
                 - number normalization indices
                 - string normalization indices
        """
        try:
            string_case_sensitive_indices = []
            string_case_insensitive_indices = []
            number_indices = []
            string_indices = []

            for index, field_info in enumerate(
                sanity_inputs.get("sanitization_input", [])
            ):
                if field_info.get("normalization", "") == "number":
                    number_indices.append(index)
                elif field_info.get("normalization", "") == "string":
                    string_indices.append(index)

                if field_info.get("caseSensitivity", "") == "sensitive":
                    string_case_sensitive_indices.append(index)
                elif field_info.get("caseSensitivity", "") == "insensitive":
                    string_case_insensitive_indices.append(index)
            string_cs = ",".join(map(str, string_case_sensitive_indices))
            string_cins = ",".join(map(str, string_case_insensitive_indices))
            num_norm = ",".join(map(str, number_indices))
            str_norm = ",".join(map(str, string_indices))

            return string_cs, string_cins, num_norm, str_norm
        except Exception as error:
            error_message = (
                "Error occurred while getting indices from sanity input "
                "fields based on normalization and sensitivity."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the sanitization parameters are valid."
                ),
            )
            raise AWSS3EDMException(
                value=error, message=error_message
            ) from error

    def remove_files(
        self,
        temp_edm_hash_dir_path: str,
        input_file_dir: str,
        output_path: str,
    ) -> None:
        """Remove files and temp EDM hashes after EDM hash generation.

        The ``edm_hashes`` directory is preserved.

        Args:
            temp_edm_hash_dir_path (str): Temporary EDM Hash Path
            input_file_dir (str): Input File Path
            output_path (str): Path where all files are located

        Raises:
            AWSS3EDMException: If there's an issue removing files.
        """
        try:
            if os.path.exists(temp_edm_hash_dir_path):
                shutil.rmtree(temp_edm_hash_dir_path)
            if os.path.exists(input_file_dir):
                shutil.rmtree(input_file_dir)
            for file in os.listdir(output_path):
                file_path = os.path.join(output_path, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
        except Exception as error:
            err_msg = "Error occurred while removing files."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Cloud Exchange host has permission to "
                    "delete the temporary files."
                ),
            )
            raise AWSS3EDMException(
                value=error, message=err_msg
            ) from error

    def _build_edm_hash_config(
        self, input_csv_file: str, output_dir_path: str
    ) -> dict:
        """Build the EDM hash generator configuration.

        Args:
            input_csv_file (str): Path of the sanitized CSV file.
            output_dir_path (str): Directory for the generated hashes.

        Returns:
            dict: EDM hash configuration.
        """
        sanity_inputs = self.configuration.get("sanity_inputs", {})
        dict_cs, dict_cins, norm_num, norm_str = self.get_field_indices(
            sanity_inputs
        )
        edm_hash_config = deepcopy(EDM_HASH_CONFIG)
        edm_hash_config.update(
            {
                "delimiter": self.get_delimiter(),
                "dict_cs": dict_cs,
                "dict_cins": dict_cins,
                "norm_num": norm_num,
                "norm_str": norm_str,
                "input_csv": input_csv_file,
                "output_dir": output_dir_path,
                "remove_quotes": self._get_step_value(
                    "remove_quotes", False
                ),
            }
        )
        return edm_hash_config

    def _store_hash_result(
        self,
        metadata_file: str,
        output_path: str,
        temp_edm_hash_dir_path: str,
    ) -> None:
        """Move the generated hashes and record them in storage.

        Args:
            metadata_file (str): Name of the generated ``.tgz`` file.
            output_path (str): Local working directory.
            temp_edm_hash_dir_path (str): Temporary hash directory.
        """
        edm_hash_dir_path = f"{output_path}/edm_hashes"
        if os.path.exists(edm_hash_dir_path):
            shutil.rmtree(edm_hash_dir_path)
        self.create_directory(dir_path=edm_hash_dir_path)
        temp_metadata_file = f"{output_path}/{metadata_file}"
        if os.path.exists(temp_metadata_file):
            shutil.move(temp_metadata_file, f"{edm_hash_dir_path}/")
        self.storage["edm_hash_folder"] = edm_hash_dir_path
        self.storage["edm_hash_available"] = True
        metadata_file = metadata_file.replace(".tgz", ".json")
        temp_metadata_file = f"{temp_edm_hash_dir_path}/{metadata_file}"
        edm_hash_cfg = f"{edm_hash_dir_path}/{metadata_file}"
        if os.path.exists(temp_metadata_file):
            shutil.move(temp_metadata_file, f"{edm_hash_dir_path}/")
        if os.path.exists(edm_hash_cfg):
            self.storage["edm_hashes_cfg"] = edm_hash_cfg

    def generate_csv_edm_hash(self, csv_file: str) -> None:
        """Generate EDM Hashes from sanitized data.

        Args:
            csv_file (str): Local file name without extension.

        Raises:
            AWSS3EDMException: If an error occurs while generating EDM
                hashes.
        """
        try:
            self.logger.info(
                message=f"{self.log_prefix}: Generating EDM Hashes."
            )
            csv_storage_path = self.storage.get("csv_path")
            if not csv_storage_path:
                raise self._build_error(
                    "CSV path is not available for EDM hash generation.",
                    "Ensure that the file was pulled successfully.",
                    "generating the EDM hash",
                )
            output_path = os.path.dirname(csv_storage_path)

            good_csv_path = f"{output_path}/{csv_file}.good"
            input_file_dir = f"{output_path}/input"
            self.create_directory(dir_path=input_file_dir)
            input_csv_file = f"{input_file_dir}/{csv_file}.csv"
            shutil.move(good_csv_path, input_csv_file)

            temp_edm_hash_dir_path = f"{output_path}/temp_edm_hashes"
            self.create_directory(dir_path=temp_edm_hash_dir_path)

            edm_hash_config = self._build_edm_hash_config(
                input_csv_file, temp_edm_hash_dir_path
            )
            status, metadata_file = generate_edm_hash(
                conf_name=self._name, edm_conf=edm_hash_config
            )
            if os.path.exists(input_file_dir):
                shutil.rmtree(input_file_dir)
            if status is not True:
                self.storage["edm_hash_available"] = False
                raise self._build_error(
                    "Error occurred while generating EDM Hash.",
                    "Ensure that the pulled file is a valid CSV/TXT file.",
                    "generating the EDM hash",
                )
            self._store_hash_result(
                metadata_file, output_path, temp_edm_hash_dir_path
            )
            self.remove_files(
                temp_edm_hash_dir_path, input_file_dir, output_path
            )
            self.logger.info(
                message=f"{self.log_prefix}: EDM Hash generated successfully."
            )
        except Exception as error:
            if self.storage.get("csv_path"):
                self._cleanup_files(os.path.dirname(self.storage["csv_path"]))
            if isinstance(error, AWSS3EDMException):
                raise
            err_msg = "Error occurred while generating EDM Hash."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the pulled file is a valid CSV/TXT file "
                    "and the sanitization parameters are valid."
                ),
            )
            raise AWSS3EDMException(
                value=error, message=err_msg
            ) from error

    def get_fields(self, name: str, configuration: dict) -> list:
        """Get the fields of a dynamic step.

        The ``configuration`` step returns ALL fields for every
        authentication method (the Roles Anywhere fields carry a condition
        so the UI hides them), because the diagnose redactor only removes
        the keys it can enumerate from here. The name and storage of the
        plugin may be None; nothing here uses the proxy, database or
        network.

        Args:
            name (str): The name of the step.
            configuration (dict): Configuration parameters dictionary.

        Raises:
            NotImplementedError: If the step name is not supported.

        Returns:
            list: List of fields of the step.
        """
        if name not in AWS_S3_EDM_FIELDS:
            raise NotImplementedError()
        fields = deepcopy(AWS_S3_EDM_FIELDS[name])
        if name == "sanity_inputs":
            for field in fields:
                if field.get("type") == "sanitization_input":
                    input_path = (
                        f"{FILE_PATH}/{self.name}/{SAMPLE_CSV_FILE_NAME}"
                    )
                    if self.storage is not None:
                        self.storage.update({"csv_path": input_path})
                    field["default"] = self._get_column_names_only(
                        input_path, self.get_delimiter()
                    )
        elif name == "sanity_results":
            for field in fields:
                if field.get("type") == "sanitization_preview":
                    field["default"] = {
                        "sanitizationStatus": True,
                        "message": "Sanitization Done Successfully",
                    }
        return fields
