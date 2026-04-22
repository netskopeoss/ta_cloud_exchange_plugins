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

Amazon Security Lake Batch Manager.

This module implements a robust batch processing system for uploading data to
Amazon Security Lake with the following key features:

- Fresh data priority: Current staging data is uploaded before pending files
- No data loss: Failed uploads are preserved as pending files for retry
- Consolidation: Small pending files are combined to meet AWS's 256MB minimum
- Size limits: Batches are capped at 512MB for Python memory efficiency
"""

import os
import re
import glob
import time
import json
import pyarrow as pa
import pyarrow.parquet as pq
import fasteners
import traceback

from .amazon_security_lake_exceptions import AmazonSecurityLakeException
from .amazon_security_lake_client import AmazonSecurityLakeClient
from .amazon_security_lake_constants import (
    STAGING_DIR,
    MAX_FILE_SIZE_BYTES,
    MAX_FILE_AGE_MINUTES,
    FILE_SUFFIX_UNSAFE_CHARS_PATTERN,
    PENDING_FILE_PREFIX,
    MIN_UPLOAD_SIZE_BYTES,
    MAX_BATCH_SIZE_BYTES,
    INVALID_FILE_SUFFIX,
)


class ParquetBatchWriter:
    """
    Manages batch writing of data to Amazon Security Lake with process-safe
    locking, threshold-based uploads, and retry handling for failed uploads.
    
    File States:
        - Staging: Active file receiving new data (staging_data_{suffix}.json)
        - Pending: Frozen files waiting for upload (pending_{suffix}_{timestamp}.json)
    
    Upload Flow:
        1. Append new data to staging file
        2. If staging threshold met → upload staging (fresh data first)
           - Success: Delete staging, process pending files
           - Failure: Freeze staging to pending, stop
        3. If staging threshold not met → process pending files
        4. For pending files: combine if needed, upload, retry on failure
    """

    def __init__(
        self,
        aws_client: AmazonSecurityLakeClient,
        logger,
        log_prefix: str,
        subtype: str,
        s3_location: str,
        provider_role_arn=None,
        custom_source_name=None,
    ):
        """Initialize ParquetBatchWriter.

        Args:
            aws_client (AmazonSecurityLakeClient): Client for AWS operations.
            logger (logging.Logger): Logger object.
            log_prefix (str): Log prefix for messages.
            subtype (str): Data subtype for file separation (e.g., 'dlp', 'c2').
            s3_location (str): Destination S3 location for uploads.
            provider_role_arn (str, optional): Provider role ARN for cross-account uploads.
            custom_source_name (str, optional): Custom source name for logging.
        """
        self.aws_client = aws_client
        self.subtype = subtype
        self.s3_location = s3_location
        self.custom_source_name = custom_source_name
        self.provider_role_arn = provider_role_arn
        os.makedirs(STAGING_DIR, exist_ok=True)
        self.logger = logger

        # Calculate file_suffix before enriching log_prefix
        normalized_subtype = subtype.lower().replace(" ", "").replace("-", "")
        raw_suffix = f"{log_prefix}_{normalized_subtype}"
        self.file_suffix = self._sanitize_file_suffix(raw_suffix)

        # Enrich log_prefix with subtype for readable logs
        self.log_prefix = f"{log_prefix} [{subtype}]"

    # File Path Helpers

    def _get_staging_json_path(self, file_suffix):
        """Get path for active staging file."""
        return os.path.join(STAGING_DIR, f"staging_data_{file_suffix}.json")

    def _get_lock_path(self, file_suffix):
        """Get path for inter-process lock file."""
        return os.path.join(STAGING_DIR, f"json_writer_{file_suffix}.lock")

    def _get_metadata_path(self, file_suffix):
        """Get path for staging metadata file."""
        return os.path.join(STAGING_DIR, f"staging_metadata_{file_suffix}.json")

    def _get_pending_file_path(self, file_suffix, timestamp):
        """Get path for a pending file with given timestamp.
        
        Args:
            file_suffix: Sanitized file suffix.
            timestamp: Epoch timestamp (int or float).
        Returns:
            str: Full path to pending file.
        """
        return os.path.join(
            STAGING_DIR,
            f"{PENDING_FILE_PREFIX}{file_suffix}_{int(timestamp)}.json"
        )

    def _sanitize_file_suffix(self, raw_suffix):
        """Sanitize file suffix to ensure safe filesystem characters.

        Replaces unsafe characters with underscore, collapses consecutive
        underscores, and strips leading/trailing underscores.

        Args:
            raw_suffix: The raw suffix string to sanitize.
        Returns:
            str: Sanitized suffix safe for use in file paths.
        """
        sanitized = re.sub(FILE_SUFFIX_UNSAFE_CHARS_PATTERN, "_", raw_suffix)
        sanitized = re.sub(r"_+", "_", sanitized)
        sanitized = sanitized.strip("_")
        return sanitized

    # Pending File Operations

    def _list_pending_files(self, file_suffix):
        """List all pending files for this suffix, sorted oldest first.
        
        Args:
            file_suffix: Sanitized file suffix.
        Returns:
            list: List of tuples (filepath, timestamp, size_bytes) sorted by timestamp.
        """
        pattern = os.path.join(
            STAGING_DIR,
            f"{PENDING_FILE_PREFIX}{file_suffix}_*.json"
        )
        pending_files = []
        
        for filepath in glob.glob(pattern):
            try:
                # Extract timestamp from filename
                # Format: pending_{suffix}_{timestamp}.json
                filename = os.path.basename(filepath)
                # Remove prefix and suffix to get timestamp
                timestamp_str = filename.replace(
                    f"{PENDING_FILE_PREFIX}{file_suffix}_", ""
                ).replace(".json", "")
                timestamp = int(timestamp_str)
                size_bytes = os.path.getsize(filepath)
                pending_files.append((filepath, timestamp, size_bytes))
            except (ValueError, OSError) as e:
                self.logger.error(
                    f"{self.log_prefix}: Skipping invalid pending file "
                    f"'{filepath}': {str(e)}"
                )
                continue
        
        # Sort by timestamp (oldest first)
        pending_files.sort(key=lambda x: x[1])
        return pending_files

    def _freeze_staging_to_pending(self, staging_json_file, metadata_file, file_suffix):
        """Convert staging file to pending file.
        
        Renames the staging file to a pending file with current timestamp,
        and deletes the metadata file (no longer needed for pending files).
        
        Args:
            staging_json_file: Path to staging JSON file.
            metadata_file: Path to metadata file.
            file_suffix: Sanitized file suffix.
        Returns:
            str: Path to the new pending file, or None if staging file doesn't exist.
        """
        if not os.path.exists(staging_json_file):
            return None
        
        pending_file = self._get_pending_file_path(file_suffix, time.time())
        
        try:
            os.rename(staging_json_file, pending_file)
            self.logger.info(
                f"{self.log_prefix}: Frozen staging file to pending: "
                f"{os.path.basename(pending_file)}"
            )
            
            # Delete metadata file (not needed for pending files)
            if os.path.exists(metadata_file):
                os.remove(metadata_file)
            
            return pending_file
        except OSError as e:
            self.logger.error(
                f"{self.log_prefix}: Failed to freeze staging file: {str(e)}"
            )
            return None

    # Data Conversion Helpers

    def _list_of_dicts_to_table(self, list_of_dicts):
        """Convert a list of dicts to columnar format (dict with lists).
        
        Transforms row-oriented data (list of dicts) into column-oriented data
        (dict of lists) for efficient storage and Parquet compatibility.
        
        Conversion Algorithm:
            1. Collect all unique keys across all dictionaries
            2. Initialize empty list for each key
            3. For each dictionary, append value for each key (None if missing)
            4. Result: dict where each key maps to a list of values
        
        Example:
            Input (2 rows, sparse keys):
                [
                    {"A": 1, "B": 2},
                    {"A": 3, "C": 4}
                ]
            
            Step 1 - Collect all keys:
                all_keys = {"A", "B", "C"}
            
            Step 2 - Initialize table:
                {"A": [], "B": [], "C": []}
            
            Step 3 - Process first dict {"A": 1, "B": 2}:
                {"A": [1], "B": [2], "C": [None]}
            
            Step 4 - Process second dict {"A": 3, "C": 4}:
                {"A": [1, 3], "B": [2, None], "C": [None, 4]}
            
            Final Result:
                {"A": [1, 3], "B": [2, None], "C": [None, 4]}
        
        Args:
            list_of_dicts: List of dicts to convert.
        Returns:
            dict: Columnar format with keys mapping to lists of values.
        """
        if not list_of_dicts:
            return {}
        
        table = {}
        all_keys = set()
        for d in list_of_dicts:
            all_keys.update(d.keys())
        
        for key in all_keys:
            table[key] = []
        
        for d in list_of_dicts:
            for key in all_keys:
                table[key].append(d.get(key, None))
        
        return table

    def _merge_columnar_data(self, base_data, new_data):
        """Merge two columnar datasets with schema evolution support.
        
        Handles columns that exist in one dataset but not the other by
        padding with None values to maintain consistent row counts.
        
        Merge Algorithm:
            1. For columns in new_data that exist in base_data:
               - Append new values to existing column lists
            2. For columns in new_data that DON'T exist in base_data:
               - Backfill existing rows with None, then add new values
            3. For columns in base_data that are missing from new_data:
               - Pad with None for the new rows
            4. Validate all columns have equal length (done by caller)
        
        Example:
            Existing base data (2 rows):
                {"A": [1, 2], "B": [3, 4]}
            
            New incoming data (1 row):
                {"A": [5], "C": [6]}
            
            Step 1 - Column A exists in both, append new values:
                {"A": [1, 2, 5]}
            
            Step 2 - Column C is new, backfill previous rows (length of base_data) with None, then add:
                {"A": [1, 2, 5], "C": [None, None, 6]}
            
            Step 3 - Column B missing from new data, pad rows (length of new data) with None:
                {"A": [1, 2, 5], "B": [3, 4, None], "C": [None, None, 6]}
            
            Final Result (3 rows, 3 columns, all equal length):
                {"A": [1, 2, 5], "B": [3, 4, None], "C": [None, None, 6]}
        
        Args:
            base_data: Existing columnar data (dict of lists).
            new_data: New columnar data to merge (dict of lists).
        Returns:
            dict: Merged columnar data.
        """
        if not base_data:
            return new_data.copy() if new_data else {}
        if not new_data:
            return base_data.copy()
        
        merged = {}
        base_row_count = len(next(iter(base_data.values()))) if base_data else 0
        new_row_count = len(next(iter(new_data.values()))) if new_data else 0
        
        all_keys = set(base_data.keys()) | set(new_data.keys())
        
        for key in all_keys:
            if key in base_data and key in new_data:
                # Column exists in both - concatenate
                merged[key] = base_data[key] + new_data[key]
            elif key in base_data:
                # Column only in base - pad new rows with None
                merged[key] = base_data[key] + [None] * new_row_count
            else:
                # Column only in new - backfill base rows with None
                merged[key] = [None] * base_row_count + new_data[key]
        
        return merged

    def _validate_columnar_data(self, data):
        """Validate that all columns have equal length.
        
        Args:
            data: Columnar data (dict of lists).
        Returns:
            bool: True if valid, False otherwise.
        """
        if not data:
            return True
        lengths = [len(v) for v in data.values()]
        return len(set(lengths)) <= 1

    # Orphan Cleanup

    def _cleanup_orphaned_files(self, staging_json_file, metadata_file):
        """Clean up orphaned files from previous crashes.

        Handles:
        1. Orphaned metadata without staging file - removes metadata
        2. Orphaned staging file without metadata - resets metadata

        Args:
            staging_json_file: Path to the staging JSON file.
            metadata_file: Path to the metadata file.
        """
        if os.path.exists(metadata_file) and not os.path.exists(staging_json_file):
            self.logger.info(
                f"{self.log_prefix}: Found orphaned metadata file "
                "(staging file missing). Cleaning up."
            )
            os.remove(metadata_file)

        if os.path.exists(staging_json_file) and not os.path.exists(metadata_file):
            self.logger.info(
                f"{self.log_prefix}: Found orphaned staging file "
                "(metadata missing). Resetting metadata with current timestamp."
            )
            with open(metadata_file, 'w') as f:
                json.dump({'creation_timestamp': time.time()}, f)

    # Staging File Operations

    def _append_to_staging(self, new_data, file_suffix):
        """Append new data to staging file.
        
        Creates staging file if it doesn't exist, otherwise merges with
        existing data using schema evolution.
        
        Args:
            new_data: New data to append (list of dicts).
            file_suffix: Sanitized file suffix.
        Returns:
            tuple: (staging_json_file, metadata_file, current_data, creation_timestamp)
        """
        staging_json_file = self._get_staging_json_path(file_suffix)
        metadata_file = self._get_metadata_path(file_suffix)
        
        self._cleanup_orphaned_files(staging_json_file, metadata_file)
        
        new_data_columns = self._list_of_dicts_to_table(new_data)
        current_data = {}
        creation_timestamp = time.time()
        
        if not os.path.exists(staging_json_file):
            # New batch
            current_data = new_data_columns
            with open(metadata_file, 'w') as f:
                json.dump({'creation_timestamp': creation_timestamp}, f)
            self.logger.info(
                f"{self.log_prefix}: Created new staging file. "
                f"Records: {len(next(iter(current_data.values()))) if current_data else 0}"
            )
        else:
            # Existing batch - load and merge
            try:
                with open(staging_json_file, 'r') as f:
                    current_data = json.load(f)
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                creation_timestamp = metadata.get('creation_timestamp', time.time())
            except json.JSONDecodeError as e:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Corrupted staging file. "
                        f"Quarantining and starting fresh. Error: {str(e)}"
                    ),
                    resolution=(
                        "The staging file is corrupted. The file has been "
                        "quarantined and a new staging file has been created."
                        "Please re-validate the mapping file and check if data "
                        "in the staging file is formatted correctly."
                    ),
                )
                # Quarantine corrupted files
                for filepath in [staging_json_file, metadata_file]:
                    if os.path.exists(filepath):
                        invalid_path = filepath + INVALID_FILE_SUFFIX
                        try:
                            os.rename(filepath, invalid_path)
                            self.logger.info(
                                f"{self.log_prefix}: Quarantined corrupt file: "
                                f"'{os.path.basename(filepath)}' -> '{os.path.basename(invalid_path)}'"
                            )
                        except OSError as rename_err:
                            self.logger.error(
                                f"{self.log_prefix}: Failed to quarantine corrupt file "
                                f"'{filepath}': {str(rename_err)}. Removing file."
                            )
                            try:
                                os.remove(filepath)
                            except OSError:
                                pass
                
                current_data = new_data_columns
                creation_timestamp = time.time()
                with open(metadata_file, 'w') as f:
                    json.dump({'creation_timestamp': creation_timestamp}, f)
            else:
                # Merge data
                current_data = self._merge_columnar_data(current_data, new_data_columns)
                
                # Validate merged data
                if not self._validate_columnar_data(current_data):
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Schema inconsistency after merge. "
                            "Resetting to current data only."
                        ),
                        resolution=(
                            "Schema inconsistency after merge detected. "
                            "Staging file has been reset to the current data only."
                            "Please re-validate the mapping file and check if data "
                            "in the staging file is formatted correctly."
                        ),
                    )
                    if os.path.exists(staging_json_file):
                        os.remove(staging_json_file)
                    if os.path.exists(metadata_file):
                        os.remove(metadata_file)
                    
                    current_data = new_data_columns
                    creation_timestamp = time.time()
                    with open(metadata_file, 'w') as f:
                        json.dump({'creation_timestamp': creation_timestamp}, f)
        
        # Write updated data
        with open(staging_json_file, 'w') as f:
            json.dump(current_data, f)
        
        return staging_json_file, metadata_file, current_data, creation_timestamp

    def _check_staging_threshold(self, staging_json_file, creation_timestamp):
        """Check if staging file meets upload threshold.
        
        Args:
            staging_json_file: Path to staging JSON file.
            creation_timestamp: When the staging batch was created.
        Returns:
            tuple: (threshold_met, size_bytes, age_seconds, size_met, age_met)
        """
        size_bytes = os.path.getsize(staging_json_file)
        age_seconds = time.time() - creation_timestamp
        
        size_met = size_bytes >= MAX_FILE_SIZE_BYTES
        age_met = age_seconds >= (MAX_FILE_AGE_MINUTES * 60)
        threshold_met = size_met or age_met
        
        return threshold_met, size_bytes, age_seconds, size_met, age_met

    # Upload Operations

    def _upload_data_to_s3(self, data):
        """Convert columnar data to Parquet and upload to S3.
        
        Takes data directly in memory, avoiding redundant file I/O.
        Handles 'unmapped' column specially to ensure consistent MAP<STRING, STRING>
        schema across all batches.
        
        Args:
            data: Columnar data dict (keys -> lists of values).
        Returns:
            bool: True if upload succeeded, False otherwise.
        """
        parquet_path = None
        try:
            if not data:
                self.logger.error(
                    f"{self.log_prefix}: Empty data, skipping upload."
                )
                return True  # Consider empty as "success" to allow cleanup

            record_count = len(next(iter(data.values()))) if data else 0
            
            # Create table for all standard columns (PyArrow infers schema)
            if data:
                table = pa.table(data)
            else:
                table = None

            # Create temp file path
            os.makedirs(STAGING_DIR, exist_ok=True)
            parquet_path = os.path.join(
                STAGING_DIR,
                f"temp_{os.getpid()}_{int(time.time() * 1000)}.parquet"
            )
            
            pq.write_table(table, parquet_path, compression='zstd')
            
            parquet_size_mb = os.path.getsize(parquet_path) / 1024**2
            self.logger.info(
                f"{self.log_prefix}: Created Parquet file. "
                f"Size: {parquet_size_mb:.2f} MB, Records: {record_count}"
            )

            self.aws_client.upload_file_to_s3(
                parquet_path,
                s3_location=self.s3_location,
                provider_role_arn=self.provider_role_arn,
                custom_source_name=self.custom_source_name,
            )

            self.logger.info(
                f"{self.log_prefix}: Successfully uploaded to S3."
            )
            return True
            
        except AmazonSecurityLakeException as e:
            self.logger.error(
                f"{self.log_prefix}: Upload failed: {str(e)}"
            )
            return False
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Upload failed: {str(e)}",
                details=str(traceback.format_exc()),
            )
            return False
        finally:
            # Always clean up temp parquet file
            if parquet_path and os.path.exists(parquet_path):
                try:
                    os.remove(parquet_path)
                except Exception:
                    pass

    def _load_pending_file(self, filepath):
        """Load a pending JSON file, quarantining if corrupted.
        
        Args:
            filepath: Path to the pending JSON file.
        Returns:
            dict: Loaded columnar data, or None if file is corrupt/missing.
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            return data
        except json.JSONDecodeError as e:
            # Quarantine corrupt file
            invalid_path = filepath + INVALID_FILE_SUFFIX
            self.logger.error(
                f"{self.log_prefix}: Corrupted pending file detected: "
                f"'{os.path.basename(filepath)}'. Error: {str(e)}. "
                f"Quarantining to {INVALID_FILE_SUFFIX}"
            )
            try:
                os.rename(filepath, invalid_path)
                self.logger.info(
                    f"{self.log_prefix}: Quarantined corrupt file: "
                    f"'{os.path.basename(filepath)}' -> '{os.path.basename(invalid_path)}'"
                )
            except OSError as rename_err:
                self.logger.error(
                    f"{self.log_prefix}: Failed to quarantine corrupt file "
                    f"'{filepath}': {str(rename_err)}"
                )
            return None
        except OSError as e:
            self.logger.error(
                f"{self.log_prefix}: Failed to read pending file "
                f"'{filepath}': {str(e)}"
            )
            return None

    # Pending File Batch Processing

    def _build_upload_batch(self, pending_files):
        """Build an upload batch from pending files, loading data into memory.
        
        Determines which files to include in the batch based on size thresholds,
        loads them into memory, and returns the combined data. Does NOT write
        any intermediate files - that's deferred until upload failure (if needed).
        
        Args:
            pending_files: List of (filepath, timestamp, size_bytes) tuples, oldest first.
        Returns:
            tuple: (combined_data, source_files, is_consolidated) where:
                - combined_data: Merged columnar data dict (or None if no valid batch)
                - source_files: List of (filepath, timestamp, size_bytes) included in batch
                - is_consolidated: True if multiple files were merged
            Returns (None, [], False) if no batch is ready or all files are corrupt.
        """
        if not pending_files:
            return None, [], False
        
        _, oldest_ts, _ = pending_files[0]
        
        # Determine which files to include in this batch
        files_to_include = []
        cumulative_size = 0
        
        for filepath, timestamp, size_bytes in pending_files:
            # Check if adding this file would exceed max batch size
            if cumulative_size > 0 and cumulative_size + size_bytes > MAX_BATCH_SIZE_BYTES:
                # Stop here - don't exceed the cap
                break
            
            files_to_include.append((filepath, timestamp, size_bytes))
            cumulative_size += size_bytes
        
        # Check if we have enough data to upload
        oldest_pending_age_minutes = (time.time() - oldest_ts) / 60
        force_upload = oldest_pending_age_minutes >= MAX_FILE_AGE_MINUTES
        
        if cumulative_size < MIN_UPLOAD_SIZE_BYTES and not force_upload:
            self.logger.info(
                f"{self.log_prefix}: Pending batch too small "
                f"({cumulative_size / 1024**2:.2f} MB < {MIN_UPLOAD_SIZE_BYTES / 1024**2:.0f} MB). "
                f"Oldest age: {oldest_pending_age_minutes:.1f}m. Waiting for more data."
            )
            return None, [], False
        
        if force_upload and cumulative_size < MIN_UPLOAD_SIZE_BYTES:
            self.logger.info(
                f"{self.log_prefix}: Force uploading pending batch "
                f"({cumulative_size / 1024**2:.2f} MB) - oldest file exceeds "
                f"{MAX_FILE_AGE_MINUTES}m age threshold."
            )
        
        # Load files into memory
        is_consolidated = len(files_to_include) > 1
        combined_data = {}
        valid_source_files = []
        
        if is_consolidated:
            self.logger.info(
                f"{self.log_prefix}: Loading {len(files_to_include)} "
                f"pending files for consolidation ({cumulative_size / 1024**2:.2f} MB total)."
            )
        
        for filepath, timestamp, size_bytes in files_to_include:
            try:
                file_data = self._load_pending_file(filepath)
                if file_data is None:
                    # File was corrupt and quarantined, skip it
                    continue
                
                combined_data = self._merge_columnar_data(combined_data, file_data)
                valid_source_files.append((filepath, timestamp, size_bytes))
            except Exception as e:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to process pending file "
                        f"'{os.path.basename(filepath)}'. Marking as invalid. Error: {str(e)}"
                    ),
                    resolution=(
                        "The pending file could not be processed and has been quarantined. "
                        f"File renamed with suffix {INVALID_FILE_SUFFIX}. "
                        "Validate the mapping configuration and upstream data."
                    ),
                    details=str(traceback.format_exc()),
                )
                invalid_path = filepath + INVALID_FILE_SUFFIX
                try:
                    if os.path.exists(filepath):
                        os.rename(filepath, invalid_path)
                        self.logger.info(
                            f"{self.log_prefix}: Quarantined corrupt file: "
                            f"'{os.path.basename(filepath)}' -> '{os.path.basename(invalid_path)}'"
                        )
                except OSError as rename_err:
                    self.logger.error(
                        f"{self.log_prefix}: Failed to quarantine file "
                        f"'{filepath}': {str(rename_err)}"
                    )
        
        # Check if we got any valid data
        if not combined_data:
            self.logger.error(
                f"{self.log_prefix}: No valid data after loading pending files. "
                "All files may be corrupt."
            )
            return None, [], False
        
        # Validate merged data schema
        if not self._validate_columnar_data(combined_data):
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Schema inconsistency in merged data. "
                    "Marking source files as invalid."
                ),
                resolution=(
                    "Schema inconsistency in merged data detected. "
                    "All source files have been quarantined."
                    "Please re-validate the mapping file and check if data "
                    "in the source files is formatted correctly."
                ),
            )
            for filepath, _, _ in valid_source_files:
                invalid_path = filepath + INVALID_FILE_SUFFIX
                try:
                    if os.path.exists(filepath):
                        os.rename(filepath, invalid_path)
                        self.logger.error(
                            f"{self.log_prefix}: Quarantined invalid file: "
                            f"'{os.path.basename(filepath)}' -> '{os.path.basename(invalid_path)}'"
                        )
                except OSError as e:
                    self.logger.error(
                        f"{self.log_prefix}: Failed to quarantine file "
                        f"'{filepath}': {str(e)}"
                    )
            return None, [], False
        
        record_count = len(next(iter(combined_data.values()))) if combined_data else 0
        self.logger.debug(
            f"{self.log_prefix}: Built upload batch: "
            f"{len(valid_source_files)} file(s), {record_count} records, "
            f"consolidated={is_consolidated}"
        )
        
        return combined_data, valid_source_files, is_consolidated

    def _process_pending_files(self, file_suffix):
        """Process all pending files: load, upload, handle success/failure.
        
        Processes pending files in FIFO order (oldest first). For each batch:
        1. Build batch (load files into memory, combine if needed)
        2. Upload data directly to S3
        3. On success: delete source files, continue to next batch
        4. On failure: persist data for retry, stop processing
        
        Key optimization: Data flows directly from memory to upload, avoiding
        intermediate file writes. Files are only written on failure for retry.
        
        Args:
            file_suffix: Sanitized file suffix.
        """
        while True:
            pending_files = self._list_pending_files(file_suffix)
            
            if not pending_files:
                self.logger.debug(
                    f"{self.log_prefix}: No pending files to process."
                )
                return
            
            self.logger.info(
                f"{self.log_prefix}: Found {len(pending_files)} pending file(s). "
                f"Total size: {sum(p[2] for p in pending_files) / 1024**2:.2f} MB"
            )
            
            # Build batch (load data into memory)
            batch_data, source_files, is_consolidated = self._build_upload_batch(pending_files)
            
            if batch_data is None:
                # No batch ready (waiting for more data, or files were corrupt/quarantined)
                # Next push() cycle will re-list files
                return
            
            # Upload data directly (no intermediate file write)
            upload_success = self._upload_data_to_s3(batch_data)
            
            if upload_success:
                # Success - delete all source files
                for filepath, _, _ in source_files:
                    try:
                        if os.path.exists(filepath):
                            os.remove(filepath)
                            self.logger.debug(
                                f"{self.log_prefix}: Deleted uploaded file: "
                                f"{os.path.basename(filepath)}"
                            )
                    except OSError as e:
                        self.logger.error(
                            f"{self.log_prefix}: Failed to delete uploaded file "
                            f"'{filepath}': {str(e)}. File may be re-uploaded on next cycle."
                        )
                
                self.logger.info(
                    f"{self.log_prefix}: Successfully processed "
                    f"{len(source_files)} pending file(s)."
                )
                # Continue to next batch
            else:
                # Upload failed - need to persist data for retry
                if is_consolidated:
                    # Multiple files were merged - write combined data to new pending file
                    pending_file = self._get_pending_file_path(file_suffix, time.time())
                    
                    try:
                        with open(pending_file, 'w') as f:
                            json.dump(batch_data, f)
                        self.logger.info(
                            f"{self.log_prefix}: Persisted consolidated batch "
                            f"for retry: {os.path.basename(pending_file)}"
                        )
                        
                        # Delete original source files (data is now in consolidated file)
                        for filepath, _, _ in source_files:
                            try:
                                if os.path.exists(filepath):
                                    os.remove(filepath)
                            except OSError:
                                pass
                    except OSError as e:
                        self.logger.error(
                            f"{self.log_prefix}: Failed to persist consolidated "
                            f"batch: {str(e)}. Source files retained for retry."
                        )
                else:
                    # Single file - just keep it for retry (no write needed)
                    self.logger.info(
                        f"{self.log_prefix}: Upload failed. "
                        f"Keeping pending file for retry: {os.path.basename(source_files[0][0])}"
                    )
                
                # Stop processing - same error would likely occur for other files
                self.logger.error(
                    f"{self.log_prefix}: Pending file upload failed. "
                    "Stopping pending file processing. Will retry on next push."
                )
                return

    # Main Entry Point
    def _process_data(self, new_data, file_suffix):
        """Process new data with fresh-data-first priority.
        
        Flow:
        1. Append new data to staging file
        2. If staging threshold met:
           - Try to upload staging (fresh data first)
           - On success: delete staging, process pending files
           - On failure: freeze staging to pending, DON'T process pending files
        3. If staging threshold not met:
           - Process pending files anyway
        
        Args:
            new_data: New data to process (list of dicts).
            file_suffix: Sanitized file suffix.
        """
        # Step 1: Append new data to staging
        (
            staging_json_file,
            metadata_file,
            current_data,
            creation_timestamp
        ) = self._append_to_staging(new_data, file_suffix)
        
        # Step 2: Check staging thresholds
        (
            threshold_met,
            size_bytes,
            age_seconds,
            size_met,
            age_met
        ) = self._check_staging_threshold(staging_json_file, creation_timestamp)
        
        record_count = len(next(iter(current_data.values()))) if current_data else 0
        
        if not threshold_met:
            # Staging threshold not met - log status
            self.logger.info(
                f"{self.log_prefix}: Batch accumulating. "
                f"Size: {size_bytes / 1024**2:.2f}/{MAX_FILE_SIZE_BYTES / 1024**2:.0f} MB, "
                f"Age: {age_seconds:.0f}/{MAX_FILE_AGE_MINUTES * 60} sec, "
                f"Records: {record_count}"
            )
            # Process pending files even if staging threshold not met
            self._process_pending_files(file_suffix)
            return
        
        # Staging threshold met - try to upload fresh data first
        self.logger.info(
            f"{self.log_prefix}: Staging threshold met. "
            f"Size: {size_bytes / 1024**2:.2f} MB ({'✓' if size_met else '✗'}), "
            f"Age: {age_seconds:.0f}s ({'✓' if age_met else '✗'}), "
            f"Records: {record_count}. Uploading fresh data first..."
        )
        
        upload_success = self._upload_data_to_s3(current_data)
        
        if upload_success:
            # Success - delete staging files
            for file_path, desc in [
                (staging_json_file, "staging JSON"),
                (metadata_file, "metadata"),
            ]:
                if file_path and os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        self.logger.debug(
                            f"{self.log_prefix}: Deleted {desc} file."
                        )
                    except OSError as e:
                        self.logger.error(
                            f"{self.log_prefix}: "
                            f"Failed to delete {desc} file: {str(e)}"
                        )
            
            self.logger.info(
                f"{self.log_prefix}: Parquet file for {self.subtype} uploaded to S3."
            )
            # Now process pending files
            self._process_pending_files(file_suffix)
        else:
            # Failure - freeze staging to pending, don't process other pending files
            self.logger.error(
                message = (
                    f"{self.log_prefix}: Fresh data upload failed. "
                    "Freezing staging to pending file. NOT processing other pending files."
                ),
                resolution=(
                    "The upload of fresh data failed. The staging file has been "
                    "frozen to a pending file and will be retried on the next push."
                    "Please check the logs to see if the error is in the data itself "
                    "or AWS credentials."
                ),
            )
            self._freeze_staging_to_pending(staging_json_file, metadata_file, file_suffix)

    def push(self, new_data):
        """Push new data with process-safe locking.
        
        Main entry point. Acquires inter-process lock, processes data
        (append, check thresholds, upload if needed), and releases lock.
        
        Args:
            new_data: New data to push (list of dicts).
        """
        lock_file = self._get_lock_path(self.file_suffix)
        lock = fasteners.InterProcessLock(lock_file)

        try:
            with lock:
                self.logger.debug(
                    f"{self.log_prefix}: Acquired file lock."
                )
                try:
                    self._process_data(new_data, self.file_suffix)
                except AmazonSecurityLakeException:
                    raise
                except Exception as e:
                    self.logger.error(
                        f"{self.log_prefix}: Error processing data: {str(e)}",
                        details=str(traceback.format_exc()),
                    )
                    raise AmazonSecurityLakeException(
                        f"Failed to process batch: {str(e)}"
                    )
                finally:
                    self.logger.debug(
                        f"{self.log_prefix}: Released file lock."
                    )
        except AmazonSecurityLakeException:
            raise
        except Exception as e:
            error_message = (
                "Error acquiring file lock for batch processing."
            )
            self.logger.error(
                f"{self.log_prefix}: {error_message} Error: {str(e)}"
            )
            raise AmazonSecurityLakeException(error_message)
