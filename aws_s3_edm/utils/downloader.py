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

Sample pull and full download of the file.
"""

import errno
import gzip
import io
import os
import zipfile
from typing import List

from botocore.exceptions import BotoCoreError, ClientError

from .constants import (
    ARCHIVE_READ_ERRORS,
    ARCHIVE_TEMP_FILE_NAME,
    CHUNK_SIZE,
    DOWNLOAD_MAX_ATTEMPTS,
    DOWNLOAD_RANGE_SIZE,
    FORMAT_GZIP,
    FORMAT_PLAIN,
    FORMAT_ZIP,
    GZIP_MAGIC,
    MAX_LINE_BYTES,
    RANGE_MAX_ATTEMPTS,
    SAMPLE_DATA_RECORD_COUNT,
    STREAM_BUFFER_SIZE,
    UTF8_BOM,
    ZIP_MAGIC,
)
from .exception import ObjectChangedError
from .helper import (
    AWSS3EDMBase,
    S3BodyReader,
    archive_name,
    format_size,
    get_data_extension,
    get_object_format,
    remove_local_file,
)


class AWSS3EDMDownloader(AWSS3EDMBase):
    """Sample pull and full download of the file."""

    default_action = "downloading the file"

    def __init__(
        self, logger, log_prefix: str, client, decompressor
    ) -> None:
        """Initialize the downloader.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix.
            client (AWSS3EDMClient): Client used for the S3 calls.
            decompressor (AWSS3EDMDecompressor): Archive extraction.
        """
        super().__init__(logger, log_prefix)
        self.client = client
        self.decompressor = decompressor

    def _read_lines(self, reader, key: str) -> List[bytes]:
        """Read the header and sample records from a binary stream.

        Args:
            reader: Binary stream supporting ``readline(size)``.
            key (str): Object key (for messages).

        Raises:
            AWSS3EDMException: If a line is longer than the supported size.

        Returns:
            List[bytes]: Up to ``SAMPLE_DATA_RECORD_COUNT + 1`` lines.
        """
        lines = []
        for _ in range(SAMPLE_DATA_RECORD_COUNT + 1):
            line = reader.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_LINE_BYTES:
                raise self._error(
                    f"A line of '{archive_name(key)}' is longer than "
                    f"the supported {format_size(MAX_LINE_BYTES)}.",
                    "Ensure that the file is a valid delimited text file.",
                    details="Line too long.",
                    action="pulling the sample data",
                )
            lines.append(line)
        return lines

    @staticmethod
    def _write_sample_file(path: str, lines: List[bytes]) -> None:
        """Write the sample lines as UTF-8 with LF line endings.

        A UTF-8 BOM in the header is removed and CRLF is normalized.

        Args:
            path (str): Sample file path.
            lines (List[bytes]): Raw sample lines.
        """
        with open(path, "wb") as sample_file:
            for index, line in enumerate(lines):
                if index == 0 and line.startswith(UTF8_BOM):
                    line = line[len(UTF8_BOM):]
                sample_file.write(line.rstrip(b"\r\n") + b"\n")

    def _sample_from_stream(
        self, client, bucket: str, key: str, data_format: str
    ) -> List[bytes]:
        """Stream the beginning of a plain or gzip object.

        Args:
            client: boto3 S3 client.
            bucket (str): Bucket name.
            key (str): Object key.
            data_format (str): ``plain`` or ``gzip``.

        Returns:
            List[bytes]: Sample lines.
        """
        response = self.client.call(
            "get_object",
            client.get_object,
            bucket,
            key,
            Bucket=bucket,
            Key=key,
        )
        body = response["Body"]
        try:
            reader = io.BufferedReader(
                S3BodyReader(body), buffer_size=STREAM_BUFFER_SIZE
            )
            if data_format == FORMAT_GZIP:
                if reader.peek(len(GZIP_MAGIC))[: len(GZIP_MAGIC)] != (
                    GZIP_MAGIC
                ):
                    self.decompressor.raise_format_mismatch(key)
                reader = gzip.GzipFile(fileobj=reader, mode="rb")
            return self._read_lines(reader, key)
        except ARCHIVE_READ_ERRORS as error:
            raise self.decompressor.corrupt_archive_error(
                key, error
            ) from error
        except (BotoCoreError, ClientError) as error:
            raise self.client.map_error(
                error, "get_object", bucket, key
            ) from error
        finally:
            body.close()

    def _sample_from_zip(
        self, configuration: dict, info: dict, archive_path: str
    ) -> List[bytes]:
        """Download a zip object and read the sample from its data file.

        Args:
            configuration (dict): Step 1 configuration parameters.
            info (dict): Object metadata.
            archive_path (str): Local path used for the archive.

        Returns:
            List[bytes]: Sample lines.
        """
        key = configuration.get("filepath", "").strip()
        try:
            self.download_object(configuration, info, archive_path)
            self.decompressor.verify_magic(archive_path, ZIP_MAGIC, key)
            with zipfile.ZipFile(archive_path) as archive:
                entry = self.decompressor.select_zip_entry(archive, key)
                with archive.open(entry) as data_file:
                    return self._read_lines(data_file, key)
        except ARCHIVE_READ_ERRORS as error:
            raise self.decompressor.corrupt_archive_error(
                key, error
            ) from error
        finally:
            remove_local_file(archive_path)

    def pull_sample(
        self, configuration: dict, info: dict, sample_path: str
    ) -> None:
        """Pull the sample (header + records) of the object to a file.

        Plain and gzip objects are streamed so only the beginning of the
        object is downloaded. Zip objects are downloaded to a fixed local
        file because the zip index is at the end of the archive.

        Args:
            configuration (dict): Step 1 configuration parameters.
            info (dict): Object metadata from ``validate_object``.
            sample_path (str): Local path of the sample file.

        Raises:
            AWSS3EDMException: If the sample cannot be pulled.
        """
        bucket = configuration.get("bucket_name", "").strip()
        key = configuration.get("filepath", "").strip()
        data_format = get_object_format(key)
        try:
            if data_format == FORMAT_ZIP:
                archive_path = os.path.join(
                    os.path.dirname(sample_path), ARCHIVE_TEMP_FILE_NAME
                )
                lines = self._sample_from_zip(
                    configuration, info, archive_path
                )
            else:
                lines = self._sample_from_stream(
                    self.client.get_client(configuration),
                    bucket,
                    key,
                    data_format,
                )
            self._write_sample_file(sample_path, lines)
            self.logger.debug(
                f"{self.log_prefix}: Successfully pulled the sample of "
                f"file path '{key}' from the bucket '{bucket}'."
            )
        except Exception:
            remove_local_file(sample_path)
            raise

    @staticmethod
    def _write_body(body, target, strip_bom: bool) -> int:
        """Stream an S3 body into an open file.

        Args:
            body: botocore StreamingBody.
            target: Binary file object opened for writing.
            strip_bom (bool): Remove a UTF-8 BOM from the first chunk.

        Returns:
            int: Number of bytes received from S3.
        """
        received = 0
        try:
            for chunk in body.iter_chunks(CHUNK_SIZE):
                if strip_bom and received == 0 and chunk.startswith(
                    UTF8_BOM
                ):
                    target.write(chunk[len(UTF8_BOM):])
                else:
                    target.write(chunk)
                received += len(chunk)
        finally:
            body.close()
        return received

    def _download_range(
        self,
        configuration: dict,
        info: dict,
        target,
        offset: int,
        strip_bom: bool,
    ) -> int:
        """Download one range of the object into the open file.

        A streaming error in the middle of the body is retried once for
        this range only, so a large download is not lost.

        Args:
            configuration (dict): Step 1 configuration parameters.
            info (dict): Object metadata.
            target: Binary file object opened for writing.
            offset (int): First byte of the range.
            strip_bom (bool): Remove a UTF-8 BOM at the file start.

        Raises:
            AWSS3EDMException: If the range cannot be downloaded.

        Returns:
            int: Number of bytes received for the range.
        """
        bucket = configuration.get("bucket_name", "").strip()
        key = configuration.get("filepath", "").strip()
        end = min(offset + DOWNLOAD_RANGE_SIZE, info["content_length"]) - 1
        request = {
            "Bucket": bucket,
            "Key": key,
            "Range": f"bytes={offset}-{end}",
        }
        if info.get("etag"):
            request["IfMatch"] = info["etag"]
        position = target.tell()
        for attempt in range(1, RANGE_MAX_ATTEMPTS + 1):
            client = self.client.get_client(configuration)
            response = self.client.call(
                "get_object", client.get_object, bucket, key, **request
            )
            try:
                return self._write_body(response["Body"], target, strip_bom)
            except BotoCoreError as error:
                if attempt >= RANGE_MAX_ATTEMPTS:
                    raise self.client.map_error(
                        error, "get_object", bucket, key
                    ) from error
                self.logger.info(
                    f"{self.log_prefix}: Streaming error while downloading "
                    f"bytes {offset}-{end} of file path '{key}'. Retrying "
                    "this range once."
                )
                target.seek(position)
                target.truncate()
            except ClientError as error:
                raise self.client.map_error(
                    error, "get_object", bucket, key
                ) from error
        return 0

    def _download_ranges(
        self,
        configuration: dict,
        info: dict,
        destination: str,
        strip_bom: bool,
    ) -> None:
        """Download the object with ranged requests, refreshing creds.

        Every request is conditional on the ETag of the validated object,
        so a change of the object during the download is detected.

        Args:
            configuration (dict): Step 1 configuration parameters.
            info (dict): Object metadata.
            destination (str): Local file path.
            strip_bom (bool): Remove a UTF-8 BOM at the file start.

        Raises:
            ObjectChangedError: If the object changed or the size differs.
        """
        key = configuration.get("filepath", "").strip()
        total = info["content_length"]
        offset = 0
        with open(destination, "wb") as target:
            while offset < total:
                end = min(offset + DOWNLOAD_RANGE_SIZE, total) - 1
                received = self._download_range(
                    configuration,
                    info,
                    target,
                    offset,
                    strip_bom and offset == 0,
                )
                if received != end - offset + 1:
                    raise ObjectChangedError(
                        message=(
                            f"The size of the downloaded file path '{key}' "
                            "does not match the size reported by AWS S3."
                        )
                    )
                offset = end + 1

    def _write_error(self, key: str, error: OSError):
        """Build the error for a local write failure during a download.

        Args:
            key (str): Object key.
            error (OSError): The local I/O error.

        Returns:
            AWSS3EDMException: Exception to raise (already logged).
        """
        if error.errno == errno.ENOSPC:
            err_msg = (
                "The Cloud Exchange host ran out of disk space (file path "
                f"'{key}')."
            )
            resolution = (
                "Ensure that the Cloud Exchange host has enough free disk "
                "space for the file and its working copies and run the "
                "pull again."
            )
        else:
            err_msg = (
                f"Unable to write the downloaded file path '{key}' on the "
                "Cloud Exchange host."
            )
            resolution = (
                "Ensure that the Cloud Exchange host can write to its data "
                "directory."
            )
        return self._error(f"{err_msg} Error: {error}", resolution)

    def download_object(
        self,
        configuration: dict,
        info: dict,
        destination: str,
        strip_bom: bool = False,
    ) -> None:
        """Download the raw object to a local file (one retry, risk R4).

        Args:
            configuration (dict): Step 1 configuration parameters.
            info (dict): Object metadata from ``validate_object``.
            destination (str): Local file path.
            strip_bom (bool): Remove a UTF-8 BOM at the file start.

        Raises:
            AWSS3EDMException: If the download fails. The partial file is
                removed.
        """
        bucket = configuration.get("bucket_name", "").strip()
        key = configuration.get("filepath", "").strip()
        current = info
        for attempt in range(1, DOWNLOAD_MAX_ATTEMPTS + 1):
            try:
                self._download_ranges(
                    configuration, current, destination, strip_bom
                )
                return
            except ObjectChangedError as error:
                remove_local_file(destination)
                if attempt >= DOWNLOAD_MAX_ATTEMPTS:
                    raise self._error(
                        f"The file path '{key}' was modified while it was "
                        "being downloaded.",
                        "Ensure that the export job writes the file "
                        "atomically and is not running during the pull.",
                    ) from error
                self.logger.info(
                    f"{self.log_prefix}: The file path '{key}' changed during "
                    "the download. Retrying the download once."
                )
                client = self.client.get_client(configuration)
                current = self.client.get_object_info(client, bucket, key)
                self.client.validate_object_info(current, key)
            except OSError as error:
                remove_local_file(destination)
                raise self._write_error(key, error) from error
            except Exception:
                remove_local_file(destination)
                raise

    def fetch_object(
        self,
        configuration: dict,
        info: dict,
        output_dir: str,
        file_base: str,
    ) -> str:
        """Download the object and decompress it when required.

        The local file name is ``{file_base}.{csv|txt}`` (the extension of
        the key, or of the inner file for zip archives). The raw archive
        is always removed.

        Args:
            configuration (dict): Step 1 configuration parameters.
            info (dict): Object metadata from ``validate_object``.
            output_dir (str): Local output directory.
            file_base (str): Local file name without extension.

        Returns:
            str: Path of the local CSV/TXT file.
        """
        key = configuration.get("filepath", "").strip()
        data_format = get_object_format(key)
        if data_format == FORMAT_PLAIN:
            destination = os.path.join(
                output_dir, f"{file_base}.{get_data_extension(key)}"
            )
            self.download_object(
                configuration, info, destination, strip_bom=True
            )
            return destination
        archive_path = os.path.join(output_dir, ARCHIVE_TEMP_FILE_NAME)
        try:
            self.download_object(configuration, info, archive_path)
            if data_format == FORMAT_GZIP:
                return self.decompressor.extract_gzip(
                    archive_path, output_dir, file_base, key
                )
            return self.decompressor.extract_zip(
                archive_path, output_dir, file_base, key
            )
        finally:
            remove_local_file(archive_path)
