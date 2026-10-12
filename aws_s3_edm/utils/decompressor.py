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

Decompression of .gz and .zip objects with bomb protection.
"""

import gzip
import os
import posixpath
import zipfile

from .constants import (
    ARCHIVE_READ_ERRORS,
    CHUNK_SIZE,
    DATA_EXTENSIONS,
    GZIP_MAGIC,
    IGNORED_ZIP_NAMES,
    IGNORED_ZIP_PREFIXES,
    MAX_COMPRESSION_RATIO,
    MAX_DECOMPRESSED_SIZE,
    MIN_BYTES_BEFORE_RATIO_CHECK,
    NESTED_ARCHIVE_EXTENSIONS,
    UTF8_BOM,
    ZIP_ENCRYPTED_FLAG,
    ZIP_MAGIC,
)
from .exception import AWSS3EDMException
from .helper import (
    AWSS3EDMBase,
    archive_name,
    format_size,
    get_data_extension,
    remove_local_file,
)


class AWSS3EDMDecompressor(AWSS3EDMBase):
    """Decompression of .gz and .zip files with bomb protection."""

    default_action = "extracting the archive"

    def __init__(self, logger, log_prefix: str) -> None:
        """Initialize the decompressor.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix.
        """
        super().__init__(logger, log_prefix)

    def verify_magic(self, path: str, magic: bytes, key: str) -> None:
        """Verify the first bytes of a downloaded archive.

        Args:
            path (str): Local archive path.
            magic (bytes): Expected leading bytes.
            key (str): Object key (for messages).

        Raises:
            AWSS3EDMException: If the content does not match the extension.
        """
        with open(path, "rb") as archive:
            head = archive.read(len(magic))
        if head != magic:
            self.raise_format_mismatch(key)

    def raise_format_mismatch(self, key: str) -> None:
        """Raise the extension and content mismatch error.

        Args:
            key (str): Object key.

        Raises:
            AWSS3EDMException: Always.
        """
        raise self._error(
            f"The content of '{archive_name(key)}' does not match its "
            "file extension.",
            "Ensure that only real .gz or .zip archives use these "
            "extensions and that plain files use .csv or .txt.",
            details="Magic bytes do not match the file extension.",
        )

    def corrupt_archive_error(
        self, key: str, error: Exception
    ) -> AWSS3EDMException:
        """Build the error for an unreadable or unsupported archive.

        Args:
            key (str): Object key.
            error (Exception): The archive exception.

        Returns:
            AWSS3EDMException: Exception to raise (already logged).
        """
        return self._error(
            f"The archive '{archive_name(key)}' is corrupt, "
            "password-protected or uses an unsupported format.",
            "Ensure that the file is a valid, unencrypted .gz or .zip "
            "archive.",
            details=f"{type(error).__name__}: {error}",
        )

    @staticmethod
    def _is_ignored_zip_entry(filename: str) -> bool:
        """Check whether a zip entry is OS metadata that must be ignored.

        Args:
            filename (str): Entry name inside the archive.

        Returns:
            bool: True for ``__MACOSX/``, ``.DS_Store`` and AppleDouble.
        """
        normalized = filename.replace("\\", "/")
        basename = posixpath.basename(normalized)
        return (
            normalized.startswith(IGNORED_ZIP_PREFIXES)
            or "/__MACOSX/" in normalized
            or basename in IGNORED_ZIP_NAMES
            or basename.startswith("._")
        )

    def select_zip_entry(self, archive: zipfile.ZipFile, key: str):
        """Select the single CSV/TXT data entry of a zip archive.

        Entry names are only used for classification, never to build a
        local path.

        Args:
            archive (zipfile.ZipFile): Opened archive.
            key (str): Object key (for messages).

        Raises:
            AWSS3EDMException: If the archive has no data entry, several
                data entries, a nested archive or an encrypted entry.

        Returns:
            zipfile.ZipInfo: The data entry.
        """
        name = archive_name(key)
        data_entries = []
        for entry in archive.infolist():
            if entry.is_dir() or self._is_ignored_zip_entry(entry.filename):
                continue
            lowered = entry.filename.lower()
            if lowered.endswith(NESTED_ARCHIVE_EXTENSIONS):
                raise self._error(
                    f"The archive '{name}' contains a nested archive, "
                    "which is not supported.",
                    "Ensure that the zip archive contains exactly one .csv "
                    "or .txt file.",
                    details="Nested archive found.",
                )
            if lowered.endswith(DATA_EXTENSIONS):
                data_entries.append(entry)
        if not data_entries:
            raise self._error(
                f"The archive '{name}' contains no .csv/.txt file.",
                "Ensure that the zip archive contains exactly one .csv or "
                ".txt file.",
                details="No data entry found.",
            )
        if len(data_entries) > 1:
            raise self._error(
                f"The archive '{name}' contains {len(data_entries)} "
                "files, expected exactly one.",
                "Ensure that the zip archive contains exactly one .csv or "
                ".txt file.",
                details=f"Data entries found: {len(data_entries)}.",
            )
        if data_entries[0].flag_bits & ZIP_ENCRYPTED_FLAG:
            raise self._error(
                f"The archive '{name}' is password-protected, which is not "
                "supported.",
                "Ensure that the archive is not password-protected.",
                details="Encrypted entry found.",
            )
        return data_entries[0]

    def _check_expansion(
        self, written: int, archive_size: int, key: str
    ) -> None:
        """Enforce the decompression size and ratio limits.

        Args:
            written (int): Decompressed bytes so far.
            archive_size (int): Size of the archive on disk.
            key (str): Object key (for messages).

        Raises:
            AWSS3EDMException: If a limit is exceeded.
        """
        name = archive_name(key)
        if written > MAX_DECOMPRESSED_SIZE:
            raise self._error(
                f"The decompressed size of '{name}' exceeds the maximum "
                f"supported size of {format_size(MAX_DECOMPRESSED_SIZE)}.",
                "Ensure that the extracted file is smaller than the supported "
                "size or split it into smaller files.",
                details=f"Limit: {MAX_DECOMPRESSED_SIZE} bytes.",
            )
        if (
            written >= MIN_BYTES_BEFORE_RATIO_CHECK
            and archive_size > 0
            and written / archive_size > MAX_COMPRESSION_RATIO
        ):
            raise self._error(
                f"The compression ratio of '{name}' exceeds the maximum "
                f"supported ratio of {MAX_COMPRESSION_RATIO}:1.",
                "Ensure that the archive is a valid export of the data and "
                "not a decompression bomb.",
                details=f"Limit: {MAX_COMPRESSION_RATIO}:1.",
            )

    def _copy_with_limits(
        self, source, destination: str, archive_size: int, key: str
    ) -> None:
        """Stream decompressed data to a file enforcing the limits.

        The byte count of the stream is enforced, the sizes declared in
        the archive headers are never trusted. The partial file is removed
        on any failure.

        Args:
            source: Binary stream of the decompressed data.
            destination (str): Local file path.
            archive_size (int): Size of the archive on disk.
            key (str): Object key (for messages).

        Raises:
            AWSS3EDMException: If a limit is exceeded, the data is empty
                or it is a nested archive.
        """
        written = 0
        try:
            with open(destination, "wb") as target:
                while True:
                    # The +1 is deliberate: reading one byte past the limit
                    # tells "exactly at the limit" from "over it". Without
                    # it the read size would be 0 at the limit, read(0)
                    # returns b"" and the loop would treat it as the end
                    # of the data, silently accepting a truncated file. The
                    # overshoot is at most 1 byte and the file is removed
                    # when _check_expansion raises.
                    size = min(CHUNK_SIZE, MAX_DECOMPRESSED_SIZE - written + 1)
                    chunk = source.read(size)
                    if not chunk:
                        break
                    if written == 0:
                        self._check_not_nested(chunk, key)
                        first_chunk = chunk
                        if chunk.startswith(UTF8_BOM):
                            first_chunk = chunk[len(UTF8_BOM):]
                        target.write(first_chunk)
                    else:
                        target.write(chunk)
                    written += len(chunk)
                    self._check_expansion(written, archive_size, key)
            if written == 0:
                raise self._error(
                    f"The archive '{archive_name(key)}' contains an "
                    "empty file.",
                    "Ensure that the file contains a header row and at "
                    "least one record.",
                    details="Decompressed data is empty.",
                )
        except Exception:
            remove_local_file(destination)
            raise

    def _check_not_nested(self, chunk: bytes, key: str) -> None:
        """Reject decompressed data that is itself an archive.

        Args:
            chunk (bytes): First decompressed bytes.
            key (str): Object key (for messages).

        Raises:
            AWSS3EDMException: If the data starts with an archive marker.
        """
        if chunk.startswith((GZIP_MAGIC, ZIP_MAGIC)):
            raise self._error(
                f"The archive '{archive_name(key)}' contains a nested "
                "archive, which is not supported.",
                "Ensure that the archive contains exactly one .csv or .txt "
                "file.",
                details="Nested archive found.",
            )

    def extract_gzip(
        self, archive_path: str, output_dir: str, file_base: str, key: str
    ) -> str:
        """Extract a gzip archive to a fixed local path.

        Args:
            archive_path (str): Local gzip file.
            output_dir (str): Output directory.
            file_base (str): Local file name without extension.
            key (str): Object key.

        Returns:
            str: Path of the extracted file.
        """
        self.verify_magic(archive_path, GZIP_MAGIC, key)
        destination = os.path.join(
            output_dir, f"{file_base}.{get_data_extension(key)}"
        )
        try:
            with gzip.open(archive_path, "rb") as source:
                self._copy_with_limits(
                    source, destination, os.path.getsize(archive_path), key
                )
        except ARCHIVE_READ_ERRORS as error:
            remove_local_file(destination)
            raise self.corrupt_archive_error(key, error) from error
        return destination

    def extract_zip(
        self, archive_path: str, output_dir: str, file_base: str, key: str
    ) -> str:
        """Extract the single data entry of a zip to a fixed local path.

        Args:
            archive_path (str): Local zip file.
            output_dir (str): Output directory.
            file_base (str): Local file name without extension.
            key (str): Object key.

        Returns:
            str: Path of the extracted file.
        """
        self.verify_magic(archive_path, ZIP_MAGIC, key)
        destination = ""
        try:
            with zipfile.ZipFile(archive_path) as archive:
                entry = self.select_zip_entry(archive, key)
                destination = os.path.join(
                    output_dir,
                    f"{file_base}.{get_data_extension(entry.filename)}",
                )
                with archive.open(entry) as source:
                    self._copy_with_limits(
                        source,
                        destination,
                        os.path.getsize(archive_path),
                        key,
                    )
        except ARCHIVE_READ_ERRORS as error:
            if destination:
                remove_local_file(destination)
            raise self.corrupt_archive_error(key, error) from error
        return destination
