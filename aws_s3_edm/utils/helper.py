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

AWS S3 EDM plugin shared helpers (pure pieces used by several modules).
"""

import io
import os
import posixpath
import re
import sys
import traceback
from typing import Optional

from .constants import (
    CUSTOM_REGION_VALUE,
    DATA_EXTENSIONS,
    ERROR_MESSAGE_LEAD,
    FORMAT_GZIP,
    FORMAT_PLAIN,
    FORMAT_ZIP,
    GZIP_EXTENSION,
    MAX_ERROR_TEXT_LENGTH,
    PARTITION_AWS,
    PARTITION_AWS_CN,
    PARTITION_AWS_US_GOV,
    ROLES_ANYWHERE_DOMAIN,
    SENSITIVE_TEXT_PATTERNS,
    UNSUPPORTED_REGION_MARKERS,
    UNSUPPORTED_REGION_PREFIXES,
    ZIP_EXTENSION,
)
from .exception import AWSS3EDMException


class S3BodyReader(io.RawIOBase):
    """Adapt a botocore StreamingBody to a raw readable stream."""

    def __init__(self, body) -> None:
        """Initialize the reader.

        Args:
            body: botocore StreamingBody of a get_object response.
        """
        super().__init__()
        self._body = body

    def readable(self) -> bool:
        """Return True as the stream can be read.

        Returns:
            bool: Always True.
        """
        return True

    def readinto(self, buffer) -> int:
        """Read bytes from the S3 body into the given buffer.

        Args:
            buffer: Writable bytes-like object.

        Returns:
            int: Number of bytes read (0 at the end of the stream).
        """
        data = self._body.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


def format_size(size: int) -> str:
    """Convert a size in bytes to a human readable string.

    Args:
        size (int): Size in bytes.

    Returns:
        str: Size such as ``1.0 GiB``.
    """
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def redact_sensitive_text(text: str) -> str:
    """Remove secret-looking parts from a text (also used for log details).

    Args:
        text (str): Text that may contain an original error.

    Returns:
        str: Text without PEM blocks, credential/signature like values,
            user info of URLs and query strings.
    """
    text = str(text)
    for pattern, replacement in SENSITIVE_TEXT_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.DOTALL)
    return text


def sanitize_error_text(text: str) -> str:
    """Make an original error text safe to show to the user.

    PEM blocks, credential/signature like values, user info of URLs and
    query strings are removed and the text is truncated.

    Args:
        text (str): Original error text.

    Returns:
        str: Sanitized text.
    """
    text = " ".join(redact_sensitive_text(text).split())
    if len(text) > MAX_ERROR_TEXT_LENGTH:
        text = text[:MAX_ERROR_TEXT_LENGTH] + "..."
    return text


def safe_error_text(error: Exception) -> str:
    """Get the original text of a boto3/botocore/AWS/requests error.

    For an AWS ``ClientError`` it is ``<code>: <AWS message>``, otherwise
    ``str(error)``. The text is sanitized (never ``repr`` of a request).

    Args:
        error (Exception): The raised exception.

    Returns:
        str: Sanitized original error text.
    """
    response = getattr(error, "response", None)
    if isinstance(response, dict) and isinstance(
        response.get("Error"), dict
    ):
        details = response["Error"]
        return sanitize_error_text(
            f"{details.get('Code', '')}: {details.get('Message', '')}"
        )
    return sanitize_error_text(str(error))


def get_object_format(key: str) -> str:
    """Get the object format from the key extension.

    Args:
        key (str): S3 object key.

    Returns:
        str: ``plain``, ``gzip`` or ``zip``.
    """
    lowered = key.lower()
    if lowered.endswith(GZIP_EXTENSION):
        return FORMAT_GZIP
    if lowered.endswith(ZIP_EXTENSION):
        return FORMAT_ZIP
    return FORMAT_PLAIN


def get_data_extension(name: str) -> str:
    """Get the CSV/TXT extension of a file name or key.

    For ``.gz`` keys the inner extension (before ``.gz``) is used.

    Args:
        name (str): File name or object key.

    Returns:
        str: ``csv`` or ``txt`` (defaults to ``csv``).
    """
    lowered = name.lower()
    if lowered.endswith(GZIP_EXTENSION):
        lowered = lowered[: -len(GZIP_EXTENSION)]
    extension = posixpath.splitext(lowered)[1]
    if extension in DATA_EXTENSIONS:
        return extension[1:]
    return "csv"


def archive_name(key: str) -> str:
    """Get the file name of an object key for messages.

    Args:
        key (str): S3 object key.

    Returns:
        str: Last path segment of the key.
    """
    return posixpath.basename(key) or key


def remove_local_file(path: str) -> None:
    """Remove a local file, ignoring a missing file.

    Args:
        path (str): File path.
    """
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def build_error_message(action: str, err_msg: str) -> str:
    """Build an error message starting with "Error occurred while".

    Args:
        action (str): What was being done (e.g. "validating the file path").
        err_msg (str): The specific reason.

    Returns:
        str: ``Error occurred while <action>. <err_msg>`` (the reason is
            returned unchanged when it already has that lead).
    """
    if err_msg.startswith(ERROR_MESSAGE_LEAD):
        return err_msg
    return f"{ERROR_MESSAGE_LEAD} {action}. {err_msg}"


class AWSS3EDMBase:
    """Base class holding the logger and building logged errors.

    Every error message starts with "Error occurred while <action>." and
    every resolution is expected to start with "Ensure that" (enforced by
    a unit test); the action defaults to ``default_action`` of the class.
    """

    default_action = "processing the request"

    def __init__(self, logger, log_prefix: str) -> None:
        """Initialize the base class.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix.
        """
        self.logger = logger
        self.log_prefix = log_prefix

    def _error(
        self,
        err_msg: str,
        resolution: str,
        details: Optional[str] = None,
        action: Optional[str] = None,
    ) -> AWSS3EDMException:
        """Log an error and build the exception to raise.

        Args:
            err_msg (str): The specific reason (without log prefix).
            resolution (str): Actionable resolution ("Ensure that ...").
            details (str, optional): Error details. Defaults to the
                current traceback.
            action (str, optional): What was being done. Defaults to the
                ``default_action`` of the class.

        Returns:
            AWSS3EDMException: Exception carrying the same message that is
                logged (``Error occurred while <action>. <err_msg>``).
        """
        message = build_error_message(action or self.default_action, err_msg)
        if details is None:
            details = (
                traceback.format_exc() if sys.exc_info()[0] else err_msg
            )
        self.logger.error(
            message=f"{self.log_prefix}: {message}",
            details=redact_sensitive_text(details),
            resolution=resolution,
        )
        return AWSS3EDMException(message=message)


def get_effective_region(configuration) -> str:
    """Get the region used everywhere (the single place of the decision).

    Args:
        configuration: Step 1 configuration (dict-like).

    Returns:
        str: The trimmed AWS Custom Region when the dropdown is set to
            ``custom``, else the trimmed dropdown value. Empty when missing.
    """
    selected = configuration.get("region_name")
    selected = selected.strip() if isinstance(selected, str) else ""
    if selected == CUSTOM_REGION_VALUE:
        custom = configuration.get("custom_region_name")
        return custom.strip() if isinstance(custom, str) else ""
    return selected


def get_region_partition(region: str):
    """Get the AWS partition of a region.

    Args:
        region (str): Region code.

    Returns:
        str: ``aws``, ``aws-cn`` or ``aws-us-gov``; None for the ISO and
            AWS European Sovereign Cloud (``eusc-``) regions, which cannot
            be represented. Other unknown prefixes fall back to ``aws``.
    """
    if region.startswith("cn-"):
        return PARTITION_AWS_CN
    if region.startswith("us-gov-"):
        return PARTITION_AWS_US_GOV
    if region.startswith(UNSUPPORTED_REGION_PREFIXES) or any(
        marker in region for marker in UNSUPPORTED_REGION_MARKERS
    ):
        return None
    return PARTITION_AWS


def get_roles_anywhere_host(region: str) -> str:
    """Build the IAM Roles Anywhere endpoint host of a region.

    Args:
        region (str): Region code of a supported partition.

    Returns:
        str: ``rolesanywhere.<region>.amazonaws.com`` (``.com.cn`` for
            China regions).
    """
    domain = ROLES_ANYWHERE_DOMAIN.get(
        get_region_partition(region) or PARTITION_AWS
    )
    return f"rolesanywhere.{region}.{domain}"


def get_arn_region(value) -> Optional[str]:
    """Read the region field of an ARN with a plain split on ":".

    An ARN is ``arn:partition:service:region:account:resource``. This is a
    diagnostic helper only (nothing is validated) and never raises.

    Args:
        value: The ARN (any type).

    Returns:
        Optional[str]: The region, or None when the value is not a string,
            has fewer than 6 fields, does not start with ``arn`` or the
            region is empty.
    """
    if not isinstance(value, str):
        return None
    fields = value.strip().split(":")
    if len(fields) < 6 or fields[0] != "arn":
        return None
    return fields[3].strip() or None


def describe_arn_region_mismatch(configuration, region: str):
    """Describe a region mismatch of the Profile and Trust Anchor ARNs.

    Only region codes are put into the texts (never ARNs or account ids).

    Args:
        configuration: Step 1 configuration (dict-like).
        region (str): The effective region.

    Returns:
        Optional[tuple]: ``(sentence, resolution)`` when at least one ARN
            region is readable and differs from ``region``, else None.
    """
    found = []
    for key, label in (
        ("profile_arn", "Profile ARN"),
        ("trust_anchor_arn", "Trust Anchor ARN"),
    ):
        arn_region = get_arn_region(configuration.get(key))
        if arn_region:
            found.append((label, arn_region))
    differing = [item for item in found if item[1] != region]
    if not differing:
        return None
    described = " and the ".join(
        f"{label} is in the region '{arn_region}'"
        for label, arn_region in differing
    )
    sentence = (
        f"The configured AWS S3 Bucket Region is '{region}' but the "
        f"{described}."
    )
    regions = {arn_region for _, arn_region in found}
    if len(differing) == 1 and len(found) == 2 and len(regions) == 2:
        label, arn_region = differing[0]
        resolution = (
            f"Ensure that the AWS S3 Bucket Region is the region of the "
            f"{label} ('{arn_region}'), or that the {label} belongs to "
            "the configured region."
        )
    elif len(differing) == 1 or len(regions) == 1:
        label_text = " and the ".join(label for label, _ in differing)
        arn_region = differing[0][1]
        resolution = (
            "Ensure that the AWS S3 Bucket Region is the region of the "
            f"{label_text} ('{arn_region}'), or that the ARNs belong to "
            "the configured region."
        )
    else:
        resolution = (
            "Ensure that the Profile ARN and the Trust Anchor ARN are in "
            "the same region as the AWS S3 Bucket Region."
        )
    return sentence, resolution
