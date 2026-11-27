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
Google Cloud Storage client.
"""

from typing import Any, Optional

import requests
from google.api_core import exceptions as gexc
from google.api_core.client_info import ClientInfo
from google.auth import exceptions as auth_exc
from google.auth.transport.requests import AuthorizedSession, Request
from google.cloud import storage
from google.oauth2 import service_account

from . import constants as CONST
from .exceptions import GCPStorageException
from .helper import (
    build_object_name,
    get_location,
    log_and_raise,
    parse_key_file,
    sanitize_error_text,
)


class GCPStorageClient:
    """Client of Google Cloud Storage (proxy and SSL aware)."""

    def __init__(
        self,
        configuration: dict,
        logger: Any,
        log_prefix: str,
        proxy: Optional[dict],
        ssl_validation: bool,
        user_agent: str,
    ) -> None:
        """Initialize the client.

        Args:
            configuration (dict): Plugin configuration parameters.
            logger: CE logger object.
            log_prefix (str): Log prefix.
            proxy (Optional[dict]): Proxy dict provided by CE.
            ssl_validation (bool): SSL validation flag provided by CE.
            user_agent (str): User-Agent of the requests.
        """
        self.configuration = configuration
        self.logger = logger
        self.log_prefix = log_prefix
        self.proxy = proxy or {}
        self.ssl_validation = ssl_validation
        self.user_agent = user_agent
        self._client = None

    def _new_session(self) -> requests.Session:
        """Create a session using the CE proxy and SSL settings.

        Returns:
            requests.Session: The session.
        """
        session = requests.Session()
        session.proxies = dict(self.proxy)
        session.verify = self.ssl_validation
        return session

    def get_client(self) -> storage.Client:
        """Create (once) the Storage client.

        The proxy and the SSL validation flag are applied to the API calls
        and to the token requests.

        Returns:
            storage.Client: The client.

        Raises:
            GCPStorageException: When the key file cannot be used.
        """
        if self._client is not None:
            return self._client
        action = "creating the Google Cloud Storage client"
        try:
            info = parse_key_file(self.configuration.get(CONST.KEY_FILE_KEY))
            credentials = service_account.Credentials.from_service_account_info(
                info, scopes=[CONST.STORAGE_SCOPE]
            )
            session = AuthorizedSession(
                credentials,
                auth_request=Request(session=self._new_session()),
            )
            session.proxies = dict(self.proxy)
            session.verify = self.ssl_validation
            self._client = storage.Client(
                project=info.get("project_id"),
                credentials=credentials,
                _http=session,
                client_info=ClientInfo(user_agent=self.user_agent),
            )
        except (ValueError, KeyError) as err:
            log_and_raise(
                self.logger,
                self.log_prefix,
                action,
                "Ensure that a valid Service Account JSON key file is "
                "provided.",
                cause="Key File is invalid.",
                err=err,
            )
        except Exception as err:
            self._raise_api_error(action, err)
        return self._client

    def _raise_api_error(self, action: str, err: BaseException) -> None:
        """Translate a Google Cloud or network error and raise.

        Args:
            action (str): What was being done.
            err (BaseException): The original error.

        Raises:
            GCPStorageException: Always.
        """
        text = sanitize_error_text(err)
        if isinstance(err, requests.exceptions.ProxyError):
            cause = "Proxy error occurred."
            resolution = "Ensure that the proxy configuration is valid."
        elif isinstance(
            err,
            (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                auth_exc.TransportError,
            ),
        ):
            cause = "Unable to connect to Google Cloud Storage."
            resolution = (
                "Ensure that Google Cloud Storage is reachable from Cloud "
                "Exchange and the proxy configuration is valid."
            )
        elif isinstance(
            err,
            (
                gexc.Unauthorized,
                gexc.Unauthenticated,
                auth_exc.RefreshError,
            ),
        ):
            cause = "Authentication failed."
            resolution = (
                "Ensure that the Service Account key file is valid and the "
                "key is not deleted or disabled."
            )
        elif isinstance(err, gexc.Forbidden):
            cause = "Permission denied."
            resolution = (
                "Ensure that the Service Account has the "
                "'storage.buckets.get' (e.g. Storage Bucket Viewer) and "
                "'storage.objects.create' (e.g. Storage Object Creator) "
                "permissions on the bucket, and 'storage.buckets.create' "
                "(e.g. Storage Admin) if the plugin should create the "
                "bucket."
            )
        elif isinstance(err, gexc.NotFound):
            cause = "Bucket not found."
            resolution = "Ensure that the Bucket Name is correct."
        elif isinstance(err, gexc.Conflict):
            cause = "The Bucket Name is not available."
            resolution = (
                "Ensure that the Bucket Name is not used by another "
                "project; bucket names are globally unique."
            )
        elif isinstance(err, gexc.BadRequest):
            cause = "Google Cloud Storage rejected the request."
            resolution = (
                "Ensure that the Bucket Name, Location and Storage Class "
                "are valid and supported together, and that the Service "
                "Account's project is allowed to create buckets."
            )
        elif isinstance(err, gexc.TooManyRequests):
            cause = "Google Cloud Storage rate limit exceeded."
            resolution = "Ensure that the request rate is within the quota."
        elif isinstance(err, gexc.GoogleAPICallError):
            cause = f"Received HTTP status code {getattr(err, 'code', '')}."
            resolution = (
                "Ensure that the plugin configuration is valid. Check the "
                "logs for details."
            )
        else:
            cause = "Unexpected error occurred."
            resolution = (
                "Ensure that the plugin configuration is valid. Check the "
                "logs for details."
            )
        log_and_raise(
            self.logger,
            self.log_prefix,
            action,
            resolution,
            cause=f"{cause} Error: {text}",
            err=err,
        )

    def _verify_upload_permission(self, bucket_name: str) -> None:
        """Check that the Service Account can create objects in the bucket.

        Uses ``testIamPermissions``, which needs no permission of its own.

        Args:
            bucket_name (str): Name of the bucket.

        Raises:
            GCPStorageException: When the permission is missing.
        """
        action = f"checking the permissions on the bucket '{bucket_name}'"
        try:
            granted = (
                self.get_client()
                .bucket(bucket_name)
                .test_iam_permissions([CONST.UPLOAD_PERMISSION])
            )
        except GCPStorageException:
            raise
        except Exception as err:
            self._raise_api_error(action, err)
        if CONST.UPLOAD_PERMISSION not in (granted or []):
            log_and_raise(
                self.logger,
                self.log_prefix,
                action,
                f"Ensure that the Service Account has the "
                f"'{CONST.UPLOAD_PERMISSION}' permission (e.g. Storage "
                "Object Creator) on the bucket.",
                cause=(
                    "Permission denied. The Service Account cannot create "
                    f"objects in the bucket '{bucket_name}'."
                ),
            )

    def verify_bucket(self) -> None:
        """Check the bucket and create it when it does not exist.

        It also checks that the Service Account can create objects in it.

        Raises:
            GCPStorageException: When the bucket cannot be used.
        """
        bucket_name = self.configuration.get(CONST.BUCKET_NAME_KEY).strip()
        action = f"verifying the bucket '{bucket_name}'"
        client = self.get_client()
        try:
            if client.lookup_bucket(bucket_name) is not None:
                self._verify_upload_permission(bucket_name)
                return
        except GCPStorageException:
            raise
        except Exception as err:
            self._raise_api_error(action, err)
        action = f"creating the bucket '{bucket_name}'"
        try:
            bucket = client.bucket(bucket_name)
            bucket.storage_class = self.configuration.get(
                CONST.STORAGE_CLASS_KEY
            ).strip()
            client.create_bucket(
                bucket, location=get_location(self.configuration)
            )
            self.logger.info(
                f"{self.log_prefix}: Created the bucket '{bucket_name}'."
            )
        except gexc.Conflict:
            # Created by someone else in the meantime, use it if visible.
            try:
                client.get_bucket(bucket_name)
            except Exception as err:
                self._raise_api_error(action, err)
        except Exception as err:
            self._raise_api_error(action, err)
        self._verify_upload_permission(bucket_name)

    def push(
        self,
        file_path: str,
        data_type: str,
        subtype: Optional[str],
        compress: bool = True,
    ) -> str:
        """Upload a JSON Lines file as a new object.

        Args:
            file_path (str): Local file to upload.
            data_type (str): Data type, ``alerts``, ``events`` or ``webtx``.
            subtype (Optional[str]): Subtype of the data.
            compress (bool): Whether the file is gzip-compressed.

        Returns:
            str: Name of the created object.

        Raises:
            GCPStorageException: When the upload fails (CE retries).
        """
        bucket_name = self.configuration.get(CONST.BUCKET_NAME_KEY).strip()
        prefix = self.configuration.get(CONST.OBJECT_PREFIX_KEY).strip()
        object_name = build_object_name(prefix, data_type, subtype, compress)
        action = f"uploading the object '{object_name}' to '{bucket_name}'"
        try:
            blob = self.get_client().bucket(bucket_name).blob(object_name)
            blob.upload_from_filename(
                file_path,
                content_type=(
                    CONST.OBJECT_CONTENT_TYPE_GZIP
                    if compress
                    else CONST.OBJECT_CONTENT_TYPE_JSON
                ),
                if_generation_match=CONST.IF_GENERATION_MATCH,
            )
        except GCPStorageException:
            raise
        except gexc.PreconditionFailed:
            # The object name is unique (uuid4), so an existing object with
            # this name is this upload, created by an attempt whose response
            # was lost before the library retried it.
            self.logger.debug(
                f"{self.log_prefix}: Object '{object_name}' already exists; "
                "treating the upload as complete."
            )
        except Exception as err:
            self._raise_api_error(action, err)
        return object_name
