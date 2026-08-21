"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

CRE Orca Security plugin helper module.
"""

import time
import traceback
from typing import Callable, Dict, List, Literal, Optional, Tuple
from urllib.parse import urlparse

import requests
from netskope.common.utils import add_user_agent
from netskope.integrations.crev2.plugin_base import ValidationResult
from requests.models import Response

from .constants import (
    BASE_URL_CUSTOM_VALUE,
    BASE_URL_ENDPOINT,
    CLIENT_ERROR_MSG,
    CLIENT_ERROR_RESOLUTION_MESSAGE,
    CLOUD_PROVIDER_PREFIX_MAP,
    CONFIG_API_TOKEN,
    CONFIG_BASE_URL,
    CONFIG_CUSTOM_BASE_URL,
    CONFIG_DEVICE_MODELS,
    CONFIG_USER_MODELS,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_WAIT_TIME,
    EMPTY_ERROR_MESSAGE,
    ERROR_MESSAGE_MAP,
    EXPOSURE_PUBLIC_FACING,
    FIELD_PORT_PROTOCOLS,
    FIELD_PORT_SERVICES,
    FIELD_PORTS,
    GENERIC_ERROR_MSG,
    INVALID_VALUE_ERROR_MESSAGE,
    LINKED_ENTITIES_COUNT_ENDPOINT,
    LOCAL_PORT_BATCH_SIZE,
    LOCAL_PORT_DEVICE_ID_KEY,
    LOCAL_PORT_DEVICE_ID_TYPE,
    LOCAL_PORT_MODEL,
    LOCAL_PORT_PARENT_KEYS,
    MANUAL_TAGS_ENDPOINT,
    MAX_API_CALLS,
    MAX_ORCA_SCORE,
    MAX_RETRY_AFTER,
    MIN_ORCA_SCORE,
    MODULE_NAME,
    NO_MORE_RETRIES_ERROR_MSG,
    PAGE_SIZE,
    PLATFORM_NAME,
    RELATION_KEY_FIELD_MAP,
    RESOLUTION_MESSAGE_MAP,
    RETRY_ERROR_MSG,
    SCAN_ENDPOINT,
    SCAN_NOT_FOUND_RESOLUTION_MESSAGE,
    SERVER_ERROR_MSG,
    SERVER_ERROR_RESOLUTION_MESSAGE,
    TAG_NOT_FOUND_RESOLUTION_MESSAGE,
    TYPE_ERROR_MESSAGE,
    VALIDATION_ERROR_MESSAGE,
)
from .exceptions import OrcaSecurityPluginException


class OrcaSecurityPluginHelper:
    """Helper class for the Orca Security CRE ZTRE plugin.

    Provides authentication headers, request execution with retry logic,
    pagination, field extraction/normalization, and enrichment/action API
    wrappers for Orca Security.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        ssl_validation,
        proxy,
    ):
        """Initialize OrcaSecurityPluginHelper.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix string for all log messages.
            plugin_name (str): Human-readable plugin name.
            plugin_version (str): Plugin version string.
            ssl_validation: SSL certificate verification flag or path.
            proxy: Proxy configuration dictionary.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.verify = ssl_validation
        self.proxies = proxy

    # ------------------------------------------------------------------
    # Headers / configuration
    # ------------------------------------------------------------------

    def _add_user_agent(self, headers: Optional[Dict] = None) -> Dict:
        """Add a User-Agent header to outgoing requests.

        Args:
            headers (Dict | None): Existing headers dictionary, or
                ``None`` to start from an empty dict.

        Returns:
            Dict: Headers dictionary with ``User-Agent`` set.
        """
        if headers and "User-Agent" in headers:
            return headers
        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def get_auth_headers(self, api_token: str) -> Dict:
        """Build the standard Orca Security authentication headers.

        Args:
            api_token (str): Orca Security API token.

        Returns:
            Dict: Headers dict containing ``Authorization`` and
                ``Content-Type``.
        """
        return {
            "Authorization": f"Token {api_token}",
            "Content-Type": "application/json",
        }

    def get_configuration_parameters(self, configuration: Dict) -> Tuple:
        """Extract plugin configuration parameters.

        ``base_url`` is resolved from the ``Base URL`` dropdown: when its
        value is ``custom`` (:const:`BASE_URL_CUSTOM_VALUE`), the actual
        URL comes from the ``Custom Base URL`` free-text field instead;
        otherwise the dropdown value itself (one of the fixed regional
        tenant URLs) is used directly. Both ``base_url`` and ``api_token``
        are stripped of surrounding whitespace here (and ``base_url`` of
        any trailing ``/``) so every caller builds URLs and auth headers
        from the same normalised values — a token pasted with a trailing
        newline would otherwise be sent verbatim and rejected as
        unauthorized.

        Args:
            configuration (Dict): Plugin configuration dictionary as
                provided by the Netskope CE framework.

        Returns:
            Tuple: ``(base_url, api_token, device_models, user_models)``.
        """
        configuration = configuration or {}
        base_url_choice = configuration.get(CONFIG_BASE_URL, "")
        if isinstance(base_url_choice, str):
            base_url_choice = base_url_choice.strip()
        if base_url_choice == BASE_URL_CUSTOM_VALUE:
            base_url = configuration.get(CONFIG_CUSTOM_BASE_URL, "")
        else:
            base_url = base_url_choice
        if isinstance(base_url, str):
            base_url = base_url.strip().rstrip("/")
        api_token = configuration.get(CONFIG_API_TOKEN, "")
        if isinstance(api_token, str):
            api_token = api_token.strip()
        return (
            base_url,
            api_token,
            configuration.get(CONFIG_DEVICE_MODELS) or [],
            configuration.get(CONFIG_USER_MODELS) or [],
        )

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True if the URL is valid, False otherwise.
        """
        if not isinstance(url, str):
            return False
        parsed = urlparse(url.strip())
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def validate_entity(self, entity: str, supported_entities: List) -> None:
        """Ensure the requested entity is supported by this plugin.

        Args:
            entity (str): Name of the entity requested by the caller.
            supported_entities (List): Entity names this plugin supports.

        Raises:
            OrcaSecurityPluginException: if the entity is not supported.
        """
        if entity not in supported_entities:
            err_msg = (
                f"Invalid entity '{entity}' found. This plugin only"
                f" supports {', '.join(supported_entities)} entities."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the selected entity is one of"
                    f" {', '.join(supported_entities)}."
                ),
            )
            raise OrcaSecurityPluginException(err_msg)

    def validate_parameters(
        self,
        field_name: str,
        field_value,
        field_type: type,
        parameter_type: Literal["configuration", "action"] = "configuration",
        allowed_values: Optional[List] = None,
        custom_validation_func: Optional[Callable] = None,
        is_required: bool = True,
        check_dollar: bool = False,
    ) -> Optional[ValidationResult]:
        """Validate a configuration or action parameter.

        Args:
            field_name (str): Parameter name.
            field_value: Parameter value.
            field_type (type): Expected type.
            parameter_type (Literal): "configuration" or "action".
            allowed_values (Optional[List]): Allowed values.
            custom_validation_func (Optional[Callable]): Custom validation
                function. Should return True when the field is valid, or
                either False or a specific error message string when it
                is not.
            is_required (bool): Whether the field is required.
            check_dollar (bool): When True, a string value containing
                ``$`` is treated as a Source field and validation is
                deferred to execution time (returns ``None``).

        Returns:
            ValidationResult or None: ValidationResult on failure, else
                None.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        def _fail(
            err_msg: str, resolution: str
        ) -> ValidationResult:
            """Log a validation failure and build its result."""
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
                    f" {err_msg}"
                ),
                resolution=resolution,
            )
            return ValidationResult(success=False, message=err_msg)

        invalid_value_resolution = (
            "Ensure that a valid value is provided for the"
            f" '{field_name}' {parameter_type} parameter."
        )

        if (
            check_dollar
            and isinstance(field_value, str)
            and "$" in field_value
        ):
            self.logger.info(
                f"{self.log_prefix}: '{field_name}' contains the Source"
                " Field hence validation for this field will be performed"
                " while executing the action."
            )
            return None

        is_empty = (
            field_value is None
            or field_value == ""
            or (isinstance(field_value, (list, dict)) and not field_value)
        )
        # A numeric 0 / False is a legitimate value, not an empty one.
        if isinstance(field_value, (int, float)) and not isinstance(
            field_value, bool
        ):
            is_empty = False

        if is_empty:
            if not is_required:
                return None
            return _fail(
                EMPTY_ERROR_MESSAGE.format(
                    field_name=field_name, parameter_type=parameter_type
                ),
                resolution=(
                    "Ensure that a value is provided for the"
                    f" '{field_name}' {parameter_type} parameter."
                ),
            )

        if not isinstance(field_value, field_type):
            return _fail(
                TYPE_ERROR_MESSAGE.format(
                    field_name=field_name, parameter_type=parameter_type
                ),
                resolution=invalid_value_resolution,
            )

        if custom_validation_func:
            outcome = custom_validation_func(field_value)
            if outcome is not True:
                err_msg = (
                    outcome
                    if isinstance(outcome, str)
                    else TYPE_ERROR_MESSAGE.format(
                        field_name=field_name,
                        parameter_type=parameter_type,
                    )
                )
                return _fail(
                    err_msg, resolution=invalid_value_resolution
                )

        if allowed_values:
            values_to_check = (
                field_value
                if isinstance(field_value, list)
                else [field_value]
            )
            invalid = [
                value
                for value in values_to_check
                if value not in allowed_values
            ]
            if invalid:
                return _fail(
                    INVALID_VALUE_ERROR_MESSAGE.format(
                        invalid_values=invalid,
                        field_name=field_name,
                        parameter_type=parameter_type,
                        allowed_values=allowed_values,
                    ),
                    resolution=(
                        "Ensure that a valid value is provided from the"
                        " allowed values."
                    ),
                )

        return None

    # ------------------------------------------------------------------
    # Field extraction / normalization helpers
    # ------------------------------------------------------------------

    def _extract_field_from_event(
        self, key: str, event: Dict, default=None, transformation=None
    ):
        """Resolve a dot-notation key path against a nested dict and
        optionally apply a named transformation method.

        Args:
            key (str): Dot-separated path, e.g. ``"CloudAccount.Name"``.
            event (dict): Source dictionary to traverse.
            default: Value to return when any segment is missing.
            transformation (str | None): Name of an instance method to
                call on the resolved value before returning it.

        Returns:
            The resolved (and optionally transformed) value, or
            *default* if any segment is absent.
        """
        parts = key.split(".")
        val = event
        for part in parts:
            if not isinstance(val, dict):
                return default
            val = val.get(part)
            if val is None:
                return default
        if transformation:
            transform_fn = getattr(self, transformation)
            return transform_fn(val)
        return val if val is not None else default

    def _first_item(self, value):
        """Return the first element of a list, or ``None``.

        Args:
            value: Candidate list value.

        Returns:
            The first element, or ``None`` when *value* is not a
            non-empty list.
        """
        if isinstance(value, list) and value:
            return value[0]
        return None

    def _first_non_empty(self, *vals):
        """Return the first non-empty value among *vals*.

        Args:
            *vals: Candidate values, in priority order.

        Returns:
            The first value that is neither ``None`` nor an empty
            string, or ``None`` if all are empty.
        """
        for val in vals:
            if val not in (None, ""):
                return val
        return None

    def get_scalar_value(self, value):
        """Unwrap a single-element list into a plain scalar value.

        The CE platform can hand back even ``STRING``-typed values
        wrapped in a single-element list — both in records re-delivered
        to ``update_records`` and in action parameters resolved from a
        Source field. This normalizes such values before they are used
        in a URL path or API payload, so a call never accidentally sends
        a Python list's ``str()`` representation (e.g.
        ``"['abc-123']"``) as a value.

        Args:
            value: Raw value, possibly wrapped in a list.

        Returns:
            The value as-is if it is not a list, its first element if it
            is a non-empty list, or ``None`` for an empty list.
        """
        if isinstance(value, list):
            return value[0] if value else None
        return value

    def get_scalar_field(self, record: Dict, field_name: str):
        """Read a record field, unwrapping a single-element list.

        Args:
            record (Dict): Record dictionary to read from.
            field_name (str): Field name to look up.

        Returns:
            The scalar value, or ``None`` when the field is absent or an
            empty list. See :meth:`get_scalar_value`.
        """
        return self.get_scalar_value(record.get(field_name))

    def get_stripped_param(self, parameters: Dict, key: str) -> str:
        """Read an action parameter as a stripped, unwrapped string.

        Action parameters arrive either as a static value typed into the
        UI or resolved from a Source field, in which case the platform
        may deliver them wrapped in a list. This collapses both shapes
        to a plain, whitespace-stripped string.

        Args:
            parameters (Dict): The action's ``parameters`` dictionary.
            key (str): Parameter key to read.

        Returns:
            str: The parameter value, or ``""`` when absent or empty.
        """
        value = self.get_scalar_value((parameters or {}).get(key, ""))
        if value is None:
            return ""
        return str(value).strip()

    def _cloud_provider_from_type(self, type_value) -> Optional[str]:
        """Derive the Cloud Provider from a model Type/type prefix.

        Args:
            type_value: The raw ``Type``/``type`` model name, e.g.
                ``"OciComputeVmInstance"``.

        Returns:
            str | None: One of ``AWS``, ``Azure``, ``GCP``, ``OCI``,
                ``Kubernetes``, or ``None`` if no prefix matches.
        """
        if not isinstance(type_value, str):
            return None
        for prefix, provider in CLOUD_PROVIDER_PREFIX_MAP.items():
            if type_value.startswith(prefix):
                return provider
        return None

    def format_tag_pairs(self, tags: Optional[Dict]) -> List[str]:
        """Render a tag dictionary as a list of ``"key: value"`` strings.

        Args:
            tags (Dict | None): Tag key/value mapping.

        Returns:
            List[str]: One ``"key: value"`` string per entry, or an
                empty list when *tags* is absent or not a dict.
        """
        if not isinstance(tags, dict):
            return []
        return [f"{key}: {value}" for key, value in tags.items()]

    def add_field(self, fields_dict: Dict, field_name: str, value) -> None:
        """Conditionally add a field to a record dictionary.

        Empty collections are stored as ``None`` (MongoDB safety).
        Numeric zero is stored as-is. All other falsy values are
        omitted.

        Args:
            fields_dict (dict): Target record dictionary.
            field_name (str): Key to insert.
            value: Value to store.
        """
        if isinstance(value, (dict, list)) and not value:
            fields_dict[field_name] = None
        elif isinstance(value, (int, float)):
            fields_dict[field_name] = value
        elif value:
            fields_dict[field_name] = value

    def extract_entity_fields(self, flat: Dict, mapping: Dict) -> Dict:
        """Build a record dict from a flattened raw item using a field
        mapping dict (see constants.py's ``*_FIELD_MAPPING``).

        Args:
            flat (Dict): Flattened raw item (see
                :meth:`flatten_orca_object`).
            mapping (Dict): One of ``DEVICE_FIELD_MAPPING`` /
                ``USER_FIELD_MAPPING``.

        Returns:
            Dict: Extracted (and MongoDB-safe) record dictionary.
        """
        record: Dict = {}
        for field_name, field_map in mapping.items():
            if "keys" in field_map:
                candidates = [
                    self._extract_field_from_event(
                        key, flat, None, field_map.get("transformation")
                    )
                    for key in field_map["keys"]
                ]
                value = self._first_non_empty(*candidates)
                if value is None:
                    value = field_map.get("default")
            else:
                value = self._extract_field_from_event(
                    field_map["key"],
                    flat,
                    field_map.get("default"),
                    field_map.get("transformation"),
                )
            self.add_field(record, field_name, value)
        return record

    def _extract_tag_dict(self, flat: Dict, key: str) -> List[str]:
        """Convert a single raw tag dict field into a list of
        ``"key: value"`` strings. All entries are kept, uncapped.

        Args:
            flat (Dict): Flattened raw item.
            key (str): Raw field name to read (``"Tags"`` or
                ``"ModelTags"``).

        Returns:
            List[str]: All tag entries as ``"key: value"`` strings.
        """
        return self.format_tag_pairs(flat.get(key))

    def normalize_score(self, orca_score) -> Tuple[Optional[int], bool]:
        """Compute the Netskope Normalized Score (0-1000, higher=safer).

        ``round((10 - OrcaScore) * 100)`` when ``OrcaScore`` is present
        and within ``[0.0, 10.0]``. When ``OrcaScore`` is absent, not
        numeric, or outside that range, the score is left empty
        (``None``) — there is no fallback to Risk Level or any other
        field.

        Args:
            orca_score: Raw ``OrcaScore`` value (may be ``None``).

        Returns:
            Tuple[int | None, bool]: ``(score, invalid_orca_score)``.
                ``invalid_orca_score`` is True only when ``orca_score``
                was present but unusable (not a number, or out of
                range), so the caller can aggregate a skip count for
                that condition specifically (a simply-absent OrcaScore
                is not counted as invalid).
        """
        if orca_score is None:
            return None, False
        try:
            score_val = float(orca_score)
        except (TypeError, ValueError):
            return None, True
        if MIN_ORCA_SCORE <= score_val <= MAX_ORCA_SCORE:
            return round((MAX_ORCA_SCORE - score_val) * 100), False
        return None, True

    def flatten_orca_object(self, item: Dict) -> Dict:
        """Flatten one raw ``object_set`` response item.

        Every field under ``data`` is wrapped in a ``{"value": ...}``
        envelope (e.g. ``data.Hostname = {"value": "..."}"``); this
        unwraps that envelope recursively (so nested objects such as
        ``CloudAccount`` also come out as plain nested dicts) and merges
        the result with the item's top-level fields (``id``,
        ``asset_unique_id``, ``type``, ``name``, ``group_unique_id``,
        ``cluster_unique_id``, ``last_seen``).

        Args:
            item (Dict): One raw item from the ``data`` array of an
                ``object_set`` response.

        Returns:
            Dict: Flattened dict suitable for
                :meth:`_extract_field_from_event`.
        """
        if not isinstance(item, dict):
            return {}
        data = item.get("data", {})
        flat = {
            "id": item.get("id"),
            "asset_unique_id": item.get("asset_unique_id"),
            "type": item.get("type"),
            "name": item.get("name"),
            "group_unique_id": item.get("group_unique_id"),
            "cluster_unique_id": item.get("cluster_unique_id"),
            "last_seen": item.get("last_seen"),
        }
        unwrapped = self._unwrap_value_envelope(data)
        if isinstance(unwrapped, dict):
            flat.update(unwrapped)
        return flat

    def _unwrap_value_envelope(self, obj):
        """Recursively unwrap ``{"value": ...}`` envelopes.

        Args:
            obj: Raw value (dict, list, or scalar) from the Orca API.

        Returns:
            The same shape with every ``{"value": X}`` dict replaced by
            ``X`` (applied recursively).
        """
        if isinstance(obj, dict):
            if set(obj.keys()) == {"value"}:
                return self._unwrap_value_envelope(obj["value"])
            return {
                key: self._unwrap_value_envelope(val)
                for key, val in obj.items()
            }
        if isinstance(obj, list):
            return [self._unwrap_value_envelope(val) for val in obj]
        return obj

    # ------------------------------------------------------------------
    # HTTP / retry / error handling
    # ------------------------------------------------------------------

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str = "POST",
        headers: Dict = None,
        params: Dict = None,
        json_data: Dict = None,
        is_validation: bool = False,
        is_handle_error_required: bool = True,
    ):
        """Execute an HTTP request against the Orca Security API.

        Automatically injects the User-Agent header, retries on HTTP
        429 (rate limit) and 5xx (server error) responses up to
        ``MAX_API_CALLS`` times, and delegates error handling to
        :meth:`handle_error` when requested. The retry loop is bypassed
        entirely when ``is_validation`` is True, so an invalid
        configuration fails fast instead of retrying for minutes.

        Args:
            logger_msg (str): Short description of the operation, used
                in log lines and exception messages.
            url (str): Full request URL.
            method (str): HTTP method (default ``"POST"`` - most Orca
                endpoints used by this plugin are POST; ``GET``/
                ``DELETE`` are passed explicitly by their callers).
            headers (Dict): Request headers dict (optional).
            params (Dict): Query-string parameters dict (optional).
            json_data (Dict): JSON-serialisable request body (optional).
            is_validation (bool): When ``True`` the retry loop is
                bypassed for 429/5xx so that validation fails fast.
            is_handle_error_required (bool): When ``True`` the raw
                :class:`Response` is passed through
                :meth:`handle_error` before being returned.

        Returns:
            Dict | Response: Parsed response dict when
                ``is_handle_error_required`` is ``True``, otherwise the
                raw :class:`requests.models.Response`.

        Raises:
            OrcaSecurityPluginException: On any error condition
                including connection failures, timeouts, proxy errors,
                HTTP errors, and exhausted retries.
        """
        headers = self._add_user_agent(headers)
        debug_log_msg = (
            f"{self.log_prefix}: API Request for {logger_msg}. Endpoint:"
            f" {method} {url}"
        )
        if params:
            debug_log_msg += f", params: {params}"
        self.logger.debug(f"{debug_log_msg}.")
        try:
            for retry_count in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    json=json_data,
                    headers=headers,
                    verify=self.verify,
                    proxies=self.proxies,
                    timeout=DEFAULT_REQUEST_TIMEOUT,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for"
                    f" {logger_msg}. Status Code={status_code}."
                )
                if not is_validation and (
                    status_code == 429 or 500 <= status_code <= 600
                ):
                    api_err_msg = str(response.text)
                    if retry_count == MAX_API_CALLS - 1:
                        err_msg = NO_MORE_RETRIES_ERROR_MSG.format(
                            status_code=status_code, logger_msg=logger_msg
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise OrcaSecurityPluginException(err_msg)
                    error_reason = (
                        "API rate limit exceeded"
                        if status_code == 429
                        else "HTTP server error occurred"
                    )
                    retry_after = self._get_retry_after(response.headers)
                    err_msg = RETRY_ERROR_MSG.format(
                        status_code=status_code,
                        error_reason=error_reason,
                        logger_msg=logger_msg,
                        wait_time=retry_after,
                        retry_remaining=(MAX_API_CALLS - 1 - retry_count),
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=api_err_msg,
                    )
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(
                            response=response,
                            logger_msg=logger_msg,
                            is_validation=is_validation,
                        )
                        if is_handle_error_required
                        else response
                    )
        except OrcaSecurityPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read Timeout error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    f"Please check if the {PLATFORM_NAME} API server is"
                    " reachable."
                ),
            )
            raise OrcaSecurityPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the"
                " proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy configuration"
                    " provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Please check if the proxy configuration provided is"
                    " correct and the proxy server is reachable."
                ),
            )
            raise OrcaSecurityPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME}"
                f" platform while {logger_msg}. Proxy server or"
                f" {PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME}"
                    f" platform. Proxy server or {PLATFORM_NAME} server"
                    " is not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    f"Please check if the {PLATFORM_NAME} API server is"
                    " reachable."
                ),
            )
            raise OrcaSecurityPluginException(err_msg)
        except requests.HTTPError as error:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify configuration parameters"
                    " provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Please verify the configuration parameters provided."
                ),
            )
            raise OrcaSecurityPluginException(err_msg)
        except Exception as error:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing API call to"
                    f" {PLATFORM_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Please verify the configuration parameters provided."
                ),
            )
            raise OrcaSecurityPluginException(err_msg)

    def _get_retry_after(self, headers) -> int:
        """Determine how long to wait before the next retry attempt.

        Reads the ``Retry-After``/``retry-after`` response header and
        clamps the value to ``MAX_RETRY_AFTER`` seconds.

        Args:
            headers: Response headers mapping.

        Returns:
            int: Number of seconds to wait, between 0 and
                ``MAX_RETRY_AFTER``.
        """
        val = headers.get("Retry-After") or headers.get("retry-after")
        try:
            wait = int(val) if val else DEFAULT_WAIT_TIME
        except (TypeError, ValueError):
            wait = DEFAULT_WAIT_TIME
        return min(wait, MAX_RETRY_AFTER)

    def parse_response(self, response: Response, logger_msg: str) -> Dict:
        """Parse the JSON body of a successful API response.

        Args:
            response (Response): The :class:`requests.models.Response`
                object to parse.
            logger_msg (str): Operation description for log messages.

        Returns:
            Dict: Deserialised JSON body.

        Raises:
            OrcaSecurityPluginException: If the response body is not
                valid JSON or any other parsing error occurs.
        """
        try:
            return response.json()
        except ValueError as error:
            err_msg = f"Invalid JSON response received while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=f"API response: {response.text}",
            )
            raise OrcaSecurityPluginException(err_msg)
        except Exception as error:
            err_msg = (
                f"Unexpected error occurred while parsing response for"
                f" {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=f"API response: {response.text}",
            )
            raise OrcaSecurityPluginException(err_msg)

    def handle_error(
        self,
        response: Response,
        logger_msg: str,
        is_validation: bool = False,
        is_scan_action: bool = False,
        not_found_resolution: Optional[str] = None,
    ) -> Dict:
        """Interpret an HTTP response and raise on non-success codes.

        Success is judged by the HTTP status code alone: a 200/201/202
        body is parsed as JSON and returned as-is, with no assertion on
        its shape or contents. Each caller is responsible for checking
        whatever field it actually needs (e.g. :meth:`trigger_scan`
        checks for ``scan_unique_id``); this keeps the transport layer
        from being coupled to an unconfirmed, endpoint-specific response
        envelope.

        Args:
            response (Response): The :class:`requests.models.Response`
                to inspect.
            logger_msg (str): Operation description for log messages.
            is_validation (bool): When ``True`` the logged message is
                prefixed with the standard validation wording and the
                operation suffix is omitted, since the operator is
                looking at a configuration form rather than a pull
                cycle.
            is_scan_action (bool): When True, use the Scan Data Now
                specific 404 resolution message (asset likely no longer
                exists) instead of the generic Base URL resolution.
            not_found_resolution (str | None): When provided, overrides
                the 404 resolution message (takes precedence over the
                ``is_scan_action`` default).

        Returns:
            Dict: Parsed response body (200/201/202) or ``{}`` (204).

        Raises:
            OrcaSecurityPluginException: For any non-2xx status code.
        """
        status_code = response.status_code

        def _raise(err_msg: str, resolution: Optional[str] = None):
            # Outside validation the status-code message alone does not
            # say whether the failure came from a pull, an enrichment or
            # an action, so the operation is appended.
            log_msg = (
                f"{VALIDATION_ERROR_MESSAGE} {err_msg}"
                if is_validation
                else f"{err_msg} Error occurred while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {log_msg}",
                details=f"API response: {response.text}",
                resolution=resolution,
            )
            raise OrcaSecurityPluginException(err_msg)

        if status_code in (200, 201, 202):
            return self.parse_response(
                response=response, logger_msg=logger_msg
            )
        elif status_code == 204:
            return {}
        elif status_code in ERROR_MESSAGE_MAP:
            resolution = RESOLUTION_MESSAGE_MAP.get(status_code)
            if status_code == 404:
                resolution = (
                    not_found_resolution
                    or (
                        SCAN_NOT_FOUND_RESOLUTION_MESSAGE
                        if is_scan_action
                        else resolution
                    )
                )
            _raise(ERROR_MESSAGE_MAP.get(status_code), resolution=resolution)
        elif 400 <= status_code < 500:
            # 409/422, and a 429 that reaches here because retries are
            # bypassed during validation, would otherwise be reported as
            # a bare "HTTP Error".
            _raise(
                CLIENT_ERROR_MSG.format(status_code=status_code),
                resolution=CLIENT_ERROR_RESOLUTION_MESSAGE,
            )
        elif 500 <= status_code < 600:
            _raise(
                SERVER_ERROR_MSG.format(status_code=status_code),
                resolution=SERVER_ERROR_RESOLUTION_MESSAGE,
            )
        else:
            _raise(
                GENERIC_ERROR_MSG.format(status_code=status_code),
                resolution=CLIENT_ERROR_RESOLUTION_MESSAGE,
            )

    # ------------------------------------------------------------------
    # object_set pagination
    # ------------------------------------------------------------------

    def build_object_set_payload(
        self, models: List[str], start_at_index: int = 0
    ) -> Dict:
        """Build the request body for an ``object_set`` query call.

        No ``order_by`` is applied — pages are returned in whatever
        default order the API provides for the queried type(s).

        Args:
            models (List[str]): Orca type name(s) to query.
            start_at_index (int): Pagination offset (0 for first page).

        Returns:
            Dict: JSON-serialisable request payload.
        """
        return {
            "query": {
                "type": "object_set",
                "models": models,
            },
            "limit": PAGE_SIZE,
            "start_at_index": start_at_index,
            "get_results_and_count": True,
        }

    def paginate_object_set(
        self,
        headers: Dict,
        base_url: str,
        models: List[str],
        entity_label: str,
    ) -> List[Dict]:
        """Paginate through one or more models' combined query results.

        All models in ``models`` are queried together in a single
        ``object_set`` request per page (one combined ``"models": [...]``
        array), rather than issuing one request per type. Terminates
        only when a page returns fewer than ``PAGE_SIZE`` items or
        ``start_at_index`` reaches ``total_items`` — the full combined
        dataset is always fetched, regardless of size.

        Args:
            headers (Dict): Authentication headers.
            base_url (str): Configured Orca Security base URL.
            models (List[str]): Orca type name(s) to query together in
                a single combined call (e.g. ``["AwsEc2Instance",
                "AzureVm"]``).
            entity_label (str): Singular entity label used in log lines
                (e.g. ``"Workload"``).

        Returns:
            List[Dict]: Flattened raw items across all pages for the
                combined type set (see :meth:`flatten_orca_object`).
        """
        url = f"{base_url}{BASE_URL_ENDPOINT}"
        items: List[Dict] = []
        start_at_index = 0
        page = 1
        total_items: Optional[int] = None
        models_desc = ", ".join(models)

        while True:
            payload = self.build_object_set_payload(
                models=models, start_at_index=start_at_index
            )
            response = self.api_helper(
                logger_msg=(
                    f"fetching {entity_label.lower()} records for types"
                    f" '{models_desc}' in page {page}"
                ),
                url=url,
                method="POST",
                headers=headers,
                json_data=payload,
            )
            page_data = (
                response.get("data", []) if isinstance(response, dict) else []
            )
            if total_items is None:
                # Only trust an explicitly reported count. Defaulting it
                # to the first page's size would stop after one full page
                # whenever the API omits 'total_items'.
                total_items = (
                    response.get("total_items")
                    if isinstance(response, dict)
                    else None
                )
                if total_items is not None:
                    self.logger.info(
                        f"{self.log_prefix}: Found {total_items}"
                        f" {entity_label} record(s) available in"
                        f" {PLATFORM_NAME} for type(s)"
                        f" '{models_desc}'."
                    )

            items.extend(
                self.flatten_orca_object(item) for item in page_data
            )
            start_at_index += len(page_data)
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched"
                f" {len(page_data)} {entity_label} record(s) in page"
                f" {page} for types '{models_desc}'. Total"
                f" {entity_label} record(s) fetched: {len(items)}."
            )

            if len(page_data) < PAGE_SIZE or (
                total_items is not None and start_at_index >= total_items
            ):
                break
            page += 1

        return items

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def fetch_linked_entity_counts(
        self, headers: Dict, base_url: str, model: str, asset_id: str
    ) -> Dict[str, int]:
        """Fetch linked-entity counts for a single Workload asset.

        The endpoint takes exactly one ``type``/``base_id`` pair per
        call — ``type`` is the asset's own Orca type (e.g.
        ``"OciComputeVmInstance"``, the workload's ``Type``), not a
        relation key; the response already contains a ``links[]`` array
        covering every relation for that single asset. Matches counts
        by the exact ``relation_key`` (never summed by ``related_model``,
        since ``Alerts`` legitimately appears under two different
        relation keys from two graph directions and summing would
        double-count).

        Args:
            headers (Dict): Authentication headers.
            base_url (str): Configured Orca Security base URL.
            model (str): The asset's own Orca model (its ``Type``
                field), e.g. ``"OciComputeVmInstance"``.
            asset_id (str): Workload ``id`` (Entity ID).

        Returns:
            Dict[str, int]: Mapping of every plugin field name (``"Alerts
                Count"``, ``"Login Attempts Count"``, ``"Vulnerability
                Count"``) to its count. A relation key absent from the
                response is reported as 0 rather than omitted, so a
                workload whose linked entities have since gone to zero
                (or whose relation disappeared from the response
                entirely) has its stale count cleared instead of keeping
                whatever non-zero value was written on a prior cycle.
        """
        url = f"{base_url}{LINKED_ENTITIES_COUNT_ENDPOINT}"
        payload = {
            "model": model,
            "base_id": asset_id,
        }
        response = self.api_helper(
            logger_msg=(
                f"fetching linked entity counts for asset '{asset_id}'"
            ),
            url=url,
            method="POST",
            headers=headers,
            json_data=payload,
        )
        data = response.get("data") if isinstance(response, dict) else None
        links = data.get("links", []) if isinstance(data, dict) else []
        counts: Dict[str, int] = {
            field_name: 0 for field_name in RELATION_KEY_FIELD_MAP.values()
        }
        for link in links:
            if not isinstance(link, dict):
                continue
            relation_key = link.get("relation_key")
            field_name = RELATION_KEY_FIELD_MAP.get(relation_key)
            if field_name:
                counts[field_name] = link.get("count", 0)
        return counts

    def _build_local_ports_filter(self, device_ids: List[str]) -> Dict:
        """Build the nested ``with`` clause selecting one or more
        workloads' ports in a single combined query.

        Walks ``Compute -> base -> id`` and matches any of the given
        workload Entity IDs. Rebuilt per call so the returned dict is
        never shared.

        Args:
            device_ids (List[str]): The workloads' Entity IDs (Orca
                ``id`` uuids) to include in this query's ``values``
                filter.

        Returns:
            Dict: The ``query.with`` clause for a LocalPort query.
        """
        outer_key, inner_key = LOCAL_PORT_PARENT_KEYS
        return {
            "keys": [outer_key],
            "models": [outer_key],
            "type": "object",
            "operator": "has",
            "with": {
                "keys": [inner_key],
                "models": [inner_key],
                "type": "object",
                "operator": "has",
                "with": {
                    "key": LOCAL_PORT_DEVICE_ID_KEY,
                    "values": device_ids,
                    "type": LOCAL_PORT_DEVICE_ID_TYPE,
                    "operator": "in",
                },
            },
        }

    def fetch_local_ports_for_devices(
        self, headers: Dict, base_url: str, device_ids: List[str]
    ) -> Dict[str, Dict[str, List]]:
        """Fetch the public-facing open ports of one or more Workloads.

        Up to ``LOCAL_PORT_BATCH_SIZE`` workload ids are queried together
        per call via a single combined ``values`` filter, instead of one
        call per workload. The ``select`` clause is deliberately omitted
        from the query so every returned ``LocalPort`` item carries its
        parent workload as a nested ``Compute`` object (including
        ``Compute.id``), which is what attributes each returned port
        back to the workload it belongs to.

        Only ports whose own ``Exposure`` is ``public_facing`` are kept:
        the model returns every listening port on the workload, and the
        rest are not reachable from outside.

        Distinct ``FromPort`` and ``ToPort`` are collected as integers
        alongside ``ServiceName`` and ``Protocol``; port ranges are not
        expanded (a ``0-65535`` range would otherwise produce 65 536
        entries). All distinct entries are kept, uncapped.

        Args:
            headers (Dict): Authentication headers.
            base_url (str): Configured Orca Security base URL.
            device_ids (List[str]): The workloads' Entity IDs (Orca
                ``id`` uuids) to fetch ports for.

        Returns:
            Dict[str, Dict[str, List]]: ``device_id -> {"Ports": [...],
                "Port Services": [...], "Port Protocols": [...]}`` for
                every ``device_id`` whose batch succeeded. A workload with
                no public-facing port present is included with all-empty
                lists (never omitted), so the caller can still clear
                stale data. A ``device_id`` is absent entirely when its
                batch's query call failed, so a transient error never
                clears ports that are still open on those workloads.
        """
        url = f"{base_url}{BASE_URL_ENDPOINT}"
        result: Dict[str, Dict[str, List]] = {}

        for batch_start in range(0, len(device_ids), LOCAL_PORT_BATCH_SIZE):
            batch_end = batch_start + LOCAL_PORT_BATCH_SIZE
            batch_ids = device_ids[batch_start:batch_end]
            batch_no = (batch_start // LOCAL_PORT_BATCH_SIZE) + 1
            # dict keys give O(1) de-duplication while preserving
            # first-seen order; a list with an `in` test would be
            # O(n^2) per workload.
            ports: Dict[str, Dict[int, None]] = {
                device_id: {} for device_id in batch_ids
            }
            services: Dict[str, Dict[str, None]] = {
                device_id: {} for device_id in batch_ids
            }
            protocols: Dict[str, Dict[str, None]] = {
                device_id: {} for device_id in batch_ids
            }
            device_filter = self._build_local_ports_filter(batch_ids)
            start_at_index = 0
            page = 1

            try:
                while True:
                    payload = {
                        "query": {
                            "type": "object_set",
                            "models": [LOCAL_PORT_MODEL],
                            "with": device_filter,
                        },
                        "limit": PAGE_SIZE,
                        "start_at_index": start_at_index,
                        "get_results_and_count": False,
                    }
                    response = self.api_helper(
                        logger_msg=(
                            f"fetching {LOCAL_PORT_MODEL} records for"
                            f" {len(batch_ids)} workload(s) in ports batch"
                            f" {batch_no}, page {page}"
                        ),
                        url=url,
                        method="POST",
                        headers=headers,
                        json_data=payload,
                    )
                    page_data = (
                        response.get("data", [])
                        if isinstance(response, dict)
                        else []
                    )
                    for item in page_data:
                        flat = self.flatten_orca_object(item)
                        compute = flat.get("Compute")
                        device_id = (
                            compute.get("id")
                            if isinstance(compute, dict)
                            else None
                        )
                        if device_id not in ports:
                            continue
                        exposure = flat.get("Exposure")
                        if (
                            not isinstance(exposure, str)
                            or exposure.strip() != EXPOSURE_PUBLIC_FACING
                        ):
                            continue
                        for port_val in (
                            flat.get("FromPort"),
                            flat.get("ToPort"),
                        ):
                            if isinstance(
                                port_val, (int, float)
                            ) and not isinstance(port_val, bool):
                                ports[device_id][int(port_val)] = None
                        if flat.get("ServiceName"):
                            services[device_id][flat["ServiceName"]] = None
                        if flat.get("Protocol"):
                            protocols[device_id][flat["Protocol"]] = None

                    start_at_index += len(page_data)
                    # 'get_results_and_count' is False, so the response
                    # carries no total; a short page is the only
                    # end-of-data signal.
                    if len(page_data) < PAGE_SIZE:
                        break
                    page += 1
            except OrcaSecurityPluginException as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while"
                        f" fetching open ports for {len(batch_ids)}"
                        f" workload(s) in ports batch {batch_no}. These"
                        f" record(s) will not be enriched. Error: {exp}"
                    ),
                    resolution=(
                        "Ensure the API Token has read access to the"
                        " Orca serving layer."
                    ),
                )
                continue

            for device_id in batch_ids:
                result[device_id] = {
                    FIELD_PORTS: list(ports[device_id]),
                    FIELD_PORT_SERVICES: list(services[device_id]),
                    FIELD_PORT_PROTOCOLS: list(protocols[device_id]),
                }

        return result

    # ------------------------------------------------------------------
    # Scan Data Now action
    # ------------------------------------------------------------------

    def trigger_scan(
        self, headers: Dict, base_url: str, asset_unique_id: str
    ) -> Dict:
        """Trigger an on-demand Orca scan of a single asset.

        Args:
            headers (Dict): Authentication headers.
            base_url (str): Configured Orca Security base URL.
            asset_unique_id (str): The asset to scan.

        Returns:
            Dict: Parsed response body (contains ``scan_unique_id`` and
                ``asset_unique_id`` on success).

        Raises:
            OrcaSecurityPluginException: On any status outside
                (200, 201, 202), or a 200/201/202 response missing
                ``scan_unique_id``.
        """
        scan_path = SCAN_ENDPOINT.format(asset_unique_id=asset_unique_id)
        url = f"{base_url}{scan_path}"
        logger_msg = f"triggering scan for asset '{asset_unique_id}'"
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers=headers,
            is_handle_error_required=False,
        )
        if response.status_code in (200, 201, 202):
            parsed = self.parse_response(response, logger_msg)
            scan_unique_id = (
                parsed.get("scan_unique_id")
                if isinstance(parsed, dict)
                else None
            )
            if not scan_unique_id:
                err_msg = (
                    "Scan trigger response did not contain a"
                    f" 'scan_unique_id' for asset '{asset_unique_id}'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                )
                raise OrcaSecurityPluginException(err_msg)
            return parsed
        return self.handle_error(
            response=response,
            logger_msg=logger_msg,
            is_validation=False,
            is_scan_action=True,
        )

    # ------------------------------------------------------------------
    # Add/Remove Custom Tag action
    # ------------------------------------------------------------------

    def add_custom_tag(
        self, headers: Dict, base_url: str, asset_id: str, tag_key: str,
        tag_value: str,
    ) -> Dict:
        """Add a custom tag to a single asset.

        Args:
            headers (Dict): Authentication headers.
            base_url (str): Configured Orca Security base URL.
            asset_id (str): The Orca ``id`` (Entity ID) of the asset to
                tag.
            tag_key (str): Tag key to set.
            tag_value (str): Tag value to set.

        Returns:
            Dict: Parsed response body on success.

        Raises:
            OrcaSecurityPluginException: On any non-2xx status.
        """
        url = f"{base_url}{MANUAL_TAGS_ENDPOINT.format(asset_id=asset_id)}"
        logger_msg = f"adding tag '{tag_key}' to asset '{asset_id}'"
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers=headers,
            json_data={"tag_key": tag_key, "tag_value": tag_value},
            is_handle_error_required=False,
        )
        return self.handle_error(
            response=response,
            logger_msg=logger_msg,
            not_found_resolution=TAG_NOT_FOUND_RESOLUTION_MESSAGE,
        )

    def remove_custom_tag(
        self, headers: Dict, base_url: str, asset_id: str, tag_key: str,
    ) -> Dict:
        """Remove a custom tag from a single asset.

        Args:
            headers (Dict): Authentication headers.
            base_url (str): Configured Orca Security base URL.
            asset_id (str): The Orca ``id`` (Entity ID) of the asset to
                untag.
            tag_key (str): Tag key to remove.

        Returns:
            Dict: Parsed response body on success.

        Raises:
            OrcaSecurityPluginException: On any non-2xx status.
        """
        url = f"{base_url}{MANUAL_TAGS_ENDPOINT.format(asset_id=asset_id)}"
        logger_msg = f"removing tag '{tag_key}' from asset '{asset_id}'"
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="DELETE",
            headers=headers,
            json_data={"tag_key": tag_key},
            is_handle_error_required=False,
        )
        return self.handle_error(
            response=response,
            logger_msg=logger_msg,
            not_found_resolution=TAG_NOT_FOUND_RESOLUTION_MESSAGE,
        )

    # ------------------------------------------------------------------
    # Custom Tags enrichment
    # ------------------------------------------------------------------

    def fetch_custom_tags(
        self, headers: Dict, base_url: str, asset_id: str
    ) -> Dict[str, str]:
        """Fetch the custom tags currently set on a single asset.

        Calls Orca's ``manual_tags`` API (surfaced in the Orca UI as
        "Custom Tags").

        Args:
            headers (Dict): Authentication headers.
            base_url (str): Configured Orca Security base URL.
            asset_id (str): The Orca ``id`` (Entity ID) of the asset.

        Returns:
            Dict[str, str]: The asset's custom tag key/value pairs (the
                response's ``data`` object), or ``{}`` if absent.

        Raises:
            OrcaSecurityPluginException: On any non-2xx status.
        """
        url = f"{base_url}{MANUAL_TAGS_ENDPOINT.format(asset_id=asset_id)}"
        logger_msg = f"fetching custom tags for asset '{asset_id}'"
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="GET",
            headers=headers,
            is_handle_error_required=False,
        )
        parsed = self.handle_error(
            response=response,
            logger_msg=logger_msg,
            not_found_resolution=TAG_NOT_FOUND_RESOLUTION_MESSAGE,
        )
        data = parsed.get("data") if isinstance(parsed, dict) else None
        return data if isinstance(data, dict) else {}
