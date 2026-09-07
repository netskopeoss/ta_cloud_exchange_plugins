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

Anthropic LLM provider plugin.
"""

import os
import sys
import traceback
from typing import List, Optional, Sequence, Union

from netskope.common.utils import add_user_agent
from netskope.common.utils.llm_provider_plugin_base import (
    LLMErrorType,
    PluginBase,
)
from netskope.common.utils.provider_plugin_base import ValidationResult

from .utils import api_client
from .utils.anthropic_constants import (
    DEFAULT_EFFORT,
    DEFAULT_MAX_RETRIES,
    EFFORT_FIELD_DESCRIPTION,
    EFFORT_FIELD_KEY,
    EFFORT_FIELD_LABEL,
    EFFORT_LABELS,
    FETCH_MODEL_DEFAULT_RESOLUTION,
    FETCH_MODEL_ERROR_RESOLUTIONS,
    FULL_EFFORT,
    KNOWN_WEB_SEARCH_VERSIONS,
    MAX_TOKENS_ENV_VAR,
    MODULE_NAME,
    ModelSpec,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    RETRYABLE_STATUSES,
    STOP_REASON_MAP,
    SUPPORTED_MODELS,
    TIMEOUT,
    WEB_SEARCH_PARAMS,
)

# Prefer the bundled langchain_anthropic in lib/ over whatever is in site-packages.
# To populate lib/, run from the plugin directory:
# pip install -U anthropic langchain-anthropic distro docstring-parser jiter \
#     --no-deps --target ./lib
_lib_path = os.path.join(os.path.dirname(__file__), "lib")
if os.path.isdir(_lib_path) and _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)


try:
    import anthropic as _anthropic_sdk
    from langchain_anthropic import ChatAnthropic
except Exception as exp:
    raise ValueError(
        "langchain_anthropic and anthropic dependencies are required for Anthropic provider."
    ) from exp


def _effort_label(level: str) -> str:
    """Human-readable label for an effort level token."""
    if level in EFFORT_LABELS:
        return EFFORT_LABELS[level]
    return level.capitalize() if level else level


def _positive_int(
    value, name: str, default: int, *, allow_zero: bool = False
) -> int:
    """Validate a numeric runtime_config value; raise ValueError on a bad one.

    Returns ``default`` unchanged when the value IS the default (the common no-override
    path). Otherwise coerces to int and enforces > 0 (or >= 0 when ``allow_zero``), raising
    a clear ValueError — consistent with how _get_model/_get_api_key/_get_effort_levels
    guard configuration-sourced values instead of passing junk deep into the SDK.
    """
    if value is default:
        return default
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"'{name}' must be an integer, got {value!r}.")
    if coerced < 0 or (coerced == 0 and not allow_zero):
        raise ValueError(
            f"'{name}' must be a {'non-negative' if allow_zero else 'positive'} "
            f"integer, got {coerced}."
        )
    return coerced


def _default_effort_for(levels: Sequence[str]) -> Optional[str]:
    """Effort level to pre-select for a model.

    DEFAULT_EFFORT when supported, else the highest supported level, else None
    (model supports no effort).
    """
    if not levels:
        return None
    if DEFAULT_EFFORT in levels:
        return DEFAULT_EFFORT
    return levels[-1]


def _resolution_for_fetch_error(exp: Exception) -> str:
    """Pick the resolution matching the HTTP status api_client's ValueError carries.

    ``status_code`` is set by api_client._api_error for every status-based failure
    (400/401/403/404/429/5xx/unexpected); it is absent when the request never got an
    HTTP response at all (network/proxy connectivity failure), which also falls back
    to FETCH_MODEL_DEFAULT_RESOLUTION.
    """
    status_code = getattr(exp, "status_code", None)
    return FETCH_MODEL_ERROR_RESOLUTIONS.get(status_code, FETCH_MODEL_DEFAULT_RESOLUTION)


def _resolve_max_tokens(
    spec: "ModelSpec", runtime_value, log_prefix: str, logger
) -> int:
    """Resolve the max_tokens budget for a turn: env > runtime_config > per-model default.

    Precedence (all clamped to the model's ``max_tokens_ceiling`` so no source can exceed the
    model's hard per-response cap):
      1. AI_COPILOT_MAX_TOKENS env var — the deployment 'use it to the max' override; WINS when
         set + a positive int. A malformed value is logged and ignored (a bad env var must not
         break the plugin), falling through to (2).
      2. runtime_config['max_tokens'] — the per-turn caller override, when provided.
      3. spec.max_tokens — the per-model tuned optimum.
    """
    ceiling = spec.max_tokens_ceiling

    env_raw = os.getenv(MAX_TOKENS_ENV_VAR)
    if env_raw not in (None, ""):
        try:
            env_val = int(env_raw)
            if env_val <= 0:
                raise ValueError("must be positive")
        except (TypeError, ValueError):
            logger.info(
                f"{log_prefix}: Ignoring invalid {MAX_TOKENS_ENV_VAR}={env_raw!r} "
                f"(expected a positive integer); using the per-turn/model value instead."
            )
        else:
            resolved = min(env_val, ceiling)
            if env_val > ceiling:
                logger.info(
                    f"{log_prefix}: {MAX_TOKENS_ENV_VAR}={env_val} exceeds the model's "
                    f"{ceiling}-token ceiling; capping at {ceiling}."
                )
            return resolved

    if runtime_value is not None:
        return min(
            _positive_int(runtime_value, "max_tokens", spec.max_tokens),
            ceiling,
        )

    return min(spec.max_tokens, ceiling)


class AnthropicLLMProviderPlugin(PluginBase):
    """Plugin for configuring and exposing LLM runnable instances."""

    def __init__(self, name, *args, **kwargs) -> None:
        """Anthropic provider plugin initialization.

        Args:
            name (str): name of the plugin.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest metadata."""
        try:
            manifest_json = AnthropicLLMProviderPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME}: Error occurred while getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _get_api_key(self, configuration: dict) -> str:
        api_key = configuration.get("api_key") or ""
        if not api_key:
            err_msg = "API key is required."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while validating "
                    f"LLM provider parameters. {err_msg}"
                ),
                resolution=(
                    "Ensure that a valid API key is provided in the LLM provider parameters."
                ),
            )
            raise ValueError(err_msg)
        return api_key

    def _add_user_agent(self, headers: Union[dict, None] = None) -> dict:
        """Add User-Agent in the headers for third-party requests.

        Args:
            headers (dict): Dictionary containing headers for any request.
        Returns:
            dict: Dictionary after adding User-Agent.
        """
        if headers and "User-Agent" in headers:
            return headers
        headers = add_user_agent(header=headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def _get_model(self, configuration: dict, key: str = "model") -> str:
        model = configuration.get(key)
        if not model:
            err_msg = "Model is not configured."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while validating "
                    f"LLM provider parameters. {err_msg}"
                ),
                resolution="Ensure that a model is selected in the LLM provider parameters.",
            )
            raise ValueError(err_msg)
        return model

    def _get_effort_levels(
        self, configuration: dict, key: str = "agentic_effort_calibration"
    ) -> str:
        # Note: no error log here — get_runnable() also hits this branch for models
        # that support no effort tuning at all, which is an expected/benign case
        # (see the ValueError handling around _get_effort_levels in get_runnable()).
        # The real, user-actionable validation failure is logged by validate().
        effort = configuration.get(key)
        if not effort:
            raise ValueError("Agentic Effort Calibration is not configured.")
        return effort

    def get_dynamic_fields(self) -> List[dict]:
        """Return config fields whose options depend on the selected model.

        The config UI drives this via the cascade contract: the manifest 'model'
        field is marked has_api_call with payload_fields=["model"], so changing
        the model POSTs the current selection here. We return the
        agentic_effort_calibration choice field populated with only the levels
        the chosen model supports — labels included — so the UI never hardcodes
        provider vocabulary. Returns [] when the model supports no effort tuning
        (the effort field then simply does not render).
        """
        model = self.configuration.get("model")
        spec = SUPPORTED_MODELS.get(model)
        levels = list(spec.effort_levels) if spec else []
        if not levels:
            return []
        return [
            {
                "label": EFFORT_FIELD_LABEL,
                "key": EFFORT_FIELD_KEY,
                "type": "choice",
                "choices": [
                    {"key": _effort_label(level), "value": level}
                    for level in levels
                ],
                "default": _default_effort_for(levels),
                "mandatory": True,
                "description": EFFORT_FIELD_DESCRIPTION,
            }
        ]

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate plugin configuration."""
        try:
            api_key = self._get_api_key(configuration)
            model = self._get_model(configuration)
            if model not in SUPPORTED_MODELS:
                err_msg = (
                    f"Unsupported model '{model}'. Choose one of: {', '.join(SUPPORTED_MODELS)}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while validating "
                        f"LLM provider parameters. {err_msg}"
                    ),
                    resolution=(
                        "Ensure that a supported Anthropic model is selected "
                        "in the LLM provider parameters."
                    ),
                )
                raise ValueError(err_msg)
            try:
                effort = self._get_effort_levels(configuration)
            except ValueError as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while validating "
                        f"LLM provider parameters. {exp}"
                    ),
                    resolution="Ensure that the Agentic Effort Calibration field is configured.",
                )
                raise
            if effort not in SUPPORTED_MODELS[model].effort_levels:
                err_msg = (
                    f"Unsupported effort '{effort}' for model '{model}'. Choose one of: "
                    f"{', '.join(SUPPORTED_MODELS[model].effort_levels)}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while validating "
                        f"LLM provider parameters. {err_msg}"
                    ),
                    resolution=(
                        "Ensure that a supported Agentic Effort Calibration value is "
                        "selected for the chosen model."
                    ),
                )
                raise ValueError(err_msg)
            headers = self._add_user_agent()
            # fetch_model validates the key+model (404 handling for an
            # unavailable/deprecated model) before we persist the configuration.
            self.logger.debug(
                f"{self.log_prefix}: Fetching model details from the Anthropic API for validation."
            )
            try:
                api_client.fetch_model(
                    api_key,
                    model,
                    proxy=self.proxy,
                    use_proxy=self.use_proxy,
                    ssl_validation=self.ssl_validation,
                    headers=headers,
                    timeout=TIMEOUT,
                )
            except ValueError as exp:
                # api_client attaches .status_code (see _api_error) for every status-based
                # failure; absent only when no HTTP response was ever received (network/proxy
                # failure). Folded into a new message so the status code is visible both in
                # this log entry AND in the ValidationResult surfaced to the CE UI (the outer
                # `except ValueError` below re-uses str(exp) verbatim for that message).
                status_code = getattr(exp, "status_code", None)
                err_msg = (
                    f"Anthropic API returned HTTP {status_code}: {exp}"
                    if status_code is not None
                    else str(exp)
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while validating "
                        f"LLM provider parameters. {err_msg}"
                    ),
                    resolution=_resolution_for_fetch_error(exp),
                )
                raise ValueError(err_msg) from exp
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched the model details from the Anthropic API."
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully validated the LLM provider."
            )
            return ValidationResult(
                success=True,
                message="Validation successful for LLM provider plugin.",
                checkpoint=None,
            )
        except ValueError as exp:
            return ValidationResult(
                success=False, message=str(exp), checkpoint=None
            )
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while validating "
                    f"LLM provider configuration. {exp}"
                ),
                details=traceback.format_exc(),
                error_code="CE_1300",
                resolution=(
                    "Ensure that the API key and model are correct and the Anthropic API is "
                    "reachable via the configured network/proxy settings."
                ),
            )
            return ValidationResult(
                success=False,
                message="Unable to validate credentials. Check logs for more details.",
                checkpoint=None,
            )

    def get_runnable(self, runtime_config: Optional[dict] = None):
        """Return LangChain runnable for Anthropic provider."""
        runtime_config = runtime_config or {}
        api_key = self._get_api_key(self.configuration)

        model = self._get_model(
            {
                "model": runtime_config.get("model")
                or self.configuration.get("model")
            }
        )
        # Coerce/validate the well-known numeric runtime_config keys before they reach
        # ChatAnthropic / the raw anthropic clients (a negative timeout or non-numeric
        # max_tokens would otherwise fail deep inside the SDK with an opaque error).
        # Consistent with how _get_model/_get_api_key/_get_effort_levels guard config values.
        # max_tokens resolves per-model with the precedence env > runtime_config > per-model
        # default, clamped to the model's ceiling (see _resolve_max_tokens). An unknown model
        # (not in SUPPORTED_MODELS) falls back to a default ModelSpec so the plugin still runs.
        spec = SUPPORTED_MODELS.get(model) or ModelSpec(
            model, FULL_EFFORT, None
        )
        max_tokens = _resolve_max_tokens(
            spec,
            runtime_config.get("max_tokens"),
            self.log_prefix,
            self.logger,
        )
        timeout = _positive_int(
            runtime_config.get("timeout", TIMEOUT), "timeout", TIMEOUT
        )

        # Strip keys handled here so they don't leak through as ChatAnthropic kwargs.
        _handled = {"model", "max_tokens", "timeout", "max_retries"}
        extra = {k: v for k, v in runtime_config.items() if k not in _handled}
        max_retries = _positive_int(
            runtime_config.get("max_retries", DEFAULT_MAX_RETRIES),
            "max_retries",
            DEFAULT_MAX_RETRIES,
            allow_zero=True,
        )
        try:
            effort = self._get_effort_levels(self.configuration)
        except ValueError:
            effort = None
            self.logger.error(
                f"{self.log_prefix}: Could not find effort configuration, "
                "skipping the effort config."
            )

        if effort:
            extra["output_config"] = {"effort": effort}

        self.logger.debug(
            f"{self.log_prefix}: Building LLM runnable for model={model}, "
            f"max_tokens={max_tokens}, timeout={timeout}, max_retries={max_retries}, "
            f"output_config={extra.get('output_config')}."
        )
        try:
            chat = ChatAnthropic(
                model=model,
                anthropic_api_key=api_key,
                max_tokens=max_tokens,
                timeout=timeout,
                max_retries=max_retries,
                default_headers=self._add_user_agent(),
                # Force non-streaming requests. The agent path runs under
                # astream_events, which attaches a streaming callback handler — so even
                # `.ainvoke()` would otherwise hit the streaming API and assemble the
                # response from chunks. That chunk-stitching drops the
                # `code_execution_tool_result` half of web_search_20260209's dynamic-
                # filtering server-tool pair, leaving an orphaned `server_tool_use` in
                # history that fails the next turn with a 400. A non-streaming
                # `messages.create` returns the turn atomically with both halves paired.
                # It also makes a 529 overload arrive as an HTTP status the SDK retries,
                # rather than a mid-stream error. We surface no token-level streaming to
                # the UI, so nothing is lost (lifecycle events still fire under
                # astream_events for progress/usage/web_search detection).
                disable_streaming=True,
                **extra,
            )

            log_prefix = self.log_prefix

            def _log_retryable(response) -> None:
                """Warn (once per response) only for statuses the SDK will retry."""
                if response.status_code in RETRYABLE_STATUSES:
                    self.logger.debug(
                        f"{log_prefix}: Anthropic API returned {response.status_code} "
                        f"(request_id={response.headers.get('request-id', '?')}) — "
                        f"SDK will retry (max_retries={max_retries})."
                    )

            def _on_sync_response(response) -> None:
                _log_retryable(response)

            async def _on_async_response(response) -> None:
                _log_retryable(response)

            sync_http = _anthropic_sdk.DefaultHttpxClient(
                verify=self.ssl_validation,
                event_hooks={"response": [_on_sync_response]},
            )
            async_http = _anthropic_sdk.DefaultAsyncHttpxClient(
                verify=self.ssl_validation,
                event_hooks={"response": [_on_async_response]},
            )
            default_headers = self._add_user_agent()
            chat.__dict__["_client"] = _anthropic_sdk.Client(
                api_key=api_key,
                http_client=sync_http,
                max_retries=max_retries,
                timeout=timeout,
                default_headers=default_headers,
            )
            chat.__dict__["_async_client"] = _anthropic_sdk.AsyncClient(
                api_key=api_key,
                http_client=async_http,
                max_retries=max_retries,
                timeout=timeout,
                default_headers=default_headers,
            )
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while initializing "
                    f"the Anthropic LLM runnable. {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the API key, model, and proxy/SSL configuration "
                    "in the plugin are correct."
                ),
            )
            raise
        return chat

    def get_web_search_tool(self):
        """Return the Anthropic native web search tool dict, or None.

        Web search is attached only for models whose ModelSpec pins a
        web_search_version; models without one return None (no built-in tool).
        web_search_20260209 enables dynamic filtering automatically — no
        companion code_execution tool or beta header is added here. The extra
        params (max_uses, etc.) are only included for versions we have tested
        (see KNOWN_WEB_SEARCH_VERSIONS).
        """
        spec = SUPPORTED_MODELS.get(self.configuration.get("model"))
        version = spec.web_search_version if spec else None
        if not version:
            return None
        extra_params = (
            WEB_SEARCH_PARAMS if version in KNOWN_WEB_SEARCH_VERSIONS else {}
        )
        return {"type": version, "name": "web_search", **extra_params}

    def extract_token_usage(self, message) -> dict:
        """Extract token counts including thinking tokens from an Anthropic response MESSAGE.

        LangChain 1.x carries canonical counts on ``message.usage_metadata`` (input/output +
        ``output_token_details.reasoning``); Anthropic's raw block (with its own
        ``output_tokens_details.thinking_tokens``) rides on ``message.response_metadata["usage"]``.
        Read the canonical usage first, then top up thinking tokens from the raw block if the
        canonical reasoning field was absent. Anthropic may send either as an explicit null (not
        just an absent key), so coerce with ``... or {}`` / ``... or 0`` at each level.
        """
        um = getattr(message, "usage_metadata", None) or {}
        meta = getattr(message, "response_metadata", None) or {}
        raw = (meta.get("usage") if isinstance(meta, dict) else None) or {}
        details = raw.get("output_tokens_details") or {}
        thinking = (
            (um.get("output_token_details") or {}).get("reasoning")
            or details.get("thinking_tokens")
            or 0
        )
        usage = {
            "input_tokens": um.get("input_tokens")
            or raw.get("input_tokens")
            or 0,
            "output_tokens": um.get("output_tokens")
            or raw.get("output_tokens")
            or 0,
            "thinking_tokens": thinking,
        }
        self.logger.debug(
            f"{self.log_prefix}: Extracted token usage from the model response.",
            details=f"{usage}",
        )
        return usage

    def classify_error(self, exc: Exception) -> LLMErrorType:
        """Map Anthropic SDK exceptions to LLMErrorType before falling back to base."""
        if isinstance(exc, _anthropic_sdk.AuthenticationError):
            return LLMErrorType.AUTH_ERROR
        if isinstance(exc, _anthropic_sdk.RateLimitError):
            return LLMErrorType.RATE_LIMIT
        if isinstance(exc, _anthropic_sdk.APITimeoutError):
            return LLMErrorType.TIMEOUT
        if isinstance(exc, _anthropic_sdk.BadRequestError):
            msg = str(exc)
            msg_lower = msg.lower()
            # Grammar/schema-compilation 400s ("compiled grammar too large", "grammar
            # compilation timed out") mean OUR request shape overflowed constrained
            # decoding — an engineering bug, not a user/context error. Checked BEFORE
            # the context fallthrough, which previously swallowed these as 422s.
            if "grammar" in msg_lower or (
                "schema" in msg_lower
                and ("too large" in msg_lower or "too complex" in msg_lower)
            ):
                # Older cores predate this enum member; fall through to the legacy
                # classification there instead of raising AttributeError inside the
                # retry callback (which would mask the real provider error).
                schema_compilation = getattr(
                    LLMErrorType, "SCHEMA_COMPILATION", None
                )
                if schema_compilation is not None:
                    return schema_compilation
            if "context" in msg_lower or "too long" in msg_lower:
                return LLMErrorType.CONTEXT_LIMIT_EXCEEDED
            if "deprecated" in msg_lower:
                return LLMErrorType.DEPRECATED_MODEL
        if isinstance(exc, _anthropic_sdk.InternalServerError):
            return LLMErrorType.SERVER_ERROR
        # 529 overloaded_error — older SDK versions raise APIStatusError directly
        # instead of InternalServerError for this status code.
        if isinstance(exc, _anthropic_sdk.APIStatusError):
            if getattr(exc, "status_code", None) == 529:
                return LLMErrorType.SERVER_ERROR
        return super().classify_error(exc)

    def classify_stop_reason(self, stop_reason: Optional[str]):
        """Map an Anthropic ``stop_reason`` to a neutral kind.

        Returns 'truncated' / 'refusal' / 'context_exceeded', or None for a stop
        reason needing no special gateway reaction.
        """
        return STOP_REASON_MAP.get(stop_reason)

    def cleanup(self, configuration: Optional[dict] = None) -> None:
        """Cleanup before deleting configuration."""
        return None
