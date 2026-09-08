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

Constants for the Anthropic LLM provider plugin.
"""

from dataclasses import dataclass
from typing import Optional, Tuple

MODULE_NAME = "LLM-PROVIDER"
PLUGIN_NAME = "Anthropic"
PLUGIN_VERSION = "1.0.0"

# Ref: https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool
ALLOWED_DOMAINS = ["docs.netskope.com"]
WEB_SEARCH_PARAMS: dict = {"max_uses": 5, "allowed_domains": ALLOWED_DOMAINS}
KNOWN_WEB_SEARCH_VERSIONS = frozenset(
    {"web_search_20250305", "web_search_20260209"}
)

# Effort levels shared by every current Opus/Sonnet model (low → max).
FULL_EFFORT = ("low", "medium", "high")
# Output-token ceiling for the current 1M-context Opus/Sonnet models (Fable 5 too).
# max_tokens caps thinking + answer combined; this is the API hard cap per response.
MAX_OUTPUT_128K = 128000


@dataclass(frozen=True)
class ModelSpec:
    """Capabilities of a single supported Anthropic model.

    A frozen record keeps each model's display name, effort levels, web_search
    version, and output-token budget together in one place, instead of parallel
    dicts that must be kept in sync.

    ``max_tokens`` is the per-model OPTIMUM default (comfortable headroom for
    thinking + a full structured turn). ``max_tokens_ceiling``
    is the model's HARD per-response cap — the env override is clamped to it so a
    deployment can dial the budget up to the model's max but never past it.
    """

    display_name: str
    # Ref: https://platform.claude.com/docs/en/build-with-claude/effort
    effort_levels: Tuple[str, ...] = ()
    web_search_version: Optional[str] = None
    max_tokens: int = 16384
    max_tokens_ceiling: int = MAX_OUTPUT_128K


# Ref: https://platform.claude.com/docs/en/about-claude/model-deprecations#model-status
# Every current model here is a 1M-context model with a 128K output ceiling; the
# per-model max_tokens is the tuned optimum (thinking + a full structured turn), and
# a deployment can raise it to the ceiling via the AI_COPILOT_MAX_TOKENS env var.
SUPPORTED_MODELS: dict = {
    "claude-opus-5": ModelSpec(
        "Claude Opus 5", FULL_EFFORT, "web_search_20260209"
    ),
    "claude-opus-4-8": ModelSpec(
        "Claude Opus 4.8", FULL_EFFORT, "web_search_20260209"
    ),
    "claude-sonnet-5": ModelSpec(
        "Claude Sonnet 5", FULL_EFFORT, "web_search_20260209"
    ),
}

# Deployment-level ceiling override: set AI_COPILOT_MAX_TOKENS to raise the per-response budget
# (e.g. to run a model up to its 128K output ceiling). When set + valid it WINS over both the
# per-turn runtime_config value and the per-model default — precedence env > runtime_config >
# per-model default — and is clamped to the selected model's max_tokens_ceiling. Unset/invalid
# → ignored (fall through to runtime_config, then the per-model default). Read per get_runnable.
MAX_TOKENS_ENV_VAR = "AI_COPILOT_MAX_TOKENS"
TIMEOUT = 120
DEFAULT_MAX_RETRIES = 4
DEFAULT_EFFORT = "medium"

# Manifest key for the model-dependent effort field. Its choices are not static
# (they depend on the selected model), so the field is delivered to the config
# UI via get_dynamic_fields() rather than the static manifest.
EFFORT_FIELD_KEY = "agentic_effort_calibration"
EFFORT_FIELD_LABEL = "Agentic Effort Calibration"
EFFORT_FIELD_DESCRIPTION = (
    "Effort to apply for the Cloud Exchange Agentic workflows like multi-audit "
    "logs analysis. The available levels depend on the selected model."
)

# Display labels for effort levels shown in the config UI; falls back to a
# capitalised token for any future level not listed here. Owning the labels here
# (instead of the frontend) keeps all provider vocabulary in the plugin.
EFFORT_LABELS = {
    "low": "Low",
    "medium": "Medium",
    "high": "High",
}

# Kept in sync with the anthropic SDK's own _should_retry() (anthropic/_base_client.py):
# 408 (request timeout), 409 (lock timeout), 429 (rate limit), and any >=500 — plus 529
# (overloaded). Drives only a best-effort "SDK will retry" log in get_runnable().
RETRYABLE_STATUSES = {408, 409, 429, 500, 502, 503, 504, 529}

# Anthropic stop_reason wire values → neutral StopReasonKind values. Ref:
# https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons
# Values are the neutral STRING (not the StopReasonKind enum) on purpose: an older core may
# predate StopReasonKind, so importing it at module top would fail the whole plugin load.
# StopReasonKind extends str, so the gateway's == comparisons match either form. Anthropic
# reasons the gateway does NOT react to (end_turn / tool_use / pause_turn / stop_sequence)
# map to None → the gateway treats the turn as ordinary.
STOP_REASON_MAP = {
    "max_tokens": "truncated",
    "refusal": "refusal",
    "model_context_window_exceeded": "context_exceeded",
}

# Anthropic API HTTP details used by utils/api_client.py.
ANTHROPIC_MODEL_DETAIL_URL = "https://api.anthropic.com/v1/models/{model}"
ANTHROPIC_VERSION = "2023-06-01"

# Resolution text for validate()'s fetch_model() failure, keyed by the HTTP status code
# api_client.py's ValueError carries (see api_client._api_error). Picked in main.py so the
# logged resolution matches what actually went wrong instead of one generic message for
# every status. FETCH_MODEL_DEFAULT_RESOLUTION covers a 5xx, an unmapped status, and the
# no-status-code case (network/proxy connectivity failure — no HTTP response was received).
FETCH_MODEL_ERROR_RESOLUTIONS = {
    400: (
        "Ensure that a valid API key and a supported model are provided "
        "in the LLM provider parameters."
    ),
    401: "Ensure that a valid API key is provided in the LLM provider parameters.",
    403: "Ensure that a valid API key is provided in the LLM provider parameters.",
    404: "Ensure that the selected Anthropic model is available for your account.",
    429: (
        "The Anthropic API rate limit was reached; wait a while before retrying validation."
    ),
}
FETCH_MODEL_DEFAULT_RESOLUTION = (
    "Ensure that the Anthropic API is reachable via the configured network/proxy "
    "settings and that the Anthropic service is not experiencing an outage."
)
