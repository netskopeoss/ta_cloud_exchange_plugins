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

Anthropic API HTTP helpers for Anthropic LLM provider.
"""

from typing import Optional

import requests

from .anthropic_constants import ANTHROPIC_MODEL_DETAIL_URL, ANTHROPIC_VERSION


def _api_error(message: str, status_code: int) -> ValueError:
    """Build a ValueError carrying the HTTP status code that caused it.

    The caller (main.py's validate()) reads ``.status_code`` off the caught exception
    to pick a resolution that actually matches the failure (rate limit vs. bad API key
    vs. service outage) instead of one generic resolution for every error status.
    """
    exc = ValueError(message)
    exc.status_code = status_code
    return exc


def _get(
    url: str,
    api_key: str,
    params: Optional[dict] = None,
    proxy=None,
    use_proxy: bool = False,
    ssl_validation: bool = True,
    status_messages: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: int = 60,
) -> requests.Response:
    """Make an authenticated GET request to the Anthropic API.

    Returns the response on HTTP 200.
    Raises ValueError with a human-readable message for all error statuses; the raised
    exception carries a ``.status_code`` attribute (see ``_api_error``) so callers can
    pick a resolution based on the actual failure. Not set when the request never got
    an HTTP response at all (connection/timeout/DNS failure).
    status_messages: optional dict of {status_code: message} for caller-specific
    overrides (e.g. {404: "Model not found"}).
    headers: optional dict of headers for 3rd-party api calls.
    """
    if headers is None:
        headers = {}

    headers.update(
        {
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
    )
    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            proxies=proxy if use_proxy else None,
            verify=ssl_validation,
            timeout=timeout,
        )
    except requests.exceptions.RequestException as exc:
        raise ValueError(
            "Unable to reach the Anthropic API. Check network/proxy connectivity and try again."
        ) from exc
    if response.status_code == 200:
        return response
    if status_messages and response.status_code in status_messages:
        raise _api_error(status_messages[response.status_code], response.status_code)
    if response.status_code == 400:
        raise _api_error(
            "Invalid API key or model provided for Anthropic.",
            response.status_code,
        )
    if response.status_code in [401, 403]:
        raise _api_error("Invalid API key provided for Anthropic.", response.status_code)
    if response.status_code == 429:
        raise _api_error("Anthropic rate limit exceeded. Try again later.", response.status_code)
    if 500 <= response.status_code < 600:
        raise _api_error(
            "Anthropic service is unavailable. Try again later.", response.status_code
        )
    raise _api_error(
        "Unexpected response from Anthropic API.",
        response.status_code,
    )


def fetch_model(
    api_key: str,
    model: str,
    proxy=None,
    use_proxy: bool = False,
    ssl_validation: bool = True,
    headers: Optional[dict] = None,
    timeout: int = 60,
) -> dict:
    """Fetch a single model's metadata from the Anthropic model-detail endpoint.

    Used at validation time to confirm the api_key + model are valid (a 404 is
    surfaced as a human-readable "not available" message).

    Returns the raw model dict: {id, display_name, created_at, capabilities, ...}.
    Raises ValueError (via _get) for any non-200 status; the caller (validate())
    is responsible for logging that ValueError with a resolution.
    """
    response = _get(
        ANTHROPIC_MODEL_DETAIL_URL.format(model=model),
        api_key,
        proxy=proxy,
        use_proxy=use_proxy,
        ssl_validation=ssl_validation,
        status_messages={
            404: f"The selected Anthropic model '{model}' is not available."
        },
        headers=headers,
        timeout=timeout,
    )
    return response.json()
