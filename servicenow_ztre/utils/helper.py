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

CRE ServiceNow Plugin helper module.
"""

from base64 import b64encode
from json import JSONDecodeError
import re
import requests
import time
import traceback
from urllib.parse import quote
from pydantic import BaseModel, Field, model_validator, field_validator
from typing import Dict, List, Optional, Set, Tuple, Union

from netskope.common.utils import add_user_agent

from .constants import (
    CUSTOM_SEPARATOR,
    DEFAULT_API_TIMEOUT,
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MAX_WAIT,
    MODULE_NAME,
    PLATFORM_NAME,
    SYS_ID_REGEX,
)


class ServiceNowZTREPluginException(Exception):
    """ServiceNow plugin custom exception class."""

    pass


class ServiceNowZTREPluginHelper(object):
    """ServiceNowZTREPluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self, logger, log_prefix: str, plugin_name: str, plugin_version: str
    ):
        """Service Now Plugin Helper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers for ServiceNow requests.

        Args:
            headers (Dict): Dictionary containing headers for any request.
        Returns:
            Dict: Dictionary after adding User-Agent.
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

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data=None,
        files=None,
        headers: Optional[Dict] = None,
        json=None,
        verify=True,
        proxies=None,
        is_handle_error_required=True,
        is_validation=False,
        timeout=DEFAULT_API_TIMEOUT,
    ):
        """API helper to perform API request on ThirdParty platform \
        and captures all the possible errors for requests.

        Args:
            logger_msg (str): Logger message.
            url (str): API Endpoint.
            method (str): Method for the endpoint.
            params (Dict, optional): Request parameters dictionary.
            Defaults to None.
            data (Any,optional): Data to be sent to API. Defaults to None.
            files (Any, optional): Files to be sent to API. Defaults to None.
            headers (Dict, optional): Headers for the request. Defaults
            to None.
            json (optional): Json payload for request. Defaults to None.
            verify (bool, optional): Verify SSL. Defaults to True.
            proxies (Dict, optional): Proxies. Defaults to None.
            is_handle_error_required (bool, optional): Does the API helper
            should handle the status codes. Defaults to True.
            is_validation (bool, optional): Does this request coming from
            validate method?. Defaults to False.
            timeout (int, optional): Seconds to wait for the platform to
            respond before giving up on the request. Defaults to
            DEFAULT_API_TIMEOUT (300).

        Returns:
            dict: Response dictionary.
        """
        try:
            params = params or {}
            headers = self._add_user_agent(headers or {})

            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}. "
                f"Endpoint: {method} {url}"
            )
            if params:
                debug_log_msg += f", params: {params}."

            self.logger.debug(debug_log_msg)
            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                    json=json,
                    files=files,
                    timeout=timeout,
                )
                status_code = response.status_code
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: Received API Response for "
                        f"{logger_msg}. Status Code={status_code}."
                    )
                )
                if (
                    status_code == 429
                    or 500 <= status_code <= 600
                ) and not is_validation:
                    api_err_msg = str(response.text)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}, API rate limit"
                            f" exceeded while {logger_msg}. Max retries for"
                            " rate limit handler exceeded hence returning"
                            f" status code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise ServiceNowZTREPluginException(err_msg)
                    retry_after = int(
                        response.headers.get("Retry-After", DEFAULT_WAIT_TIME)
                    )
                    if retry_after > 300:
                        err_msg = (
                            "'Retry-After' value received from response "
                            f"headers while {logger_msg} is greater than 5"
                            " minutes hence returning status code"
                            f" {status_code}."
                        )
                        self.logger.error(f"{self.log_prefix}: {err_msg}")
                        raise ServiceNowZTREPluginException(err_msg)
                    if status_code == 429:
                        log_err_msg = "API rate limit exceeded"
                    else:
                        log_err_msg = "HTTP server error occurred"
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code "
                            f"{status_code}, {log_err_msg} while {logger_msg}."
                            f" Retrying after "
                            f"{min(retry_after, MAX_WAIT)} seconds. "
                            f"{MAX_API_CALLS - 1 - retry_counter} retries"
                            " remaining."
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(min(retry_after, MAX_WAIT))
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )
        except ServiceNowZTREPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = (
                f"Read Timeout error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = "Read Timeout error occurred."

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ServiceNowZTREPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the "
                "proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify "
                    "the proxy configuration provided."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ServiceNowZTREPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    f"platform. Proxy server or {PLATFORM_NAME} "
                    "server is not reachable."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ServiceNowZTREPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify "
                    "configuration parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise ServiceNowZTREPluginException(err_msg)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing "
                    f"API call to {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                raise ServiceNowZTREPluginException(err_msg)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg,
        is_validation: bool = False,
    ):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.
            logger_msg (str): Logger message
            is_validation: (bool): Check for validation

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except JSONDecodeError as err:
            err_msg = (
                f"Invalid JSON response received from API while {logger_msg}."
                f" Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify Instance URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise ServiceNowZTREPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing "
                f"json response while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify Instance URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise ServiceNowZTREPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object
            returned from API call.
            logger_msg: logger message.
            is_validation : API call from validation method or not
        Returns:
            dict: Returns the dictionary of response JSON
            when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        status_code = resp.status_code
        validation_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, Bad Request",
            403: "Received exit code 403, Forbidden",
            401: "Received exit code 401, Unauthorized access",
            404: "Received exit code 404, Resource not found",
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request, "
                    "Verify the Instance URL provided in "
                    "the configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, "
                    "Verify Username and Password provided in "
                    "the configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, "
                    "Verify permission for Username provided in "
                    "the configuration parameters."
                ),
                404: (
                    "Received exit code 404, Resource not found, "
                    "Verify the Instance URL provided in "
                    "the configuration parameters."
                ),
            }

        if status_code in [200, 201]:
            return self.parse_response(
                response=resp,
                logger_msg=logger_msg,
                is_validation=is_validation
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise ServiceNowZTREPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                if status_code == 401:
                    err_msg = (
                        f"{err_msg} Verify Username and Password provided "
                        "in configuration parameters."
                    )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise ServiceNowZTREPluginException(err_msg)

        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{validation_msg+err_msg} while {logger_msg}."
                ),
                details=f"API response: {resp.text}",
            )
            raise ServiceNowZTREPluginException(err_msg)

    def get_config_params(self, configuration: Dict) -> tuple:
        """Get Configuration params.

        Args:
            configuration (Dict): Configuration parameter dictionary.

        Returns:
            Tuple: Tuple containing Instance URL, Username and Password.
        """
        return (
            configuration.get("instance_url", "").strip().strip("/"),
            configuration.get("username", "").strip(),
            configuration.get("password")
        )

    def basic_auth(self, username, password):
        """Generate Basic Auth token.

        Args:
            username (str): Username.
            password (str): Password.

        Returns:
            str: Basic Auth token.
        """
        try:
            token = b64encode(f"{username}:{password}".encode("utf-8")).decode(
                "ascii"
            )
            return {"Authorization": f"Basic {token}"}
        except Exception as exp:
            err_msg = "Error occurred while generating basic auth token."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ServiceNowZTREPluginException(err_msg)


class ServiceNowQuery(BaseModel):
    """ServiceNow Query."""

    company_name: Optional[Union[str, List[str]]] = Field(None)
    parent_company_name: Optional[Union[str, List[str]]] = Field(None)
    operator: Optional[str] = Field(None)
    cci: Optional[int] = Field(None)

    @field_validator("company_name", "parent_company_name", mode="before")
    def validate_string_or_list_of_strings(cls, value, field):
        """Validate string or list of strings."""
        if isinstance(value, str):
            return value
        elif isinstance(value, list) and all(
            isinstance(item, str) for item in value
        ):
            return value
        field_name = field.field_name.replace("_", " ").title()
        raise ValueError(
            f"Invalid {field_name} found in the action parameters. "
            f"The {field_name} must be a string or a list of strings."
        )

    @model_validator(mode="after")
    def check_requirements(cls, values):
        """Check requirements."""
        company_name, parent_company_name, operator = (
            values.company_name,
            values.parent_company_name,
            values.operator
        )

        if not (company_name or parent_company_name):
            raise ValueError(
                "Either Company Name or Parent Company Name is a required "
                "in the action parameters. Both can not be empty."
            )

        if company_name and parent_company_name and not operator:
            raise ValueError(
                "Operator is a required action parameter when both "
                "Company Name and Parent Company Name are provided."
            )
        if operator and operator not in {"and", "or"}:
            raise ValueError(
                "Invalid Operator provided in the action parameters. "
                "Supported operators are: 'AND', 'OR'."
            )

        return values

    @field_validator("cci")
    def validate_cci(cls, value):
        """Validate CCI."""
        if value and not (0 <= value <= 100):
            raise ValueError(
               "Invalid CCI provided in the action parameters. "
               "Valid range should be between 0 to 100."
            )
        return value


# ----------------------------------------------------------------------
# Shared stateless utility functions. Plain module-level functions, not
# plugin methods, since none of them touch plugin instance state
# (configuration, ssl_validation, proxy, servicenow_helper, logger).
# ----------------------------------------------------------------------

def is_sys_id(value: str) -> bool:
    """Return True when the value looks like a ServiceNow sys_id."""
    return bool(
        isinstance(value, str)
        and re.match(SYS_ID_REGEX, value.strip())
    )


def normalize_csv_values(raw_value) -> List[str]:
    """Normalize a Source field or Static value into a value list.

    A Source field resolves to either a list (List-type entity
    field) or a comma-separated string; a Static field is always a
    comma-separated string. Either shape is flattened, trimmed,
    de-duplicated (order preserved) and empty entries dropped.

    Args:
        raw_value: The raw action parameter value (str or list).

    Returns:
        List[str]: Cleaned, de-duplicated values.
    """
    if isinstance(raw_value, list):
        candidates = []
        for item in raw_value:
            candidates.extend(str(item).split(","))
    else:
        candidates = str(raw_value or "").split(",")
    cleaned = []
    seen = set()
    for candidate in candidates:
        value = candidate.strip()
        if value and value not in seen:
            seen.add(value)
            cleaned.append(value)
    return cleaned


def is_valid_csv_value(raw_value) -> bool:
    """Whether every comma-separated entry of a value is non-empty.

    Written for `_validate_parameters`' custom_validation_func hook, so
    it returns True when the value is acceptable. "abc,,def",
    ",,abc,def" and ",,,," all leave nothing between (or around) a pair
    of commas. `normalize_csv_values` would silently drop those blanks
    at execution time, so they are rejected up front as a malformed
    value instead. A value with no comma at all is never malformed by
    this rule - the required-field check covers an empty one.

    Args:
        raw_value: The raw action parameter value.

    Returns:
        bool: False when any comma-separated entry is empty.
    """
    if not isinstance(raw_value, str) or "," not in raw_value:
        return True
    return all(entry.strip() for entry in raw_value.split(","))


def is_positive_int(raw_value) -> bool:
    """Whether a value is a whole number greater than zero.

    Written for `_validate_parameters`' custom_validation_func hook, so
    it returns True when the value is acceptable. A CE number field can
    hand over either an int or the typed string, so both are accepted -
    "5" and 5 alike - while "5.5", "abc", "" and anything <= 0 are not.

    Args:
        raw_value: The raw action parameter value.

    Returns:
        bool: True when the value is a positive whole number.
    """
    try:
        return int(raw_value) > 0
    except (TypeError, ValueError):
        return False


def chunk_list(items: List, size: int):
    """Yield successive chunks of at most `size` items."""
    for index in range(0, len(items), size):
        yield items[index:index + size]


def build_lookup_url(
    url_path: str,
    query: str,
    fields: str,
    limit: Optional[int] = None,
) -> str:
    """Build a GET sub-request url with a URL-encoded query.

    The sysparm_query value is percent-encoded so free-text values
    (application names, tag keys) containing spaces or special
    characters do not break the batch sub-request url.

    Args:
        url_path (str): Path-only endpoint from URLS.
        query (str): Raw sysparm_query value.
        fields (str): Comma-separated sysparm_fields.
        limit (Optional[int]): Caps sysparm_limit. Pass 1 when the
            caller only needs to know whether a row exists, so
            ServiceNow doesn't materialize/return more matching
            rows than necessary.

    Returns:
        str: The encoded sub-request url.
    """
    url = (
        f"{url_path}?sysparm_query={quote(query, safe='')}"
        f"&sysparm_fields={fields}"
    )
    if limit is not None:
        url += f"&sysparm_limit={limit}"
    return url


def describe_targets(
    sub_meta: Dict,
    sub_requests: List[Dict],
    name_keys: Union[str, Tuple[str, ...]],
    singular_noun: str,
    plural_noun: str,
) -> str:
    """Name a batch round's target(s) for a log line.

    Looks up name_keys in sub_meta for each request id and returns
    "<singular_noun> '<name>'" when every request shares the same
    single name (e.g. one group, one role, one tag key), else
    "<count> <plural_noun>" so a heterogeneous round (several
    different groups/roles/keys in one call) isn't misdescribed as
    having just one target.

    Args:
        sub_meta (Dict): sub_id -> metadata, as built by the caller.
        sub_requests (List[Dict]): The sub-requests for this round.
        name_keys (Union[str, Tuple[str, ...]]): sub_meta key(s) to
            read the name from; the first present key wins per
            entry (e.g. an existing group's "group_name" vs a
            newly-created group's "new_group_name").
        singular_noun (str): Noun used with a single named target.
        plural_noun (str): Noun used with a count of targets.

    Returns:
        str: e.g. "group 'Engineers'" or "3 groups".
    """
    if isinstance(name_keys, str):
        name_keys = (name_keys,)
    names = set()
    for req in sub_requests:
        meta = sub_meta.get(req["id"])
        if not meta:
            continue
        for key in name_keys:
            if meta.get(key):
                names.add(meta[key])
                break
    if len(names) == 1:
        return f"{singular_noun} '{names.pop()}'"
    return f"{len(names) or len(sub_requests)} {plural_noun}"


def outcome_bucket(
    stats: Dict[str, Dict[str, Set[str]]], label: str
) -> Dict[str, Set[str]]:
    """Get or create the success/failed/already_exists bucket for one
    fan-out target.

    Shared by the actions whose targets fan out two ways and so cannot
    honestly report a single count: Tag (configuration items x tag
    values, labelled "<key>=<value>") and Add/Remove User from Role
    (users x roles, labelled by role name). Each bucket holds *sets* of
    the other dimension's sys_ids, so a target named by several records
    is still counted once.

    "already_exists" is the internal name for the third outcome - the
    targets an add skipped or a remove found nothing to do for. It is
    rendered under a direction-specific label by `outcome_counts`, since
    "already exists" only reads correctly for an add.
    """
    return stats.setdefault(
        label,
        {
            "success": set(),
            "failed": set(),
            "already_exists": set(),
        },
    )


def outcome_counts(
    stats: Dict[str, Dict[str, Set[str]]],
    exists_label: str,
) -> Dict[str, Dict[str, int]]:
    """Convert label -> {outcome: {sys_id, ...}} sets into distinct
    counts for the log payload.

    Args:
        stats (Dict): label -> outcome -> set of sys_ids, as built by
            `outcome_bucket`.
        exists_label (str): Display label for the "already_exists"
            outcome - "Already Exists" when adding (the target already
            holds the state the action asks for), "Does Not Exist" when
            removing (there was nothing to remove).

    Returns:
        Dict[str, Dict[str, int]]: label -> outcome label -> count.
    """
    labels = {"already_exists": exists_label}
    return {
        label: {
            labels.get(outcome, outcome): len(sys_ids)
            for outcome, sys_ids in buckets.items()
        }
        for label, buckets in stats.items()
    }


def normalize_choice_values(raw_value) -> List[str]:
    """Normalize a multichoice dropdown value into a list of entries.

    A multichoice always hands over a list, so entries are taken as they
    are - unlike `normalize_csv_values`, nothing is comma-split. Any
    other shape yields an empty list, which the caller reports as a
    missing value.

    Args:
        raw_value: The raw action parameter value.

    Returns:
        List[str]: Trimmed, de-duplicated entries, order preserved.
    """
    if not isinstance(raw_value, list):
        return []
    cleaned = []
    seen = set()
    for item in raw_value:
        value = str(item).strip()
        if value and value not in seen:
            seen.add(value)
            cleaned.append(value)
    return cleaned


def unpack_choice_value(packed: str) -> Tuple[str, str]:
    """Split a packed "<name><CUSTOM_SEPARATOR><sys_id>" dropdown value.

    Args:
        packed (str): The packed action parameter value.

    Returns:
        Tuple[str, str]: (name, sys_id), or ("", "") when the value is
            not packed or either half is empty - so one falsy check on
            the sys_id is enough to tell a caller the value is unusable.
    """
    name, sep, sys_id = str(packed).rpartition(CUSTOM_SEPARATOR)
    if not sep or not name.strip() or not sys_id.strip():
        return "", ""
    return name.strip(), sys_id.strip()

# ----------------------------------------------------------------------
# Share Application Data - Core Company query builders. Stateless like
# the functions above: they turn an action's Company Name / Parent
# Company Name / Operator parameters into a sysparm_query and touch no
# plugin state.
# ----------------------------------------------------------------------

def make_query_list(
    action_parameters: dict,
):
    """Make query list.

    Args:
        action_parameters (dict): Action parameters.

    Returns:
        List: List of queries.
    """
    company_name = action_parameters.get("company_name", "")
    parent_company_name = action_parameters.get("parent_company_name", "")
    operator = action_parameters.get("operator", "")
    operator = "or" if not operator else operator.strip().lower()

    query_list = []
    if company_name and parent_company_name and operator:
        for field in ["company_name", "parent_company_name"]:
            snow_field_name = (
                "name" if field == "company_name" else "parent.name"
            )
            ce_field_value = action_parameters.get(field, "")
            query = get_query(
                snow_field_name=snow_field_name,
                ce_field_value=ce_field_value,
            )
            query_list.append(query)
    if company_name and not parent_company_name:
        snow_field_name = "name"
        ce_field_value = action_parameters.get("company_name", "")
        query = get_query(
            snow_field_name=snow_field_name,
            ce_field_value=ce_field_value,
        )
        query_list.append(query)

    if not company_name and parent_company_name:
        snow_field_name = "parent.name"
        ce_field_value = action_parameters.get("parent_company_name", "")
        query = get_query(
            snow_field_name=snow_field_name,
            ce_field_value=ce_field_value,
        )
        query_list.append(query)

    if operator == "and":
        final_query = "^".join(query_list)
    else:
        final_query = "^OR".join(query_list)

    return final_query

def get_query(
    snow_field_name: str,
    ce_field_value: Union[str, List],
):
    """Get query.

    Args:
        snow_field_name (str): ServiceNow field name.
        ce_field_value (Union[str, List]): Company or parent name.

    Returns:
        List: List of queries.
    """
    if ce_field_value is None:
        ce_field_value = ""
    if isinstance(ce_field_value, list):
        sub_query = ",".join(ce_field_value)
        query = f"{snow_field_name}IN{sub_query}"
    else:
        query = f"{snow_field_name}={ce_field_value}"
    return query
