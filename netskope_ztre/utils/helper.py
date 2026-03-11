"""Netskope CRE plugin helper module."""
import requests
import time
import traceback
from typing import Dict

from netskope.common.utils import (
    add_installation_id,
    add_user_agent,
)
from netskope.common.utils.handle_exception import (
    handle_exception,
    handle_status_code,
)
from .constants import (
    DEFAULT_WAIT_TIME,
    MAX_RETRY_COUNT,
)


class NetskopeException(Exception):
    """Netskope exception class."""

    pass


class NetskopePluginHelper(object):
    """NetskopePluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self, logger, log_prefix: str
    ):
        """Netskope Plugin Helper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger

    def _api_call_helper(
        self,
        url: str,
        method,
        error_codes,
        logger_msg,
        message="",
        params: Dict = {},
        headers: Dict = {},
        data=None,
        json=None,
        proxies=None,
        show_params: bool = True,
        is_handle_error_required=True
    ):
        """Call the API helper for getting application related data."""
        request_func = getattr(requests, method)
        try:
            headers = add_installation_id(add_user_agent(headers))
            response = {}
            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" Endpoint: {method.upper()} {url}"
            )
            if params and show_params:
                debug_log_msg += f", params: {params}."
            self.logger.debug(debug_log_msg)
            for attempt in range(MAX_RETRY_COUNT):
                success, response = handle_exception(
                    request_func,
                    error_code=error_codes[0],
                    custom_message=message,
                    plugin=self.log_prefix,
                    url=url,
                    headers=headers,
                    data=data,
                    json=json,
                    params=params,
                    proxies=proxies,
                )
                if not success:
                    raise response
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )

                if (
                    status_code == 429
                    or 500 <= status_code <= 600
                ):
                    api_err_msg = str(response.text)
                    if attempt == MAX_RETRY_COUNT - 1:
                        err_msg = (
                            f"Received exit code {status_code}, "
                            f"API rate limit exceeded while {logger_msg}. "
                            "Max retries for rate limit handler exceeded "
                            f"hence returning status code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise NetskopeException(err_msg)
                    if status_code == 429:
                        log_err_msg = "API rate limit exceeded"
                    else:
                        log_err_msg = "HTTP server error occurred"
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code "
                            f"{status_code}, "
                            f"{log_err_msg} while {logger_msg}. "
                            f"Retrying after {DEFAULT_WAIT_TIME} seconds. "
                            f"{MAX_RETRY_COUNT - 1 - attempt} "
                            "retries remaining."
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    if is_handle_error_required:
                        response = handle_status_code(
                            response,
                            error_code=error_codes[1],
                            custom_message=message,
                            plugin=self.log_prefix,
                            notify=False,
                            log=True,
                        )
                    return response
            else:
                self.logger.error(
                    f"{self.log_prefix}: Maximum retry "
                    f"limit reached for url {url}."
                )
                raise requests.exceptions.HTTPError(
                    "Maximum retry limit reached"
                )
        except NetskopeException:
            raise
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise NetskopeException(err_msg)
