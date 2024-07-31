# -*- coding: utf-8 -*-

"""Provides utility functions for the Illumio plugin.

Copyright:
    © 2023 Illumio

License:
    Apache2
"""
from illumio import PolicyComputeEngine

from .exceptions import IllumioPluginException
from illumio.exceptions import IllumioApiException
import traceback

class IllumioPluginHelper(object):
    """IllumioHelper class.

    Args:
        object (object): Object class.
    """
    def __init__(
        self, logger, log_prefix: str, plugin_name: str, plugin_version: str, ssl_validation, proxy,
    ):
        """CrowdStrikePluginHelper initializer.

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
        self.ssl_validation = ssl_validation
        self.proxy = proxy

    def parse_label_scope(self, logger_message, scope: str, is_validation=False) -> dict:
        """Parse label scopes passed as a string of the form k1:v1,k2:v2,...

        Args:
            scope (str): Policy scope as a comma-separated key:value pair list.

        Returns:
            dict: dict containing label key:value pairs.

        Raises:
            ValueError: if the given scope format is invalid.
        """
        try:
            label_dimensions = scope.split(",")
            labels = {}
            for label in label_dimensions:
                if not label.strip():
                    continue

                try:
                    k, v = label.split(":")
                except Exception:
                    raise IllumioPluginException(
                        "Invalid format provided for the Label Scope: must be key1:value1,key2:value2..."
                    )

                if k.strip() in labels:
                    raise IllumioPluginException("Label Scope keys must be unique, duplicate keys are not allowed.")

                labels[k.strip()] = v.strip()
            if not labels:
                raise IllumioPluginException("Label Scope is a required field.")
            return labels
        except IllumioPluginException as err:
            err_msg = f"Error: {err}"
            if is_validation:
                err_msg = f"Validation error occurred. {err_msg}"
            self.logger.error(f"{self.log_prefix}: {err}")
            raise IllumioPluginException(err_msg)
        except Exception as err:
            err_msg = (
                f"Error occurred while {logger_message}."
            )
            self.logger.error(
              f"{self.log_prefix}: {err_msg} "
              f"Error: {err}"  
            )
            raise IllumioPluginException(err_msg + ". Check logs for more details")



    def connect_to_pce(
            self,
            logger_msg,
            configuration: dict,
            headers: dict = None,
            **kwargs
        ) -> PolicyComputeEngine:  # noqa: E501
        """Connect to the PCE, returning the PolicyComputeEngine client.

        Args:
            conf (dict): dict containing plugin configuration values.
            proxies (dict): dict containing HTTP/S proxy server settings.
            verify (bool): if False, disables TLS verification for PCE requests.

        Returns:
            PolicyComputeEngine: PCE API client object.

        Raises:
            IllumioException: if the PCE connection fails.
        """
        try:
            pce = PolicyComputeEngine(
                url=configuration.get("pce_url", "").strip().strip("/"),
                port=configuration.get("pce_port"),
                org_id=configuration.get("org_id"),
                **kwargs
            )
            pce._session.headers.update(headers)
            pce.set_credentials(configuration.get("api_username").strip(), configuration.get("api_secret"))
            pce.set_tls_settings(verify=self.ssl_validation)
            if self.proxy:
                pce.set_proxies(
                    http_proxy=self.proxy.get('http', ''),
                    https_proxy=self.proxy.get('https', '')
                )
            pce.must_connect()
            return pce
        except IllumioApiException as err:
            err_msg = (
                f"Illumio API Exception occurred while {logger_msg}. "
                f"Validate the provided configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(err)}",
                details=str(traceback.format_exc()),
            )
            raise IllumioPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                details=str(traceback.format_exc()),
            )
            raise IllumioPluginException(err_msg)