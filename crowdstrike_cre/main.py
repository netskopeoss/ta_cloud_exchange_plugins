"""Crowdstrike CRE plugin."""
import datetime
import requests
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cre.models import (
    Record,
    RecordType,
    ActionWithoutParams,
    Action,
)
from netskope.common.utils import add_user_agent

PAGE_SIZE = 1000


class CrowdstrikeException(Exception):
    """Crowdstrike exception class."""

    pass


class CrowdstrikePlugin(PluginBase):
    """Crowdstrike plugin implementation."""

    def handle_error(self, resp):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API call.
        Returns:
            dict: Returns the dictionary of response JSON when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                raise CrowdstrikeException(
                    "Plugin: CrowdStrike,"
                    "Exception occurred while parsing JSON response."
                )

        elif resp.status_code == 401:
            raise CrowdstrikeException(
                "Plugin: CrowdStrike, "
                "Received exit code 401, Authentication Error"
            )

        elif resp.status_code == 403:
            raise CrowdstrikeException(
                "Plugin: CrowdStrike, "
                "Received exit code 403, Forbidden User"
            )

        elif resp.status_code >= 400 and resp.status_code < 500:
            raise CrowdstrikeException(
                f"Plugin: CrowdStrike, "
                f"Received exit code {resp.status_code}, HTTP client Error"
            )

        elif resp.status_code >= 500 and resp.status_code < 600:
            raise CrowdstrikeException(
                f"Plugin: CrowdStrike, "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )

        else:
            raise CrowdstrikeException(
                f"Plugin: CrowdStrike, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )

        resp.raise_for_status()

    def get_agent_ids(self, headers):
        """Get the all the Agent ID list from the Query Endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token.
        Returns:
            dict: JSON response dict received from query endpoint.
        """
        query_endpoint = f"{self.configuration['base_url'].strip()}/devices/queries/devices/v1"
        agent_ids = []
        offset = 0
        while True:
            headers = self.reload_auth_token(headers)
            all_agent_resp = requests.get(
                query_endpoint,
                headers=add_user_agent(headers),
                params={"limit": PAGE_SIZE, "offset": offset},
                proxies=self.proxy,
            )
            agent_resp_json = self.handle_error(all_agent_resp)
            errors = agent_resp_json.get("errors")
            if errors:
                err_msg = errors[0].get("message", "")
                self.notifier.error(
                    "Plugin: CrowdStrike Unable to Fetch agents, "
                    f"Error: {err_msg}"
                )
                self.logger.error(
                    "Plugin: CrowdStrike Unable to Fetch Agents, "
                    f"Error: {err_msg}"
                )
                raise requests.HTTPError(
                    f"Plugin: CrowdStrike Unable to Fetch Agents, "
                    f"Error: {err_msg}"
                )
            resources = agent_resp_json.get("resources", [])
            offset += PAGE_SIZE
            agent_ids.extend(resources)
            if len(resources) < PAGE_SIZE:
                break
        return agent_ids

    def fetch_records(self):
        """Get the all the Agent ID list from the Query Endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token.
        Returns:
            dict: JSON response dict received from query endpoint.
        """
        self.configuration["client_id"] = self.configuration[
            "client_id"
        ].strip()
        self.configuration["client_secret"] = self.configuration[
            "client_secret"
        ].strip()
        try:
            auth_json = self.get_auth_json(
                self.configuration.get("client_id"),
                self.configuration.get("client_secret"),
                self.configuration.get("base_url"),
            )
            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}"}
            agent_ids = self.get_agent_ids(headers)
            uids_names = []
            for ids in agent_ids:
                uids_names.append(Record(uid=ids, type=RecordType.HOST))
            return uids_names

        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin: CrowdStrike "
                "Exception occurred while making an API call to CrowdStrike platform"
            )
            raise e
        return []

    def fetch_scores(self, agent_ids):
        """Fetch user scores."""
        self.configuration["client_id"] = self.configuration[
            "client_id"
        ].strip()
        self.configuration["client_secret"] = self.configuration[
            "client_secret"
        ].strip()
        try:
            auth_json = self.get_auth_json(
                self.configuration.get("client_id"),
                self.configuration.get("client_secret"),
                self.configuration.get("base_url"),
            )
            aids = []
            for ids in agent_ids:
                if ids.type == RecordType.HOST:
                    aids.append(ids.uid)

            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}"}
            query_endpoint = f"{self.configuration['base_url']}/zero-trust-assessment/entities/assessments/v1"
            payload = {"ids": aids}
            headers = self.reload_auth_token(headers)
            resp = requests.get(
                query_endpoint,
                headers=add_user_agent(headers),
                params=payload,
                proxies=self.proxy,
            )
            all_scores_json = resp.json()
            scores = all_scores_json.get("resources", [])
            dict1 = {}
            for sub in scores:
                dict1[sub["aid"]] = sub["assessment"]["overall"] * 10
            scored_uids = []
            count_host = 0
            for ids, score in dict1.items():
                if score <= int(self.configuration["minimum_score"]):
                    count_host = count_host + 1
                    continue
                else:
                    scored_uids.append(
                        Record(uid=ids, type=RecordType.HOST, score=score)
                    )
            self.logger.info(
                "Plugin: CrowdStrike "
                f"Unable to store scores of {count_host} Hosts to CrowdStrike."
            )
            return scored_uids
        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            raise requests.HTTPError(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin: CrowdStrike "
                "Exception occurred while making an API call to CrowdStrike platform"
            )
            raise e
        return []

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def validate_action(self, action: Action):
        """Validate Netskope configuration."""
        if action.value not in ["generate"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []

    def execute_action(self, record: str, action: Action):
        """Execute action on the record."""
        pass

    def reload_auth_token(self, headers):
        """Reload the OAUTH2 token after Expiry."""
        if self.storage["token_expiry"] < datetime.datetime.now():
            self.logger.info(
                "Plugin: Crowdstrike OAUTH2 token expired generating new token"
            )
            auth_json = self.get_auth_json(
                self.configuration.get("client_id"),
                self.configuration.get("client_secret"),
                self.configuration.get("base_url"),
            )
            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}"}
            return headers
        else:
            return headers

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.info(
            "Plugin: CrowdStrike Executing validate method for CrowdStrike plugn"
        )

        if "base_url" not in data or data["base_url"].strip() not in [
            "https://api.crowdstrike.com",
            "https://api.us-2.crowdstrike.com",
            "https://api.laggar.gcw.crowdstrike.com",
            "https://api.eu-1.crowdstrike.com",
        ]:
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred "
                "Error: Type of Pulling configured should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid value base_url.",
            )

        if (
            "client_id" not in data
            or not data["client_id"].strip()
            or type(data["client_id"]) != str
        ):
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred"
                "Error: Type of Client ID should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Client ID provided.",
            )

        if (
            "minimum_score" not in data
            or not data["minimum_score"]
            or 1 > int(data["minimum_score"])
            or 1000 < int(data["minimum_score"])
        ):
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred"
                "Error: Type of minimum_score should be non-empty integer."
            )
            return ValidationResult(
                success=False,
                message="Invalid minimum_score provided.Range is from 1 to 1000.",
            )

        if (
            "client_secret" not in data
            or not data["client_secret"]
            or type(data["client_secret"]) != str
        ):
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred"
                "Error: Type of Client Secret should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Client Secret provided.",
            )

        return self.validate_auth_params(
            data["client_id"], data["client_secret"], data["base_url"]
        )

    def validate_auth_params(self, client_id, client_secret, base_url):
        """Validate the authentication params with CrowdStrike platform.

        Args:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2 token.
            base_url (str): Base url of crowd strike
        Returns:
            ValidationResult: ValidationResult object having validation results after making
            an API call.
        """
        try:
            self.check_url_valid(client_id, client_secret, base_url)
            return ValidationResult(
                success=True,
                message="Validation successfull for CrowdStrike Plugin",
            )
        except requests.exceptions.ProxyError:
            self.logger.error(
                "Plugin: CrowdStrike Validation Error, "
                "Invalid proxy configuration."
            )
            return ValidationResult(
                success=False,
                message="Validation Error, Invalid proxy configuration.",
            )
        except requests.exceptions.ConnectionError:
            self.logger.error(
                "Plugin: CrowdStrike Validation Error, "
                "Unable to establish connection with CrowdStrike Platform API"
            )
            return ValidationResult(
                success=False,
                message="Validation Error, Unable to establish connection with CrowdStrike Platform API",
            )
        except requests.HTTPError as err:
            self.logger.error(
                f"Plugin: CrowdStrike Validation Error, "
                f"Error in validating Credentials {repr(err)}"
            )
            return ValidationResult(
                success=False,
                message=f"Validation Error, Error in validating Credentials {repr(err)}",
            )

    def check_url_valid(self, client_id, client_secret, base_url):
        """
        Validate the authentication params with CrowdStrike platform.

        Args:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2 token.
            base_url (str): Base url of crowd strike
        Returns:
            Raise error if valid base url is not selected.
        """
        auth_json = self.get_auth_json(client_id, client_secret, base_url)
        auth_token = auth_json.get("access_token")
        headers = {"Authorization": f"Bearer {auth_token}"}
        query_endpoint = f"{base_url}/devices/queries/devices/v1?limit=1"
        all_agent_resp = requests.get(
            query_endpoint, headers=add_user_agent(headers), proxies=self.proxy
        )
        if all_agent_resp.status_code == 401:
            raise requests.HTTPError("Invalid base url.")

        agent_resp_json = self.handle_error(all_agent_resp)
        errors = agent_resp_json.get("errors")
        if errors:
            err_msg = errors[0].get("message", "")
            self.notifier.error(
                "Plugin: CrowdStrike Unable to Fetch agents, "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to Fetch Agents, "
                f"Error: {err_msg}"
            )
            raise requests.HTTPError(
                f"Plugin: CrowdStrike Unable to Fetch Agents, "
                f"Error: {err_msg}"
            )
        return agent_resp_json

    def get_auth_json(self, client_id, client_secret, base_url):
        """Get the OAUTH2 Json object with access token from CrowdStrike platform.

        Args:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2 token.
            base_url (str): Base URL of crowdstrike.
        Returns:
            json: JSON response data in case of Success.
        """
        client_id = client_id.strip()
        client_secret = client_secret.strip()
        auth_endpoint = f"{base_url}/oauth2/token"

        auth_params = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        resp = requests.post(
            auth_endpoint,
            data=auth_params,
            verify=self.ssl_validation,
            proxies=self.proxy,
            headers=add_user_agent()
        )
        auth_json = self.handle_error(resp)
        auth_errors = auth_json.get("errors")
        if auth_errors:
            err_msg = auth_errors[0].get("message", "")
            self.notifier.error(
                "Plugin: CrowdStrike Unable to generate Auth token. "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to generate Auth token. "
                f"Error: {err_msg}"
            )
            raise requests.HTTPError(
                f"Plugin: CrowdStrike Unable to generate Auth token. "
                f"Error: {err_msg}"
            )
        if self.storage is not None:
            self.storage[
                "token_expiry"
            ] = datetime.datetime.now() + datetime.timedelta(
                seconds=int(auth_json.get("expires_in", 1799))
            )
        return auth_json
