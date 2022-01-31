"""Chronicle CLient."""
import requests
import json
from netskope.common.utils import add_user_agent


class ChronicleClient:
    """Chronicle Client."""

    def __init__(self, configuration: dict, logger):
        """Initialize."""
        self.configuration = configuration
        self.logger = logger

    def _api_request(self, transformed_data):
        """Call the API for data Ingestion.

        :transformed_data : The transformed data to be ingested.
        """
        try:
            base_url = self.configuration["base_url"]
            url = f"{base_url.strip().strip('/')}/v1/udmevents"
            data = {"events": transformed_data}
            payload = json.dumps(data)
            headers = {"Content-Type": "application/json"}
            response = requests.request(
                "POST",
                url,
                params={"key": self.configuration["api_key"].strip()},
                headers=add_user_agent(headers),
                data=payload,
            )
            status_code = response.status_code
            response_body = response.text
            if status_code >= 500:
                raise Exception(
                    "Server Error : Status Code: {}. Response: {}".format(
                        status_code, response_body
                    )
                )
            elif status_code == 429:
                raise Exception(
                    f"Either out of resource quota or reaching rate limiting."
                    f" Status Code: {status_code}. Response: {response_body}"
                )

            elif status_code in [400, 404]:
                raise Exception(
                    "Client specified an invalid argument . Status code: {}. Response: {}".format(
                        status_code, response_body
                    )
                )
            elif status_code == 499:
                raise Exception(
                    "Request Cancelled by the client :  Status code: {}. Response: {}".format(
                        status_code, response_body
                    )
                )
            elif status_code == 403:
                raise Exception(
                    "Invalid Authorization. Status code: {}. Response: {}".format(
                        status_code, response_body
                    )
                )

        except requests.exceptions.HTTPError as err:
            self.logger.error(
                "Chronicle: HTTP error occurred: {}.".format(err)
            )
            raise
        except requests.exceptions.ConnectionError as err:
            self.logger.error(
                "Chronicle: Connection error occurred: {}.".format(err)
            )
            raise
        except requests.exceptions.Timeout as err:
            self.logger.error("Chronicle: Request timed out: {}.".format(err))
            raise
        except requests.exceptions.RequestException as err:
            self.logger.error(
                f"Chronicle: An error occurred while making REST API call to"
                f" Chronicle: {err}."
            )
            raise
        except Exception as err:
            self.logger.error(
                f"Chronicle: An error occurred while processing the "
                f"API response: {err}."
            )
            raise
