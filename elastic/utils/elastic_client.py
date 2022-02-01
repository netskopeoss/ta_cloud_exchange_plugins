"""Elastic CLient."""

import socket


class ElasticClient:
    """Elastic Client."""

    def __init__(self, configuration: dict, logger):
        """Initialize."""
        self.configuration = configuration
        self.logger = logger

    def get_socket(self):
        """To Get TCP socket."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect(
                (
                    self.configuration["server_address"],
                    self.configuration["server_port"],
                )
            )
        except Exception as e:
            self.logger.error(f"Error while connection to server: {e}")
            raise

    def push_data(self, data):
        """To Push the data to TCP server."""
        try:
            self.sock.send(bytes(data, encoding="utf-8"))
        except Exception:
            raise

    def close(self):
        """To Close socket connection."""
        try:
            self.sock.close()
        except Exception as e:
            self.logger.error(
                f"Elastic Plugin: Error while Closing socket connection: {e}"
            )
