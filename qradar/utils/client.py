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

QRadar Plugin Syslog client."""

import errno
import logging
import socket
import ssl
import threading
import time
import traceback

from . import constants as CONST
from .exceptions import (
    QRadarCertificateError,
    QRadarPluginError,
    QRadarSendError,
)
from .ssl_handler import SSLSysLogHandler


class QRadarSyslogClient:
    """Connect to QRadar and send Syslog messages.

    This is the only place where the plugin opens a socket. It applies
    the socket timeout, retries a failed send after reconnecting, and
    classifies connection errors into user-facing messages.
    """

    def __init__(self, configuration, logger, log_prefix, is_json):
        """Initialize.

        Args:
            configuration (dict): Plugin configuration.
            logger: Cloud Exchange logger.
            log_prefix (str): Prefix of every log message.
            is_json (bool): True when the data is JSON formatted.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.server = str(configuration.get(CONST.CONFIG_SERVER, "")).strip()
        self.protocol = (
            str(configuration.get(CONST.CONFIG_PROTOCOL, "")).strip().upper()
        )
        self.port = configuration.get(CONST.CONFIG_PORT)
        self.certificate = configuration.get(CONST.CONFIG_CERTIFICATE)
        exclude_priority = (
            str(configuration.get(CONST.CONFIG_EXCLUDE_PRIORITY, CONST.NO))
            .strip()
            .lower()
        )
        self.skip_priority = is_json and exclude_priority == CONST.YES
        self.syslogger = None
        self.handler = None

    def _log_error(self, message, resolution=None):
        """Log an error with the traceback of the current exception.

        Args:
            message (str): Message, starting with "Error occurred while".
            resolution (str): Resolution, when the user can fix the cause.
        """
        log_kwargs = {
            "message": CONST.LOG_MESSAGE_TEMPLATE.format(
                self.log_prefix, message
            ),
            "details": str(traceback.format_exc()),
        }
        if resolution:
            log_kwargs["resolution"] = resolution
        self.logger.error(**log_kwargs)

    def classify_error(self, error):
        """Return the message and resolution for a connection error.

        Args:
            error (Exception): Error raised while connecting or sending.

        Returns:
            tuple: (message, resolution).
        """
        if isinstance(error, QRadarCertificateError):
            return (
                CONST.CERTIFICATE_LOAD_MESSAGE,
                CONST.CERTIFICATE_LOAD_RESOLUTION,
            )
        if isinstance(error, ssl.SSLCertVerificationError):
            return (
                CONST.CERTIFICATE_VERIFY_MESSAGE,
                CONST.CERTIFICATE_VERIFY_RESOLUTION,
            )
        if isinstance(error, socket.gaierror):
            return (
                CONST.CONNECTION_RESOLVE_MESSAGE.format(server=self.server),
                CONST.CONNECTION_RESOLVE_RESOLUTION,
            )
        if isinstance(error, TimeoutError):
            return (
                CONST.CONNECTION_TIMEOUT_MESSAGE,
                CONST.CONNECTION_TIMEOUT_RESOLUTION,
            )
        if isinstance(error, ConnectionRefusedError):
            return (
                CONST.CONNECTION_REFUSED_MESSAGE,
                CONST.CONNECTION_REFUSED_RESOLUTION,
            )
        return (
            CONST.CONNECTION_ERROR_MESSAGE.format(cause=error),
            CONST.CONNECTION_ERROR_RESOLUTION,
        )

    def _open(self):
        """Create the per-thread logger and the Syslog handler."""
        syslogger = logging.getLogger(
            CONST.SYSLOG_LOGGER_NAME.format(threading.get_ident())
        )
        syslogger.setLevel(logging.INFO)
        syslogger.handlers = []
        syslogger.propagate = False
        handler = SSLSysLogHandler(
            self.protocol,
            address=(self.server, self.port),
            certs=(
                self.certificate
                if self.protocol == CONST.PROTOCOL_TLS
                else None
            ),
            skip_priority=self.skip_priority,
            timeout=CONST.SOCKET_TIMEOUT,
        )
        if self.protocol == CONST.PROTOCOL_TCP:
            # One record per line, without the NUL terminator.
            handler.setFormatter(logging.Formatter(CONST.TCP_MESSAGE_FORMAT))
            handler.append_nul = False
        syslogger.addHandler(handler)
        self.syslogger = syslogger
        self.handler = handler

    def connect(self):
        """Open the connection to QRadar.

        Raises:
            QRadarPluginError: When the connection can not be opened. The
                error is logged with its resolution.
        """
        try:
            self._open()
        except Exception as err:
            message, resolution = self.classify_error(err)
            self._log_error(message, resolution)
            raise QRadarPluginError(message) from err

    def validate_connectivity(self):
        """Check that QRadar can be reached with the configuration.

        UDP has no connection, so only the QRadar Server is resolved and
        nothing is sent.

        Raises:
            QRadarPluginError: When QRadar can not be reached.
        """
        if self.protocol == CONST.PROTOCOL_UDP:
            try:
                socket.getaddrinfo(
                    self.server, self.port, type=socket.SOCK_DGRAM
                )
            except Exception as err:
                message, resolution = self.classify_error(err)
                self._log_error(message, resolution)
                raise QRadarPluginError(message) from err
            return
        self.connect()
        self.close()

    def close(self):
        """Close the connection. Errors are logged at debug level."""
        handler, syslogger = self.handler, self.syslogger
        self.handler = None
        self.syslogger = None
        if not handler:
            return
        try:
            handler.flush()
            handler.close()
            if syslogger:
                syslogger.removeHandler(handler)
        except Exception as err:
            self.logger.debug(
                CONST.LOG_MESSAGE_TEMPLATE.format(
                    self.log_prefix,
                    CONST.CLEANUP_FAILED_MESSAGE.format(
                        platform=CONST.PLATFORM_NAME, error=err
                    ),
                )
            )

    def _is_oversized(self, error):
        """Return True when a UDP record is too large for one datagram.

        Args:
            error (OSError): Send error.

        Returns:
            bool: True for the "message too long" error over UDP.
        """
        return (
            self.protocol == CONST.PROTOCOL_UDP
            and error.errno == errno.EMSGSIZE
        )

    def _send_record(self, record):
        """Send one record, reconnecting and retrying on a socket error.

        Args:
            record (str): Record to send.

        Returns:
            bool: True when sent, False when the record is too large for
                UDP (not retried).

        Raises:
            OSError: When every attempt failed.
        """
        last_error = None
        for attempt in range(1, CONST.MAX_SEND_RETRIES + 1):
            try:
                if self.handler is not None and self.handler.is_peer_closed():
                    self.logger.info(
                        CONST.LOG_MESSAGE_TEMPLATE.format(
                            self.log_prefix,
                            CONST.PEER_CLOSED_MESSAGE.format(
                                platform=CONST.PLATFORM_NAME
                            ),
                        )
                    )
                    self.close()
                if self.syslogger is None:
                    self._open()
                self.syslogger.info(record)
                self.handler.flush()
                return True
            except OSError as err:
                if self._is_oversized(err):
                    return False
                last_error = err
                self.close()
                if attempt < CONST.MAX_SEND_RETRIES:
                    self.logger.info(
                        CONST.LOG_MESSAGE_TEMPLATE.format(
                            self.log_prefix,
                            CONST.SEND_RETRY_MESSAGE.format(
                                platform=CONST.PLATFORM_NAME,
                                interval=CONST.RETRY_INTERVAL,
                                attempt=attempt + 1,
                                maximum=CONST.MAX_SEND_RETRIES,
                                error=err,
                            ),
                        )
                    )
                    time.sleep(CONST.RETRY_INTERVAL)
        raise last_error

    def send(self, records):
        """Send the records, one Syslog message each.

        Args:
            records (list): Transformed records.

        Returns:
            tuple: (sent, empty, oversized_records). ``sent`` and ``empty``
                are counts; ``oversized_records`` lists the records that
                do not fit in one UDP datagram and were not sent.

        Raises:
            QRadarSendError: When a record can not be sent after the
                retries. ``processed`` tells how many records were handled
                before it, so the caller can drop them before Cloud
                Exchange retries the batch.
        """
        sent = empty = 0
        oversized = []
        for index, record in enumerate(records):
            if not record:
                empty += 1
                continue
            try:
                if self._send_record(record):
                    sent += 1
                else:
                    oversized.append(record)
            except Exception as err:
                raise QRadarSendError(
                    str(err),
                    processed=index,
                    sent=sent,
                    oversized=len(oversized),
                ) from err
        return sent, empty, oversized
