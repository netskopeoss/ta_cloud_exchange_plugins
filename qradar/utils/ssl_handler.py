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

QRadar Plugin Syslog handler for the UDP, TCP and TLS protocols."""

import errno
import logging
import logging.handlers
import os
import selectors
import socket
import ssl

from . import constants as CONST
from .exceptions import QRadarCertificateError


class SSLSysLogHandler(logging.handlers.SysLogHandler):
    """Syslog handler sending one record per message over UDP, TCP or TLS.

    The TLS connection follows the 3.1.0 workflow (no hostname check, CA
    verification when a certificate is configured). ssl.wrap_socket() was
    removed in Python 3.12, hence SSLContext is used.
    """

    def __init__(
        self,
        protocol,
        address,
        certs=None,
        facility=CONST.SYSLOG_FACILITY,
        skip_priority=False,
        timeout=None,
    ):
        """Open the connection to the Syslog server.

        Args:
            protocol (str): "UDP", "TCP" or "TLS".
            address (tuple): (server, port).
            certs (str): PEM CA certificate (TLS only).
            facility (int): Syslog facility.
            skip_priority (bool): Do not add the "<PRI>" prefix.
            timeout (float): Connect and send timeout for TCP and TLS.
        """
        self.protocol = protocol
        self.skip_priority = skip_priority
        self.socket = None
        if protocol == CONST.PROTOCOL_UDP:
            super().__init__(
                address=address,
                facility=facility,
                socktype=socket.SOCK_DGRAM,
            )
            return
        logging.Handler.__init__(self)
        self.address = address
        self.facility = facility
        self.socktype = socket.SOCK_STREAM
        self.unixsocket = False
        if protocol == CONST.PROTOCOL_TLS:
            self._connect_tls(address, certs, timeout)
        else:
            try:
                self.socket = socket.create_connection(
                    address, timeout=timeout
                )
            except Exception:
                logging.Handler.close(self)
                raise

    def _connect_tls(self, address, certs, timeout):
        """Open the TLS connection.

        Args:
            address (tuple): (server, port).
            certs (str): PEM CA certificate.
            timeout (float): Connect and send timeout.

        Raises:
            QRadarCertificateError: When the certificate can not be loaded.
        """
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plain_socket.settimeout(timeout)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # The server hostname is not checked, as in 3.1.0.
            context.check_hostname = False
            if certs:
                context.verify_mode = ssl.CERT_REQUIRED
                try:
                    context.load_verify_locations(cadata=certs)
                except (ssl.SSLError, ValueError) as err:
                    raise QRadarCertificateError(
                        CONST.CERTIFICATE_LOAD_CAUSE.format(error=err)
                    ) from err
            else:
                context.verify_mode = ssl.CERT_NONE
            self.socket = context.wrap_socket(plain_socket)
            self.socket.connect(address)
        except Exception:
            # The handler is not returned to the caller, so close() is
            # never called for it. wrap_socket() detaches the plain
            # socket, so closing it is a no-op once the TLS socket exists.
            if self.socket:
                self.socket.close()
            plain_socket.close()
            logging.Handler.close(self)
            raise

    def close(self):
        """Close the connection.

        With TLS 1.3 the server sends session tickets which this client
        never reads. Closing a socket with unread data resets the
        connection and the server can drop the messages it has not read
        yet, so the pending data is read and close_notify is sent first.
        """
        sock = self.socket
        if self.protocol == CONST.PROTOCOL_TLS and sock:
            try:
                sock.setblocking(False)
                while sock.recv(CONST.TLS_READ_BUFFER_SIZE):
                    pass
            except (ssl.SSLError, BlockingIOError, OSError):
                pass
            try:
                sock.settimeout(CONST.TLS_CLOSE_TIMEOUT)
                sock.unwrap()
            except (ssl.SSLError, OSError, ValueError):
                pass
        if sock:
            sock.close()
            self.socket = None
        logging.Handler.close(self)

    def is_peer_closed(self):
        """Return True when the server closed the TCP or TLS connection.

        After the server closes the connection, the next send still
        succeeds locally and its data is lost; only the send after it
        fails. Checking before each send lets the caller reconnect first.

        Returns:
            bool: True when the connection is closed or reset.
        """
        sock = self.socket
        if self.protocol == CONST.PROTOCOL_UDP or sock is None:
            return False
        timeout = sock.gettimeout()
        try:
            # selectors has no limit on the file descriptor number, unlike
            # select.select() (FD_SETSIZE).
            with selectors.DefaultSelector() as selector:
                selector.register(sock, selectors.EVENT_READ)
                readable = bool(selector.select(0))
            is_tls = self.protocol == CONST.PROTOCOL_TLS
            if not readable and not (is_tls and sock.pending()):
                return False
            sock.setblocking(False)
            if is_tls:
                # TLS 1.3 session tickets are consumed here and raise
                # SSLWantReadError; an empty read means the peer closed.
                return sock.recv(CONST.TLS_READ_BUFFER_SIZE) == b""
            return sock.recv(1, socket.MSG_PEEK) == b""
        except (ssl.SSLWantReadError, BlockingIOError):
            return False
        except OSError:
            return True
        except ValueError:
            # The check itself failed; it must never block a send.
            return False
        finally:
            try:
                sock.settimeout(timeout)
            except OSError:
                pass

    def _priority(self, record):
        """Return the "<PRI>" prefix of a record.

        Args:
            record (logging.LogRecord): Record being sent.

        Returns:
            str: Priority prefix, or an empty string when it is skipped.
        """
        if self.skip_priority:
            return ""
        return CONST.SYSLOG_PRIORITY_TEMPLATE.format(
            self.encodePriority(
                self.facility, self.mapPriority(record.levelname)
            )
        )

    def emit(self, record):
        """Send one record. Errors are raised to the caller.

        Args:
            record (logging.LogRecord): Record to send.
        """
        if self.protocol == CONST.PROTOCOL_TLS:
            message = self.format(record) + CONST.LINE_TERMINATOR
            self.socket.sendall(
                (self._priority(record) + message).encode(CONST.ENCODING)
            )
            return
        message = self.format(record)
        if self.ident:
            message = self.ident + message
        if self.append_nul:
            message += CONST.SYSLOG_NUL_TERMINATOR
        payload = (self._priority(record) + message).encode(CONST.ENCODING)
        if self.socktype == socket.SOCK_DGRAM:
            if len(payload) > CONST.UDP_MAX_PAYLOAD_SIZE:
                raise OSError(errno.EMSGSIZE, os.strerror(errno.EMSGSIZE))
            self.socket.sendto(payload, self.address)
        else:
            self.socket.sendall(payload)
