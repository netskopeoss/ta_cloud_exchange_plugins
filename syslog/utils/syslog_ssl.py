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
"""

"""Syslog Plugin SSL Log Handler."""


import os
import codecs
import logging
import logging.handlers
import ssl
import socket

from tempfile import NamedTemporaryFile


class SSLSysLogHandler(logging.handlers.SysLogHandler):
    """SSL SysLogHandler Class."""

    # We need to paste all this in because __init__ complains otherwise
    # This all comes from logging.handlers.SysLogHandler

    LOG_EMERG = 0  # system is unusable
    LOG_ALERT = 1  # action must be taken immediately
    LOG_CRIT = 2  # critical conditions
    LOG_ERR = 3  # error conditions
    LOG_WARNING = 4  # warning conditions
    LOG_NOTICE = 5  # normal but significant condition
    LOG_INFO = 6  # informational
    LOG_DEBUG = 7  # debug-level messages

    #  facility codes
    LOG_KERN = 0  # kernel messages
    LOG_USER = 1  # random user-level messages
    LOG_MAIL = 2  # mail system
    LOG_DAEMON = 3  # system daemons
    LOG_AUTH = 4  # security/authorization messages
    LOG_SYSLOG = 5  # messages generated internally by syslogd
    LOG_LPR = 6  # line printer subsystem
    LOG_NEWS = 7  # network news subsystem
    LOG_UUCP = 8  # UUCP subsystem
    LOG_CRON = 9  # clock daemon
    LOG_AUTHPRIV = 10  # security/authorization messages (private)
    LOG_FTP = 11  # FTP daemon

    #  other codes through 15 reserved for system use
    LOG_LOCAL0 = 16  # reserved for local use
    LOG_LOCAL1 = 17  # reserved for local use
    LOG_LOCAL2 = 18  # reserved for local use
    LOG_LOCAL3 = 19  # reserved for local use
    LOG_LOCAL4 = 20  # reserved for local use
    LOG_LOCAL5 = 21  # reserved for local use
    LOG_LOCAL6 = 22  # reserved for local use
    LOG_LOCAL7 = 23  # reserved for local use

    priority_names = {
        "alert": LOG_ALERT,
        "crit": LOG_CRIT,
        "critical": LOG_CRIT,
        "debug": LOG_DEBUG,
        "emerg": LOG_EMERG,
        "err": LOG_ERR,
        "error": LOG_ERR,  # DEPRECATED
        "info": LOG_INFO,
        "notice": LOG_NOTICE,
        "panic": LOG_EMERG,  # DEPRECATED
        "warn": LOG_WARNING,  # DEPRECATED
        "warning": LOG_WARNING,
    }

    facility_names = {
        "auth": LOG_AUTH,
        "authpriv": LOG_AUTHPRIV,
        "cron": LOG_CRON,
        "daemon": LOG_DAEMON,
        "ftp": LOG_FTP,
        "kern": LOG_KERN,
        "lpr": LOG_LPR,
        "mail": LOG_MAIL,
        "news": LOG_NEWS,
        "security": LOG_AUTH,  # DEPRECATED
        "syslog": LOG_SYSLOG,
        "user": LOG_USER,
        "uucp": LOG_UUCP,
        "local0": LOG_LOCAL0,
        "local1": LOG_LOCAL1,
        "local2": LOG_LOCAL2,
        "local3": LOG_LOCAL3,
        "local4": LOG_LOCAL4,
        "local5": LOG_LOCAL5,
        "local6": LOG_LOCAL6,
        "local7": LOG_LOCAL7,
    }

    # The map below appears to be trivially lowercase the key. However,
    # there's more to it than meets the eye - in some locales, lowercase
    # gives unexpected results. See SF #1524081: in the Turkish locale,
    # "INFO".lower() != "info"
    priority_map = {
        "DEBUG": "debug",
        "INFO": "info",
        "WARNING": "warning",
        "ERROR": "error",
        "CRITICAL": "critical",
    }

    def __init__(
        self,
        transform_data,
        protocol,
        address,
        certs=None,
        facility=LOG_USER,
        socktype=None,
    ):
        """Init method."""
        self.protocol = protocol
        self.transform_data = transform_data
        if protocol == "TLS":
            logging.Handler.__init__(self)

            self.address = address
            self.facility = facility

            self.unixsocket = 0
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if certs:
                cert = NamedTemporaryFile(delete=False)

                cert.write(str.encode(certs))
                cert.flush()
                self.socket = ssl.wrap_socket(
                    s, ca_certs=cert.name, cert_reqs=ssl.CERT_REQUIRED
                )
                cert.close()
                os.unlink(cert.name)
            else:
                self.socket = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE)
            self.socket.connect(address)

        else:
            super().__init__(address=address, socktype=socktype)

    def close(self):
        """Close method."""
        self.socket.close()
        logging.Handler.close(self)

    def emit(self, record):
        """Emit Method."""
        if self.protocol == "TLS":
            msg = self.format(record) + "\n"
            prio = "<%d>" % self.encodePriority(
                self.facility, self.mapPriority(record.levelname)
            )
            if type(msg) == "unicode":
                msg = msg.encode("utf-8")
                if codecs:
                    msg = codecs.BOM_UTF8 + msg
            if self.transform_data:
                msg = prio + msg
            try:
                self.socket.write(str.encode(msg))
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                self.handleError(record)
        else:
            try:
                msg = self.format(record)
                if self.ident:
                    msg = self.ident + msg
                if self.append_nul:
                    msg += "\000"

                # We need to convert record level to lowercase, maybe this will
                # change in the future.
                prio = "<%d>" % self.encodePriority(
                    self.facility, self.mapPriority(record.levelname)
                )
                prio = prio.encode("utf-8")
                # Message is a string. Convert to bytes as required by RFC 5424
                msg = msg.encode("utf-8")
                if self.transform_data:
                    msg = prio + msg
                if self.unixsocket:
                    try:
                        self.socket.send(msg)
                    except OSError:
                        self.socket.close()
                        self._connect_unixsocket(self.address)
                        self.socket.send(msg)
                elif self.socktype == socket.SOCK_DGRAM:
                    self.socket.sendto(msg, self.address)
                else:
                    self.socket.sendall(msg)
            except Exception:
                self.handleError(record)
