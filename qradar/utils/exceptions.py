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

QRadar Plugin exceptions."""


class QRadarPluginError(Exception):
    """Exception raised by the plugin to Cloud Exchange."""


class QRadarCertificateError(Exception):
    """Exception raised when the QRadar Certificate can not be loaded."""


class QRadarSendError(Exception):
    """Exception raised when a record can not be sent to QRadar.

    Attributes:
        processed (int): Number of records handled (sent, empty or
            oversized) before the record that failed.
        sent (int): Number of records sent before the failure.
        oversized (int): Number of oversized records skipped before the
            failure.
    """

    def __init__(self, message, processed, sent, oversized):
        """Initialize."""
        super().__init__(message)
        self.processed = processed
        self.sent = sent
        self.oversized = oversized


class MappingValidationError(Exception):
    """Exception raised when the QRadar mapping file is not valid."""


class FieldNotFoundError(Exception):
    """Exception raised when a mapped field is not found in the data."""
