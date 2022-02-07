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

class NotifierException(Exception):
    """Base notifier exception. Catch this to catch all of :mod:`notifiers` errors"""

    def __init__(self, *args, **kwargs):
        """
        Looks for ``provider``, ``message`` and ``data`` in kwargs
        :param args: Exception arguments
        :param kwargs: Exception kwargs
        """
        self.provider = kwargs.get("provider")
        self.message = kwargs.get("message")
        self.data = kwargs.get("data")
        self.response = kwargs.get("response")
        super().__init__(self.message)

    def __repr__(self):
        return f"<NotificationError: {self.message}>"


class BadArguments(NotifierException):
    """
    Raised on schema data validation issues

    :param validation_error: The validation error message
    :param args: Exception arguments
    :param kwargs: Exception kwargs
    """

    def __init__(self, validation_error: str, *args, **kwargs):
        kwargs["message"] = f"Error with sent data: {validation_error}"
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"<BadArguments: {self.message}>"


class SchemaError(NotifierException):
    """
    Raised on schema issues, relevant probably when creating or changing a provider schema

    :param schema_error: The schema error that was raised
    :param args: Exception arguments
    :param kwargs: Exception kwargs
    """

    def __init__(self, schema_error: str, *args, **kwargs):
        kwargs["message"] = f"Schema error: {schema_error}"
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"<SchemaError: {self.message}>"


class NotificationError(NotifierException):
    """
    A notification error. Raised after an issue with the sent notification.
    Looks for ``errors`` key word in kwargs.

    :param args: Exception arguments
    :param kwargs: Exception kwargs
    """

    def __init__(self, *args, **kwargs):
        self.errors = kwargs.pop("errors", None)
        kwargs["message"] = f'Notification errors: {",".join(self.errors)}'
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"<NotificationError: {self.message}>"


class ResourceError(NotifierException):
    """
    A notifier resource request error, occurs when an error happened in a
     :meth:`notifiers.core.ProviderResource._get_resource` call
    """

    def __init__(self, *args, **kwargs):
        self.errors = kwargs.pop("errors", None)
        self.resource = kwargs.pop("resource", None)
        kwargs["message"] = f'Notifier resource errors: {",".join(self.errors)}'
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"<ResourceError: {self.message}>"


class NoSuchNotifierError(NotifierException):
    """
    An unknown notifier was requests, one that was not registered
    """

    def __init__(self, name: str, *args, **kwargs):
        self.name = name
        kwargs["message"] = f"No such notifier with name {name}"
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"<NoSuchNotifierError: {self.name}>"
