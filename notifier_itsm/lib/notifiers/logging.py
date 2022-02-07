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

import copy
import logging
import sys

import notifiers
from notifiers.exceptions import NotifierException


class NotificationHandler(logging.Handler):
    """A :class:`logging.Handler` that enables directly sending log messages to notifiers"""

    def __init__(self, provider: str, defaults: dict = None, **kwargs):
        """
        Sets ups the handler

        :param provider: Provider name to use
        :param defaults: Default provider data to use. Can fallback to environs
        :param kwargs: Additional kwargs
        """
        self.defaults = defaults or {}
        self.provider = None
        self.fallback = None
        self.fallback_defaults = None
        self.init_providers(provider, kwargs)
        super().__init__(**kwargs)

    def init_providers(self, provider, kwargs):
        """
        Inits main and fallback provider if relevant

        :param provider: Provider name to use
        :param kwargs: Additional kwargs
        :raises ValueError: If provider name or fallback names are not valid providers, a :exc:`ValueError` will
         be raised
        """
        self.provider = notifiers.get_notifier(provider, strict=True)
        if kwargs.get("fallback"):
            self.fallback = notifiers.get_notifier(kwargs.pop("fallback"), strict=True)
            self.fallback_defaults = kwargs.pop("fallback_defaults", {})

    def emit(self, record):
        """
        Override the :meth:`~logging.Handler.emit` method that takes the ``msg`` attribute from the log record passed

        :param record: :class:`logging.LogRecord`
        """
        data = copy.deepcopy(self.defaults)
        data["message"] = self.format(record)
        try:
            self.provider.notify(raise_on_errors=True, **data)
        except Exception:
            self.handleError(record)

    def __repr__(self):
        level = logging.getLevelName(self.level)
        name = self.provider.name
        return "<%s %s(%s)>" % (self.__class__.__name__, name, level)

    def handleError(self, record):
        """
        Handles any errors raised during the :meth:`emit` method. Will only try to pass exceptions to fallback notifier
        (if defined) in case the exception is a sub-class of :exc:`~notifiers.exceptions.NotifierException`

        :param record: :class:`logging.LogRecord`
        """
        if logging.raiseExceptions:
            t, v, tb = sys.exc_info()
            if issubclass(t, NotifierException) and self.fallback:
                msg = f"Could not log msg to provider '{self.provider.name}'!\n{v}"
                self.fallback_defaults["message"] = msg
                self.fallback.notify(**self.fallback_defaults)
            else:
                super().handleError(record)
