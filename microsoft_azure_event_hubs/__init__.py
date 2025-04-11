"""CLS Microsoft Azure Event Hubs plugin."""

import sys
import importlib
import os


cpath = os.path.join(str(os.path.dirname(os.path.abspath(__file__))), "lib")


class CustomFinder(importlib.machinery.PathFinder):
    _path = [cpath]

    @classmethod
    def find_spec(cls, fullname, path=None, target=None):
        return super().find_spec(fullname, cls._path, target)


sys.meta_path.append(CustomFinder)
