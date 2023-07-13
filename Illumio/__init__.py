# -*- coding: utf-8 -*-

"""Entrypoint init for the Illumio plugin for Netskope Threat Exchange.

Adds the lib directory to the python PATH.

Copyright:
    © 2023 Illumio

License:
    Apache2
"""
import sys
from pathlib import Path

src_path = Path(__file__).resolve()
src_dir = src_path.parent
sys.path.insert(0, str(src_dir / "lib"))
