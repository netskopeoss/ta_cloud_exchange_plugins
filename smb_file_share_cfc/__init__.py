"""SMB File Share CFC Plugin."""
import os
import sys

project_path = os.path.abspath(os.path.dirname(__file__))
lib_path = os.path.join(project_path, "lib")
if lib_path not in sys.path:
    sys.path.insert(0, lib_path)
