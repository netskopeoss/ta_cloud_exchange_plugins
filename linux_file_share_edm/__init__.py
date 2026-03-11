"""Linux File Share EDM Plugin."""
import os
import sys

project_path = os.path.abspath(os.path.dirname(__file__))
lib_path = os.path.join(project_path, "lib")
sys.path.append(lib_path)
