"""CRE AWS Security Hub OCSF Plugin."""
import sys
from pathlib import Path

# Get lib directory
lib_dir = str(Path(__file__).resolve().parent / "lib")

# Insert lib directory at the very beginning of sys.path
# This ensures boto3 imports will find botocore in the same lib directory
if lib_dir in sys.path:
    sys.path.remove(lib_dir)
sys.path.insert(0, lib_dir)

# Clear cached boto3/botocore modules ONLY if they're from system (not from our lib)
modules_to_clear = []
for key in list(sys.modules.keys()):
    if key.startswith(('boto3', 'botocore')):
        module = sys.modules[key]
        if hasattr(module, '__file__') and module.__file__:
            if lib_dir not in module.__file__:
                modules_to_clear.append(key)
        else:
            modules_to_clear.append(key)

for module in modules_to_clear:
    del sys.modules[module]
