"""Netskope Provider Plugin Package."""
import sys
from pathlib import Path

src_path = Path(__file__).resolve()
src_dir = src_path.parent
sys.path.insert(0, str(src_dir / "lib"))
