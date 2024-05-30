import sys
from pathlib import Path

BIN_NINJA_INSTALL_PATH = Path("~/binaryninja/python/").expanduser().resolve()
sys.path.append(str(BIN_NINJA_INSTALL_PATH))
import binaryninja
