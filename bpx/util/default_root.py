from __future__ import annotations

import os
from pathlib import Path

DEFAULT_ROOT_PATH = Path(os.path.expanduser(os.getenv("BPX_ROOT", "~/.bpx/mainnet"))).resolve()

DEFAULT_KEYS_ROOT_PATH = Path(os.path.expanduser(os.getenv("BPX_KEYS_ROOT", "~/.bpx_keys"))).resolve()
