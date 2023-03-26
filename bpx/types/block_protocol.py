from __future__ import annotations

from typing import List, Optional

from typing_extensions import Protocol

from bpx.types.blockchain_format.sized_bytes import bytes32
from bpx.util.ints import uint32


class BlockInfo(Protocol):
    @property
    def prev_header_hash(self) -> bytes32:
        pass
