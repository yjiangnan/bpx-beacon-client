from __future__ import annotations

import collections
import logging
from typing import Awaitable, Callable, Dict, List, Optional, Set, Tuple, Union

from bpx.consensus.block_record import BlockRecord
from bpx.consensus.blockchain_interface import BlockchainInterface
from bpx.consensus.constants import ConsensusConstants
from bpx.consensus.find_fork_point import find_fork_point_in_chain
from bpx.beacon.block_store import BlockStore
from bpx.types.block_protocol import BlockInfo
from bpx.types.blockchain_format.sized_bytes import bytes32, bytes48
from bpx.types.full_block import FullBlock
from bpx.types.unfinished_block import UnfinishedBlock
from bpx.util import cached_bls
from bpx.util.errors import Err
from bpx.util.hash import std_hash
from bpx.util.ints import uint32, uint64
from bpx.beacon.execution_client import ExecutionClient

log = logging.getLogger(__name__)


async def validate_block_body(
    constants: ConsensusConstants,
    blocks: BlockchainInterface,
    block_store: BlockStore,
    execution_client: ExecutionClient,
    peak: Optional[BlockRecord],
    block: Union[FullBlock, UnfinishedBlock],
    height: uint32,
    fork_point_with_peak: Optional[uint32],
) -> Optional[Err]:
    """
    This assumes the header block has been completely validated.
    Validates the body of the block. Returns None if everything validates correctly, or an Err if something does not validate.
    """
    if isinstance(block, FullBlock):
        assert height == block.height
        return await execution_client.new_block(block, blocks, peak)
    
    return await execution_client.new_unfinished_block(block, height, blocks)
