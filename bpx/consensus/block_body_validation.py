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

log = logging.getLogger(__name__)


async def validate_block_body(
    constants: ConsensusConstants,
    execution_client: ExecutionClient,
    blocks: BlockchainInterface,
    block_store: BlockStore,
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
    
    if block.execution_payload is None:
        return None
    
    optimistic_import = execution_client.beacon.config.get("optimistic_import", True)
    
    status = await execution_client.new_payload(block.execution_payload)
    if status == "INVALID" or status == "INVALID_BLOCK_HASH":
        return Err.PAYLOAD_INVALIDATED
    elif status == "SYNCING" or status == "ACCEPTED":
        if not optimistic_import or isinstance(block, UnfinishedBlock):
            return Err.PAYLOAD_NOT_VALIDATED
    elif status != "VALID":
        return Err.UNKNOWN
    
    if isinstance(block, FullBlock):
        status = await execution_client.forkchoice_update(block)
        if status == "INVALID" or status == "INVALID_BLOCK_HASH":
            return Err.PAYLOAD_INVALIDATED
        if status != "VALID" and status != "SYNCING" and status != "ACCEPTED":
            return Err.UNKNOWN
    
    return None
