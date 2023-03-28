from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from bpx.types.blockchain_format.foliage import Foliage, FoliageTransactionBlock, TransactionsInfo
from bpx.types.blockchain_format.reward_chain_block import RewardChainBlockUnfinished
from bpx.types.blockchain_format.serialized_program import SerializedProgram
from bpx.types.blockchain_format.sized_bytes import bytes32
from bpx.types.blockchain_format.vdf import VDFProof
from bpx.types.end_of_slot_bundle import EndOfSubSlotBundle
from bpx.util.ints import uint32, uint128
from bpx.util.streamable import Streamable, streamable


@streamable
@dataclass(frozen=True)
class UnfinishedBlock(Streamable):
    # Full block, without the final VDFs
    finished_sub_slots: List[EndOfSubSlotBundle]  # If first sb
    reward_chain_block: RewardChainBlockUnfinished  # Reward chain trunk data
    challenge_chain_sp_proof: Optional[VDFProof]  # If not first sp in sub-slot
    reward_chain_sp_proof: Optional[VDFProof]  # If not first sp in sub-slot
    foliage: Foliage  # Reward chain foliage data
    foliage_transaction_block: Optional[FoliageTransactionBlock]  # Reward chain foliage data (tx block)
    transactions_info: Optional[TransactionsInfo]  # Reward chain foliage data (tx block additional)
    transactions_generator: Optional[SerializedProgram]  # Program that generates transactions
    transactions_generator_ref_list: List[
        uint32
    ]  # List of block heights of previous generators referenced in this block

    @property
    def prev_header_hash(self) -> bytes32:
        return self.foliage.prev_block_hash

    @property
    def partial_hash(self) -> bytes32:
        return self.reward_chain_block.get_hash()

    @property
    def total_iters(self) -> uint128:
        return self.reward_chain_block.total_iters
