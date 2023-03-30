from __future__ import annotations

from typing import List, Optional, Union

from bpx.consensus.block_record import BlockRecord
from bpx.consensus.blockchain_interface import BlockchainInterface
from bpx.consensus.constants import ConsensusConstants
from bpx.consensus.deficit import calculate_deficit
from bpx.consensus.difficulty_adjustment import get_next_sub_slot_iters_and_difficulty
from bpx.consensus.make_sub_epoch_summary import make_sub_epoch_summary
from bpx.consensus.pot_iterations import is_overflow_block
from bpx.types.blockchain_format.classgroup import ClassgroupElement
from bpx.types.blockchain_format.sized_bytes import bytes32
from bpx.types.blockchain_format.slots import ChallengeBlockInfo
from bpx.types.blockchain_format.sub_epoch_summary import SubEpochSummary
from bpx.types.full_block import FullBlock
from bpx.types.header_block import HeaderBlock
from bpx.util.errors import Err
from bpx.util.ints import uint8, uint32, uint64


def block_to_block_record(
    constants: ConsensusConstants,
    blocks: BlockchainInterface,
    required_iters: uint64,
    full_block: Optional[Union[FullBlock, HeaderBlock]],
    header_block: Optional[HeaderBlock],
    sub_slot_iters: Optional[uint64] = None,
) -> BlockRecord:
    if full_block is None:
        assert header_block is not None
        block: Union[HeaderBlock, FullBlock] = header_block
    else:
        block = full_block
    prev_b = blocks.try_block_record(block.prev_header_hash)
    if block.height > 0:
        assert prev_b is not None
    if sub_slot_iters is None:
        sub_slot_iters, _ = get_next_sub_slot_iters_and_difficulty(
            constants, len(block.finished_sub_slots) > 0, prev_b, blocks
        )
    overflow = is_overflow_block(constants, block.reward_chain_block.signage_point_index)
    deficit = calculate_deficit(
        constants,
        block.height,
        prev_b,
        overflow,
        len(block.finished_sub_slots),
    )

    found_ses_hash: Optional[bytes32] = None
    ses: Optional[SubEpochSummary] = None
    if len(block.finished_sub_slots) > 0:
        for sub_slot in block.finished_sub_slots:
            if sub_slot.challenge_chain.subepoch_summary_hash is not None:
                found_ses_hash = sub_slot.challenge_chain.subepoch_summary_hash
    if found_ses_hash:
        assert prev_b is not None
        assert len(block.finished_sub_slots) > 0
        ses = make_sub_epoch_summary(
            constants,
            blocks,
            block.height,
            blocks.block_record(prev_b.prev_hash),
            block.finished_sub_slots[0].challenge_chain.new_difficulty,
            block.finished_sub_slots[0].challenge_chain.new_sub_slot_iters,
        )
        if ses.get_hash() != found_ses_hash:
            raise ValueError(Err.INVALID_SUB_EPOCH_SUMMARY)

    return header_block_to_sub_block_record(
        constants,
        required_iters,
        block,
        sub_slot_iters,
        overflow,
        deficit,
        ses,
    )


def header_block_to_sub_block_record(
    constants: ConsensusConstants,
    required_iters: uint64,
    block: Union[FullBlock, HeaderBlock],
    sub_slot_iters: uint64,
    overflow: bool,
    deficit: uint8,
    ses: Optional[SubEpochSummary],
) -> BlockRecord:
    cbi = ChallengeBlockInfo(
        block.reward_chain_block.proof_of_space,
        block.reward_chain_block.challenge_chain_sp_vdf,
        block.reward_chain_block.challenge_chain_sp_signature,
        block.reward_chain_block.challenge_chain_ip_vdf,
    )

    if block.reward_chain_block.infused_challenge_chain_ip_vdf is not None:
        icc_output: Optional[ClassgroupElement] = block.reward_chain_block.infused_challenge_chain_ip_vdf.output
    else:
        icc_output = None

    if len(block.finished_sub_slots) > 0:
        finished_challenge_slot_hashes: Optional[List[bytes32]] = [
            sub_slot.challenge_chain.get_hash() for sub_slot in block.finished_sub_slots
        ]
        finished_reward_slot_hashes: Optional[List[bytes32]] = [
            sub_slot.reward_chain.get_hash() for sub_slot in block.finished_sub_slots
        ]
        finished_infused_challenge_slot_hashes: Optional[List[bytes32]] = [
            sub_slot.infused_challenge_chain.get_hash()
            for sub_slot in block.finished_sub_slots
            if sub_slot.infused_challenge_chain is not None
        ]
    elif block.height == 0:
        finished_challenge_slot_hashes = [constants.GENESIS_CHALLENGE]
        finished_reward_slot_hashes = [constants.GENESIS_CHALLENGE]
        finished_infused_challenge_slot_hashes = None
    else:
        finished_challenge_slot_hashes = None
        finished_reward_slot_hashes = None
        finished_infused_challenge_slot_hashes = None
    timestamp = block.foliage.foliage_block_data.timestamp

    return BlockRecord(
        block.header_hash,
        block.prev_header_hash,
        block.height,
        block.weight,
        block.total_iters,
        block.reward_chain_block.signage_point_index,
        block.reward_chain_block.challenge_chain_ip_vdf.output,
        icc_output,
        block.reward_chain_block.get_hash(),
        cbi.get_hash(),
        sub_slot_iters,
        required_iters,
        deficit,
        overflow,
        timestamp,
        finished_challenge_slot_hashes,
        finished_infused_challenge_slot_hashes,
        finished_reward_slot_hashes,
        ses,
    )
