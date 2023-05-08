from __future__ import annotations

from typing import List

from bpx.util.ints import uint64
from bpx.types.blockchain_format.execution_payload import WithdrawalV1
from bpx.consensus.block_record import BlockRecord
from bpx.consensus.blockchain_interface import BlockchainInterface
from bpx.consensus.constants import ConsensusConstants

_bpx_to_gwei = 1000000000
_blocks_per_year = 1681920  # 32 * 6 * 24 * 365

def create_withdrawals(
    constants: ConsensusConstants,
    prev_tx_block: BlockRecord,
    blocks: BlockchainInterface,
) -> List[WithdrawalV1]:
    withdrawals: List[WithdrawalV1] = []
    
    next_wd_index: uint64
    if prev_tx_block.last_withdrawal_index is None:
        next_wd_index = 0
    else:
        next_wd_index = prev_tx_block.last_withdrawal_index + 1
    
    if prev_tx_block.height == 0:
        # Add bridge withdrawal
        withdrawals.append(
            WithdrawalV1(
                next_wd_index,
                uint64(0),
                constants.BRIDGE_ADDRESS,
                _calculate_v3_bridge(constants.V2_EOL_HEIGHT),
            )
        )
        next_wd_index += 1
    
    # Add block rewards
    curr: BlockRecord = prev_tx_block
    while True:
        withdrawals.append(
            WithdrawalV1(
                next_wd_index,
                uint64(1),
                curr.coinbase,
                _calculate_v3_reward(curr.height, constants.V2_EOL_HEIGHT),
            )
        )
        next_wd_index += 1
        
        if curr.prev_hash == constants.GENESIS_CHALLENGE:
            break
        curr = blocks.block_record(curr.prev_hash)
        if curr.is_transaction_block:
            break
    
    return withdrawals

def _calculate_v3_bridge(
    v2_eol_height: uint64,
) -> uint64:
    bridge: uint64 = 0
    
    for i in range(0, v2_eol_height+1):
        bridge += _calculate_v2_reward(i)
    
    return bridge

def _calculate_v3_reward(
    v3_height: uint64,
    v2_eol_height: uint64,
) -> uint64:
    v2_equiv_height = v2_eol_height + v3_height + 1
    return _calculate_v2_reward(v2_equiv_height)

def _calculate_v2_reward(
    v2_height: uint64
) -> uint64:
    if v2_height == 0:
        return uint64(20000000 * _bpx_to_gwei)
    elif v2_height < 1000000:
        return uint64(200 * _bpx_to_gwei)
    elif v2_height < 1000000 + (3 * _blocks_per_year):
        return uint64(20 * _bpx_to_gwei)
    elif v2_height < 1000000 + (6 * _blocks_per_year):
        return uint64(10 * _bpx_to_gwei)
    elif v2_height < 1000000 + (9 * _blocks_per_year):
        return uint64(5 * _bpx_to_gwei)
    elif v2_height < 1000000 + (12 * _blocks_per_year):
        return uint64(2.5 * _bpx_to_gwei)
    elif v2_height < 1000000 + (15 * _blocks_per_year):
        return uint64(1.25 * _bpx_to_gwei)
    else:
        return uint64(0)
