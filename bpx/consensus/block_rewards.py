from __future__ import annotations

from bpx.util.ints import uint64

_bpx_to_gwei = 1000000000
_blocks_per_year = 1681920  # 32 * 6 * 24 * 365

def calculate_v3_reward(
    v3_height: uint64,
    v2_eol_height: uint64,
) -> uint64:
    if v3_height == 0:
        return uint64(0)
    
    v2_equiv_height = v2_eol_height + v3_height - 2
    # -2 -> skip V2 EOL block and V3 genesis block 
    return _calculate_v2_reward(v2_equiv_height)

def calculate_v3_prefarm(
    v3_additional_prefarm: uint64,
    v2_eol_height: uint64
) -> uint64:
    prefarm: uint64 = v3_additional_prefarm
    
    for i in range(0, v2_eol_height):
        prefarm += _calculate_v2_reward(i)
    
    return prefarm

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