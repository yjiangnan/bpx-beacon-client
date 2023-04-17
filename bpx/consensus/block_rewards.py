from __future__ import annotations

from chia.util.ints import uint64

_bpx_prec = 1000000000000000000
_blocks_per_year = 1681920  # 32 * 6 * 24 * 365

def calculate_v3_reward(
    v3_height: uint64,
    v2_eol_height: uint64,
) -> uint64:
    if v3_height == 0:
        return uint64(0)
    
    v2_equiv_height = v2_eol_height + v3_height - 1
    reward = _calculate_v2_reward(v2_equiv_height)
     
    if v3_height == 1:
        reward += _calculate_v2_supply(v2_eol_height)
    
    return reward

def _calculate_v2_reward(
    v2_height: uint64
) -> uint64:
    if v2_height == 0:
        return uint64(20000000 * _bpx_prec)
    elif v2_height < 1000000:
        return uint64(200 * _bpx_prec)
    elif v2_height < 1000000 + (3 * _blocks_per_year):
        return uint64(20 * _bpx_prec)
    elif v2_height < 1000000 + (6 * _blocks_per_year):
        return uint64(10 * _bpx_prec)
    elif v2_height < 1000000 + (9 * _blocks_per_year):
        return uint64(5 * _bpx_prec)
    elif v2_height < 1000000 + (12 * _blocks_per_year):
        return uint64(2.5 * _bpx_prec)
    elif v2_height < 1000000 + (15 * _blocks_per_year):
        return uint64(1.25 * _bpx_prec)
    else:
        return uint64(0)

def _calculate_v2_supply(
    v2_eol_height: uint64
) -> uint64:
    supply: uint64 = uint64(0)
    
    for i in range(0, v2_eol_height):
        supply += _calculate_v2_reward(i)
    
    return supply