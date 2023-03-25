from __future__ import annotations

from enum import Enum


class ProtocolMessageTypes(Enum):
    # Shared protocol (all services)
    handshake = 1

    # Harvester protocol (harvester <-> farmer)
    harvester_handshake = 3
    # new_signage_point_harvester = 4 Changed to 66 in new protocol
    new_proof_of_space = 5
    request_signatures = 6
    respond_signatures = 7

    # Farmer protocol (farmer <-> beacon)
    new_signage_point = 8
    declare_proof_of_space = 9
    request_signed_values = 10
    signed_values = 11
    farming_info = 12

    # Timelord protocol (timelord <-> beacon)
    new_peak_timelord = 13
    new_unfinished_block_timelord = 14
    new_infusion_point_vdf = 15
    new_signage_point_vdf = 16
    new_end_of_sub_slot_vdf = 17
    request_compact_proof_of_time = 18
    respond_compact_proof_of_time = 19

    # Beacon client protocol (beacon <-> beacon)
    new_peak = 20
    request_proof_of_weight = 24
    respond_proof_of_weight = 25
    request_block = 26
    respond_block = 27
    reject_block = 28
    request_blocks = 29
    respond_blocks = 30
    reject_blocks = 31
    new_unfinished_block = 32
    request_unfinished_block = 33
    respond_unfinished_block = 34
    new_signage_point_or_end_of_sub_slot = 35
    request_signage_point_or_end_of_sub_slot = 36
    respond_signage_point = 37
    respond_end_of_sub_slot = 38
    request_compact_vdf = 40
    respond_compact_vdf = 41
    new_compact_vdf = 42
    request_peers = 43
    respond_peers = 44
    none_response = 91

    # Introducer protocol (introducer <-> beacon)
    request_peers_introducer = 63
    respond_peers_introducer = 64

    # New harvester protocol
    new_signage_point_harvester = 66
    request_plots = 67
    respond_plots = 68
    plot_sync_start = 78
    plot_sync_loaded = 79
    plot_sync_removed = 80
    plot_sync_invalid = 81
    plot_sync_keys_missing = 82
    plot_sync_duplicates = 83
    plot_sync_done = 84
    plot_sync_response = 85
