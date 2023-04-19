from __future__ import annotations

import logging
import asyncio
from datetime import datetime, timezone
import pathlib

from typing import (
    Optional,
    Union,
)

from web3 import Web3, HTTPProvider
from web3.method import Method
from web3.module import Module
from web3.providers.rpc import URI
import jwt

from bpx.util.path import path_from_root
from bpx.consensus.block_record import BlockRecord
from bpx.types.blockchain_format.sized_bytes import bytes20, bytes32, bytes256
from bpx.util.ints import uint64, uint256
from bpx.types.blockchain_format.execution_payload import ExecutionPayloadV2, WithdrawalV1

log = logging.getLogger(__name__)

class HTTPAuthProvider(HTTPProvider):
    secret: str

    def __init__(
        self,
        secret: str,
        endpoint_uri: Optional[Union[URI, str]] = None,
    ) -> None:
        self.secret = bytes.fromhex(secret[2:])
        super().__init__(endpoint_uri)
    
    def get_request_headers(self) -> Dict[str, str]:
        headers = super().get_request_headers()
        
        encoded_jwt = jwt.encode(
            {
                "iat": datetime.now(tz=timezone.utc)
            },
            self.secret,
            algorithm="HS256"
        )
        
        headers.update(
            {
                "Authorization": "Bearer " + encoded_jwt
            }
        )
        return headers

class EngineModule(Module):
    exchange_transition_configuration_v1 = Method("engine_exchangeTransitionConfigurationV1")
    forkchoice_updated_v2 = Method("engine_forkchoiceUpdatedV2")
    get_payload_v2 = Method("engine_getPayloadV2")
    new_payload_v2 = Method("engine_newPayloadV2")

class ExecutionClient:
    beacon: Beacon
    w3: Web3
    payload_id: Optional[str]
    payload_head: Optional[bytes32]

    def __init__(
        self,
        beacon,
    ):
        self.beacon = beacon
        self.w3 = None
        self.payload_id = None
        self.payload_head = None


    def ensure_web3_init(self) -> None:
        if self.w3 is not None:
            return None
        
        log.debug(f"Initializing execution client connection: {self.exe_host}:{self.exe_port} using JWT secret {self.secret_path}")

        try:
            selected_network = self.beacon.config.get("selected_network")
            secret_path = path_from_root(
                beacon.root_path,
                "../execution/" + selected_network + "/geth/jwtsecret"
            )
            secret_file = open(secret_path, 'r')
            secret = secret_file.readline()
            secret_file.close()
        except Exception as e:
            log.error(f"Exception in Web3 init: {e}")
            raise RuntimeError("Cannot open JWT secret file. Execution client is not running or needs more time to start")
        
        ec_config = self.beacon.config.get("execution_client")
        self.w3 = Web3(
            HTTPAuthProvider(
                secret,
                "http://" + ec_config["host"] + ":" + str(ec_config["port"]),
            )
        )

        self.w3.attach_modules({
            "engine": EngineModule
        })

        log.info("Initialized execution client connection")


    async def exchange_transition_configuration_task(self):
        log.debug("Starting exchange transition configuration loop")

        while True:
            try:
                self.ensure_web3_init()
                self.w3.engine.exchange_transition_configuration_v1({
                    "terminalTotalDifficulty": "0x0",
                    "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "terminalBlockNumber": "0x0"
                })
            except Exception as e:
                log.error(f"Exception in exchange transition configuration: {e}")
            await asyncio.sleep(60)
    
    
    async def new_block(
        self,
        block: FullBlock,
        blockchain: Blockchain,
        peak: Optional[BlockRecord],
    ) -> Optional[Err]:
        log.debug(f"Validating finished block of height: {block.height}")
        
        self.ensure_web3_init()
        
        # Prepare ForkchoiceStateV1
            
        head_height = block.height
        head_hash = "0x" + block.foliage.foliage_block_data.execution_block_hash.hex()
        log.debug(f"Head height: {head_height}, hash: {head_hash}")
            
        safe_height = 0
        if head_height > 6:
            safe_height = (head_height - 6) - (head_height % 6)
            
        safe_block = await blockchain.get_full_block(blockchain.height_to_hash(safe_height))
        safe_hash = "0x" + safe_block.foliage.foliage_block_data.execution_block_hash.hex()
        log.debug(f"Safe height: {safe_height}, hash: {safe_hash}")
        
        final_height = 0
        if head_height > 32:
            final_height = (head_height - 32) - (head_height % 32)
            
        final_block = await blockchain.get_full_block(blockchain.height_to_hash(final_height))
        final_hash = "0x" + final_block.foliage.foliage_block_data.execution_block_hash.hex()
        log.debug(f"Finalized height: {final_height}, hash: {final_hash}")
        
        forkchoice_state = {
            "headBlockHash": head_hash,
            "safeBlockHash": safe_hash,
            "finalizedBlockHash": final_hash,
        }
            
        # Prepare PayloadAttributesV2
        
        payload_attributes = None
        
        if peak is not None and peak.height == head_height and self.coinbase != COINBASE_NULL:
            payload_attributes = {
                "timestamp": Web3.to_hex(block.foliage.foliage_block_data.timestamp),
                "prevRandao": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "suggestedFeeRecipient": self.coinbase,
                "withdrawals": [],
            }
        
        result = self.w3.engine.forkchoice_updated_v2(forkchoice_state, payload_attributes)
        self.payload_id = resp.payloadId
        
        return self.validation_result(result.payloadStatus)
    
    
    def get_payload(
        self,
        prev_block: BlockRecord
    ) -> ExecutionPayloadV2:
        log.debug(f"Get payload for head: height={prev_block.height}, hash={prev_block.execution_block_hash}")
        
        self.ensure_web3_init()
        
        if self.payload_id is None:
            raise RuntimeError("Execution payload not built")
        
        if self.payload_head != prev_block.execution_block_hash:
            raise RuntimeError(f"Payload head ({self.payload_head}) differs from requested ({prev_block.execution_block_hash})")
        
        raw_payload = self.w3.engine.get_payload_v2(self.payload_id).executionPayload
        
        transactions: List[bytes] = []
        for raw_transaction in raw_payload.transactions:
            transactions.append(bytes.from_hexstr(raw_transaction))
        
        withdrawals: List[WithdrawalV1] = []
        for raw_withdrawal in raw_payload.withdrawals:
            withdrawals.append(
                WithdrawalV1(
                    uint64(raw_withdrawal.index),
                    uint64(raw_withdrawal.validatorIndex),
                    bytes20.from_hexstr(raw_withdrawal.address),
                    uint64(raw_withdrawal.amount),
                )
            )
        
        return ExecutionPayloadV2(
            bytes32.from_hexstr(raw_payload.parentHash),
            bytes20.from_hexstr(raw_payload.feeRecipient),
            bytes32.from_hexstr(raw_payload.stateRoot),
            bytes32.from_hexstr(raw_payload.receiptsRoot),
            bytes256.from_hexstr(raw_payload.logsBloom),
            bytes32.from_hexstr(raw_payload.prevRandao),
            uint64(raw_payload.blockNumber),
            uint64(raw_payload.gasLimit),
            uint64(raw_payload.gasUsed),
            uint64(raw_payload.timestamp),
            bytes.from_hexstr(raw_payload.extraData),
            uint256(raw_payload.baseFeePerGas),
            bytes32.from_hexstr(raw_payload.blockHash),
            transactions,
            withdrawals,
        )        
