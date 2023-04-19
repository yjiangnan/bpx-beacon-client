from __future__ import annotations

import logging
import asyncio
import pathlib
import time

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
from bpx.util.byte_types import hexstr_to_bytes

COINBASE_NULL = bytes20.fromhex("0000000000000000000000000000000000000000")

log = logging.getLogger(__name__)

class HTTPAuthProvider(HTTPProvider):
    secret: bytes

    def __init__(
        self,
        secret: bytes,
        endpoint_uri: Optional[Union[URI, str]] = None,
    ) -> None:
        self.secret = secret
        super().__init__(endpoint_uri)
    
    def get_request_headers(self) -> Dict[str, str]:
        headers = super().get_request_headers()
        
        encoded_jwt = jwt.encode(
            {
                "iat": int(time.time())
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
        
        ec_config = self.beacon.config.get("execution_client")
        selected_network = self.beacon.config.get("selected_network")
        secret_path = path_from_root(
            self.beacon.root_path,
            "../execution/" + selected_network + "/geth/jwtsecret"
        )
        
        log.debug(f"Initializing execution client connection: {ec_config['host']}:{ec_config['port']} using JWT secret {secret_path}")

        try:
            secret_file = open(secret_path, 'r')
            secret = secret_file.readline()
            secret_file.close()
        except Exception as e:
            log.error(f"Exception in Web3 init: {e}")
            raise RuntimeError("Cannot open JWT secret file. Execution client is not running or needs more time to start")
        
        self.w3 = Web3(
            HTTPAuthProvider(
                hexstr_to_bytes(secret),
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
    
    
    async def forkchoice_update(
        self,
        block: FullBlock,
        blockchain: Blockchain,
        peak: Optional[BlockRecord],
    ) -> str:
        log.debug(f"Fork choice update")
        
        self.ensure_web3_init()
        
        # Prepare ForkchoiceStateV1
            
        head_height = block.height
        head_hash = block.foliage.foliage_block_data.execution_block_hash
        log.debug(f"Head height: {head_height}, hash: {head_hash}")
            
        if head_height == 0:
            safe_height = 0
            safe_hash = head_hash
        else:
            if head_height > 6:
                safe_height = (head_height - 6) - (head_height % 6)
            else:
                safe_height = 0
            safe_hash = blockchain.height_to_block_record(safe_height).execution_block_hash
        log.debug(f"Safe height: {safe_height}, hash: {safe_hash}")
        
        if head_height == 0:
            final_height = 0
            final_hash = head_hash
        else:
            if head_height > 32:
                final_height = (head_height - 32) - (head_height % 32)
            else:
                final_height = 0
            final_hash = blockchain.height_to_block_record(final_height).execution_block_hash
        log.debug(f"Finalized height: {final_height}, hash: {final_hash}")
        
        forkchoice_state = {
            "headBlockHash": "0x" + head_hash.hex(),
            "safeBlockHash": "0x" + safe_hash.hex(),
            "finalizedBlockHash": "0x" + final_hash.hex(),
        }
            
        # Prepare PayloadAttributesV2
        
        payload_attributes = None
        
        if (
            peak is None
            or peak.height == head_height
        ):
            coinbase = self.beacon.config.get("coinbase")
            if coinbase == COINBASE_NULL:
                log.error("Coinbase not set! FARMING NOT POSSIBLE!")
            elif not Web3.is_address(coinbase):
                log.error("Coinbase address invalid! FARMING NOT POSSIBLE!")
            else:
                payload_attributes = self._create_payload_attributes(block, coinbase)
        else:
            log.debug("Beacon node not synced, no payload expected")
        
        result = self.w3.engine.forkchoice_updated_v2(forkchoice_state, payload_attributes)
        
        if result.payloadId is not None:
            self.payload_head = head_hash
            self.payload_id = result.payloadId
            log.debug(f"Started building payload for head: height={head_height}, hash={self.payload_head}, id={self.payload_id}")
        else:
            self.payload_head = None
            self.payload_id = None
            if payload_attributes is not None:
                log.error("Payload expected but building not started, head height={head_height}, hash={self.payload_head} ({result.payloadStatus.validationError})")
        
        return result.payloadStatus.status
    
    
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
            transactions.append(hexstr_to_bytes(raw_transaction))
        
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
            hexstr_to_bytes(raw_payload.extraData),
            uint256(raw_payload.baseFeePerGas),
            bytes32.from_hexstr(raw_payload.blockHash),
            transactions,
            withdrawals,
        )
    
    
    async def new_payload(
        self,
        payload: ExecutionPayloadV2,
    ) -> str:
        log.debug(f"New payload: height={payload.blockNumber}, hash={payload.blockHash}")
        
        self.ensure_web3_init()
        
        result = self.w3.engine.new_payload_v2(payload)
        if result.validationError is not None:
            log.error(f"New payload validation error: {result.validationError}")
        return result.status
    
    
    def _create_payload_attributes(
        self,
        prev_block: FullBlock,
        coinbase: bytes20,
    ):
        return {
            "timestamp": Web3.to_hex(int(time.time())),
            "prevRandao": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "suggestedFeeRecipient": "0x" + coinbase.hex(),
            "withdrawals": [],
        }