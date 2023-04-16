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
import json

from bpx.util.path import path_from_root
from bpx.types.full_block import FullBlock
from bpx.types.unfinished_block import UnfinishedBlock
from bpx.consensus.blockchain import Blockchain
from bpx.consensus.block_record import BlockRecord
from bpx.util.errors import Err

log = logging.getLogger(__name__)

COINBASE_NULL = "0x0000000000000000000000000000000000000000"

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
    exe_host: str
    exe_port: int
    jwtsecret_path: pathlib.Path
    w3: Web3
    coinbase: str
    payload_id: str

    def __init__(
        self,
        exe_host: str,
        exe_port: int,
        root_path: pathlib.Path,
        selected_network: str,
    ):
        self.exe_host = exe_host
        self.exe_port = exe_port
        self.secret_path = path_from_root(root_path, "../execution/" + selected_network + "/geth/jwtsecret")
        self.w3 = None
        self.coinbase = COINBASE_NULL
        self.payload_id = None


    def ensure_web3_init(self) -> None:
        if self.w3 is not None:
            return None
        
        log.debug(f"Initializing Web3 connection to {self.exe_host}:{self.exe_port} using JWT secret {self.secret_path}")

        try:
            secret_file = open(self.secret_path, 'r')
            secret = secret_file.readline()
            log.debug(f"JWT secret key: {secret}")
            secret_file.close()
        except Exception as e:
            log.error(f"Exception in Web3 init: {e}")
            raise RuntimeError("Cannot open jwtsecret file. Execution client is not running or needs more time to start")
        
        self.w3 = Web3(
            HTTPAuthProvider(
                secret,
                'http://' + self.exe_host + ':' + str(self.exe_port),
            )
        )

        self.w3.attach_modules({
            "engine": EngineModule
        })

        log.info("Initialized Web3 connection")


    async def exchange_transition_configuration_task(self):
        log.debug("Starting exchangeTransactionConfigurationV1 loop")

        while True:
            try:
                self.ensure_web3_init()
                self.w3.engine.exchange_transition_configuration_v1({
                    "terminalTotalDifficulty": "0x0",
                    "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "terminalBlockNumber": "0x0"
                })
            except Exception as e:
                log.error(f"Exception in exchange transition configuration loop: {e}")
            await asyncio.sleep(60)
    
    
    def set_coinbase(
        self,
        coinbase: str,
    ):
        if not Web3.is_address(coinbase):
            raise ValueError("Invalid coinbase address")
            
        self.coinbase = coinbase
    
    
    async def new_unfinished_block(
        self,
        block: UnfinishedBlock,
        height: uint32,
        blockchain: Blockchain,
    ) -> Optional[Err]:
        log.debug(f"Validating unfinished block of height: {height}")
        
        if head_height == 0:
            return None
        
        self.ensure_web3_init()
            
        payload = json.loads(block.payload)
        if payload.blockHash != block.foliage.foliage_block_data.execution_block_hash:
            return Err.PAYLOAD_HASH_MISMATCH
        
        payload_status = self.w3.engine.new_payload_v2(payload)
        return self.validation_result(payload_status)
    
    
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
    
    
    def validation_result(
        self,
        payload_status
    ) -> Optional[Err]:
        log.debug(f"Payload status: {payload_status.status}")
        if payload_status.validationError is not None:
            log.error(f"Validation error: {payload_status.validationError}")
    
        if payload_status.status == "VALID":
            return None
        if payload_status.status == "INVALID":
            return Err.PAYLOAD_INVALID
        if payload_status.status == "SYNCING":
            raise RuntimeError("Execution client is syncing")
        if payload_status.status == "ACCEPTED":
            return Err.PAYLOAD_SIDECHAIN
        if payload_status.status == "INVALID_BLOCK_HASH":
            return Err.PAYLOAD_INVALID_BLOCK_HASH
        if payload_status.status == "INVALID_TERMINAL_BLOCK":
            return Err.PAYLOAD_INVALID_TERMINAL_BLOCK
        return Err.UNKNOWN
    
    
    def get_payload(
        self,
        prev_block: Optional[BlockRecord]
    ):
        log.debug("Get payload")
        
        self.ensure_web3_init()
        
        if prev_block is None:
            genesis_block = self.w3.eth.get_block(0)
            log.debug(f"Genesis hash is 0x{genesis_block.hash.hex()}")
            return bytes32(genesis_block.hash), None
        
        if self.payload_id is None:
            raise RuntimeError("Get payload called but no payload_id")
        
        payload = self.w3.engine.get_payload_v2(self.payload_id).executionPayload
        return bytes32.from_hexstr(payload.blockHash), Web3.to_json(payload)
