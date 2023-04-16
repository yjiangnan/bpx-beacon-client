from __future__ import annotations

import logging
import asyncio
from datetime import datetime, timezone
import pathlib

from typing import (
    Optional,
    Union,
    Dict,
    Any
)

from web3 import Web3, HTTPProvider
from web3.method import Method
from web3.module import Module
from web3.providers.rpc import URI
import jwt

from bpx.util.path import path_from_root
from bpx.types.unfinished_block import UnfinishedBlock
from bpx.consensus.blockchain import Blockchain
from bpx.beacon.beacon_store import BeaconStore
from bpx.types.blockchain_format.sized_bytes import bytes32

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
    exe_host: str
    exe_port: int
    jwtsecret_path: pathlib.Path
    w3: Web3
    coinbase: str
    farming: bool
    payload_ids: Dict[bytes32, str]

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
        self.coinbase = "0x0000000000000000000000000000000000000000"
        self.farming = False
        self.payload_ids = {}

    def ensure_web3_init(self) -> None:
        if self.w3 is not None:
            return None
        
        log.debug(f"Trying connect to execution client at {self.exe_host}:{self.exe_port} using JWT secret {self.secret_path}")

        try:
            secret_file = open(self.secret_path, 'r')
            secret = secret_file.readline()
            log.debug(f"JWT secret key: {secret}")
            secret_file.close()
        except Exception as e:
            log.error(f"Exception in Web3 init: {e}")
            raise RuntimeError("Cannot open jwtsecret file. Execution client is not running or needs more time to run")
        
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
        
        if coinbase == "0x0000000000000000000000000000000000000000":
            self.farming = False
        else:
            self.farming = True
    
    async def forkchoice_update(
        self,
        blockchain: Blockchain,
        beacon_store: BeaconStore,
    ):
        log.debug("Processing new peak")
        
        try:
            self.ensure_web3_init()
            
            # Prepare ForkChoiceStateV1
            
            safe_block = await blockchain.get_full_peak()
            safe_height = safe_block.height
            safe_exe_hash = "0x" + safe_block.foliage.foliage_block_data.execution_block_hash.hex()
            log.debug(f"Got safe block with height = {safe_height}, execution hash = {safe_exe_hash}")
            
            
            fin_height = 0
            if safe_height > 64:
                fin_height = (safe_height - 64) - (safe_height % 64)
                
            fin_block = await blockchain.get_full_block(blockchain.height_to_hash(fin_height))
            fin_exe_hash = "0x" + fin_block.foliage.foliage_block_data.execution_block_hash.hex()
            log.debug(f"Got finalized block with height = {fin_height}, execution hash = {fin_exe_hash}")
            
            
            head_height = -1
            head_blocks = []
            
            if self.farming:
                unf_blocks = beacon_store.get_unfinished_blocks()
                for _, (unf_height, _, _) in unf_blocks.items():
                    if unf_height > head_height:
                        head_height = unf_height
                for _, (unf_height, unf_block, _) in unf_blocks.items():
                    if unf_height == head_height:
                        head_blocks.append(unf_block)
                log.debug(f"Got {len(head_blocks)} head blocks with height = {head_height}")
            else:
                log.debug("Not farming, ignoring unfinished blocks")
            
            forkchoice_states: Dict[bytes32, Any] = {}
            
            if head_height == -1:
                forkchoice_states[safe_block.header_hash] = {
                    "headBlockHash": safe_exe_hash,
                    "safeBlockHash": safe_exe_hash,
                    "finalizedBlockHash": fin_exe_hash,
                }
            else:
                for head_block in head_blocks:
                    forkchoice_states[head_block.header_hash] = {
                        "headBlockHash": "0x" + head_block.foliage.foliage_block_data.execution_block_hash.hex(),
                        "safeBlockHash": safe_exe_hash,
                        "finalizedBlockHash": fin_exe_hash,
                    }
            
            # Prepare PayloadAttributesV2
            
            payload_attributes = None
            
            if self.farming:
                payload_attributes = {
                    "timestamp": Web3.to_hex(block.foliage.foliage_block_data.timestamp),
                    "prevRandao": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "suggestedFeeRecipient": self.coinbase,
                    "withdrawals": [],
                }
            
            # Call ForkchoiceUpdatedV2
            
            for beacon_hash in forkchoice_states:
                resp = self.w3.engine.forkchoice_updated_v2(forkchoice_state[beacon_hash], payload_attributes)
            
                if self.farming and resp.payloadId is None:
                    log.error("Farming but no payload id received")
                else:
                    self.payload_ids[beacon_hash] = resp.payloadId
            
        except Exception as e:
            log.error(f"Exception in fork choice update: {e}")
    
    def get_genesis_hash(self):
        log.debug("Get genesis hash")
        
        self.ensure_web3_init()
        
        block = self.w3.eth.get_block(0)
        log.debug(f"Genesis hash is 0x{block.hash.hex()}")
        return block.hash
    
    def get_payload(
        self,
        beacon_hash: bytes32
    ):
        log.debug(f"Get payload for beacon head hash {head_hash.hex()}")
        
        if beacon_hash not in self.payload_ids:
            raise RuntimeError("No payload ID for specified beacon head hash")
        
        self.ensure_web3_init()
            
        resp = self.w3.engine.get_payload_v2(self.payload_ids[beacon_hash])
        return resp.executionPayload.blockHash, Web3.to_json(resp.executionPayload)
