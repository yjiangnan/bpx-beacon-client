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
from bpx.types.full_block import FullBlock
from bpx.consensus.blockchain import Blockchain

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
        self.coinbase = "0x0000000000000000000000000000000000000000"
        self.farming = False
        self.payload_id = None

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
    
    async def new_peak(
        self,
        block: FullBlock,
        blockchain: Blockchain,
    ):
        log.debug("Processing new peak")
        
        try:
            self.ensure_web3_init()
            
            # Prepare ForkChoiceStateV1
            
            headBlockHash = "0x" + block.foliage.foliage_block_data.execution_block_hash.hex()
            log.debug(f"Head block hash: {headBlockHash}")
            
            safeBlockHeight = 0
            if block.height > 32:
                safeBlockHeight = (block.height - 32) - (block.height % 32)
                
            safeBlock = await blockchain.get_full_block(blockchain.height_to_hash(safeBlockHeight))
            safeBlockHash = "0x" + safeBlock.foliage.foliage_block_data.execution_block_hash.hex()
            log.debug(f"Safe block hash: {safeBlockHash}")
            
            finalizedBlockHeight = 0
            if block.height > 64:
                finalizedBlockHeight = (block.height - 64) - (block.height % 64)
                
            finalizedBlock = await blockchain.get_full_block(blockchain.height_to_hash(finalizedBlockHeight))
            finalizedBlockHash = "0x" + finalizedBlock.foliage.foliage_block_data.execution_block_hash.hex()
            log.debug(f"Finalized block hash: {finalizedBlockHash}")
            
            forkchoice_state = {
                "headBlockHash": headBlockHash,
                "safeBlockHash": safeBlockHash,
                "finalizedBlockHash": finalizedBlockHash,
            }
            
            # Prepare PayloadAttributesV2
            
            payload_attributes = None
            
            if self.farming:
                payload_attributes = {
                    "timestamp": block.foliage.timestamp,
                    "prevRandao": "",
                    "suggestedFeeRecipient": self.coinbase,
                    "withdrawals": [],
                }
            
            resp = self.w3.engine.forkchoice_updated_v2(forkchoice_state, payload_attributes)
            self.payload_id = resp.payloadId
            
            if self.farming and self.payload_id is None:
                log.error("Farming but no payload id received")
            
        except Exception as e:
            log.error(f"Exception in fork choice update: {e}")
    
    def get_genesis_hash(self):
        log.debug("Get genesis hash")
        
        self.ensure_web3_init()
        
        block = self.w3.eth.get_block(0)
        log.debug(f"Genesis hash is {block.hash}")
        return block.hash
    
    def get_payload(self):
        log.debug("Get payload")
        
        if self.payload_id is None:
            raise RuntimeError("Get payload called but no payload_id")
        
        self.ensure_web3_init()
            
        return self.w3.engine.get_payload_v2(self.payload_id)
