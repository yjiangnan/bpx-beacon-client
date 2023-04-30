from __future__ import annotations

import logging
import asyncio
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
from hexbytes import HexBytes

from bpx.util.path import path_from_root
from bpx.consensus.block_record import BlockRecord
from bpx.types.blockchain_format.sized_bytes import bytes20, bytes32, bytes256
from bpx.util.ints import uint64, uint256
from bpx.types.blockchain_format.execution_payload import ExecutionPayloadV2, WithdrawalV1
from bpx.util.byte_types import hexstr_to_bytes
from bpx.consensus.block_rewards import calculate_v3_reward, calculate_v3_prefarm

COINBASE_NULL = "0x0000000000000000000000000000000000000000"
BLOCK_HASH_NULL = bytes32.fromhex("0000000000000000000000000000000000000000000000000000000000000000")

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
    replay_lock: asyncio.Lock

    def __init__(
        self,
        beacon,
    ):
        self.beacon = beacon
        self.w3 = None
        self.payload_id = None
        self.payload_head = None
        self.replay_lock = asyncio.Lock()


    def ensure_web3_init(self) -> None:
        if self.w3 is not None:
            return None
        
        ec_config = self.beacon.config.get("execution_client")
        selected_network = self.beacon.config.get("selected_network")
        if selected_network == "mainnet":
            secret_path = path_from_root(
                self.beacon.root_path,
                "../execution/geth/jwtsecret"
            )
        else:
            secret_path = path_from_root(
                self.beacon.root_path,
                "../execution/" + selected_network + "/geth/jwtsecret"
            )
        
        log.info(f"Initializing execution client connection: {ec_config['host']}:{ec_config['port']} using JWT secret {secret_path}")

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
        log.info("Starting exchange transition configuration loop")

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
        synced: bool,
        after_replay: bool = False,
    ) -> None:
        log.info("Fork choice update")
        
        self.payload_head = None
        self.payload_id = None
        
        try:
            self.ensure_web3_init()
            
            head_hash = block.foliage.foliage_block_data.execution_block_hash
            log.info(f" |- New head height: {block.height}, hash: {head_hash}")
            
            safe_hash = head_hash
            log.info(f" |- New safe height: {block.height}, hash: {safe_hash}")
            
            if block.height > 32:
                final_height = (block.height - 32) - (block.height % 32)
                final_hash = self.beacon.blockchain.height_to_block_record(final_height).execution_block_hash
            else:
                final_height = None
                final_hash = BLOCK_HASH_NULL
            log.info(f" |- New final height: {final_height}, hash: {final_hash}")
            
            forkchoice_state = {
                "headBlockHash": "0x" + head_hash.hex(),
                "safeBlockHash": "0x" + safe_hash.hex(),
                "finalizedBlockHash": "0x" + final_hash.hex(),
            }
            payload_attributes = None
            
            if synced:
                coinbase = self.beacon.config.get("coinbase")
                if coinbase == COINBASE_NULL:
                    log.error("Coinbase not set! FARMING NOT POSSIBLE!")
                elif not Web3.is_address(coinbase):
                    log.error("Coinbase address invalid! FARMING NOT POSSIBLE!")
                else:
                    payload_attributes = self._create_payload_attributes(block, coinbase)
            
            result = self.w3.engine.forkchoice_updated_v2(forkchoice_state, payload_attributes)
            
            if result.payloadStatus.status == "ACCEPTED":
                log.warning("Execution chain reorg!")
            elif result.payloadStatus.status != "VALID":
                if result.payloadStatus.status == "SYNCING" and not after_replay:
                    log.info(f"Trying to start replay sync")
                    log.error(f"Lvh: {result.payloadStatus.latestValidHash}")
                    asyncio.create_task(
                        self.replay_sync(
                            result.payloadStatus.latestValidHash,
                            block,
                            synced,
                        )
                    )
                raise RuntimeError(f"Payload status {result.payloadStatus.status}: {result.payloadStatus.validationError}")
            
            if result.payloadId is not None:
                self.payload_head = head_hash
                self.payload_id = result.payloadId
        except Exception as e:
            log.error(f"Exception in fork choice update: {e}")
        
        if self.payload_id is not None:
            log.info(f"Payload building started, id: {self.payload_id}")
        else:
            log.error(f"Payload building not started")
    
    
    def get_payload(
        self,
        prev_block: BlockRecord
    ) -> ExecutionPayloadV2:
        log.info(f"Get payload for head: height={prev_block.height}, hash={prev_block.execution_block_hash}")
        
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
                    uint64(Web3.to_int(HexBytes(raw_withdrawal.index))),
                    uint64(Web3.to_int(HexBytes(raw_withdrawal.validatorIndex))),
                    bytes20.from_hexstr(raw_withdrawal.address),
                    uint64(Web3.to_int(HexBytes(raw_withdrawal.amount))),
                )
            )
        
        return ExecutionPayloadV2(
            bytes32.from_hexstr(raw_payload.parentHash),
            bytes20.from_hexstr(raw_payload.feeRecipient),
            bytes32.from_hexstr(raw_payload.stateRoot),
            bytes32.from_hexstr(raw_payload.receiptsRoot),
            bytes256.from_hexstr(raw_payload.logsBloom),
            bytes32.from_hexstr(raw_payload.prevRandao),
            uint64(Web3.to_int(HexBytes(raw_payload.blockNumber))),
            uint64(Web3.to_int(HexBytes(raw_payload.gasLimit))),
            uint64(Web3.to_int(HexBytes(raw_payload.gasUsed))),
            uint64(Web3.to_int(HexBytes(raw_payload.timestamp))),
            hexstr_to_bytes(raw_payload.extraData),
            uint256(Web3.to_int(HexBytes(raw_payload.baseFeePerGas))),
            bytes32.from_hexstr(raw_payload.blockHash),
            transactions,
            withdrawals,
        )
    
    
    async def new_payload(
        self,
        payload: ExecutionPayloadV2,
    ) -> str:
        log.info(f"New payload: height={payload.blockNumber}, hash={payload.blockHash}")
        
        self.ensure_web3_init()
        
        raw_transactions = []
        for transaction in payload.transactions:
            raw_transactions.append("0x" + transaction.hex())
        
        raw_withdrawals = []
        for withdrawal in payload.withdrawals:
            raw_withdrawals.append({
                "index": Web3.to_hex(withdrawal.index),
                "validatorIndex": Web3.to_hex(withdrawal.validatorIndex),
                "address": "0x" + withdrawal.address.hex(),
                "amount": Web3.to_hex(withdrawal.amount),
            })
        
        raw_payload = {
            "parentHash": "0x" + payload.parentHash.hex(),
            "feeRecipient": "0x" + payload.feeRecipient.hex(),
            "stateRoot": "0x" + payload.stateRoot.hex(),
            "receiptsRoot": "0x" + payload.receiptsRoot.hex(),
            "logsBloom": "0x" + payload.logsBloom.hex(),
            "prevRandao": "0x" + payload.prevRandao.hex(),
            "blockNumber": Web3.to_hex(payload.blockNumber),
            "gasLimit": Web3.to_hex(payload.gasLimit),
            "gasUsed": Web3.to_hex(payload.gasUsed),
            "timestamp": Web3.to_hex(payload.timestamp),
            "extraData": "0x" + payload.extraData.hex(),
            "baseFeePerGas": Web3.to_hex(payload.baseFeePerGas),
            "blockHash": "0x" + payload.blockHash.hex(),
            "transactions": raw_transactions,
            "withdrawals": raw_withdrawals,
        }
        
        result = self.w3.engine.new_payload_v2(raw_payload)
        if result.validationError is not None:
            log.error(f"New payload validation error: {result.validationError}")
        return result.status
    
    
    async def replay_sync(
        self,
        header_hash: bytes32,
    ) -> None:
        async with self.replay_lock:
            log.info(f"Starting replay sync to block {header_hash}")
            
            self.ensure_web3_init()
            
            while True:
                block = self.beacon.blockchain.get_full_block(header_hash)
                log.info(f"Replaying block: height={blok.height}, hash={header_hash}, execution hash={block.foliage.foliage_block_data.execution_block_hash}")
                
                status = await self.new_payload(block.execution_payload)
                if status == "SYNCING":
                    header_hash = block.header_hash
                    continue
                elif status == "VALID":
                    log.info(f"Replay sync complete at height {block.height}")
                    break
                else:
                    raise RuntimeError(f"Status {status} during replay block {i}")
    
    
    def _create_payload_attributes(
        self,
        prev_block: FullBlock,
        coinbase: str,
    ) -> Dict[str, Any]:
        withdrawals = []
        height = prev_block.height + 1
        
        if height == 1:
            prefarm_amount = calculate_v3_prefarm(
                self.beacon.constants.V3_PREFARM_AMOUNT,
                self.beacon.constants.V2_EOL_HEIGHT,
            )
            
            if prefarm_amount > 0:
                reward_withdrawal_index = 1
                
                withdrawals.append({
                    "index": "0x0",
                    "validatorIndex": "0x0",
                    "address": "0x" + self.beacon.constants.PREFARM_ADDRESS.hex(),
                    "amount": Web3.to_hex(prefarm_amount)
                })
            else:
                reward_withdrawal_index = 0
        else:
            reward_withdrawal_index = prev_block.execution_payload.withdrawals[-1].index + 1
        
        reward_amount = calculate_v3_reward(
            height,
            self.beacon.constants.V2_EOL_HEIGHT,
        )
        
        withdrawals.append({
            "index": Web3.to_hex(reward_withdrawal_index),
            "validatorIndex": "0x1",
            "address": coinbase,
            "amount": Web3.to_hex(reward_amount)
        })
        
        return {
            "timestamp": Web3.to_hex(int(time.time())),
            "prevRandao": "0x" + prev_block.reward_chain_block.get_hash().hex(),
            "suggestedFeeRecipient": coinbase,
            "withdrawals": withdrawals,
        }