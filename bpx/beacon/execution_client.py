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
from bpx.consensus.block_rewards import create_withdrawals

COINBASE_NULL = bytes20.fromhex("0000000000000000000000000000000000000000")
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
    peak_txb_hash: Optional[bytes32]
    payload_id: Optional[str]
    sync_lock: asyncio.Lock

    def __init__(
        self,
        beacon,
    ):
        self.beacon = beacon
        self.w3 = None
        self.peak_txb_hash = None
        self.payload_id = None
        self.sync_lock = asyncio.Lock()
    
    
    async def exchange_transition_configuration_task(self):
        log.info("Starting exchange transition configuration loop")

        while True:
            try:
                self._ensure_web3_init()
                self.w3.engine.exchange_transition_configuration_v1({
                    "terminalTotalDifficulty": "0x0",
                    "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "terminalBlockNumber": "0x0"
                })
            except Exception as e:
                log.error(f"Exception in exchange transition configuration: {e}")
            await asyncio.sleep(60)
    
    
    async def new_peak(
        self,
        block: BlockRecord,
        synced: bool,
    ) -> Optional[str]:
        curr: BlockRecord = block
        while not curr.is_transaction_block:
            curr = self.beacon.blockchain.block_record(curr.prev_hash)
        
        if curr.header_hash == self.peak_txb_hash:
            return None
                
        async with self.sync_lock:
            status = await self._forkchoice_update(curr, synced)
            if status != "SYNCING":
                return status
            await self._replay_sync(curr.execution_block_hash)
            return await self._forkchoice_update(curr, synced)
    
    
    async def new_payload(
        self,
        payload: ExecutionPayloadV2,
    ) -> str:
        async with self.sync_lock:
            status = await self._new_payload(payload)
            if status != "SYNCING":
                return status
            await self._replay_sync(payload.prevHash)
            return await self._new_payload(payload)
    
    
    def get_payload(
        self,
        prev_block: BlockRecord
    ) -> ExecutionPayloadV2:
        log.info(f"Get payload for: height={prev_block.height}, hash={prev_block.header_hash}")
        
        self._ensure_web3_init()
        
        if self.peak_txb_hash != prev_block.header_hash:
            raise RuntimeError(f"Payload build on ({self.peak_txb_hash}) but requested ({prev_block.header_hash})")
        
        if self.payload_id is None:
            raise RuntimeError("Execution payload not built")
        
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


    def _ensure_web3_init(self) -> None:
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
    
    
    async def _forkchoice_update(
        self,
        block: BlockRecord,
        synced: bool,
    ) -> None:
        log.info("Fork choice update")
        
        self.payload_id = None
        
        self._ensure_web3_init()
        
        head_hash = block.execution_block_hash
        log.info(f" |- New head height: {block.height}, hash: {head_hash}")
        
        safe_hash = head_hash
        log.info(f" |- New safe height: {block.height}, hash: {safe_hash}")
        
        final_height: Optional[uint64]
        final_hash: bytes32
        sub_slots = 0
        curr = block
        while True:
            if curr.first_in_sub_slot:
                sub_slots += 1
            
            final_height = curr.height
            final_hash = curr.execution_block_hash
            
            if sub_slots == 2:
                break
            
            if curr.prev_transaction_block_hash == self.beacon.constants.GENESIS_CHALLENGE:
                final_height = None
                final_hash = BLOCK_HASH_NULL
                break
            
            curr = self.beacon.blockchain.block_record(curr.prev_transaction_block_hash)
        log.info(f" |- New final height: {final_height}, hash: {final_hash}")
        
        forkchoice_state = {
            "headBlockHash": "0x" + head_hash.hex(),
            "safeBlockHash": "0x" + safe_hash.hex(),
            "finalizedBlockHash": "0x" + final_hash.hex(),
        }
        payload_attributes = None
        
        if synced:
            coinbase = self.beacon.config["coinbase"]
            if bytes20.from_hexstr(coinbase) == COINBASE_NULL:
                log.warning("Coinbase not set! Farming not possible!")
            else:
                payload_attributes = self._create_payload_attributes(block, coinbase)
        
        result = self.w3.engine.forkchoice_updated_v2(forkchoice_state, payload_attributes)
        
        self.peak_txb_hash = block.header_hash
        
        if result.payloadStatus.validationError is not None:
            log.error(f"Fork choice update status: {result.payloadStatus.status}, "
                       "validation error: {result.payloadStatus.validationError}")
        else:
            log.info(f"Fork choice update status: {result.payloadStatus.status}")
        
        if result.payloadId is not None:
            self.payload_id = result.payloadId
            log.info(f"Payload building started, id: {self.payload_id}")
        else:
            log.warning(f"Payload building not started")
        
        return result.payloadStatus.status
    
    
    async def _new_payload(
        self,
        payload: ExecutionPayloadV2,
    ) -> str:
        log.info(f"New payload: height={payload.blockNumber}, hash={payload.blockHash}")
        
        self._ensure_web3_init()
        
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
            log.error(f"New payload status: {result.status}, validation error: {result.validationError}")
        else:
            log.info(f"New payload status: {result.status}")
        
        return result.status
    
    
    async def _replay_sync(
        self,
        to_hash: bytes32,
    ) -> None:
        log.info(f"Starting replay sync to hash {to_hash}")
        
        latest_hash = bytes32(self.w3.eth.get_block('latest')['hash'])
        log.info(f"Latest known hash is {latest_hash}")
        
        curr = self.beacon.blockchain.get_peak()
        assert curr is not None
        while not curr.is_transaction_block:
            curr = self.beacon.blockchain.block_record(curr.prev_hash)
        prev: Optional[BlockRecord] = None
        while curr.execution_block_hash != latest_hash:
            prev = curr
            curr = self.beacon.blockchain.block_record(curr.prev_transaction_block_hash)
        assert prev is not None
        
        record = prev
        h = record.height
        log.info(f"Replay sync from height = {h}, hash = {record.execution_block_hash}") 
        
        while True:
            if record.is_transaction_block:
                log.info(f"Replaying block: height={record.height}, hash={record.execution_block_hash}")
                
                block = await self.beacon.blockchain.get_full_block(record.header_hash)
                status = await self._new_payload(block.execution_payload)
                if status != "VALID":
                    raise RuntimeError(f"Status {status} during replay block {record.height}")
                
                if record.execution_block_hash == to_hash:
                    break
            
            h += 1
            record = self.beacon.blockchain.height_to_block_record(h)
        
        log.info("Replay sync completed")
    
    
    def _create_payload_attributes(
        self,
        prev_tx_block: BlockRecord,
        coinbase: str,
    ) -> Dict[str, Any]:
        withdrawals = create_withdrawals(
            self.beacon.constants,
            prev_tx_block,
            self.beacon.blockchain,
        )
        raw_withdrawals = []
        
        for wd in withdrawals:
            raw_withdrawals.append({
                "index": Web3.to_hex(wd.index),
                "validatorIndex": Web3.to_hex(wd.validatorIndex),
                "address": "0x" + wd.address.hex(),
                "amount": Web3.to_hex(wd.amount)
            })
        
        return {
            "timestamp": Web3.to_hex(int(time.time())),
            "prevRandao": "0x" + prev_tx_block.reward_infusion_new_challenge.hex(),
            "suggestedFeeRecipient": coinbase,
            "withdrawals": raw_withdrawals,
        }