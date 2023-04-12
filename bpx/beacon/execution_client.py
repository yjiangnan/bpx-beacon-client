from __future__ import annotations

import logging
import asyncio

from web3 import Web3, HTTPProvider

log = logging.getLogger(__name__)

class ExecutionClient:
    exe_host: str
    exe_port: int
    w3: Web3

    def __init__(
        self,
        exe_host: str,
        exe_port: int,
    ):
        self.exe_host = exe_host
        self.exe_port = exe_port
        self.w3 = None

    def ensure_web3_init(
        self,
        exe_host: str,
        exe_port: str,
    ) -> None:
        if self.w3 is not None:
            return None
            
        self.w3 = Web3(HTTPProvider('http://' + self.exe_host + ':' + str(self.exe_port)))

        w3.eth.attach_methods({
            "exchangeTransitionConfigurationV1": Method("engine_exchangeTransitionConfigurationV1"),
            "forkchoiceUpdatedV2": Method("engine_forkchoiceUpdatedV2"),
            "getPayloadV2": Method("engine_getPayloadV2"),
            "newPayloadV2": Method("engine_newPayloadV2")
        })

        if not self.w3.is_connected():
            raise RuntimeError("Cannot connect to execution client")

        log.info("Connected to execution client")

    async def exchange_transition_configuration_task(self):
        log.info("Starting exchangeTransactionConfigurationV1 loop")

        while True:
            self.ensure_web3_init()
            self.w3.eth.exchangeTransitionConfigurationV1({
                "terminalTotalDifficulty": 0,
                "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "terminalBlockNumber": "0x0"
            })
            await asyncio.sleep(60)
