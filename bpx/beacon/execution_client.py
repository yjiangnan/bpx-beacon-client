from __future__ import annotations

import logging
import asyncio
import datetime
import timezone
import pathlib

from typing import (
    Optional,
    Union,
)

from web3.eth_typing import (
    URI,
)

from web3 import Web3, HTTPProvider
from web3.method import Method
import jwt

from bpx.util.path import path_from_root

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
                "Authentication": "Bearer " + encoded_jwt
            }
        )
        return headers

class ExecutionClient:
    exe_host: str
    exe_port: int
    jwtsecret_path: pathlib.Path
    w3: Web3

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

    def ensure_web3_init(self) -> None:
        if self.w3 is not None:
            return None
        
        secret_file = open(self.secret_path, 'r')
        secret = secret_file.readline()
        secret_file.close()
        
        self.w3 = Web3(
            HTTPAuthProvider(
                secret,
                'http://' + self.exe_host + ':' + str(self.exe_port),
            )
        )

        self.w3.eth.attach_methods({
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
