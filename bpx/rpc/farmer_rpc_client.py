from __future__ import annotations

from typing import Any, Dict, List, Optional, cast

from bpx.rpc.farmer_rpc_api import PlotInfoRequestData, PlotPathRequestData
from bpx.rpc.rpc_client import RpcClient
from bpx.types.blockchain_format.sized_bytes import bytes32
from bpx.util.misc import dataclass_to_json_dict


class FarmerRpcClient(RpcClient):
    async def get_signage_point(self, sp_hash: bytes32) -> Optional[Dict[str, Any]]:
        try:
            return await self.fetch("get_signage_point", {"sp_hash": sp_hash.hex()})
        except ValueError:
            return None

    async def get_signage_points(self) -> List[Dict[str, Any]]:
        return cast(List[Dict[str, Any]], (await self.fetch("get_signage_points", {}))["signage_points"])

    async def get_harvesters(self) -> Dict[str, Any]:
        return await self.fetch("get_harvesters", {})

    async def get_harvesters_summary(self) -> Dict[str, object]:
        return await self.fetch("get_harvesters_summary", {})

    async def get_harvester_plots_valid(self, request: PlotInfoRequestData) -> Dict[str, Any]:
        return await self.fetch("get_harvester_plots_valid", dataclass_to_json_dict(request))

    async def get_harvester_plots_invalid(self, request: PlotPathRequestData) -> Dict[str, Any]:
        return await self.fetch("get_harvester_plots_invalid", dataclass_to_json_dict(request))

    async def get_harvester_plots_keys_missing(self, request: PlotPathRequestData) -> Dict[str, Any]:
        return await self.fetch("get_harvester_plots_keys_missing", dataclass_to_json_dict(request))

    async def get_harvester_plots_duplicates(self, request: PlotPathRequestData) -> Dict[str, Any]:
        return await self.fetch("get_harvester_plots_duplicates", dataclass_to_json_dict(request))
    
    async def get_public_keys(self) -> List[int]:
        return (await self.fetch("get_public_keys", {}))["public_key_fingerprints"]

    async def get_private_key(self, fingerprint: int) -> Dict:
        return (await self.fetch("get_private_key", {"fingerprint": fingerprint}))["private_key"]

    async def generate_mnemonic(self) -> List[str]:
        return (await self.fetch("generate_mnemonic", {}))["mnemonic"]

    async def add_key(self, mnemonic: List[str], request_type: str = "new_wallet") -> Dict[str, Any]:
        return await self.fetch("add_key", {"mnemonic": mnemonic, "type": request_type})

    async def delete_key(self, fingerprint: int) -> Dict[str, Any]:
        return await self.fetch("delete_key", {"fingerprint": fingerprint})

    async def delete_all_keys(self) -> Dict[str, Any]:
        return await self.fetch("delete_all_keys", {})
