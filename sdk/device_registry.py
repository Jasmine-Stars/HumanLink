from __future__ import annotations

from typing import Optional

from sdk.db.store import SQLiteStore
from sdk.types import isoformat_z, utc_now

# 功能: 设备注册表，管理设备 DID 和用户绑定关系
class DeviceRegistry:
    def __init__(
        self,
        store: SQLiteStore,
        configured_did: Optional[str] = None,
        default_user_id: str = "local-user",
    ):
        self.store = store
        self.configured_did = configured_did
        self.default_user_id = default_user_id

    def get_required_issuer_did(self, user_id: str | None = None) -> str:
        if self.configured_did:
            return self.configured_did
        lookup_user_id = user_id or self.default_user_id
        binding = self.store.get_device_binding(lookup_user_id)
        if binding:
            return binding
        stored = self.store.get_device_did()
        if stored:
            return stored
        raise ValueError("No device DID configured")

    def record_device_did(self, device_did: str, user_id: str | None = None) -> None:
        binding_user_id = user_id or self.default_user_id
        self.store.upsert_device_binding(binding_user_id, device_did, isoformat_z(utc_now()))
        self.store.set_device_did(device_did)

    def get_binding(self, user_id: str | None = None) -> Optional[str]:
        return self.store.get_device_binding(user_id or self.default_user_id)
