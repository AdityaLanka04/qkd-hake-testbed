from __future__ import annotations

from pydantic import BaseModel, Field


class KeyRequest(BaseModel):
    number: int = Field(default=1, ge=1, le=128)
    size: int = Field(default=256, ge=8)


class KeyID(BaseModel):
    key_ID: str


class KeyIDsRequest(BaseModel):
    key_IDs: list[KeyID] = Field(min_length=1, max_length=128)


class EncodedKey(BaseModel):
    key_ID: str
    key: str


class KeyContainer(BaseModel):
    keys: list[EncodedKey]


class StatusResponse(BaseModel):
    source_KME_ID: str
    target_KME_ID: str
    master_SAE_ID: str
    slave_SAE_ID: str
    key_size: int
    stored_key_count: int
    max_key_count: int
    max_key_per_request: int = 128
    max_key_size: int
    min_key_size: int
    max_SAE_ID_count: int = 0
