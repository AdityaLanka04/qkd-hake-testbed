from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException, Query

from qkd_hake.qkd_mock.models import (
    KeyContainer,
    KeyIDsRequest,
    KeyRequest,
    StatusResponse,
)
from qkd_hake.qkd_mock.pool import (
    PeerQuotaExceeded,
    PoolExhausted,
    QKDKeyPool,
    UnknownKeyID,
)
from qkd_hake.settings import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings.from_env()
    pool = QKDKeyPool(
        refill_bps=cfg.refill_bps,
        depth=cfg.pool_depth,
        initial_keys=cfg.initial_keys,
        key_size_bits=cfg.key_size_bits,
        per_peer_quota=cfg.per_peer_quota,
    )
    app = FastAPI(title="ETSI GS QKD 014 Mock KME", version="0.1.0")
    app.state.pool = pool

    def caller(x_sae_id: str | None) -> str:
        if not x_sae_id:
            raise HTTPException(401, detail={"message": "X-SAE-ID is required"})
        return x_sae_id

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/v1/keys/{slave_sae_id}/status", response_model=StatusResponse)
    def get_status(
        slave_sae_id: str,
        x_sae_id: str | None = Header(default=None, alias="X-SAE-ID"),
    ) -> StatusResponse:
        master = caller(x_sae_id)
        status = pool.status()
        return StatusResponse(
            source_KME_ID="mock-kme-a",
            target_KME_ID="mock-kme-b",
            master_SAE_ID=master,
            slave_SAE_ID=slave_sae_id,
            key_size=cfg.key_size_bits,
            stored_key_count=status["stored_key_count"],
            max_key_count=cfg.pool_depth,
            max_key_size=cfg.key_size_bits,
            min_key_size=cfg.key_size_bits,
        )

    def issue(master: str, slave: str, request: KeyRequest) -> KeyContainer:
        if request.size != cfg.key_size_bits:
            raise HTTPException(400, detail={"message": "unsupported key size"})
        try:
            keys = pool.issue(master, slave, request.number)
        except (PoolExhausted, PeerQuotaExceeded) as exc:
            raise HTTPException(503, detail={"message": str(exc)}) from exc
        return KeyContainer(keys=[item.as_json() for item in keys])

    @app.post("/api/v1/keys/{slave_sae_id}/enc_keys", response_model=KeyContainer)
    def get_key(
        slave_sae_id: str,
        request: KeyRequest,
        x_sae_id: str | None = Header(default=None, alias="X-SAE-ID"),
    ) -> KeyContainer:
        return issue(caller(x_sae_id), slave_sae_id, request)

    @app.get("/api/v1/keys/{slave_sae_id}/enc_keys", response_model=KeyContainer)
    def get_one_key(
        slave_sae_id: str,
        size: int = Query(default=256),
        x_sae_id: str | None = Header(default=None, alias="X-SAE-ID"),
    ) -> KeyContainer:
        return issue(caller(x_sae_id), slave_sae_id, KeyRequest(number=1, size=size))

    def retrieve(master: str, slave: str, key_ids: list[str]) -> KeyContainer:
        try:
            keys = pool.retrieve(master, slave, key_ids)
        except UnknownKeyID as exc:
            raise HTTPException(
                400,
                detail={"message": "one or more keys specified are not found on KME"},
            ) from exc
        return KeyContainer(keys=[item.as_json() for item in keys])

    @app.post("/api/v1/keys/{master_sae_id}/dec_keys", response_model=KeyContainer)
    def get_keys_with_ids(
        master_sae_id: str,
        request: KeyIDsRequest,
        x_sae_id: str | None = Header(default=None, alias="X-SAE-ID"),
    ) -> KeyContainer:
        slave = caller(x_sae_id)
        return retrieve(master_sae_id, slave, [item.key_ID for item in request.key_IDs])

    @app.get("/api/v1/keys/{master_sae_id}/dec_keys", response_model=KeyContainer)
    def get_key_with_id(
        master_sae_id: str,
        key_ID: str,
        x_sae_id: str | None = Header(default=None, alias="X-SAE-ID"),
    ) -> KeyContainer:
        return retrieve(master_sae_id, caller(x_sae_id), [key_ID])

    return app


app = create_app()
