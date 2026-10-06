from __future__ import annotations

import hashlib
import socket
from typing import Any, Callable

from qkd_hake.mitigations.mitigations import MitigationManager
from qkd_hake.protocol.hake import AliceSession, BobSession, HandshakeResult
from qkd_hake.qkd_mock.client import QKDClient
from qkd_hake.transfer.identity import Identity
from qkd_hake.transfer.wire import TransferError, b64, unb64, send_frame, receive_frame, require_type


def mode_label(mode: str) -> str:
    if mode == 'HYBRID_QKD':
        return mode
    if mode == 'SECURITY_LEVEL_DEGRADED_PQC_ONLY':
        return 'PQC_ONLY'
    raise TransferError('unknown_security_mode')


def client_handshake(sock: socket.socket, identity: Identity, kme: QKDClient,
                     manager: MitigationManager, fallback: bool,
                     on_start: Callable[[str], None] | None = None) -> tuple[HandshakeResult, str]:
    alice = AliceSession('alice', identity.public_key, identity.secret_key, 'bob',
                         identity.peer_public_key, identity.algorithm, mitigation_mgr=manager)
    m1 = alice.message1()
    if on_start:
        on_start(hashlib.sha256(m1[1]).hexdigest()[:16])
    send_frame(sock, {'type': 'm1', 'algorithm': identity.algorithm, 'version': 1,
                      'ct1': b64(m1[0]), 'nonce_a': b64(m1[1])})
    reply = receive_frame(sock)
    require_type(reply, 'm2')
    def delivery(action: str) -> Any:
        return kme.get_status() if action == 'status' else kme.get_key()
    m3 = alice.message3(tuple(unb64(reply[name]) for name in ('pk_e', 'tau1', 'ct2', 'nonce_b')),
                        delivery, allow_explicit_fallback=fallback)
    send_frame(sock, {'type': 'm3', 'ct_star': b64(m3[0]), 'qkd_id': m3[1], 'tau2': b64(m3[2])})
    reply = receive_frame(sock)
    require_type(reply, 'm4')
    result = alice.derive_and_verify(unb64(reply['tau3']))
    if not fallback and mode_label(result.security_mode) != 'HYBRID_QKD':
        raise TransferError('hybrid_policy_violation')
    return result, alice.decision_reason


def server_handshake(sock: socket.socket, identity: Identity, kme: QKDClient) -> HandshakeResult:
    request = receive_frame(sock)
    require_type(request, 'm1')
    if request.get('version') != 1 or request.get('algorithm') != identity.algorithm:
        raise TransferError('protocol_or_algorithm_mismatch')
    bob = BobSession('alice', identity.peer_public_key, 'bob', identity.public_key,
                     identity.secret_key, identity.algorithm)
    m2 = bob.message2((unb64(request['ct1']), unb64(request['nonce_a'])))
    send_frame(sock, {'type': 'm2', **dict(zip(('pk_e', 'tau1', 'ct2', 'nonce_b'), map(b64, m2)))})
    request = receive_frame(sock)
    require_type(request, 'm3')
    if not isinstance(request.get('qkd_id'), str) or len(request['qkd_id']) > 128:
        raise TransferError('invalid_qkd_id')
    m4, result = bob.message4((unb64(request['ct_star']), request['qkd_id'], unb64(request['tau2'])),
                             kme.retrieve_key)
    send_frame(sock, {'type': 'm4', 'tau3': b64(m4)})
    return result
