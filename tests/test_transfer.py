from __future__ import annotations

import hashlib
import json
from pathlib import Path
import socket
import threading
import time
import uuid

import pytest
import uvicorn

from qkd_hake.crypto.kem import SUPPORTED_ALGORITHMS
from qkd_hake.protocol.hake import HandshakeResult
from qkd_hake.qkd_mock.server import create_app
from qkd_hake.settings import Settings
from qkd_hake.transfer.audit import Audit
from qkd_hake.transfer.channel import SecureChannel
from qkd_hake.transfer.identity import Identity, provision
from qkd_hake.transfer.queue import FileQueue
from qkd_hake.transfer.receiver import Receiver
from qkd_hake.transfer.sender import Sender, pool_status
from qkd_hake.transfer.storage import publish_file, validate_offer
from qkd_hake.transfer.wire import TransferError, MAX_FILE_BYTES, b64, unb64, receive_frame


@pytest.fixture
def environment(tmp_path):
    services = []
    def build(initial=8, depth=8, algorithm='ML-KEM-768'):
        root = tmp_path / str(len(services))
        provision(root / 'identities', algorithm)
        app = create_app(Settings(refill_bps=256, pool_depth=depth, initial_keys=initial))
        clock = [0.0]
        app.state.pool._clock = lambda: clock[0]
        app.state.pool._last_refill = 0.0
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        config = uvicorn.Config(app, log_level='error', lifespan='off')
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 5
        while not server.started:
            assert thread.is_alive() and time.monotonic() < deadline
            time.sleep(.01)
        url = f'http://127.0.0.1:{listener.getsockname()[1]}'
        audit_b = Audit(root / 'bob.jsonl', 'bob', echo=False)
        receiver = Receiver(('127.0.0.1', 0), Identity.load(root / 'identities/bob.json', 'bob'),
                            url, root / 'received', audit_b)
        receiver_thread = threading.Thread(target=receiver.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        receiver_thread.start()
        queue = FileQueue(root / 'queue')
        sender = Sender(Identity.load(root / 'identities/alice.json', 'alice'), url,
                        receiver.server_address, queue, Audit(root / 'alice.jsonl', 'alice', echo=False))
        services.append((receiver, receiver_thread, server, thread, listener))
        return root, sender, queue, clock, app
    yield build
    for receiver, receiver_thread, server, thread, listener in reversed(services):
        receiver.shutdown()
        receiver.server_close()
        receiver_thread.join(3)
        server.should_exit = True
        thread.join(3)
        listener.close()


def enqueue(root, queue, policy='hybrid-required', data=b'test file\x00\xff\n'):
    source = root / 'sample.bin'
    source.write_bytes(data)
    return queue.enqueue(source, policy), source


@pytest.mark.parametrize('algorithm', SUPPORTED_ALGORITHMS)
def test_native_rest_tcp_file_transfer(environment, algorithm):
    root, sender, queue, _, _ = environment(algorithm=algorithm)
    identifier, source = enqueue(root, queue, data=bytes(range(256)) * 4096)
    result = sender.run(identifier=identifier)[0]
    assert result['state'] == 'DELIVERED'
    assert result['mode'] == 'HYBRID_QKD'
    assert (root / 'received' / result['saved_as']).read_bytes() == source.read_bytes()

    starts = [json.loads(line)['attempt_id'] for line in (root / 'alice.jsonl').read_text().splitlines()
              if json.loads(line)['event'] == 'handshake_started']
    assert len(starts) == len(set(starts))
    assert pool_status(sender.kme)['available_keys'] == 7
    assert Identity.load(root / 'identities/alice.json', 'alice').secret_key.hex() not in (root / 'alice.jsonl').read_text()
    assert (root / 'identities/alice.json').stat().st_mode & 0o777 == 0o600


def test_empty_pool_explicit_fallback(environment):
    root, sender, queue, _, _ = environment(initial=0)
    identifier, _ = enqueue(root, queue, 'allow-pqc')
    result = sender.run(identifier=identifier)[0]
    assert (result['state'], result['mode']) == ('DELIVERED', 'PQC_ONLY')
    assert result['reason'] == 'reserve_below_5_percent'
    bob = [json.loads(line) for line in (root / 'bob.jsonl').read_text().splitlines()]
    assert any(row['event'] == 'delivered' and row['mode'] == 'PQC_ONLY' for row in bob)


def test_queue_survives_restart_and_refill(environment):
    root, sender, queue, clock, _ = environment(initial=0)
    identifier, source = enqueue(root, queue)
    result = sender.run(identifier=identifier)[0]
    assert result['state'] == 'QUEUED'
    assert not list((root / 'received').iterdir())
    # A restarted queue/worker loads the durable job, then a controlled refill occurs.
    sender.queue = FileQueue(root / 'queue')
    clock[0] = 2
    result = sender.run(identifier=identifier)[0]
    assert result['state'] == 'DELIVERED' and result['attempts'] == 2
    assert result['mode'] == 'HYBRID_QKD'
    assert (root / 'received' / result['saved_as']).read_bytes() == source.read_bytes()


def test_tampered_transfer_is_rejected_without_output(environment):
    root, sender, queue, _, _ = environment()
    identifier, _ = enqueue(root, queue)
    result = sender.run(identifier=identifier, tamper=True)[0]
    assert result['state'] == 'FAILED'
    assert result['reason'] == 'authentication_failed'
    assert not list((root / 'received').iterdir())
    assert 'authentication_failed' in (root / 'bob.jsonl').read_text()


def test_queue_detects_changed_source(environment):
    root, sender, queue, _, _ = environment(initial=0)
    identifier, source = enqueue(root, queue)
    source.write_bytes(b'changed source')
    result = sender.run(identifier=identifier)[0]
    assert result['state'] == 'FAILED' and result['reason'] == 'queued_source_changed'
    assert not list((root / 'received').iterdir())


def test_quota_fallback_and_strict_queue(environment):
    root, sender, queue, _, _ = environment()
    sender.manager.rate_limit_per_peer = 1
    identifier, _ = enqueue(root, queue, 'allow-pqc')
    sender.manager.check_quota('alice')
    result = sender.run(identifier=identifier)[0]
    assert result['state'] == 'DELIVERED' and result['mode'] == 'PQC_ONLY'
    assert result['reason'] == 'request_quota_exceeded'
    identifier, _ = enqueue(root, queue, 'hybrid-required')
    sender.manager.peer_request_history['alice'] = [time.time()]
    result = sender.run(identifier=identifier)[0]
    assert result['state'] == 'QUEUED'
    assert pool_status(sender.kme)['available_keys'] == 8


def test_boundary_reserve_and_pool_quota(environment):
    root, sender, queue, _, app = environment(initial=1, depth=20)
    identifier, _ = enqueue(root, queue)
    assert sender.run(identifier=identifier)[0]['state'] == 'DELIVERED'  # exactly 5% passes
    app.state.pool.per_peer_quota = 1
    app.state.pool.refill_bps = 0
    # Independent held key occupies the outstanding quota on a refilled test pool.
    with app.state.pool._lock:
        app.state.pool._available = 20
    app.state.pool.issue('alice', 'bob')
    identifier, _ = enqueue(root, queue, 'allow-pqc')
    result = sender.run(identifier=identifier)[0]
    assert result['mode'] == 'PQC_ONLY' and result['reason'] == 'qkd_acquisition_unavailable'


def channels():
    result = HandshakeResult(bytes(range(32)), 'HYBRID_QKD', b'transcript')
    return SecureChannel(result, 'alice'), SecureChannel(result, 'bob')


@pytest.mark.parametrize('kind', ['ciphertext', 'type', 'sequence', 'key', 'transcript'])
def test_authenticated_records_reject_modification(kind):
    alice, bob = channels()
    record = alice.seal('file', b'private data')
    if kind == 'ciphertext':
        damaged = bytearray(unb64(record['ciphertext']))
        damaged[-1] ^= 1
        record['ciphertext'] = b64(bytes(damaged))
    elif kind == 'type':
        record['type'] = 'receipt'
    elif kind == 'sequence':
        record['sequence'] = 2
    else:
        result = HandshakeResult(b'z' * 32 if kind == 'key' else bytes(range(32)),
                                 'HYBRID_QKD', b'wrong transcript' if kind == 'transcript' else b'transcript')
        bob = SecureChannel(result, 'bob')
    with pytest.raises(TransferError):
        bob.open(record, 'file')


def test_replay_and_direction_separation():
    alice, bob = channels()
    record = alice.seal('file', b'payload')
    assert bob.open(record, 'file') == b'payload'
    with pytest.raises(TransferError):
        bob.open(record, 'file')
    with pytest.raises(TransferError):
        alice.open(record, 'file')
    assert alice.open(bob.seal('receipt', b'acknowledged'), 'receipt') == b'acknowledged'


def offer(name='file.bin'):
    return {'transfer_id': str(uuid.uuid4()), 'filename': name, 'bytes': 0,
            'sha256': hashlib.sha256(b'').hexdigest(), 'policy': 'hybrid-required', 'mode': 'HYBRID_QKD'}


@pytest.mark.parametrize('name', ['../escape', '/tmp/escape', '..', 'a\\b', 'bad\nname', 'bad\x00name'])
def test_reject_unsafe_names(name):
    with pytest.raises(TransferError, match='unsafe_filename'):
        validate_offer(offer(name), 'HYBRID_QKD')


def test_policy_bound_to_authenticated_metadata():
    metadata = offer()
    metadata['mode'] = 'PQC_ONLY'
    with pytest.raises(TransferError, match='hybrid_policy_violation'):
        validate_offer(metadata, 'PQC_ONLY')


def test_atomic_publish_no_overwrite_or_partial_files(tmp_path):
    metadata = offer()
    validate_offer(metadata, 'HYBRID_QKD')
    target = publish_file(tmp_path, metadata, b'')
    with pytest.raises(TransferError, match='duplicate_transfer'):
        publish_file(tmp_path, metadata, b'')
    with pytest.raises(TransferError, match='file_verification_failed'):
        publish_file(tmp_path, metadata, b'wrong content')
    assert list(tmp_path.iterdir()) == [target]


def test_frame_size_checked_before_reading_body():
    left, right = socket.socketpair()
    try:
        left.sendall((2**32 - 1).to_bytes(4, 'big'))
        with pytest.raises(TransferError, match='invalid_frame_length'):
            receive_frame(right)
    finally:
        left.close()
        right.close()


def test_queue_exclusive_worker_and_interrupted_delivery(tmp_path):
    queue = FileQueue(tmp_path / 'queue')
    identifier, _ = enqueue(tmp_path, queue)
    queue.update(identifier, state='SENDING')
    with queue.worker():
        assert queue.get(identifier)['state'] == 'UNKNOWN'
        with pytest.raises(TransferError, match='already_running'):
            with FileQueue(tmp_path / 'queue').worker():
                pass


def test_empty_file_and_multiple_jobs(environment):
    root, sender, queue, _, _ = environment()
    identifiers = []
    for name, data in [('empty.pdf', b''), ('data.csv', b'x,y\n1,2\n')]:
        path = root / name
        path.write_bytes(data)
        identifiers.append(queue.enqueue(path, 'hybrid-required'))
    results = sender.run()
    assert all(job['state'] == 'DELIVERED' for job in results)
    assert len(list((root / 'received').iterdir())) == 2
    assert len({row['handshake_id'] for row in map(json.loads, (root / 'alice.jsonl').read_text().splitlines())
                if row['event'] == 'session_confirmed'}) == 2


def test_authentication_failure_never_queues_or_downgrades(environment, monkeypatch):
    from qkd_hake.protocol.hake import BobSession
    root, sender, queue, _, _ = environment(initial=0)
    original = BobSession.message2
    def damaged_message2(self, message):
        pk, tag, ct, nonce = original(self, message)
        return pk, bytes([tag[0] ^ 1]) + tag[1:], ct, nonce
    monkeypatch.setattr(BobSession, 'message2', damaged_message2)
    identifier, _ = enqueue(root, queue, 'allow-pqc')
    result = sender.run(identifier=identifier)[0]
    assert result['state'] == 'FAILED' and result['mode'] is None
    assert not list((root / 'received').iterdir())


def test_late_qkd_retrieval_failure_never_downgrades(environment, monkeypatch):
    from qkd_hake.qkd_mock.client import QKDClient
    root, sender, queue, _, _ = environment()
    monkeypatch.setattr(QKDClient, 'retrieve_key', lambda *args: None)
    identifier, _ = enqueue(root, queue, 'allow-pqc')
    result = sender.run(identifier=identifier)[0]
    assert result['state'] == 'FAILED' and result['mode'] is None
    assert not list((root / 'received').iterdir())


def test_truncated_encrypted_file_never_publishes_output(environment):
    from qkd_hake.transfer.handshake import client_handshake, mode_label
    from qkd_hake.transfer.wire import canonical, send_frame
    root, sender, queue, _, _ = environment()
    identifier, _ = enqueue(root, queue)
    job = queue.get(identifier)
    with socket.create_connection(sender.address, timeout=5) as sock:
        result, _ = client_handshake(sock, sender.identity, sender.kme, sender.manager, False)
        channel = SecureChannel(result, 'alice')
        metadata = {k: job[k] for k in ('transfer_id', 'filename', 'bytes', 'sha256', 'policy')}
        metadata['mode'] = mode_label(result.security_mode)
        send_frame(sock, channel.seal('offer', canonical(metadata)))
        # Declare a frame, then close the write side without transmitting it.
        sock.sendall((100).to_bytes(4, 'big') + b'{')
        sock.shutdown(socket.SHUT_WR)
        receipt = json.loads(channel.open(receive_frame(sock), 'receipt'))
        assert receipt['status'] == 'REJECTED'
    assert not list((root / 'received').iterdir())


def test_receipt_loss_is_unknown_not_automatic_retry(environment, monkeypatch):
    import qkd_hake.transfer.receiver as receiver_module
    root, sender, queue, _, _ = environment()
    original = receiver_module.send_frame
    def drop_receipt(sock, record):
        if record['type'] == 'receipt':
            raise OSError('simulated ACK loss')
        return original(sock, record)
    monkeypatch.setattr(receiver_module, 'send_frame', drop_receipt)
    identifier, source = enqueue(root, queue)
    result = sender.run(identifier=identifier)[0]
    assert result['state'] == 'UNKNOWN'
    received = list((root / 'received').iterdir())
    assert len(received) == 1 and received[0].read_bytes() == source.read_bytes()
    assert sender.run(identifier=identifier)[0]['attempts'] == 1


def test_oversized_input_rejected_before_transfer(tmp_path):
    path = tmp_path / 'oversize.bin'
    with path.open('wb') as file:
        file.truncate(MAX_FILE_BYTES + 1)
    queue = FileQueue(tmp_path / 'queue')
    with pytest.raises(TransferError, match='file_too_large'):
        queue.enqueue(path, 'allow-pqc')
    assert not queue.list()


def test_audit_rejects_secret_fields(tmp_path):
    audit = Audit(tmp_path / 'audit.jsonl', 'alice', echo=False)
    with pytest.raises(ValueError, match='unsupported audit fields'):
        audit.emit('event', session_key='must not be logged')
    assert not audit.path.exists()
