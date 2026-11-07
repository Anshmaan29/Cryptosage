"""Real liboqs operations and boundary rejection; never mocks crypto."""
import pytest

from crypto.primitives import (
    CryptoError, available_algorithms, decapsulate, decrypt, encapsulate, encrypt,
    hkdf, kem_keypair, sign, signature_keypair, verify,
)


@pytest.mark.parametrize('name', ['ML-KEM-768', 'HQC-3'])
def test_kem_roundtrip_and_malformed_sizes(name):
    public, secret = kem_keypair(name)
    ciphertext, shared = encapsulate(name, public)
    assert decapsulate(name, secret, ciphertext) == shared
    assert len(shared) == 32
    for invalid in (b'', public[:-1], public + b'x'):
        with pytest.raises(CryptoError):
            encapsulate(name, invalid)
    with pytest.raises(CryptoError):
        decapsulate(name, secret, ciphertext[:-1])
    with pytest.raises(CryptoError):
        decapsulate(name, secret[:-1], ciphertext)


def test_unsupported_algorithm_fails_closed():
    with pytest.raises(CryptoError, match='unsupported'):
        kem_keypair('Kyber512')


def test_enabled_algorithms_have_correct_security_and_names():
    algorithms = available_algorithms()
    assert {a['name'] for a in algorithms} == {'ML-KEM-768', 'HQC-3'}
    assert all(a['security_level'] == 3 for a in algorithms)
    assert next(a for a in algorithms if a['name'] == 'HQC-3')['status'] == 'experimental'


def test_signature_authenticates_only_exact_message_and_identity():
    public, secret = signature_keypair()
    other_public, _ = signature_keypair()
    signature = sign(secret, b'whole negotiation transcript')
    assert verify(public, b'whole negotiation transcript', signature)
    assert not verify(public, b'modified negotiation', signature)
    assert not verify(other_public, b'whole negotiation transcript', signature)
    assert not verify(public[:-1], b'whole negotiation transcript', signature)
    assert not verify(public, b'whole negotiation transcript', signature[:-1])


def test_hkdf_domain_separation_and_aead_integrity():
    secret = bytes(range(32))
    key = hkdf(secret, b'crytosage/test/send')
    assert key != hkdf(secret, b'crytosage/test/receive')
    nonce = bytes(12)
    ciphertext = encrypt(key, nonce, b'confidential', b'session/counter')
    assert decrypt(key, nonce, ciphertext, b'session/counter') == b'confidential'
    with pytest.raises(CryptoError, match='integrity'):
        decrypt(key, nonce, ciphertext, b'wrong/session')
    with pytest.raises(CryptoError, match='integrity'):
        decrypt(key, nonce, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), b'session/counter')
    with pytest.raises(CryptoError):
        encrypt(key[:-1], nonce, b'confidential', b'')
    with pytest.raises(CryptoError):
        encrypt(key, nonce[:-1], b'confidential', b'')


def test_attack_cli_emits_parseable_real_json():
    import json
    import subprocess
    import sys
    result = subprocess.run([sys.executable,'-m','attacks.simulator','all'],capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr
    rows = json.loads(result.stdout)
    assert len(rows)==5
    assert all(row['attempted'] and row['blocked'] and row['reason'] for row in rows)
