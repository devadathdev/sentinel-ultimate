import pytest
from crypto.vault import CryptoVault, KeyMaterial, generate_key


def vault():
    return CryptoVault(KeyMaterial.from_b64("inner-v1", generate_key()), KeyMaterial.from_b64("outer-v1", generate_key()))


def test_round_trip():
    v = vault(); data = b"SENTINEL secret payload"
    e = v.seal(data, aad=b"record-1")
    assert v.open(e, aad=b"record-1") == data
    assert e["scheme"] == "SENTINEL-2X-AES256-GCM"


def test_independent_keys_required():
    k = generate_key()
    a = KeyMaterial.from_b64("a", k)
    with pytest.raises(ValueError): CryptoVault(a, KeyMaterial.from_b64("b", k))


def test_tamper_is_rejected():
    v = vault(); e = v.seal(b"secret")
    e["outer_ct"] = e["outer_ct"][:-1] + ("A" if e["outer_ct"][-1] != "A" else "B")
    with pytest.raises(Exception): v.open(e)


def test_wrong_aad_is_rejected():
    v = vault(); e = v.seal(b"secret", aad=b"good")
    with pytest.raises(Exception): v.open(e, aad=b"bad")


def test_key_size_is_256_bit():
    assert len(KeyMaterial.from_b64("x", generate_key()).key) == 32
