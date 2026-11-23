import pytest
from src.generator import KeyGenerator


def test_aes_256():
    key = KeyGenerator().generate_aes("k1", 256)
    assert len(key.value) == 32 and key.algorithm == "AES-256"


def test_aes_keys_unique():
    gen = KeyGenerator()
    assert gen.generate_aes("a").value != gen.generate_aes("b").value


def test_aes_wrong_bits():
    with pytest.raises(ValueError):
        KeyGenerator().generate_aes("k1", 100)


def test_rsa():
    key = KeyGenerator().generate_rsa("r1", 2048)
    assert key.value.startswith(b"-----BEGIN PRIVATE KEY-----")


def test_fingerprint():
    key = KeyGenerator().generate_aes("k1")
    fp = key.fingerprint()
    assert len(fp) == 16 and fp == key.fingerprint()
    assert key.value.hex() not in fp
