import pytest
from src.validators import (validate_bits, validate_name,
                            validate_password)


def test_valid_name():
    assert validate_name("my_key-1") == "my_key-1"


@pytest.mark.parametrize("bad", ["", "a" * 33, "ключ", "a b", "../x"])
def test_invalid_name(bad):
    with pytest.raises(ValueError):
        validate_name(bad)


def test_name_not_str():
    with pytest.raises(TypeError):
        validate_name(None)


def test_bits():
    assert validate_bits(256, (128, 256)) == 256
    with pytest.raises(ValueError):
        validate_bits(-1, (128, 256))
    with pytest.raises(TypeError):
        validate_bits("256", (128, 256))


def test_short_password():
    with pytest.raises(ValueError):
        validate_password("123")
