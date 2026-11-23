from unittest import mock

import pytest
from keymanager.generator import KeyGenerator
from keymanager.storage import KeyStorage, StorageError

PASSWORD = "test_password"


def test_save_and_load(tmp_path):
    path = str(tmp_path / "keys.dat")
    s = KeyStorage(path)
    s.open(PASSWORD)
    key = KeyGenerator().generate_aes("k1")
    s.add_key(key)
    s.save()
    s2 = KeyStorage(path)
    s2.open(PASSWORD)
    assert s2.get_key("k1").value == key.value


def test_file_is_encrypted(tmp_path):
    path = tmp_path / "keys.dat"
    s = KeyStorage(str(path))
    s.open(PASSWORD)
    s.add_key(KeyGenerator().generate_aes("secret_key"))
    s.save()
    assert b"secret_key" not in path.read_bytes()


def test_wrong_password(tmp_path):
    path = str(tmp_path / "keys.dat")
    s = KeyStorage(path)
    s.open(PASSWORD)
    s.save()
    with pytest.raises(StorageError, match="Неверный пароль"):
        KeyStorage(path).open("other_password")


def test_closed_storage():
    with pytest.raises(StorageError):
        KeyStorage("x.dat").list_keys()


def test_duplicate_and_missing(tmp_path):
    s = KeyStorage(str(tmp_path / "k.dat"))
    s.open(PASSWORD)
    s.add_key(KeyGenerator().generate_aes("k1"))
    with pytest.raises(StorageError):
        s.add_key(KeyGenerator().generate_aes("k1"))
    with pytest.raises(StorageError):
        s.get_key("k2")


def test_save_error_hides_path(tmp_path):
    # заглушка: имитируем ошибку диска
    s = KeyStorage(str(tmp_path / "k.dat"))
    s.open(PASSWORD)
    with mock.patch("keymanager.storage.os.replace",
                    side_effect=OSError("disk full")):
        with pytest.raises(StorageError) as exc:
            s.save()
    assert str(tmp_path) not in str(exc.value)
