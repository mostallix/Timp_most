import pytest
from keymanager.exporter import ExportError, KeyExporter
from keymanager.generator import KeyGenerator

PASSWORD = "export_password"


@pytest.fixture
def exporter(tmp_path):
    return KeyExporter(tmp_path)


def test_export_public_rsa(exporter):
    key = KeyGenerator().generate_rsa("rsa1")
    path = exporter.export_public(key, "rsa1_pub.pem")
    assert path.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")


def test_public_not_for_aes(exporter):
    with pytest.raises(ExportError):
        exporter.export_public(KeyGenerator().generate_aes("a1"),
                               "a1.pem")


def test_secret_roundtrip(exporter):
    key = KeyGenerator().generate_aes("a1", 128)
    exporter.export_secret(key, "a1.key", PASSWORD)
    loaded = exporter.import_secret("a1.key", "a1_copy", PASSWORD)
    assert loaded.value == key.value
    assert loaded.algorithm == "AES-128"


def test_secret_file_is_encrypted(exporter, tmp_path):
    key = KeyGenerator().generate_aes("a1")
    exporter.export_secret(key, "a1.key", PASSWORD)
    assert key.value not in (tmp_path / "a1.key").read_bytes()


def test_import_wrong_password(exporter):
    exporter.export_secret(KeyGenerator().generate_aes("a1"),
                           "a1.key", PASSWORD)
    with pytest.raises(ExportError, match="Неверный пароль"):
        exporter.import_secret("a1.key", "a1", "wrong_password")


def test_no_overwrite(exporter):
    key = KeyGenerator().generate_aes("a1")
    exporter.export_secret(key, "a1.key", PASSWORD)
    with pytest.raises(ExportError, match="уже существует"):
        exporter.export_secret(key, "a1.key", PASSWORD)


@pytest.mark.parametrize("bad", ["../a1.key", "a1.txt", "/etc/a.pem",
                                 "", "a b.pem"])
def test_bad_filename(exporter, bad):
    with pytest.raises(ValueError):
        exporter.export_secret(KeyGenerator().generate_aes("a1"),
                               bad, PASSWORD)


def test_import_missing_and_bad_format(exporter, tmp_path):
    with pytest.raises(ExportError, match="не найден"):
        exporter.import_secret("none.key", "x", PASSWORD)
    (tmp_path / "plain.pem").write_bytes(b"not a key")
    with pytest.raises(ExportError, match="формат"):
        exporter.import_secret("plain.pem", "x", PASSWORD)
