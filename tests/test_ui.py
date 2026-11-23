from unittest import mock

from keymanager.exporter import KeyExporter
from keymanager.generator import KeyGenerator
from keymanager.storage import KeyStorage
from keymanager.ui import ConsoleUI

PASSWORD = "master_password"


def make_ui(tmp_path, inputs, passwords):
    """Создаёт интерфейс с заранее заданным вводом (заглушки)."""
    storage = KeyStorage(str(tmp_path / "keys.dat"))
    ui = ConsoleUI(KeyGenerator(), storage, KeyExporter(tmp_path),
                   input_func=mock.Mock(side_effect=inputs),
                   password_func=mock.Mock(side_effect=passwords))
    return ui, storage


def test_create_list_and_exit(tmp_path, capsys):
    ui, _ = make_ui(tmp_path, ["1", "2", "db_key", "2", "0"],
                    [PASSWORD])
    assert ui.run() == 0
    out = capsys.readouterr().out
    assert "Ключ \"db_key\" (AES-256) создан" in out
    assert "Значения ключей не отображаются" in out
    assert (tmp_path / "keys.dat").exists()


def test_login_three_attempts(tmp_path):
    storage = KeyStorage(str(tmp_path / "keys.dat"))
    storage.open(PASSWORD)
    storage.save()
    ui, _ = make_ui(tmp_path, [],
                    ["wrong_pass1", "wrong_pass2", "123"])
    assert ui.run() == 1


def test_invalid_input_shows_error(tmp_path, capsys):
    ui, _ = make_ui(tmp_path, ["9", "1", "2", "bad name", "0"],
                    [PASSWORD])
    ui.run()
    out = capsys.readouterr().out
    assert "Введите число от 0 до 6" in out
    assert "Недопустимое имя ключа" in out


def test_delete_needs_confirmation(tmp_path):
    ui, storage = make_ui(
        tmp_path,
        ["1", "1", "k1", "5", "k1", "нет", "5", "k1", "да", "0"],
        [PASSWORD])
    with mock.patch.object(storage, "close"):
        ui.run()
        assert storage.list_keys() == []


def test_export_and_import(tmp_path, capsys):
    ui, _ = make_ui(
        tmp_path,
        ["1", "3", "rsa1", "3", "rsa1", "1", "rsa1_pub.pem",
         "3", "rsa1", "2", "rsa1.key", "4", "rsa1.key", "rsa2", "0"],
        [PASSWORD, "file_password", "file_password"])
    ui.run()
    out = capsys.readouterr().out
    assert "экспортирован в файл rsa1_pub.pem" in out
    assert "Ключ \"rsa2\" (RSA-2048) импортирован" in out


def test_help(tmp_path, capsys):
    ui, _ = make_ui(tmp_path, ["6", "0"], [PASSWORD])
    ui.run()
    assert "Справка" in capsys.readouterr().out
