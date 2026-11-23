"""Модуль экспорта и импорта ключей.

Открытые ключи RSA сохраняются в формате PEM без защиты.
Секретные ключи (AES и закрытые RSA) сохраняются только
зашифрованными паролем.
"""
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from src import crypto_utils
from src.key import Key
from src.validators import (validate_filename, validate_name,
                            validate_password)

logger = logging.getLogger(__name__)
SECRET_HEADER = b"KEYMANAGER-SECRET-V1\n"


class ExportError(Exception):
    """Ошибка экспорта или импорта (безопасна для показа)."""


class KeyExporter:
    """Перенос ключей между хранилищем и файлами."""

    def __init__(self, export_dir):
        """Создаёт экспортёр.

        :param export_dir: Каталог для файлов экспорта.
        """
        self._dir = Path(export_dir)

    def export_public(self, key, filename):
        """Сохраняет открытый ключ RSA в формате PEM.

        :param key: Объект Key с ключом RSA.
        :param filename: Имя файла (.pem или .key).
        :return: Путь к созданному файлу.
        :raises ExportError: Если ключ не RSA или файл уже есть.
        """
        if not key.algorithm.startswith("RSA"):
            raise ExportError("Открытый ключ есть только у RSA")
        private = serialization.load_pem_private_key(key.value, None)
        pem = private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        return self._write(filename, pem, key.name)

    def export_secret(self, key, filename, password):
        """Сохраняет секретный ключ, зашифрованный паролем.

        :param key: Объект Key (AES или RSA).
        :param filename: Имя файла (.pem или .key).
        :param password: Пароль для защиты файла (от 8 символов).
        :return: Путь к созданному файлу.
        :raises ValueError: Если пароль слишком короткий.
        :raises ExportError: Если файл уже существует.
        """
        validate_password(password)
        meta = f"{key.algorithm}\n".encode("utf-8")
        blob = crypto_utils.encrypt(meta + key.value, password)
        return self._write(filename, SECRET_HEADER + blob, key.name)

    def import_secret(self, filename, name, password):
        """Загружает секретный ключ из зашифрованного файла.

        :param filename: Имя файла в каталоге экспорта.
        :param name: Имя, под которым ключ будет сохранён.
        :param password: Пароль, которым защищён файл.
        :return: Объект Key.
        :raises ExportError: Если файл не найден, имеет неверный
            формат или пароль неверный.
        """
        validate_name(name)
        path = self._dir / validate_filename(filename)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            raise ExportError("Файл не найден") from None
        if not data.startswith(SECRET_HEADER):
            raise ExportError("Неверный формат файла")
        try:
            plain = crypto_utils.decrypt(data[len(SECRET_HEADER):],
                                         password)
        except crypto_utils.DecryptionError:
            logger.warning("Неудачный импорт ключа из %s", path)
            raise ExportError("Неверный пароль или файл повреждён") \
                from None
        algorithm, value = plain.split(b"\n", 1)
        logger.info("Импортирован ключ %s", name)
        return Key(name, algorithm.decode("utf-8"), value)

    def _write(self, filename, data, key_name):
        path = self._dir / validate_filename(filename)
        self._dir.mkdir(parents=True, exist_ok=True)
        try:
            # O_EXCL - не перезаписывать существующий файл,
            # 0o600 - читать файл может только владелец
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600)
        except FileExistsError:
            raise ExportError("Файл с таким именем уже существует") \
                from None
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        logger.info("Ключ %s экспортирован в %s", key_name, path)
        return path
