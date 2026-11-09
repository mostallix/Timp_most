"""Модуль зашифрованного хранилища ключей.

Файл хранилища шифруется AES-256-GCM. Ключ шифрования
получается из мастер-пароля функцией scrypt.
"""
import base64
import json
import logging
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from src.key import Key
from src.validators import validate_name, validate_password

logger = logging.getLogger(__name__)


class StorageError(Exception):
    """Ошибка хранилища (сообщение безопасно показывать)."""


class KeyStorage:
    """Хранилище ключей, защищённое мастер-паролем."""

    def __init__(self, filename):
        """Создаёт хранилище.

        :param filename: Путь к файлу хранилища.
        """
        self._filename = filename
        self._keys = {}
        self._enc_key = None
        self._salt = None

    def open(self, password):
        """Открывает хранилище (загружает файл, если он есть).

        :param password: Мастер-пароль.
        :raises ValueError: Если пароль слишком короткий.
        :raises StorageError: Если пароль неверный или файл повреждён.
        """
        validate_password(password)
        if os.path.exists(self._filename):
            with open(self._filename, "rb") as f:
                data = f.read()
            self._salt, blob = data[:16], data[16:]
            self._enc_key = self._derive(password, self._salt)
            self._load(blob)
        else:
            self._salt = os.urandom(16)
            self._enc_key = self._derive(password, self._salt)

    def add_key(self, key):
        """Добавляет ключ.

        :param key: Объект Key.
        :raises StorageError: Если хранилище не открыто
            или ключ с таким именем уже есть.
        """
        self._check_open()
        if key.name in self._keys:
            raise StorageError("Ключ с таким именем уже существует")
        self._keys[key.name] = key

    def get_key(self, name):
        """Возвращает ключ по имени.

        :param name: Имя ключа.
        :return: Объект Key.
        :raises StorageError: Если ключ не найден.
        """
        self._check_open()
        validate_name(name)
        if name not in self._keys:
            raise StorageError("Ключ не найден")
        return self._keys[name]

    def delete_key(self, name):
        """Удаляет ключ по имени.

        :param name: Имя ключа.
        :raises StorageError: Если ключ не найден.
        """
        self.get_key(name)
        del self._keys[name]

    def list_keys(self):
        """Возвращает список ключей без их значений.

        :return: Список кортежей (имя, алгоритм, дата).
        """
        self._check_open()
        return [(k.name, k.algorithm, k.created)
                for k in self._keys.values()]

    def save(self):
        """Шифрует и сохраняет хранилище в файл.

        :raises StorageError: Если запись не удалась.
        """
        self._check_open()
        records = [{"name": k.name, "algorithm": k.algorithm,
                    "created": k.created,
                    "value": base64.b64encode(k.value).decode()}
                   for k in self._keys.values()]
        plain = json.dumps(records).encode()
        nonce = os.urandom(12)  # новый nonce при каждом сохранении
        cipher = AESGCM(self._enc_key)
        blob = nonce + cipher.encrypt(nonce, plain, None)
        tmp = self._filename + ".tmp"
        try:
            # сначала пишем во временный файл, затем заменяем
            # основной, чтобы не оставить частично записанные данные
            with open(tmp, "wb") as f:
                f.write(self._salt + blob)
            os.replace(tmp, self._filename)
        except OSError as exc:
            logger.error("Ошибка записи %s: %s", self._filename, exc)
            if os.path.exists(tmp):
                os.remove(tmp)
            raise StorageError(
                "Не удалось сохранить хранилище") from None

    def close(self):
        """Закрывает хранилище и удаляет ключи из памяти."""
        self._keys.clear()
        self._enc_key = None

    def _load(self, blob):
        try:
            cipher = AESGCM(self._enc_key)
            plain = cipher.decrypt(blob[:12], blob[12:], None)
        except InvalidTag:
            logger.warning("Неудачная попытка открыть хранилище")
            self._enc_key = None
            raise StorageError(
                "Неверный пароль или файл повреждён") from None
        for r in json.loads(plain):
            self._keys[r["name"]] = Key(
                r["name"], r["algorithm"],
                base64.b64decode(r["value"]), r["created"])

    @staticmethod
    def _derive(password, salt):
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return kdf.derive(password.encode())

    def _check_open(self):
        if self._enc_key is None:
            raise StorageError("Хранилище не открыто")
