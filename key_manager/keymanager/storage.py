"""Модуль зашифрованного хранилища ключей.

Содержимое хранилища сериализуется в JSON (а не pickle) и
шифруется паролем с помощью модуля crypto_utils (AES-256-GCM).
"""
import base64
import json
import logging
import os

from keymanager import crypto_utils
from keymanager.key import Key
from keymanager.validators import validate_name, validate_password

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
        self._password = None

    def open(self, password):
        """Открывает хранилище (загружает файл, если он есть).

        :param password: Мастер-пароль.
        :raises ValueError: Если пароль слишком короткий.
        :raises StorageError: Если пароль неверный или файл повреждён.
        """
        validate_password(password)
        if os.path.exists(self._filename):
            with open(self._filename, "rb") as f:
                blob = f.read()
            try:
                plain = crypto_utils.decrypt(blob, password)
            except crypto_utils.DecryptionError:
                logger.warning("Неудачная попытка открыть хранилище")
                raise StorageError(
                    "Неверный пароль или файл повреждён") from None
            self._keys = self._from_json(plain)
        self._password = password

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
        logger.info("Добавлен ключ %s (%s)", key.name, key.algorithm)

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
        logger.info("Удалён ключ %s", name)

    def list_keys(self):
        """Возвращает список ключей без их значений.

        :return: Список кортежей (имя, алгоритм, дата, отпечаток).
        """
        self._check_open()
        return [(k.name, k.algorithm, k.created, k.fingerprint())
                for k in self._keys.values()]

    def save(self):
        """Шифрует и сохраняет хранилище в файл.

        :raises StorageError: Если запись не удалась.
        """
        self._check_open()
        blob = crypto_utils.encrypt(self._to_json(), self._password)
        tmp = self._filename + ".tmp"
        try:
            # сначала пишем во временный файл, затем заменяем
            # основной, чтобы не оставить частично записанные данные
            with open(tmp, "wb") as f:
                f.write(blob)
            os.replace(tmp, self._filename)
        except OSError as exc:
            logger.error("Ошибка записи %s: %s", self._filename, exc)
            if os.path.exists(tmp):
                os.remove(tmp)
            raise StorageError(
                "Не удалось сохранить хранилище") from None

    def close(self):
        """Закрывает хранилище и удаляет ключи из памяти."""
        self._keys = {}
        self._password = None

    def _to_json(self):
        records = [{"name": k.name, "algorithm": k.algorithm,
                    "created": k.created,
                    "value": base64.b64encode(k.value).decode()}
                   for k in self._keys.values()]
        return json.dumps(records).encode("utf-8")

    @staticmethod
    def _from_json(plain):
        keys = {}
        for r in json.loads(plain):
            keys[r["name"]] = Key(r["name"], r["algorithm"],
                                  base64.b64decode(r["value"]),
                                  r["created"])
        return keys

    def _check_open(self):
        if self._password is None:
            raise StorageError("Хранилище не открыто")
