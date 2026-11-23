"""Криптографические функции: ключ из пароля и шифрование AES-GCM.

Используются хранилищем и модулем экспорта, поэтому вынесены
в отдельный модуль (без дублирования кода и циклических импортов).
"""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_SIZE = 16
NONCE_SIZE = 12


class DecryptionError(Exception):
    """Неверный пароль или повреждённые данные."""


def derive_key(password, salt):
    """Получает 256-битный ключ шифрования из пароля (scrypt).

    :param password: Пароль (строка).
    :param salt: Соль, 16 байт.
    :return: Ключ, 32 байта.
    """
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def encrypt(data, password):
    """Шифрует данные паролем.

    :param data: Открытые данные (bytes).
    :param password: Пароль.
    :return: соль || nonce || шифртекст с тегом.
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)  # новый nonce при каждом вызове
    key = derive_key(password, salt)
    return salt + nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt(blob, password):
    """Расшифровывает данные и проверяет их целостность.

    :param blob: Результат функции encrypt.
    :param password: Пароль.
    :return: Открытые данные (bytes).
    :raises DecryptionError: Если пароль неверный или данные
        изменены.
    """
    if len(blob) < SALT_SIZE + NONCE_SIZE + 16:
        raise DecryptionError("Данные повреждены")
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:]
    key = derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise DecryptionError(
            "Неверный пароль или данные повреждены") from None
