"""Модуль генерации симметричных и асимметричных ключей.

Используется криптографически стойкий генератор (secrets).
"""
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from keymanager.key import Key
from keymanager.validators import validate_bits, validate_name


class KeyGenerator:
    """Создание ключей AES и RSA."""

    AES_SIZES = (128, 256)
    RSA_SIZES = (2048, 3072, 4096)

    def generate_aes(self, name, bits=256):
        """Создаёт симметричный ключ AES.

        :param name: Имя ключа.
        :param bits: Длина ключа: 128 или 256 бит.
        :return: Объект Key.
        :raises TypeError: Если параметры неверного типа.
        :raises ValueError: Если имя или длина недопустимы.
        """
        validate_name(name)
        validate_bits(bits, self.AES_SIZES)
        value = secrets.token_bytes(bits // 8)
        return Key(name, f"AES-{bits}", value)

    def generate_rsa(self, name, bits=2048):
        """Создаёт закрытый ключ RSA (открытый вычисляется из него).

        :param name: Имя ключа.
        :param bits: Длина ключа: 2048, 3072 или 4096 бит.
        :return: Объект Key, value содержит закрытый ключ в PEM.
        :raises TypeError: Если параметры неверного типа.
        :raises ValueError: Если имя или длина недопустимы.
        """
        validate_name(name)
        validate_bits(bits, self.RSA_SIZES)
        private = rsa.generate_private_key(public_exponent=65537,
                                           key_size=bits)
        pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        return Key(name, f"RSA-{bits}", pem)
