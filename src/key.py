"""Модуль с описанием криптографического ключа."""
import hashlib
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Key:
    """Криптографический ключ.

    :param name: Имя ключа.
    :param algorithm: Алгоритм, например "AES-256" или "RSA-2048".
    :param value: Значение ключа (для RSA - закрытый PEM).
    """
    name: str
    algorithm: str
    value: bytes
    created: str = field(default_factory=lambda: datetime.now()
                         .isoformat(" ", "seconds"))

    def fingerprint(self):
        """Возвращает отпечаток ключа (первые 16 символов SHA-256).

        Отпечаток позволяет отличать ключи друг от друга,
        не показывая их значения.

        :return: Строка из 16 шестнадцатеричных символов.
        """
        return hashlib.sha256(self.value).hexdigest()[:16]
