"""Модуль с описанием криптографического ключа."""
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
