"""Проверка входных данных (используется всеми модулями)."""
import re

NAME_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,32}")
# простой шаблон без вложенных повторений - не подвержен ReDoS
FILE_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,50}\.(pem|key)")


def validate_name(name):
    """Проверяет имя ключа.

    :param name: Имя ключа (латиница, цифры, _ и -, до 32 символов).
    :return: Проверенное имя.
    :raises TypeError: Если имя не строка.
    :raises ValueError: Если имя пустое или содержит
        недопустимые символы.
    """
    if not isinstance(name, str):
        raise TypeError("Имя ключа должно быть строкой")
    if not NAME_PATTERN.fullmatch(name):
        raise ValueError("Недопустимое имя ключа")
    return name


def validate_bits(bits, allowed):
    """Проверяет длину ключа.

    :param bits: Длина ключа в битах.
    :param allowed: Допустимые значения.
    :return: Проверенная длина.
    :raises TypeError: Если длина не целое число.
    :raises ValueError: Если длина не входит в allowed.
    """
    # bool - подкласс int, поэтому исключаем его явно
    if not isinstance(bits, int) or isinstance(bits, bool):
        raise TypeError("Длина ключа должна быть целым числом")
    if bits not in allowed:
        raise ValueError(f"Допустимая длина ключа: {allowed}")
    return bits


def validate_password(password):
    """Проверяет мастер-пароль.

    :param password: Мастер-пароль.
    :return: Проверенный пароль.
    :raises ValueError: Если пароль короче 8 символов.
    """
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("Пароль должен быть не короче 8 символов")
    return password


def validate_filename(filename):
    """Проверяет имя файла для экспорта/импорта.

    Разрешено только имя файла без каталогов, с расширением
    .pem или .key, что исключает запись за пределы папки экспорта.

    :param filename: Имя файла, например "db_key.pem".
    :return: Проверенное имя.
    :raises TypeError: Если имя не строка.
    :raises ValueError: Если имя недопустимо.
    """
    if not isinstance(filename, str):
        raise TypeError("Имя файла должно быть строкой")
    if not FILE_PATTERN.fullmatch(filename):
        raise ValueError("Недопустимое имя файла")
    return filename
