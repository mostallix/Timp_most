"""Точка входа приложения: настройка журнала и запуск интерфейса."""
import logging
import os
import sys

from keymanager.exporter import KeyExporter
from keymanager.generator import KeyGenerator
from keymanager.storage import KeyStorage
from keymanager.ui import ConsoleUI

DEFAULT_STORAGE = "keys.dat"
DEFAULT_EXPORT_DIR = "exports"


def main():
    """Запускает программу.

    Пути к хранилищу и папке экспорта можно задать переменными
    окружения KEYMANAGER_STORAGE и KEYMANAGER_EXPORT_DIR.

    :return: Код завершения (0 - успешно).
    """
    # подробности ошибок пишутся только в журнал, не на экран
    logging.basicConfig(
        filename="keymanager.log", level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s")
    storage = KeyStorage(
        os.environ.get("KEYMANAGER_STORAGE", DEFAULT_STORAGE))
    exporter = KeyExporter(
        os.environ.get("KEYMANAGER_EXPORT_DIR", DEFAULT_EXPORT_DIR))
    return ConsoleUI(KeyGenerator(), storage, exporter).run()


if __name__ == "__main__":
    sys.exit(main())
