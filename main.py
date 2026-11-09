"""Точка входа: демонстрация работы модулей."""
import os
import getpass
import logging

from src.generator import KeyGenerator
import src.storage as st

logging.basicConfig(filename="keymanager.log", level=logging.INFO)


def main():
    """Создаёт ключи, сохраняет их и выводит список."""
    # пароль берётся из переменной окружения или вводится вручную
    password = os.environ.get("KEYMANAGER_PASSWORD") \
        or getpass.getpass("Мастер-пароль: ")
    storage = st.KeyStorage("keys.dat")
    try:
        storage.open(password)
        gen = KeyGenerator()
        for key in (gen.generate_aes("aes_key", 256),
                    gen.generate_rsa("rsa_key", 2048)):
            try:
                storage.add_key(key)
            except st.StorageError as exc:
                print(exc)
        storage.save()
        for name, algorithm, created in storage.list_keys():
            print(f"{name:10} {algorithm:9} {created}")
    except (ValueError, st.StorageError) as exc:
        print(f"Ошибка: {exc}")
    finally:
        storage.close()


if __name__ == "__main__":
    main()
