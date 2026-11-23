"""Консольный интерфейс пользователя (макет из ЛР4).

Ввод передаётся через функции input_func и password_func,
чтобы интерфейс можно было проверить автоматическими тестами.
"""
import getpass
import logging

from keymanager.exporter import ExportError
from keymanager.storage import StorageError

logger = logging.getLogger(__name__)
MAX_ATTEMPTS = 3
ALGORITHMS = {"1": ("aes", 128), "2": ("aes", 256),
              "3": ("rsa", 2048)}
HELP_TEXT = """Справка:
 1 - создать ключ AES-128, AES-256 или RSA-2048;
 2 - список ключей (значения ключей не показываются);
 3 - экспорт: открытый ключ RSA или секретный ключ с паролем;
 4 - импорт секретного ключа из файла;
 5 - удаление ключа (с подтверждением);
 0 - сохранить хранилище и выйти.
Имя ключа: латиница, цифры, _ и -, до 32 символов.
Имя файла: например my_key.pem (только в папке экспорта)."""


class ConsoleUI:
    """Текстовое меню для работы с ключами."""

    def __init__(self, generator, storage, exporter,
                 input_func=input, password_func=getpass.getpass):
        """Создаёт интерфейс.

        :param generator: Объект KeyGenerator.
        :param storage: Объект KeyStorage.
        :param exporter: Объект KeyExporter.
        :param input_func: Функция ввода строки.
        :param password_func: Функция скрытого ввода пароля.
        """
        self._gen = generator
        self._storage = storage
        self._exporter = exporter
        self._input = input_func
        self._password = password_func

    def run(self):
        """Запускает программу: вход, затем главное меню.

        :return: 0 при нормальном завершении, 1 если вход не выполнен.
        """
        if not self._login():
            return 1
        actions = {"1": self._create, "2": self._show_list,
                   "3": self._export, "4": self._import,
                   "5": self._delete, "6": self._help}
        try:
            while True:
                self._print_menu()
                choice = self._input("Выберите пункт (0-6): ").strip()
                if choice == "0":
                    break
                action = actions.get(choice)
                if action is None:
                    print("[ОШИБКА] Введите число от 0 до 6.")
                    continue
                try:
                    action()
                except (ValueError, TypeError, StorageError,
                        ExportError) as exc:
                    # пользователю - только безопасное сообщение
                    print(f"[ОШИБКА] {exc}")
            self._storage.save()
            print("Хранилище сохранено. До свидания!")
        finally:
            self._storage.close()
        return 0

    def _login(self):
        print("=== ГЕНЕРАТОР И МЕНЕДЖЕР КЛЮЧЕЙ ШИФРОВАНИЯ ===")
        for attempt in range(MAX_ATTEMPTS, 0, -1):
            try:
                self._storage.open(self._password("Мастер-пароль: "))
                return True
            except (ValueError, StorageError) as exc:
                print(f"[ОШИБКА] {exc}. Осталось попыток: "
                      f"{attempt - 1}")
        logger.warning("Вход не выполнен: попытки исчерпаны")
        return False

    def _print_menu(self):
        count = len(self._storage.list_keys())
        print(f"\nГЛАВНОЕ МЕНЮ (ключей: {count})")
        print(" 1. Создать ключ   2. Список ключей  3. Экспорт ключа")
        print(" 4. Импорт ключа   5. Удалить ключ   6. Справка")
        print(" 0. Выход")

    def _create(self):
        print("Алгоритм: 1. AES-128  2. AES-256  3. RSA-2048")
        algo = ALGORITHMS.get(self._input("Выберите (1-3): ").strip())
        if algo is None:
            raise ValueError("Выберите алгоритм от 1 до 3")
        name = self._input("Имя ключа: ").strip()
        kind, bits = algo
        if kind == "aes":
            key = self._gen.generate_aes(name, bits)
        else:
            key = self._gen.generate_rsa(name, bits)
        self._storage.add_key(key)
        print(f"[OK] Ключ \"{name}\" ({key.algorithm}) создан.")

    def _show_list(self):
        keys = self._storage.list_keys()
        if not keys:
            print("Хранилище пусто.")
            return
        print(f"{'Имя':12} {'Алгоритм':9} {'Создан':19} Отпечаток")
        for name, algorithm, created, fp in keys:
            print(f"{name:12} {algorithm:9} {created:19} {fp}")
        print("Значения ключей не отображаются.")

    def _export(self):
        name = self._input("Имя ключа: ").strip()
        key = self._storage.get_key(name)
        kind = self._input("1. Открытый ключ  2. Секретный ключ: ")
        filename = self._input("Имя файла: ").strip()
        if kind.strip() == "1":
            path = self._exporter.export_public(key, filename)
        elif kind.strip() == "2":
            password = self._password("Пароль для файла: ")
            path = self._exporter.export_secret(key, filename,
                                                password)
        else:
            raise ValueError("Выберите 1 или 2")
        print(f"[OK] Ключ экспортирован в файл {path.name}")

    def _import(self):
        filename = self._input("Имя файла: ").strip()
        name = self._input("Имя нового ключа: ").strip()
        password = self._password("Пароль файла: ")
        key = self._exporter.import_secret(filename, name, password)
        self._storage.add_key(key)
        print(f"[OK] Ключ \"{name}\" ({key.algorithm}) импортирован.")

    def _delete(self):
        name = self._input("Имя ключа: ").strip()
        self._storage.get_key(name)
        answer = self._input("Ключ будет удалён без возможности "
                             "восстановления. Удалить? (да/нет): ")
        if answer.strip().lower() == "да":
            self._storage.delete_key(name)
            print(f"[OK] Ключ \"{name}\" удалён.")
        else:
            print("Удаление отменено.")

    @staticmethod
    def _help():
        print(HELP_TEXT)
