from shared.student import VARIANT_NUMBER
from hashlib import blake2s
import csv
from pathlib import Path
from rich.console import Console
from rich.table import Table
import json
from datetime import datetime
from functools import wraps

console = Console()


class ValidationError(Exception):
    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    if password == "" or password is None:
        raise ValueError("Пароль не може бути порожнім!")
    if salt == "" or salt is None:
        raise ValueError("Сіль не може бути порожньою!")
    if len(password) < 9:
        raise ValidationError("Пароль має містити не менше 9 символів!")
    password_with_salt = password + salt
    password_hash = blake2s(password_with_salt.encode())
    return password_hash.hexdigest()


my_salt = str(VARIANT_NUMBER).zfill(5)
users_to_register = [
    ("animffi", "05!00m3369s18L"),
    ("cyber_bro", "dshn6783$ls!"),
    ("pypri_sss_tt", "abs77rf8903"),
    ("films8901", "8888dftn!"),
    ("yuliksks", "GG543hie!dn98"),
    ("titi_tati_too", "qwerTy12345"),
    ("marinad_sh", "05096ddsm"),
    ("uz_veze2026", "2026admin!ua"),
    ("videostar_popular", "security_ChECk22"),
    ("ginny_georgia", "bfbiBHEUIE2839$$"),
]


def create_user(username: str, password: str) -> tuple:
    hash_value = generate_hash(password, my_salt)
    return username, hash_value


data = Path("labs/lab01/data")
users_file = data / "users.csv"


def create_users(userlist: list) -> list:
    users_db = []
    try:
        data.mkdir(parents=True, exist_ok=True)
        with open(users_file, "w", newline="", encoding="utf-8") as csvfile:
            csvwriter = csv.writer(csvfile)

            for username, password in userlist:
                user = create_user(username, password)
                csvwriter.writerow(user)
                users_db.append(user)

    except FileNotFoundError:
        print("Файл не знайдено!")
    except PermissionError:
        print("Немає дозволу на роботу з файлами!")
    except IOError as error:
        print(f"Помилка роботи з файлом {error}")
    except ValueError as error:
        print(f"Помилка значення:{error}")
    except ValidationError as error:
        print(f"Помилка перевірки пароля: {error}")

    return users_db


def read_users() -> list:
    users_db = []
    try:
        with open(users_file, "r", newline="", encoding="utf-8") as csvfile:
            csvreader = csv.reader(csvfile)

            for row in csvreader:
                username, hash_value = row
                users_db.append((username, hash_value))
    except FileNotFoundError:
        print("Файл не знайдено!")
    except PermissionError:
        print("Немає дозволу на читання файлу!")
    except IOError as error:
        print(f"Помилка роботи з файлом {error}")

    return users_db


def print_users(users_db: list) -> None:
    table = Table(title="База користувачів")
    table.add_column("Логін")
    table.add_column("Хеш пароля")

    for username, hash_value in users_db:
        table.add_row(username, hash_value)

    console.print(table)


log_file = data / "log.json"


def log_event(function):
    @wraps(function)
    def wrapper(username, password):
        result = "failure"

        try:
            login_result = function(username, password)
            if login_result:
                result = "success"
            return login_result
        finally:
            event = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": [],
                "kwargs": {},
            }
            try:
                data.mkdir(parents=True, exist_ok=True)
                logs = []
                if log_file.exists():
                    with open(log_file, "r", newline="", encoding="utf-8") as logfile:
                        logs = json.load(logfile)
                logs.append(event)
                with open(log_file, "w", newline="", encoding="utf-8") as logfile:
                    json.dump(logs, logfile, ensure_ascii=False, indent=4)
            except FileNotFoundError:
                print("Файл логів не знайдено!")
            except PermissionError:
                print("Немає дозволу на запис логів!")
            except IOError as error:
                print(f"Помилка запису логів: {error}")
            except ValueError as error:
                print(f"Помилка JSON: {error}")

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    users_db = read_users()
    if username == "" or username is None:
        raise ValueError("Логін не може бути порожнім!")
    if password == "" or password is None:
        raise ValueError("Пароль не може бути порожнім!")
    for saved_username, saved_hash in users_db:
        if saved_username == username:
            entered_hash = generate_hash(password, my_salt)
            return entered_hash == saved_hash
    return False


def main():
    create_users(users_to_register)

    users_db = read_users()
    print_users(users_db)


if __name__ == "__main__":
    main()
