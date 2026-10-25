import json
import sqlite3
from pathlib import Path

from pydantic import ValidationError

from .database import get_connection, initialize_database
from .schemas import RecordCreate

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"


def seed_database() -> None:
    initialize_database()

    try:
        data = json.loads(SEED_PATH.read_text(encoding="utf-8"))
        categories = data["categories"]
        records = [RecordCreate(**item).model_dump() for item in data["records"]]
    except (
        OSError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValidationError,
    ) as error:
        print(f"Початкові дані некоректні, зміни не внесено: {error}")
        return

    connection = get_connection()
    try:
        with connection:
            categories_count = connection.execute(
                "SELECT COUNT(*) FROM categories"
            ).fetchone()[0]
            records_count = connection.execute(
                "SELECT COUNT(*) FROM records"
            ).fetchone()[0]
            if categories_count or records_count:
                print("База вже містить дані. Зміни не внесено.")
                return

            connection.executemany(
                "INSERT INTO categories (id, name) VALUES (?, ?)",
                [(c["id"], c["name"]) for c in categories],
            )
            connection.executemany(
                "INSERT INTO records (code, title, category_id, value, status) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (r["code"], r["title"], r["category_id"], r["value"], r["status"])
                    for r in records
                ],
            )
        print(
            f"Базу даних успішно заповнено! Додано категорій: {len(categories)}, записів: {len(records)}"
        )
    except sqlite3.Error as error:
        print(f"Помилка заповнення, усі зміни скасовано: {error}")
    finally:
        connection.close()


if __name__ == "__main__":
    seed_database()
