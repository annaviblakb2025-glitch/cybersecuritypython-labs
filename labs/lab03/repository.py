from typing import Any

from .database import get_connection


class CategoryNotFoundError(Exception):
    """Категорії з таким id не існує."""


def _ensure_category_exists(connection, category_id: int) -> None:
    row = connection.execute(
        "SELECT id FROM categories WHERE id = ?",
        (category_id,),
    ).fetchone()
    if row is None:
        raise CategoryNotFoundError("Категорію не знайдено")


def create_category(name: str) -> dict[str, Any]:
    connection = get_connection()
    try:
        with connection:
            cursor = connection.execute(
                "INSERT INTO categories (name) VALUES (?)",
                (name.strip(),),
            )
            category_id = cursor.lastrowid

        return {
            "id": category_id,
            "name": name.strip(),
        }
    finally:
        connection.close()


def list_categories() -> list[dict[str, Any]]:
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()

        return [{"id": row["id"], "name": row["name"]} for row in rows]
    finally:
        connection.close()


def delete_category(category_id: int) -> bool:
    connection = get_connection()
    try:
        with connection:
            row = connection.execute(
                "SELECT id FROM categories WHERE id = ?",
                (category_id,),
            ).fetchone()

            if row is None:
                return False

            count = connection.execute(
                "SELECT COUNT(*) FROM records WHERE category_id = ?",
                (category_id,),
            ).fetchone()[0]

            if count > 0:
                raise ValueError("Категорія містить записи.")

            connection.execute(
                "DELETE FROM categories WHERE id = ?",
                (category_id,),
            )

        return True
    finally:
        connection.close()


def get_record(record_id: int) -> dict[str, Any] | None:
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT
                r.id,
                r.code,
                r.title,
                r.category_id,
                c.name AS category_name,
                r.value,
                r.status
            FROM records AS r
            JOIN categories AS c ON c.id = r.category_id
            WHERE r.id = ?
            """,
            (record_id,),
        ).fetchone()

        return dict(row) if row is not None else None
    finally:
        connection.close()


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: int | None = None,
    search: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    conditions = []
    parameters: list[Any] = []

    if category_id is not None:
        conditions.append("r.category_id = ?")
        parameters.append(category_id)

    if status is not None:
        conditions.append("r.status = ?")
        parameters.append(status)

    if min_value is not None:
        conditions.append("r.value >= ?")
        parameters.append(min_value)

    if search is not None:
        conditions.append("instr(r.title, ?) > 0")
        parameters.append(search)

    sql = """
        SELECT
            r.id,
            r.code,
            r.title,
            r.category_id,
            c.name AS category_name,
            r.value,
            r.status
        FROM records AS r
        JOIN categories AS c ON c.id = r.category_id
    """

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)

    sql += " ORDER BY r.id LIMIT ? OFFSET ?"
    parameters.extend([limit, offset])

    connection = get_connection()

    try:
        rows = connection.execute(sql, parameters).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def create_record(
    code: str,
    title: str,
    category_id: int,
    value: int,
    status: str,
) -> dict[str, Any]:
    connection = get_connection()
    try:
        with connection:
            _ensure_category_exists(connection, category_id)
            connection.execute(
                """
                INSERT INTO records
                    (code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (code, title, category_id, value, status),
            )

            record_id = connection.execute("SELECT last_insert_rowid()").fetchone()[0]

        result = get_record(record_id)

        if result is None:
            raise RuntimeError("Не вдалося отримати створений запис.")

        return result
    finally:
        connection.close()


def update_record(
    record_id: int,
    code: str,
    title: str,
    category_id: int,
    value: int,
    status: str,
) -> dict[str, Any] | None:

    connection = get_connection()

    try:
        with connection:
            existing = connection.execute(
                "SELECT id FROM records WHERE id = ?",
                (record_id,),
            ).fetchone()

            if existing is None:
                return None

            _ensure_category_exists(connection, category_id)

            connection.execute(
                """
                UPDATE records
                SET code = ?,
                    title = ?,
                    category_id = ?,
                    value = ?,
                    status = ?
                WHERE id = ?
                """,
                (
                    code,
                    title,
                    category_id,
                    value,
                    status,
                    record_id,
                ),
            )

        return get_record(record_id)
    finally:
        connection.close()


def delete_record(record_id: int) -> bool:
    connection = get_connection()

    try:
        with connection:
            cursor = connection.execute(
                "DELETE FROM records WHERE id = ?",
                (record_id,),
            )
            deleted = cursor.rowcount > 0

        return deleted
    finally:
        connection.close()


def create_records(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    connection = get_connection()

    try:
        with connection:
            created_ids = []

            for record in records:
                _ensure_category_exists(connection, record["category_id"])
                cursor = connection.execute(
                    """
                    INSERT INTO records
                        (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record["code"],
                        record["title"],
                        record["category_id"],
                        record["value"],
                        record["status"],
                    ),
                )

                created_ids.append(cursor.lastrowid)

        result = []

        for record_id in created_ids:
            record = get_record(record_id)

            if record is not None:
                result.append(record)

        return result
    finally:
        connection.close()
