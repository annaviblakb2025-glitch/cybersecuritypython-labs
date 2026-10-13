import sys
from datetime import timedelta

from labs.lab02 import task2
from labs.lab02.task1 import (
    SESSION_TIMEOUT_SEC,
    Admin,
    User,
    UserAccount,
)

IP = "192.168.0.26"
PASSWORD = "smi1_Lee!"


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def demo() -> None:
    user = User("shevchenko", "shevchenko2005@example.com", PASSWORD)
    account = UserAccount(user)

    section("Вхід: невдалий і успішний")
    print("Хибний пароль     :", account.login("shevchenko", "wrong", IP))
    print("Правильний пароль :", account.login("shevchenko", PASSWORD, IP))
    print("Автентифікований? :", account.is_authenticated())

    section("Зміна email із валідацією")
    for new_email in ["shevchenko@com", "shevchenko_new@example.lpnu.ua"]:
        try:
            user.email = new_email
            print(f"OK        : {new_email}")
        except ValueError as error:
            print(f"ВІДХИЛЕНО : {new_email} ({error})")

    section("Права адміністратора")
    admin = Admin(
        "senior_pomidor_admin",
        "senior_pomidor_admin@example.com",
        "rO!b0t!a",
        ["read_logs"],
    )
    admin.grant_permission("manage_users")
    print(admin)
    admin.revoke_permission("manage_users")
    print(
        "Дозвіл 'manage_users' після скасування (revoke):",
        admin.has_permission("manage_users"),
    )

    section("Завершення сеансу за таймаутом")
    account["session"].last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print("Автентифікований? :", account.is_authenticated())

    section("Вихід із системи")
    account.login("shevchenko", PASSWORD, IP)
    account.logout()
    print("Автентифікований? :", account.is_authenticated())

    section("Записи аудиту")
    account["audit_log"].show_all()


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "demo":
        demo()
    elif command == "analyze":
        task2.main(sys.argv[2:])
    else:
        sys.exit("Використання: python -m labs.lab02.main {demo|analyze} [параметри]")


if __name__ == "__main__":
    main()
