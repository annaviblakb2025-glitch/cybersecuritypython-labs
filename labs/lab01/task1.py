from rich.console import Console
from rich.table import Table

console = Console()
from random import sample

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "InfoS3c@2023",
    "simple123",
    "Def3ns3@Key",
    "public",
    "Encrypt3d#Pass",
    "basic123",
    "Secur3@Analysis",
    "temp123",
    "Pr0t3ct@Data",
    "default",
]
criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {"simple123", "public", "basic123", "temp123", "default", "guest"}


table = Table(title="Аналізатор надійності паролів")
table.add_column("Пароль")
table.add_column("Результат")


def main():
    indexes = sample(range(len(passwords)), 3)
    for index in indexes:
        new_password = passwords[index]
        passwords.append(new_password)
    for password in passwords:
        digit = any(char.isdigit() for char in password)
        upper = any(char.isupper() for char in password)
        special = any(not char.isalnum() for char in password)

        if (
            digit
            and upper
            and special
            and len(password) >= criteria["min_length"] + 4
            and passwords.count(password) == 1
        ):
            table.add_row(password, "ДУЖЕ СИЛЬНИЙ!")
        elif digit and upper and special and len(password) < criteria["min_length"] + 4:
            table.add_row(password, "СИЛЬНИЙ!")
        elif (
            len(password) >= criteria["min_length"]
            and (digit and upper or special)
            and (digit or upper and special)
            and (digit and special or upper)
        ):
            table.add_row(password, "СЕРЕДНІЙ!")
        elif password not in forbidden_passwords and (digit or upper or special):
            table.add_row(password, "СЛАБКИЙ!")
        elif password in forbidden_passwords or len(password) < criteria["min_length"]:
            table.add_row(password, "ЗАБОРОНЕНИЙ!")

    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}\n")

    console.print(table)


if __name__ == "__main__":
    main()
