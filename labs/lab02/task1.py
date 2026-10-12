import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import ClassVar

PASSWORD_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900
email_validation = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def new_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )


class User:
    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        active: bool = True,
        role: str = "user",
    ) -> None:

        self.username = username
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash = None
        self.__password_salt = None
        self.set_password(password)

    @property
    def email(self) -> str:
        return self.__email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not email_validation.fullmatch(value):
            raise ValueError("Значення email некоректне!")
        self.__email = value

    def set_password(self, password: str) -> None:
        if not isinstance(password, str) or not password:
            raise ValueError("Значення пароля відсутнє або некоректне!")
        self.__password_salt = os.urandom(16)
        self.__password_hash = new_hash(password, self.__password_salt)

    def check_password(self, password: str) -> bool:
        if not isinstance(password, str):
            return False
        check_user = new_hash(password, self.__password_salt)
        return hmac.compare_digest(check_user, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        status = "active" if self.active else "inactive"
        return (
            f"User {self.username}, "
            f"email: {self.email}, "
            f"role: {self.role}, "
            f"status: {status}"
        )


class Admin(User):
    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        permissions=None,
        active: bool = True,
    ) -> None:
        super().__init__(username, email, password, role="admin", active=active)
        self.permissions = set(permissions or [])

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        return f"{super().__str__()}, permissions: {sorted(self.permissions)}"


class Session:
    def __init__(self, ip: str) -> None:
        now = datetime.now(timezone.utc)
        self.login_time = now
        self.last_activity = now
        self.ip = ip

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Time out не може бути від'ємним або дорівнювати 0!")
        time_of_session = datetime.now(timezone.utc) - self.last_activity
        return time_of_session <= timedelta(seconds=timeout_sec)


@dataclass
class AuditRegister:
    username: str
    action: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AuditLog:
    actions: ClassVar[frozenset[str]] = frozenset(
        {"login_success", "login_failure", "logout"}
    )

    def __init__(self) -> None:
        self._records: list[AuditRegister] = []

    def add_log(self, username: str, action: str) -> None:
        if action not in self.actions:
            raise ValueError(f"Невідома дія: {action}")
        self._records.append(AuditRegister(username, action))

    def show_all(self) -> None:
        if not self._records:
            print("Журнал записів порожній!")
            return
        for record in self._records:
            print(
                f"{record.timestamp:%Y-%m-%d %H:%M:%S} UTC | "
                f"{record.username:<12} | {record.action}"
            )


class UserAccount:
    def __init__(self, user, session=None, audit_log=None) -> None:
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if (
            self.user.username != username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure")
            return False
        session = Session(ip)
        session.touch()
        self["session"] = session
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        if not self.session.is_active(SESSION_TIMEOUT_SEC):
            self.session = None
            return False
        self.session.touch()
        return True

    def logout(self) -> None:
        if self.session is not None:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key):
        if key not in {"user", "session", "audit_log"}:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key, value) -> None:
        allowed_types = {
            "user": User,
            "session": Session,
            "audit_log": AuditLog,
        }

        if key not in allowed_types:
            raise KeyError(key)

        if key == "session" and value is None:
            self.session = None
            return

        if not isinstance(value, allowed_types[key]):
            raise TypeError(f"Неправильний тип для ключа {key}")

        setattr(self, key, value)
