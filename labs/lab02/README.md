# Лабораторна робота №2

**Варіант 6:** Аудитор надійності та масок словників паролів

## Встановлення залежностей

```
pip install -r requirements.txt
```

## Структура файлів

```
labs/lab02/
├── __init__.py
├── main.py          # команди demo та analyze
├── task1.py         # класи User, Admin, Session, AuditLog, UserAccount
├── task2.py         # утиліта аудиту словника паролів
├── README.md
└── data/
    ├── passwords.txt   # вхідний словник паролів
    └── audit.json      # результат аудиту (створюється автоматично)
```

## Вхідні дані

Програма приймає текстовий файл `labs/lab02/data/passwords.txt`
(Один пароль на рядок, порожні рядки пропускаються).

## Приклади запуску

Демонстрація моделі користувача й облікового запису (Завдання 1):

```
python -m labs.lab02.main demo
```

Демонстрація аудиту словника (Завдання 2):

```
python -m labs.lab02.main analyze --wordlist labs/lab02/data/passwords.txt
python -m labs.lab02.main analyze --wordlist labs/lab02/data/passwords.txt --min-length 10 --top-masks 3 --output-stats labs/lab02/data/audit.json
```

## Параметри CLI

- `--wordlist` (обов'язковий): шлях до файлу з паролями.
- `--min-length` (за замовчуванням 8): мінімальне значення символів, за яких вже не вважається слабким.
- `--top-masks` (за замовчуванням 5): кількість найчастіших масок.
- `--output-stats` (за замовчуванням `labs/lab02/data/audit.json`): куди записати файл JSON зі статистикою.

## Поведінка при помилках

- Файл словника не знайдено: повідомлення «Файл не знайдено» і завершення з кодом 2.
- `--min-length` або `--top-masks` ≤ 0: повідомлення про помилку і завершення з кодом 2.
- Нечислове значення в `--min-length` або `--top-masks`: помилку видає `argparse`.
- Порожні рядки у словнику ігноруються.