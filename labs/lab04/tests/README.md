# Лабораторна робота №4 — NVD API та pytest

Консольна утиліта: шукає CVE у NVD CVE API 2.0 (або читає локальний JSON),
застосовує правило свого варіанта (`shared/student.py`, `VARIANT_NUMBER`) і
друкує JSON-звіт.

## Встановлення
```
pip install requests pytest ruff
```
(додайте версії до спільного `requirements.txt`, зберігши попередні пакети)

## Запуск
Локально, без мережі:
```
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```
Один ручний запит до NVD:
```
python -m labs.lab04.main --cve CVE-2021-44228
```
Необов'язковий ключ: змінна середовища `NVD_API_KEY` (передається в заголовку `apiKey`).

Коди завершення: `0` — звіт сформовано (включно з `not_found`, `rejected`,
`insufficient_data`); `1` — помилка отримання, читання чи перевірки даних;
`2` — неправильні аргументи або номер варіанта.

## Формат звіту
`cve_id`, `variant`, `description`, `vuln_status`, `cvss_version`, `score`,
`score_source`, `vector`, `rule` (`threshold`, `field`, `expected`), `observed`,
`decision` (`review` / `other` / `insufficient_data` / `rejected` / `not_found`).

## Перевірка
```
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```