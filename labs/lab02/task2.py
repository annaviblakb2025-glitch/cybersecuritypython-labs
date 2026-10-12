import argparse
import json
import logging
import re
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

CHAR_MASKS = {
    "U": re.compile(r"[A-Z]"),
    "L": re.compile(r"[a-z]"),
    "D": re.compile(r"[0-9]"),
    "S": re.compile(r"[^A-Za-z0-9]"),
}
MASK_NAMES = {
    (False, True, False, False): "All-Lowercase",
    (False, False, True, False): "All-Digits",
    (True, False, False, False): "All-Uppercase",
    (False, False, False, True): "All-Special",
    (False, True, True, False): "Lowercase-Digit",
    (True, True, True, True): "Complex (Upper-Lower-Digit-Special)",
    (True, True, True, False): "Upper-Lower-Digit",
    (True, True, False, False): "Upper-Lower",
    (True, False, True, False): "Upper-Digit",
    (False, False, True, True): "Digit-Special",
    (False, True, True, True): "Lowercase-Digit-Special",
    (True, True, False, True): "Upper-Lower-Special",
    (True, False, True, True): "Upper-Digit-Special",
    (False, True, False, True): "Lowercase-Special",
    (True, False, False, True): "Uppercase-Special",
}


def read_passwords(file_passwords: Path) -> Iterator[str]:
    with file_passwords.open("r", encoding="utf-8") as file:
        for line in file:
            password = line.rstrip("\r\n")
            if password:
                yield password


def password_mask(password: str) -> str:
    key = tuple(bool(rx.search(password)) for rx in CHAR_MASKS.values())
    return MASK_NAMES.get(key, "Other")


def char_mask(password: str) -> str:
    mask = ""
    for char in password:
        for key, value in CHAR_MASKS.items():
            if value.fullmatch(char):
                mask += key
                break
    return mask


def count_top_password_masks(file_passwords: Path) -> tuple[Counter, dict[str, str]]:
    counts = Counter()
    examples = {}
    for password in read_passwords(file_passwords):
        mask = password_mask(password)
        counts[mask] += 1
        if mask not in examples:
            examples[mask] = password
    return counts, examples


def calculation_passwords(file_passwords: Path, min_length: int) -> dict:
    total_passwords = 0
    total_length_passwords = 0
    weak_passwords = 0
    for password in read_passwords(file_passwords):
        total_passwords += 1
        total_length_passwords += len(password)

        if len(password) < min_length:
            weak_passwords += 1
    weak_percent = weak_passwords / total_passwords * 100 if total_passwords > 0 else 0
    average_length_passwords = (
        total_length_passwords / total_passwords if total_passwords > 0 else 0
    )

    return {
        "total_passwords": total_passwords,
        "average_length_passwords": average_length_passwords,
        "weak_passwords": weak_passwords,
        "weak_percent": weak_percent,
    }


def write_statistics(stats: dict, outfile: Path) -> None:
    with open(outfile, "w", encoding="utf-8") as file:
        file.write(json.dumps(stats, ensure_ascii=False, indent=4))

    logger.info("Dictionary statistics saved to %s", outfile)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Аудит словника паролів")
    parser.add_argument("--wordlist", required=True, help="Шлях до файлу з паролями")
    parser.add_argument("--min-length", type=int, default=8)
    parser.add_argument("--top-masks", type=int, default=5)
    parser.add_argument("--output-stats", default="labs/lab02/data/audit.json")
    args = parser.parse_args(argv)
    wordlist = Path(args.wordlist)

    output_file = Path(args.output_stats)
    if args.min_length <= 0:
        parser.error("min_length має бути більше 0!")
    if args.top_masks <= 0:
        parser.error("top_masks має бути більше 0!")
    if not wordlist.is_file():
        parser.error(f"Файл не знайдено: {wordlist}")
    logger.info("Processing dictionary file %s using generators...", wordlist)
    length_stats = calculation_passwords(wordlist, args.min_length)
    mask_stats, mask_examples = count_top_password_masks(wordlist)
    total_passwords = length_stats["total_passwords"]
    weak_passwords = length_stats["weak_passwords"]
    average_length = length_stats["average_length_passwords"]
    weak_percent = length_stats["weak_percent"]

    print(f"[INFO] Analyzed {total_passwords:,} passwords.")
    print("\n=== Password Dictionary Audit Summary ===")
    print(f"Total Passwords     : {total_passwords:,}")
    print(
        f"Weak Passwords (<{args.min_length}) : {weak_passwords:,} ({weak_percent:.1f}%)"
    )
    print(f"Average Length      : {average_length:.1f} characters")
    print(f"\n=== Top-{args.top_masks} Password Masks ===")
    for number, (mask, count) in enumerate(
        mask_stats.most_common(args.top_masks), start=1
    ):
        percent = count / total_passwords * 100 if total_passwords else 0
        example = mask_examples[mask]
        label = f"{mask} ({char_mask(example)})"
        print(f"{number}. {label:<48}: {count:,} ({percent:.1f}%) [e.g. {example}]")
    print()
    stats = {
        "total_passwords": total_passwords,
        "weak_passwords": weak_passwords,
        "weak_percent": round(weak_percent, 2),
        "average_length": round(average_length, 2),
        "top_masks": dict(mask_stats.most_common(args.top_masks)),
        "mask_examples": {
            mask: mask_examples[mask]
            for mask, count in mask_stats.most_common(args.top_masks)
        },
        "min_length": args.min_length,
    }

    write_statistics(stats, output_file)


if __name__ == "__main__":
    main()
