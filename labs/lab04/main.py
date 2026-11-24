import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def load_response(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _error(message: str) -> int:
    print(f"Error: {message}", file=sys.stderr)
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", required=True, help="CVE id")
    parser.add_argument("--input", help="path to a local NVD JSON response")
    return parser


def main(argv: list[str] | None = None) -> int:
    variant = VARIANT_NUMBER
    if (
        not isinstance(variant, int)
        or isinstance(variant, bool)
        or not 1 <= variant <= 15
    ):
        print("Error: VARIANT_NUMBER must be an integer from 1 to 15", file=sys.stderr)
        return 2

    parser = _build_parser()
    args = parser.parse_args(argv)
    if not CVE_PATTERN.fullmatch(args.cve):
        parser.error("--cve must match CVE-YYYY-NNNNN (e.g. CVE-2021-44228)")

    try:
        if args.input is not None:
            payload = load_response(args.input)
        else:
            payload = api_client.fetch_response(args.cve)
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, variant)
    except requests.exceptions.Timeout:
        return _error("the request to NVD timed out")
    except requests.exceptions.ConnectionError:
        return _error("could not connect to NVD")
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        return _error(f"NVD returned an HTTP error (status {status})")
    except api_client.UnexpectedStatusError as exc:
        return _error(f"NVD returned an unexpected status {exc.status_code}")
    except requests.exceptions.JSONDecodeError:
        return _error("the response is not valid JSON")
    except requests.exceptions.RequestException:
        return _error("the request to NVD failed")
    except OSError:
        return _error(f"cannot read file '{args.input}'")
    except json.JSONDecodeError:
        return _error("the input file is not valid JSON")
    except UnicodeDecodeError:
        return _error("the input file is not valid UTF-8")
    except ValueError as exc:
        return _error(f"invalid data: {exc}")

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
