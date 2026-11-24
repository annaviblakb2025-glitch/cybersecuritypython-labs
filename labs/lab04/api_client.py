from pathlib import Path
from typing import Any

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = (3.05, 10)
API_KEY_FILE = Path(__file__).resolve().parent / "api_key.txt"


class UnexpectedStatusError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"Unexpected HTTP status {status_code}")
        self.status_code = status_code


def read_api_key() -> str | None:
    try:
        text = API_KEY_FILE.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    key = text.strip()
    return key or None


def build_headers() -> dict[str, str]:
    headers = {"Accept": "application/json"}
    api_key = read_api_key()
    if api_key is not None:
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve_id: str) -> Any:
    response = requests.get(
        NVD_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
