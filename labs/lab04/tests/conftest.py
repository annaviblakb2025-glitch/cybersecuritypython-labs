import copy
import json
from pathlib import Path

import pytest

from labs.lab04 import api_client

SAMPLE = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, tmp_path):
    monkeypatch.setattr(api_client, "API_KEY_FILE", tmp_path / "no_such_key.txt")
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_payload():
    return copy.deepcopy(json.loads(SAMPLE.read_text(encoding="utf-8")))


@pytest.fixture
def cve_of():
    return lambda payload: payload["vulnerabilities"][0]["cve"]


@pytest.fixture
def cvss_of(cve_of):
    return lambda payload: cve_of(payload)["metrics"]["cvssMetricV31"][0]["cvssData"]
