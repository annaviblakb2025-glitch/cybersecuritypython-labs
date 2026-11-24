import json
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client, main
from labs.lab04.tests.conftest import SAMPLE

CVE = "CVE-2099-10001"


@pytest.fixture(autouse=True)
def variant_six(monkeypatch):
    monkeypatch.setattr(main, "VARIANT_NUMBER", 6)


@pytest.fixture
def no_network(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("network must not be used")

    monkeypatch.setattr(api_client, "fetch_response", fail)


def test_local_run_prints_only_json(no_network, capsys):
    code = main.main(["--cve", CVE, "--input", str(SAMPLE)])
    captured = capsys.readouterr()
    assert code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["decision"] == "review"
    assert report["variant"] == 6
    assert report["observed"] == "HIGH"


def test_online_mode_uses_client(monkeypatch, capsys, sample_payload):
    monkeypatch.setattr(api_client, "fetch_response", Mock(return_value=sample_payload))
    assert main.main(["--cve", CVE]) == 0
    assert json.loads(capsys.readouterr().out)["cve_id"] == CVE


def test_not_found_exit_code_zero(monkeypatch, capsys):
    monkeypatch.setattr(
        api_client, "fetch_response", Mock(return_value={"vulnerabilities": []})
    )
    assert main.main(["--cve", "CVE-2021-44228"]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "not_found"


def test_cyrillic_not_escaped(tmp_path, sample_payload, cve_of, capsys):
    cve_of(sample_payload)["descriptions"] = [{"lang": "en", "value": "Тест"}]
    path = tmp_path / "r.json"
    path.write_text(json.dumps(sample_payload), encoding="utf-8")
    assert main.main(["--cve", CVE, "--input", str(path)]) == 0
    assert "Тест" in capsys.readouterr().out


@pytest.mark.parametrize(
    "bad", ["cve-2099-10001", "CVE-99-10001", "CVE-2099-123", "CVE-2099-10001 ", "x"]
)
def test_bad_cve_argument_exits_2(bad, capsys):
    with pytest.raises(SystemExit) as exc:
        main.main(["--cve", bad])
    assert exc.value.code == 2
    assert capsys.readouterr().out == ""


def test_missing_cve_exits_2():
    with pytest.raises(SystemExit) as exc:
        main.main([])
    assert exc.value.code == 2


@pytest.mark.parametrize("bad", [0, 16, True, "6", 6.0, None])
def test_bad_variant_returns_2(monkeypatch, capsys, bad):
    monkeypatch.setattr(main, "VARIANT_NUMBER", bad)
    assert main.main(["--cve", CVE, "--input", str(SAMPLE)]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "VARIANT_NUMBER" in captured.err


def test_missing_file_returns_1(tmp_path, capsys):
    code = main.main(["--cve", CVE, "--input", str(tmp_path / "nope.json")])
    captured = capsys.readouterr()
    assert code == 1 and captured.out == "" and "Traceback" not in captured.err
    assert captured.err.startswith("Error:")


def test_invalid_json_file_returns_1(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    code = main.main(["--cve", CVE, "--input", str(path)])
    captured = capsys.readouterr()
    assert code == 1 and captured.out == "" and "JSON" in captured.err


def test_invalid_structure_returns_1(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"vulnerabilities": "x"}), encoding="utf-8")
    assert main.main(["--cve", CVE, "--input", str(path)]) == 1
    assert capsys.readouterr().out == ""


def test_id_mismatch_returns_1(capsys):
    assert main.main(["--cve", "CVE-2099-10002", "--input", str(SAMPLE)]) == 1
    assert capsys.readouterr().out == ""


def _http_error():
    response = Mock(status_code=404)
    return requests.exceptions.HTTPError("secret-detail", response=response)


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectionError("secret-detail"),
        requests.exceptions.Timeout("secret-detail"),
        _http_error(),
        api_client.UnexpectedStatusError(302),
        requests.exceptions.JSONDecodeError("secret-detail", "{", 1),
    ],
)
def test_network_failures_return_1_without_leaking(monkeypatch, capsys, error):
    monkeypatch.setattr(api_client, "fetch_response", Mock(side_effect=error))
    code = main.main(["--cve", CVE])
    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert captured.err.startswith("Error:")
    assert "secret-detail" not in captured.err


def test_http_404_message_has_status_not_empty_result(monkeypatch, capsys):
    monkeypatch.setattr(api_client, "fetch_response", Mock(side_effect=_http_error()))
    assert main.main(["--cve", CVE]) == 1
    assert "404" in capsys.readouterr().err
