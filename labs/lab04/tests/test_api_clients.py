from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def make_response(status=200, payload=None):
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload
    return response


def patch_get(monkeypatch, **kwargs):
    fake_get = Mock(**kwargs)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    return fake_get


def set_key_file(monkeypatch, tmp_path, content):
    path = tmp_path / "api_key.txt"
    path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(api_client, "API_KEY_FILE", path)


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(payload=payload)
    fake_get = patch_get(monkeypatch, return_value=response)

    assert api_client.fetch_response("CVE-2099-10001") == payload

    fake_get.assert_called_once_with(
        URL,
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_headers_without_key_file():
    assert api_client.build_headers() == {"Accept": "application/json"}


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_blank_key_file_means_no_key(monkeypatch, tmp_path, value):
    set_key_file(monkeypatch, tmp_path, value)
    assert "apiKey" not in api_client.build_headers()


def test_unreadable_key_file_means_no_key(monkeypatch, tmp_path):
    # Директорія замість файла: читання завершується OSError.
    monkeypatch.setattr(api_client, "API_KEY_FILE", tmp_path)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_key_is_stripped_and_sent_in_header(monkeypatch, tmp_path):
    set_key_file(monkeypatch, tmp_path, "  fake-key-123  \n")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-key-123",
    }
    fake_get = patch_get(monkeypatch, return_value=make_response(payload={}))
    api_client.fetch_response("CVE-2099-10001")
    kwargs = fake_get.call_args.kwargs
    assert kwargs["headers"]["apiKey"] == "fake-key-123"
    assert kwargs["params"] == {"cveId": "CVE-2099-10001"}
    assert "fake-key-123" not in str(kwargs["params"])


def test_key_file_is_read_at_call_time(monkeypatch, tmp_path):
    set_key_file(monkeypatch, tmp_path, "first-key")
    assert api_client.build_headers()["apiKey"] == "first-key"
    set_key_file(monkeypatch, tmp_path, "second-key")
    assert api_client.build_headers()["apiKey"] == "second-key"


@pytest.mark.parametrize(
    "error",
    [requests.exceptions.ConnectionError("x"), requests.exceptions.Timeout("x")],
)
def test_network_errors_propagate(monkeypatch, error):
    patch_get(monkeypatch, side_effect=error)
    with pytest.raises(type(error)):
        api_client.fetch_response("CVE-2099-10001")


def test_http_error_propagates(monkeypatch):
    response = make_response(status=500)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "boom", response=response
    )
    patch_get(monkeypatch, return_value=response)
    with pytest.raises(requests.exceptions.HTTPError):
        api_client.fetch_response("CVE-2099-10001")


def test_unexpected_success_status_is_rejected(monkeypatch):
    patch_get(monkeypatch, return_value=make_response(status=204))
    with pytest.raises(api_client.UnexpectedStatusError):
        api_client.fetch_response("CVE-2099-10001")


def test_invalid_json_propagates(monkeypatch):
    response = make_response()
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    patch_get(monkeypatch, return_value=response)
    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")
