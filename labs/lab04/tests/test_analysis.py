import copy

import pytest

from labs.lab04.analysis import build_report, extract_record
from shared.student import VARIANT_NUMBER

CVE = "CVE-2099-10001"


def run(payload, variant=VARIANT_NUMBER):
    return build_report(extract_record(payload, CVE), CVE, variant)


@pytest.mark.parametrize(
    "score, integrity, expected",
    [
        (6.9, "HIGH", "other"),
        (7.0, "HIGH", "review"),
        (7.1, "HIGH", "review"),
        (9.8, "LOW", "other"),
        (9.8, "NONE", "other"),
    ],
)
def test_decision_around_threshold(sample_payload, cvss_of, score, integrity, expected):
    data = cvss_of(sample_payload)
    data["baseScore"] = score
    data["integrityImpact"] = integrity
    assert run(sample_payload)["decision"] == expected


def test_sample_report_full(sample_payload):
    assert run(sample_payload) == {
        "cve_id": CVE,
        "variant": 6,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
        "observed": "HIGH",
        "decision": "review",
    }


def test_not_found():
    report = build_report(
        extract_record({"vulnerabilities": []}, CVE), CVE, VARIANT_NUMBER
    )
    assert report["decision"] == "not_found"
    assert report["cve_id"] == CVE
    assert report["rule"]["field"] == "integrityImpact"
    for key in (
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
        "observed",
    ):
        assert report[key] is None


def test_rejected_ignores_high_score(sample_payload, cve_of):
    cve_of(sample_payload)["vulnStatus"] = "Rejected"
    report = run(sample_payload)
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None and report["observed"] is None


def test_missing_status_is_insufficient(sample_payload, cve_of):
    del cve_of(sample_payload)["vulnStatus"]
    report = run(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["score"] is None and report["observed"] is None


@pytest.mark.parametrize("mode", ["no_metrics", "no_v31", "empty_list"])
def test_missing_scores_is_insufficient(sample_payload, cve_of, mode):
    cve = cve_of(sample_payload)
    if mode == "no_metrics":
        del cve["metrics"]
    elif mode == "no_v31":
        cve["metrics"] = {"cvssMetricV40": []}
    else:
        cve["metrics"]["cvssMetricV31"] = []
    report = run(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["score"] is None


def test_missing_variant_field_is_insufficient(sample_payload, cvss_of):
    del cvss_of(sample_payload)["integrityImpact"]
    report = run(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


@pytest.mark.parametrize("bad", [None, "MEDIUM", "high", 1, True])
def test_bad_variant_field_raises(sample_payload, cvss_of, bad):
    cvss_of(sample_payload)["integrityImpact"] = bad
    with pytest.raises(ValueError):
        run(sample_payload)


@pytest.mark.parametrize(
    "bad", ["9.8", True, None, float("nan"), float("inf"), -0.1, 10.1]
)
def test_bad_score_raises(sample_payload, cvss_of, bad):
    cvss_of(sample_payload)["baseScore"] = bad
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE)


@pytest.mark.parametrize("score", [0, 10, 0.0, 10.0])
def test_score_bounds_accepted(sample_payload, cvss_of, score):
    cvss_of(sample_payload)["baseScore"] = score
    assert extract_record(sample_payload, CVE)["cvss"]["score"] == score


def _metric(source, metric_type, score):
    return {
        "source": source,
        "type": metric_type,
        "cvssData": {"version": "3.1", "baseScore": score, "integrityImpact": "HIGH"},
    }


def test_primary_beats_earlier_secondary(sample_payload, cve_of):
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = [
        _metric("other@example.com", "Secondary", 9.9),
        _metric("nvd@nist.gov", "Primary", 7.5),
    ]
    report = run(sample_payload)
    assert report["score"] == 7.5
    assert report["score_source"] == "nvd@nist.gov"


def test_first_metric_without_primary(sample_payload, cve_of):
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = [
        _metric("a@example.com", "Secondary", 8.0),
        _metric("b@example.com", "Secondary", 9.0),
    ]
    report = run(sample_payload)
    assert report["score"] == 8.0
    assert report["score_source"] == "a@example.com"


def test_english_description_selection(sample_payload, cve_of):
    cve = cve_of(sample_payload)
    cve["descriptions"] = [
        {"lang": "es", "value": "hola"},
        {"lang": "en", "value": "   "},
        {"lang": "en", "value": "second"},
    ]
    assert run(sample_payload)["description"] == "second"
    cve["descriptions"] = [{"lang": "es", "value": "hola"}]
    assert run(sample_payload)["description"] is None


def test_functions_do_not_mutate_payload(sample_payload):
    before = copy.deepcopy(sample_payload)
    record = extract_record(sample_payload, CVE)
    record_before = copy.deepcopy(record)
    build_report(record, CVE, VARIANT_NUMBER)
    assert sample_payload == before
    assert record == record_before


def test_structure_errors(sample_payload, cve_of):
    with pytest.raises(ValueError):
        extract_record([], CVE)
    with pytest.raises(ValueError):
        extract_record({"vulnerabilities": "x"}, CVE)
    with pytest.raises(ValueError):
        extract_record({}, CVE)
    with pytest.raises(ValueError):
        extract_record(sample_payload, "CVE-2099-10002")
    two = copy.deepcopy(sample_payload)
    two["vulnerabilities"].append(copy.deepcopy(two["vulnerabilities"][0]))
    with pytest.raises(ValueError):
        extract_record(two, CVE)


@pytest.mark.parametrize(
    "key, value",
    [
        ("metrics", None),
        ("vulnStatus", None),
        ("vulnStatus", ""),
        ("descriptions", "text"),
    ],
)
def test_bad_optional_fields_raise(sample_payload, cve_of, key, value):
    cve_of(sample_payload)[key] = value
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE)


def test_bad_v31_list_and_items(sample_payload, cve_of):
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = None
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE)
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = ["x"]
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE)


def test_bad_version_and_vector(sample_payload, cvss_of):
    cvss_of(sample_payload)["version"] = "3.0"
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE)
    cvss_of(sample_payload)["version"] = "3.1"
    cvss_of(sample_payload)["vectorString"] = ""
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE)


def test_unknown_variant_raises():
    with pytest.raises(ValueError):
        build_report(None, CVE, 99)
