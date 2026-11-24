import math
from typing import Any

VARIANT = 6
THRESHOLD = 7.0
FIELD = "integrityImpact"
EXPECTED = "HIGH"
ALLOWED_VALUES = {"NONE", "LOW", "HIGH"}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _optional_str(container: dict[str, Any], key: str) -> str | None:
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Field '{key}' must be a non-empty string")
    return value


def _pick_description(cve: dict[str, Any]) -> str | None:
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    _require(isinstance(descriptions, list), "Field 'descriptions' must be a list")
    chosen = None
    for item in descriptions:
        _require(isinstance(item, dict), "Each description must be an object")
        lang, value = item.get("lang"), item.get("value")
        _require(
            isinstance(lang, str) and isinstance(value, str),
            "Description 'lang' and 'value' must be strings",
        )
        if chosen is None and lang == "en" and value.strip():
            chosen = value
    return chosen


def _select_metric(cve: dict[str, Any]) -> dict[str, Any] | None:
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    _require(isinstance(metrics, dict), "Field 'metrics' must be an object")
    if "cvssMetricV31" not in metrics:
        return None
    items = metrics["cvssMetricV31"]
    _require(isinstance(items, list), "Field 'cvssMetricV31' must be a list")
    if not items:
        return None
    if not all(isinstance(item, dict) for item in items):
        raise ValueError("Each CVSS v3.1 entry must be an object")
    for item in items:
        if item.get("type") == "Primary":
            return item
    return items[0]


def _valid_score(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 <= value <= 10
    )


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    _require(isinstance(payload, dict), "Response must be an object")
    vulns = payload.get("vulnerabilities")
    _require(isinstance(vulns, list), "Field 'vulnerabilities' must be a list")
    if len(vulns) > 1:
        raise ValueError("Expected at most one vulnerability")
    if not vulns:
        return None
    item = vulns[0]
    _require(
        isinstance(item, dict) and isinstance(item.get("cve"), dict),
        "Vulnerability item must contain object 'cve'",
    )
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise ValueError("Returned CVE id does not match the requested one")

    status = _optional_str(cve, "vulnStatus")
    description = _pick_description(cve)
    record: dict[str, Any] = {
        "status": status,
        "description": description,
        "cvss": None,
    }
    if status is None or status == "Rejected":
        return record

    metric = _select_metric(cve)
    if metric is None:
        return record
    data = metric.get("cvssData")
    _require(isinstance(data, dict), "Field 'cvssData' must be an object")
    score = data.get("baseScore")
    if not _valid_score(score):
        raise ValueError("'baseScore' must be a finite number from 0 to 10")
    version = _optional_str(data, "version")
    if version is not None and version != "3.1":
        raise ValueError("CVSS version must be '3.1'")
    record["cvss"] = {
        "score": score,
        "source": _optional_str(metric, "source"),
        "version": version,
        "vector": _optional_str(data, "vectorString"),
        "data": dict(data),
    }
    return record


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    if variant != VARIANT:
        raise ValueError(f"Only variant {VARIANT} is implemented")
    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": THRESHOLD, "field": FIELD, "expected": EXPECTED},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["status"]
    if record["status"] == "Rejected":
        report["decision"] = "rejected"
        return report
    cvss = record["cvss"]
    if record["status"] is None or cvss is None:
        report["decision"] = "insufficient_data"
        return report

    report["cvss_version"] = cvss["version"]
    report["score"] = cvss["score"]
    report["score_source"] = cvss["source"]
    report["vector"] = cvss["vector"]
    data = cvss["data"]
    if FIELD not in data:
        report["decision"] = "insufficient_data"
        return report
    value = data[FIELD]
    if not isinstance(value, str) or value not in ALLOWED_VALUES:
        raise ValueError(f"Invalid value of '{FIELD}'")
    report["observed"] = value
    matches = cvss["score"] >= THRESHOLD and value == EXPECTED
    report["decision"] = "review" if matches else "other"
    return report
