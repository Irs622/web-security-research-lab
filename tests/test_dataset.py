"""Unit tests verifying dataset schema integrity and laboratory containment."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES_FILE = ROOT / "simulator" / "attack_cases.json"

REQUIRED_FIELDS = {
    "test_id",
    "category",
    "expected_class",
    "method",
    "path",
    "params",
    "headers",
    "body",
    "description",
    "expected_waf_behavior",
}

VALID_CATEGORIES = {"normal", "sqli", "xss", "path-traversal"}
VALID_CLASSES = {"benign", "malicious"}
VALID_METHODS = {"GET", "POST", "PUT", "DELETE"}
VALID_BEHAVIORS = {"allow", "block"}


def test_dataset_schema():
    assert CASES_FILE.exists(), "attack_cases.json must exist"
    with CASES_FILE.open(encoding="utf-8") as f:
        cases = json.load(f)

    assert len(cases) >= 30, f"Expected representative dataset (>= 30 cases), got {len(cases)}"

    seen_ids = set()
    for case in cases:
        missing = REQUIRED_FIELDS - set(case.keys())
        assert not missing, f"Case {case.get('test_id')} missing fields: {missing}"

        test_id = case["test_id"]
        assert test_id not in seen_ids, f"Duplicate test_id found: {test_id}"
        seen_ids.add(test_id)

        assert case["category"] in VALID_CATEGORIES, f"Invalid category in {test_id}"
        assert case["expected_class"] in VALID_CLASSES, f"Invalid expected_class in {test_id}"
        assert case["method"] in VALID_METHODS, f"Invalid method in {test_id}"
        assert case["expected_waf_behavior"] in VALID_BEHAVIORS, f"Invalid expected_waf_behavior in {test_id}"
        assert case["path"].startswith("/"), f"Path must start with '/' in {test_id}"
        assert not case["path"].startswith("http"), f"Path must be relative in {test_id}"
