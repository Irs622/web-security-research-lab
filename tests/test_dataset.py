"""Unit tests verifying dataset schema integrity and laboratory containment."""
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path
from xml.parsers import expat

import pytest

ROOT = Path(__file__).resolve().parents[1]
CASES_FILE = ROOT / "simulator" / "attack_cases.json"
EXTENDED_FILE = ROOT / "simulator" / "attack_cases_extended.json"
HOLDOUT_FILE = ROOT / "simulator" / "holdout_benign.json"

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

# Extra categories mirror CRS rule families so cases imported from the CRS regression
# suite (tests/regression in coreruleset/coreruleset) can be labelled consistently.
VALID_CATEGORIES = {
    "normal", "sqli", "xss", "path-traversal",
    "cmdi", "lfi", "rfi", "php-injection", "java-injection", "nosqli",
    "ssrf", "xxe", "protocol-violation", "scanner-detection",
}
VALID_CLASSES = {"benign", "malicious"}
VALID_METHODS = {"GET", "POST", "PUT", "DELETE"}
VALID_BEHAVIORS = {"allow", "block"}
VALID_APPLICABILITY = {"benign_control", "sink_present", "pattern_only"}

# Exact-duplicate requests in the original dataset that the extended dataset leaves out.
ORIGINAL_DUPLICATES = {"BENIGN-029": "BENIGN-006", "BENIGN-030": "BENIGN-008"}
# Original case kept verbatim for comparability; its public host is inert text the harness never fetches.
HOST_SCOPE_EXEMPT = {"XSS-006"}


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _norm_body(body):
    if isinstance(body, str):
        try:
            return json.dumps(json.loads(body), sort_keys=True)
        except ValueError:
            return body
    return json.dumps(body, sort_keys=True)


def request_key(case):
    """What actually goes on the wire: a JSON body as string or object is the same request."""
    headers = {k.lower(): v for k, v in case["headers"].items()}
    return (case["method"], case["path"], json.dumps(case["params"], sort_keys=True),
            json.dumps(headers, sort_keys=True), _norm_body(case["body"]))


def _check_cases(cases):
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
        assert not case["path"].startswith("//"), f"Protocol-relative path in {test_id}"
        assert isinstance(case["params"], dict), f"params must be an object in {test_id}"
        assert isinstance(case["headers"], dict), f"headers must be an object in {test_id}"
        assert all(isinstance(v, str) for v in case["headers"].values()), f"header values must be strings in {test_id}"
        assert case["body"] is None or isinstance(case["body"], (str, dict)), f"Invalid body type in {test_id}"
        assert case["description"].strip(), f"Empty description in {test_id}"
        # Label and expectation must agree: a benign case is never expected to be blocked.
        assert (case["expected_class"] == "benign") == (case["expected_waf_behavior"] == "allow"), test_id
        # Benign cases live in the 'normal' category so per-category recall is never mixed with FPR.
        assert (case["expected_class"] == "benign") == (case["category"] == "normal"), test_id


def test_dataset_schema():
    assert CASES_FILE.exists(), "attack_cases.json must exist"
    cases = _load(CASES_FILE)
    assert len(cases) >= 30, f"Expected representative dataset (>= 30 cases), got {len(cases)}"
    _check_cases(cases)


def test_holdout_is_benign_and_disjoint_from_main_dataset():
    holdout = _load(HOLDOUT_FILE)
    _check_cases(holdout)
    assert all(c["expected_class"] == "benign" for c in holdout)
    for main_file in (CASES_FILE, EXTENDED_FILE):
        main = _load(main_file)
        overlap = {request_key(c) for c in holdout} & {request_key(c) for c in main}
        assert not overlap, f"hold-out must not repeat tuning cases from {main_file.name}: {overlap}"
        assert not {c["test_id"] for c in holdout} & {c["test_id"] for c in main}


def test_holdout_has_no_near_duplicate_free_text_in_extended():
    """Feedback/search text must not be a light rewrite of a hold-out string (data leakage)."""
    def texts(cases):
        out = set()
        for c in cases:
            out.update(str(v).lower() for v in c["params"].values())
            body = json.loads(c["body"]) if isinstance(c["body"], str) and c["body"].startswith("{") else c["body"]
            if isinstance(body, dict) and "comment" in body:
                out.add(body["comment"].lower())
        return out

    def squash(s):
        return re.sub(r"[^a-z0-9]", "", s)

    hold = {squash(t) for t in texts(_load(HOLDOUT_FILE))}
    ext = {squash(t) for t in texts(_load(EXTENDED_FILE))}
    assert not hold & ext


# --- Extended dataset ----------------------------------------------------------------------

@pytest.fixture(scope="module")
def extended():
    return _load(EXTENDED_FILE)


def test_extended_schema(extended):
    _check_cases(extended)
    for case in extended:
        assert case.get("scenario_applicability") in VALID_APPLICABILITY, case["test_id"]
        assert (case["expected_class"] == "benign") == (case["scenario_applicability"] == "benign_control")


def test_extended_requests_are_unique(extended):
    """Repeating the same request under another id would inflate counts with dependent samples."""
    counts = Counter(request_key(c) for c in extended)
    dupes = [c["test_id"] for c in extended if counts[request_key(c)] > 1]
    assert not dupes, f"Identical requests under different test ids: {dupes}"


def test_extended_preserves_original_cases(extended):
    """Same test_id must always mean the same request so per-case results stay comparable."""
    by_id = {c["test_id"]: c for c in extended}
    for orig in _load(CASES_FILE):
        if orig["test_id"] in ORIGINAL_DUPLICATES:
            assert orig["test_id"] not in by_id
            continue
        ext = {k: v for k, v in by_id[orig["test_id"]].items() if k != "scenario_applicability"}
        assert ext == orig, f"{orig['test_id']} differs from the original dataset"


def test_original_duplicates_really_are_duplicates():
    by_id = {c["test_id"]: c for c in _load(CASES_FILE)}
    for dup, kept in ORIGINAL_DUPLICATES.items():
        assert request_key(by_id[dup]) == request_key(by_id[kept])


def test_extended_family_coverage(extended):
    counts = Counter(c["category"] for c in extended if c["expected_class"] == "malicious")
    assert set(counts) == VALID_CATEGORIES - {"normal"}, "every malicious family must be represented"
    small = {cat: n for cat, n in counts.items() if n < 8}
    assert not small, f"families below the 8-case floor give unusable per-category intervals: {small}"
    assert sum(1 for c in extended if c["expected_class"] == "benign") >= 50


def test_extended_bodies_are_well_formed(extended):
    for case in extended:
        ctype = {k.lower(): v for k, v in case["headers"].items()}.get("content-type", "")
        body = case["body"]
        if not isinstance(body, str):
            continue
        if "json" in ctype:
            json.loads(body)
        elif "xml" in ctype:
            parser = expat.ParserCreate()
            # Never resolve external entities or parameter entities while validating.
            parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
            parser.ExternalEntityRefHandler = lambda *args: 1
            parser.Parse(body, True)


_NETWORK_URL = re.compile(r"(?:https?|ftp|gopher|ldap|rmi|dict)://\[?([^/\s\"'?#\]\\]+)", re.IGNORECASE)
_RELATIVE_URL = re.compile(r"(?:^|[\s\"'=])//([^/\s\"'?#\\]+)")
_UNC_PATH = re.compile(r"^\\\\([^\\]+)")
# RFC 2606/6761 reserved names; www.w3.org only appears as the XInclude namespace identifier.
_SAFE_TLDS = ("invalid", "test", "local", "example", "localhost")
_SAFE_DOMAINS = ("example.com", "example.org", "example.net", "localhost", "www.w3.org")


def _host_is_lab_safe(host):
    host = host.split("@")[-1].lower()
    if host.count(":") == 1:  # host:port (IPv6 literals keep their colons)
        host = host.rsplit(":", 1)[0]
    if host.rsplit(".", 1)[-1] in _SAFE_TLDS or any(host == d or host.endswith("." + d) for d in _SAFE_DOMAINS):
        return True
    try:
        ip = ipaddress.ip_address(int(host) if host.isdigit() else host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_link_local or ip in ipaddress.ip_network("192.0.2.0/24")


def _payload_hosts(case):
    values = [str(v) for v in case["params"].values()]
    body = case["body"]
    values.append(body if isinstance(body, str) else json.dumps(body))
    for value in values:
        for pattern in (_NETWORK_URL, _RELATIVE_URL, _UNC_PATH):
            yield from pattern.findall(value)


def test_payload_host_extraction():
    case = {"params": {"a": "http://evil.example.net.attacker.com/x", "b": "//cdn.attacker.com/y",
                       "c": "\\\\fileserver\\share"}, "body": None}
    assert sorted(_payload_hosts(case)) == ["cdn.attacker.com", "evil.example.net.attacker.com", "fileserver"]
    assert not any(_host_is_lab_safe(h) for h in _payload_hosts(case))
    assert all(_host_is_lab_safe(h) for h in ("127.0.0.1:3000", "::1", "2130706433", "169.254.169.254", "x.invalid"))
    assert not _host_is_lab_safe("evilexample.com")


def test_extended_payload_hosts_stay_in_lab_scope(extended):
    """URLs inside payloads are inert text, but they must still only name loopback/reserved hosts."""
    offenders = [(c["test_id"], h) for c in extended if c["test_id"] not in HOST_SCOPE_EXEMPT
                 for h in _payload_hosts(c) if not _host_is_lab_safe(h)]
    assert not offenders, offenders


def test_extended_has_no_destructive_methods(extended):
    assert not [c["test_id"] for c in extended if c["method"] in {"PUT", "DELETE"}]
