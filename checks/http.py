"""HTTP check.

Config keys:
- url (str, required)
- method (str, optional, default "GET")
- timeout (float, optional, seconds, default 5)
- headers (dict, optional)
- body (str, optional)
- json (dict, optional; sets Content-Type if missing)
- expect_status (int or list[int], optional, default 200)
- expect_headers (dict, optional; exact match, case-insensitive keys)
- expect_headers_regex (bool, optional, default False)
- expect_body_contains (str, optional)
- expect_body_regex (str, optional)
- expect_json (dict, optional; dot-paths to expected values)

Example:
cfg = {
    "url": "http://127.0.0.1:8080/health",
    "expect_status": 200,
    "expect_headers": {"X-Test": "yes"},
    "expect_json": {"status": "ok"},
}
"""

import json
import re
import urllib.request


def _get_json_path(payload, path):
    current = payload
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def check_http(cfg):
    url = cfg.get("url")
    timeout = float(cfg.get("timeout", 5))
    method = cfg.get("method", "GET").upper()
    expect_status = cfg.get("expect_status", 200)
    headers = cfg.get("headers") or {}
    body = cfg.get("body")
    json_body = cfg.get("json")
    expect_body_contains = cfg.get("expect_body_contains")
    expect_body_regex = cfg.get("expect_body_regex")
    expect_headers = cfg.get("expect_headers") or {}
    expect_headers_regex = bool(cfg.get("expect_headers_regex", False))
    expect_json = cfg.get("expect_json") or {}
    if not url:
        return False, "http requires url"
    try:
        data = None
        req_headers = dict(headers)
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif body is not None:
            data = str(body).encode("utf-8")
        req = urllib.request.Request(url, method=method, data=data, headers=req_headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            response_headers = {k.lower(): v for k, v in resp.headers.items()}
            response_body = resp.read().decode("utf-8", errors="replace")
        if isinstance(expect_status, list):
            ok = status in expect_status
        else:
            ok = status == int(expect_status)
        if ok:
            if expect_headers:
                for key, expected in expect_headers.items():
                    actual = response_headers.get(str(key).lower())
                    if actual is None:
                        return False, f"http missing header {key}"
                    if expect_headers_regex:
                        if re.search(str(expected), actual) is None:
                            return False, f"http header {key} mismatch"
                    elif str(actual) != str(expected):
                        return False, f"http header {key} mismatch"
            if expect_body_contains is not None:
                if str(expect_body_contains) not in response_body:
                    return False, "http body does not contain expectation"
            if expect_body_regex is not None:
                if re.search(str(expect_body_regex), response_body) is None:
                    return False, "http body regex did not match"
            if expect_json:
                try:
                    parsed = json.loads(response_body)
                except json.JSONDecodeError:
                    return False, "http body not valid json"
                for path, expected in expect_json.items():
                    actual = _get_json_path(parsed, path)
                    if actual != expected:
                        return False, f"http json {path} mismatch"
            return True, f"http {status} ok"
        return False, f"http status {status} != {expect_status}"
    except OSError as exc:
        return False, f"http failed: {exc}"
