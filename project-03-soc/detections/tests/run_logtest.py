#!/usr/bin/env python3
"""Run the synthetic rule tests (cases.json) against the Wazuh manager's logtest API.

Runs on SIEM01, after deploy-ruleset.sh. Standard library only. Each case is sent to
PUT /logtest; "expect" must be the rule that fires on the last event, "expect_not" must not be.
Cases with "repeat" send the same event several times in one logtest session, for frequency
rules such as brute force.

    export WAZUH_API_PASSWORD="$(aws ssm get-parameter --with-decryption \\
        --name /moretti-group-lab/wazuh/api-password --query Parameter.Value --output text)"
    python3 run_logtest.py

Exit code 0 only if every case passes. The output is the evidence for tests W-05 to W-07.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import urllib.request
from pathlib import Path

API = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
USER = os.environ.get("WAZUH_API_USER", "wazuh")
CASES = Path(__file__).with_name("cases.json")
# The manager's API certificate is self-signed and only reached on localhost.
CONTEXT = ssl._create_unverified_context()


def call(method: str, path: str, token: str | None = None, body: dict | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        password = os.environ["WAZUH_API_PASSWORD"]
        credentials = base64.b64encode(f"{USER}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {credentials}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(f"{API}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, context=CONTEXT, timeout=30) as response:
        return json.loads(response.read() or b"{}")


def run_case(case: dict, token: str) -> tuple[bool, str]:
    session = None
    fired = None
    for _ in range(case.get("repeat", 1)):
        body = {
            "event": case["event"],
            "log_format": case["log_format"],
            "location": case["location"],
        }
        if session:
            body["token"] = session
        result = call("PUT", "/logtest", token, body)["data"]
        session = result.get("token", session)
        fired = result.get("output", {}).get("rule", {}).get("id")
    if session:
        call("DELETE", f"/logtest/sessions/{session}", token)

    fired_id = int(fired) if fired else None
    if "expect" in case and fired_id != case["expect"]:
        return False, f"expected rule {case['expect']}, got {fired_id}"
    if "expect_not" in case and fired_id == case["expect_not"]:
        return False, f"rule {case['expect_not']} must not fire"
    return True, f"rule {fired_id}"


def main() -> int:
    token = call("POST", "/security/user/authenticate?raw=false")["data"]["token"]
    cases = json.loads(CASES.read_text(encoding="utf-8"))["cases"]
    failures = 0
    for case in cases:
        ok, detail = run_case(case, token)
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} {case['id']}: {detail}")
    print(f"{len(cases) - failures}/{len(cases)} cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
