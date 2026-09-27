import copy

import pytest
import yaml
from conftest import REPO_DATA

from moretti_sec.render.security_groups import PolicyError, main, render


@pytest.fixture(scope="module")
def sources():
    matrix = yaml.safe_load((REPO_DATA / "network-matrix.yaml").read_text(encoding="utf-8"))
    assets = yaml.safe_load((REPO_DATA / "assets.yaml").read_text(encoding="utf-8"))["assets"]
    return matrix, assets


@pytest.fixture(scope="module")
def hosts(sources):
    return render(*sources)["hosts"]


def flows(rules):
    return {(r["protocol"], r["from_port"], r["cidr"]) for r in rules}


def test_no_host_accepts_traffic_from_the_internet(hosts):
    for host in hosts.values():
        assert all(r["cidr"] != "0.0.0.0/0" for r in host["ingress"])


def test_workstations_accept_no_inbound_traffic(hosts):
    # NM-060 (user segments cannot reach each other) and NM-004 (guest is isolated).
    for name in ("WS-DEV01", "WS-FIN01", "GUEST01"):
        assert hosts[name]["ingress"] == []


def test_guest_only_reaches_the_internet(hosts):
    assert flows(hosts["GUEST01"]["egress"]) == {
        ("tcp", 80, "0.0.0.0/0"),
        ("tcp", 443, "0.0.0.0/0"),
        ("tcp", 53, "0.0.0.0/0"),
        ("udp", 53, "0.0.0.0/0"),
    }


def test_domain_controller_serves_corporate_segments_not_guest(hosts):
    ingress = flows(hosts["DC01"]["ingress"])
    assert ("tcp", 88, "10.10.20.0/24") in ingress  # NM-010 finance
    assert not any(cidr == "10.10.90.0/24" for _, _, cidr in ingress)


def test_development_cannot_reach_the_finance_application(hosts):
    # NM-026: the finance application accepts HTTPS from finance only (NM-020, AWS segments).
    assert flows(hosts["APP-FIN01"]["ingress"]) == {("tcp", 443, "10.10.20.0/24")}


def test_siem_accepts_agents_but_nothing_else(hosts):
    ingress = hosts["SIEM01"]["ingress"]
    assert {r["from_port"] for r in ingress} == {1514, 1515}  # NM-040, then NM-043 deny
    assert all(r["rules"] == ["NM-040"] for r in ingress)


def test_every_aws_host_can_reach_systems_manager(hosts):
    for host in hosts.values():
        assert ("tcp", 443, "0.0.0.0/0") in flows(host["egress"])  # NM-072


def test_generated_file_is_up_to_date():
    assert main(["--check", "--data-dir", str(REPO_DATA)]) == 0


def _minimal(rules):
    return (
        {
            "segments": [
                {"id": "a", "name": "A", "cidr": "10.0.1.0/24", "environments": ["aws"]},
                {"id": "b", "name": "B", "cidr": "10.0.2.0/24", "environments": ["aws"]},
            ],
            "services": [
                {
                    "id": "web",
                    "ports": [{"proto": "tcp", "port": 80}, {"proto": "tcp", "port": 443}],
                },
                {"id": "https", "ports": [{"proto": "tcp", "port": 443}]},
                {"id": "any", "ports": [{"proto": "any", "port": "any"}]},
            ],
            "rules": [{"applies_to": ["aws"], **rule} for rule in copy.deepcopy(rules)],
        },
        [
            {
                "id": "H1",
                "ip": "10.0.1.10",
                "segment": "a",
                "os": "Ubuntu",
                "environments": ["aws"],
                "aws_phase": 4,
            },
            {
                "id": "H2",
                "ip": "10.0.2.10",
                "segment": "b",
                "os": "Windows Server",
                "environments": ["aws"],
                "aws_phase": 5,
            },
        ],
    )


def test_earlier_deny_removes_a_later_allow():
    doc = render(
        *_minimal(
            [
                {
                    "id": "NM-900",
                    "source": ["seg:a"],
                    "destination": ["seg:b"],
                    "service": "any",
                    "action": "deny",
                },
                {
                    "id": "NM-901",
                    "source": ["seg:a"],
                    "destination": ["seg:b"],
                    "service": "https",
                    "action": "allow",
                },
            ]
        )
    )
    assert doc["hosts"]["H2"]["ingress"] == []
    assert doc["hosts"]["H2"]["platform"] == "windows"


def test_ports_outside_an_earlier_deny_are_kept():
    doc = render(
        *_minimal(
            [
                {
                    "id": "NM-900",
                    "source": ["seg:a"],
                    "destination": ["seg:b"],
                    "service": "https",
                    "action": "deny",
                },
                {
                    "id": "NM-901",
                    "source": ["seg:a"],
                    "destination": ["seg:b"],
                    "service": "web",
                    "action": "allow",
                },
            ]
        )
    )
    assert flows(doc["hosts"]["H2"]["ingress"]) == {("tcp", 80, "10.0.1.0/24")}


def test_partly_shadowed_allow_is_rejected():
    # The deny covers one host of segment b; an allow to the whole segment cannot be split
    # into Security Group rules without losing the deny.
    with pytest.raises(PolicyError, match="partly shadowed"):
        render(
            *_minimal(
                [
                    {
                        "id": "NM-900",
                        "source": ["seg:a"],
                        "destination": ["asset:H2"],
                        "service": "https",
                        "action": "deny",
                    },
                    {
                        "id": "NM-901",
                        "source": ["seg:a"],
                        "destination": ["seg:b"],
                        "service": "https",
                        "action": "allow",
                    },
                ]
            )
        )


def test_inbound_internet_allow_is_rejected():
    with pytest.raises(PolicyError, match="inbound from the internet"):
        render(
            *_minimal(
                [
                    {
                        "id": "NM-900",
                        "source": ["internet"],
                        "destination": ["asset:H1"],
                        "service": "https",
                        "action": "allow",
                    },
                ]
            )
        )


def test_rules_for_both_ends_are_deduplicated():
    doc = render(
        *_minimal(
            [
                {
                    "id": "NM-900",
                    "source": ["seg:a"],
                    "destination": ["asset:H2"],
                    "service": "https",
                    "action": "allow",
                },
                {
                    "id": "NM-901",
                    "source": ["asset:H1"],
                    "destination": ["seg:b"],
                    "service": "https",
                    "action": "allow",
                },
            ]
        )
    )
    egress = doc["hosts"]["H1"]["egress"]
    assert [(r["rules"], r["cidr"]) for r in egress] == [
        (["NM-900"], "10.0.2.10/32"),
        (["NM-901"], "10.0.2.0/24"),
    ]
    assert [(r["rules"], r["cidr"]) for r in doc["hosts"]["H2"]["ingress"]] == [
        (["NM-900"], "10.0.1.0/24"),
        (["NM-901"], "10.0.1.10/32"),
    ]
