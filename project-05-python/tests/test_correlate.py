from datetime import datetime, timezone

from conftest import FIXTURES

from moretti_sec import correlate
from moretti_sec.parsers.flowlog import parse_flowlog
from moretti_sec.parsers.wazuh_alerts import parse_wazuh_alerts


def _flows():
    return list(parse_flowlog((FIXTURES / "synthetic-flowlog.log").read_text().splitlines()))


def _alerts():
    return list(
        parse_wazuh_alerts((FIXTURES / "synthetic-wazuh-alerts.jsonl").read_text().splitlines())
    )


def test_flowlog_parser_skips_non_flows_and_maps_protocols():
    flows = _flows()
    assert len(flows) == 4  # the NODATA record is dropped
    first = flows[0]
    assert (first.src_ip, first.dst_ip, first.dst_port, first.protocol, first.action) == (
        "10.10.90.10",
        "10.10.20.10",
        445,
        "tcp",
        "REJECT",
    )
    assert first.timestamp == datetime(2026, 9, 21, 14, 15, 0, tzinfo=timezone.utc)
    assert [f.protocol for f in flows] == ["tcp", "tcp", "icmp", "tcp"]


def test_wazuh_alert_parser_pulls_fields_from_each_shape():
    net, acc, ssh = _alerts()
    assert (net.rule_id, net.level, net.src_ip, net.agent) == ("100120", 10, "10.10.90.10", None)
    assert net.timestamp == datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
    assert (acc.rule_id, acc.user, acc.src_ip, acc.agent) == (
        "100101",
        "alan.moreira",
        "10.10.60.10",
        "DC01",
    )
    assert (ssh.rule_id, ssh.user, ssh.src_ip) == ("5710", "admin", "10.10.90.10")


def test_correlate_enriches_and_orders(company):
    timeline = correlate.build(company, flows=_flows(), alerts=_alerts())
    assert [item.timestamp for item in timeline] == sorted(item.timestamp for item in timeline)
    assert {item.source for item in timeline} == {"flow", "wazuh"}

    guest_reject = next(i for i in timeline if i.source == "flow" and i.outcome == "REJECT")
    assert guest_reject.src.segment == "guest"
    assert guest_reject.dst.segment == "finance"
    assert "GUEST01" in guest_reject.summary and "WS-FIN01" in guest_reject.summary

    acc = next(i for i in timeline if i.rule_ids == ("100101",))
    assert acc.account is not None and acc.account.status == "terminated"


def test_correlate_merges_all_three_sources(company, make_event):
    from moretti_sec.models import Outcome

    auth = [make_event("alan.moreira", "10.10.60.10", Outcome.SUCCESS, minute=6)]
    timeline = correlate.build(company, auth=auth, flows=_flows(), alerts=_alerts())
    assert {item.source for item in timeline} == {"auth", "flow", "wazuh"}
    auth_item = next(i for i in timeline if i.source == "auth")
    assert "MG-0097" in auth_item.summary  # employee id from data/
