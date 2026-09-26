from moretti_sec.company import normalize_username


def test_ip_context_resolves_asset_and_segment(company):
    ctx = company.ip_context("10.10.20.10")
    assert (ctx.asset_id, ctx.segment) == ("WS-FIN01", "finance")
    dhcp = company.ip_context("10.10.20.150")
    assert (dhcp.asset_id, dhcp.segment) == (None, "finance")
    external = company.ip_context("198.51.100.66")
    assert (external.asset_id, external.segment) == (None, None)
    assert company.ip_context("not-an-ip") is None
    assert company.ip_context(None) is None


def test_accounts_cover_every_kind(company):
    alan = company.account("CORP\\alan.moreira")
    assert (alan.kind, alan.employee_id, alan.status) == ("employee", "MG-0097", "terminated")
    admin = company.account("adm-rogerio.quintela")
    assert (admin.kind, admin.employee_id) == ("admin", "MG-0082")
    service = company.account("svc-app-fin")
    assert (service.kind, service.interactive_logon) == ("service", False)
    assert company.account("bg-admin01").kind == "break-glass"
    assert company.account("nobody").kind == "unknown"
    assert company.account("-") is None


def test_asset_by_hostname(company):
    assert company.asset_by_hostname("DC01.corp.moretti.internal") == "DC01"
    assert company.asset_by_hostname("app-fin01") == "APP-FIN01"
    assert company.asset_by_hostname("unknown-host") is None


def test_normalize_username():
    assert normalize_username("CORP\\Ana.Costa") == "ana.costa"
    assert normalize_username("ana.costa@corp.moretti.internal") == "ana.costa"
    assert normalize_username(" - ") is None
    assert normalize_username(None) is None
