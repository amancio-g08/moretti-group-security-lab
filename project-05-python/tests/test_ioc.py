from moretti_sec.ioc import extract_iocs, refang

SHA256 = "a" * 64
MD5 = "b" * 32


def test_refang():
    assert refang("hxxps://evil[.]example[.]org") == "https://evil.example.org"
    assert refang("198.51.100[.]66") == "198.51.100.66"


def test_extract_iocs_from_defanged_text():
    text = (
        "SYNTHETIC ticket: phishing from billing[@]fake-bank[.]example linking to "
        "hxxp://login.fake-bank[.]example/reset?id=1. Payload invoice.pdf.exe hash "
        f"{SHA256} (md5 {MD5}) called back to 198.51.100[.]66 and 999.1.1.1."
    )
    iocs = extract_iocs(text)
    assert iocs["emails"] == ["billing@fake-bank.example"]
    assert iocs["urls"] == ["http://login.fake-bank.example/reset?id=1"]
    assert iocs["ipv4"] == ["198.51.100.66"]  # 999.1.1.1 is not a valid address
    assert iocs["sha256"] == [SHA256]
    assert iocs["md5"] == [MD5]  # not a slice of the SHA-256
    assert iocs["sha1"] == []
    assert "fake-bank.example" in iocs["domains"]
    assert "login.fake-bank.example" in iocs["domains"]
    assert not any(d.endswith((".pdf", ".exe")) for d in iocs["domains"])
