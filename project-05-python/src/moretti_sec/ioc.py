"""Indicator of compromise (IOC) extraction from free text: tickets, e-mails, reports.

Defanged indicators ("hxxp://evil[.]example", "10.0.0[.]1") are refanged first, so they are
found in their usable form.
"""

from __future__ import annotations

import ipaddress
import re

_REFANG = (
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\[at\]", re.IGNORECASE), "@"),
)
_URL = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
_HASHES = {
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
}
# Words that look like domains but are file names.
_FILE_EXTENSIONS = frozenset(
    (  # noqa: SIM905 - a word list is easier to read and extend than 50 quoted strings
        "exe dll sys bat cmd ps1 vbs js py sh txt log csv json xml yaml yml pdf doc docx xls xlsx "
        "ppt pptx zip rar 7z gz tar iso img msi lnk html htm png jpg jpeg gif"
    ).split()
)


def refang(text: str) -> str:
    for pattern, replacement in _REFANG:
        text = pattern.sub(replacement, text)
    return text


def extract_iocs(text: str) -> dict[str, list[str]]:
    text = refang(text)
    urls = sorted({url.rstrip(".,;:!?") for url in _URL.findall(text)})
    emails = sorted({m.lower() for m in _EMAIL.findall(text)})

    ipv4 = set()
    for candidate in _IPV4.findall(text):
        try:
            ipv4.add(str(ipaddress.IPv4Address(candidate)))
        except ValueError:
            continue

    hashes: dict[str, set[str]] = {}
    remaining = text
    for kind, pattern in _HASHES.items():  # longest first, so an MD5 is not cut from a SHA-256
        hashes[kind] = {m.lower() for m in pattern.findall(remaining)}
        remaining = pattern.sub(" ", remaining)

    email_domains = {e.split("@", 1)[1] for e in emails}
    domains = set()
    for candidate in _DOMAIN.findall(_EMAIL.sub(" ", text)):
        name = candidate.lower()
        if name.rsplit(".", 1)[-1] in _FILE_EXTENSIONS or _IPV4.fullmatch(name):
            continue
        domains.add(name)
    domains |= email_domains

    return {
        "ipv4": sorted(ipv4, key=ipaddress.IPv4Address),
        "domains": sorted(domains),
        "urls": urls,
        "emails": emails,
        "md5": sorted(hashes["md5"]),
        "sha1": sorted(hashes["sha1"]),
        "sha256": sorted(hashes["sha256"]),
    }
