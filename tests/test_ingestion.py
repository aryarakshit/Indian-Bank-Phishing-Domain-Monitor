"""Tests for CertStream ingestion and domain sanitization."""

import asyncio
import contextlib
import json

from src.config import AppConfig
from src.ingestion.certstream_client import CertStreamClient
from src.ingestion.sanitizer import clean_domain, extract_domains_from_cert


class FakeSocket:
    """Replays queued frames, then stays silent forever like a stalled feed."""

    def __init__(self, frames):
        self._frames = list(frames)

    async def recv(self):
        if self._frames:
            return self._frames.pop(0)
        await asyncio.Event().wait()


class FakeConnect:
    """Stands in for websockets.connect, serving canned frames per URL."""

    def __init__(self, feeds):
        self.feeds = feeds
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append(url)
        socket = FakeSocket(self.feeds.get(url, []))

        @contextlib.asynccontextmanager
        async def session():
            yield socket

        return session()


def test_clean_domain():
    assert clean_domain("  *.Example.Com.  ") == "example.com"
    assert clean_domain("*.sub.bank.in") == "sub.bank.in"
    assert clean_domain("*.sbi-kyc.top.") == "sbi-kyc.top"
    assert clean_domain("") == ""
    assert clean_domain("NORMAL-domain.XYZ") == "normal-domain.xyz"


def test_extract_domains_from_cert():
    sample_cert_message = {
        "message_type": "certificate_update",
        "data": {
            "leaf_cert": {
                "all_domains": [
                    "*.sbi-update.xyz",
                    "sbi-update.xyz",
                    "login.sbi-update.xyz",
                ],
                "subject": {"CN": "sbi-update.xyz"},
            }
        },
    }

    domains = extract_domains_from_cert(sample_cert_message)
    assert "sbi-update.xyz" in domains
    assert "login.sbi-update.xyz" in domains
    assert len(domains) == 2  # De-duplicated *.sbi-update.xyz and sbi-update.xyz


def test_extract_domains_empty_or_malformed():
    assert extract_domains_from_cert({}) == []
    assert extract_domains_from_cert({"data": None}) == []
    assert extract_domains_from_cert({"data": {"leaf_cert": {}}}) == []


async def test_switches_to_fallback_feed_when_primary_sends_only_heartbeats():
    heartbeat = json.dumps({"message_type": "heartbeat"})
    certificate = json.dumps(
        {
            "message_type": "certificate_update",
            "data": {"leaf_cert": {"all_domains": ["sbi-kyc-update.top"]}},
        }
    )
    connect = FakeConnect(
        {
            "wss://stalled.example": [heartbeat, heartbeat],
            "ws://backup.example:8080/": [certificate],
        }
    )
    config = AppConfig(
        certstream_url="wss://stalled.example",
        certstream_fallback_urls=["ws://backup.example:8080/"],
        certstream_idle_timeout_seconds=0.05,
    )
    client = CertStreamClient(config=config, connect=connect)

    stream = client.stream_domains()
    first_domain = await asyncio.wait_for(stream.__anext__(), timeout=2)
    client.stop()
    await stream.aclose()

    assert first_domain == "sbi-kyc-update.top"
    assert connect.calls == ["wss://stalled.example", "ws://backup.example:8080/"]


def test_fallback_feeds_are_read_from_a_comma_separated_setting(monkeypatch):
    monkeypatch.setenv("CERTSTREAM_FALLBACK_URLS", " ws://localhost:8080/ , ,wss://ct.example ")

    config = AppConfig()

    assert config.certstream_fallback_urls == ["ws://localhost:8080/", "wss://ct.example"]
