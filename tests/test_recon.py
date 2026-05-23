"""Tests for MYT-R02 recon: authorization gate + mocked backends (no live calls)."""

import json

import pytest

from znextscan.checks.base_check import CheckStatus
from znextscan.checks.mythos_checks import SourceExposureReconCheck
from znextscan.connections.mock import MockConnection
from znextscan.recon import ReconContext, set_context
from znextscan.recon.engine import authorize


@pytest.fixture
def conn() -> MockConnection:
    return MockConnection("tests/fixtures")


@pytest.fixture(autouse=True)
def _clear_context():
    set_context(None)
    yield
    set_context(None)


class TestAuthorizationGate:
    def test_not_enabled(self) -> None:
        ok, reason = authorize(ReconContext())
        assert not ok and "not enabled" in reason

    def test_enabled_not_authorized(self) -> None:
        ok, reason = authorize(ReconContext(enabled=True))
        assert not ok and "not authorized" in reason

    def test_authorized_no_identifiers(self) -> None:
        ok, reason = authorize(ReconContext(enabled=True, authorized=True))
        assert not ok and "identifiers" in reason

    def test_all_gates_pass(self) -> None:
        ok, _ = authorize(ReconContext(enabled=True, authorized=True, identifiers=["acme"]))
        assert ok

    def test_none_context(self) -> None:
        ok, _ = authorize(None)
        assert not ok


class TestReconCheck:
    def test_skipped_when_not_authorized(self, conn: MockConnection) -> None:
        set_context(ReconContext(enabled=True))  # not authorized
        r = SourceExposureReconCheck().run(conn)
        assert r.status == CheckStatus.SKIPPED
        assert "not authorized" in r.findings[0]

    def test_skipped_by_default(self, conn: MockConnection) -> None:
        r = SourceExposureReconCheck().run(conn)
        assert r.status == CheckStatus.SKIPPED

    def test_pass_when_authorized_no_findings(
        self, conn: MockConnection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        set_context(ReconContext(enabled=True, authorized=True, identifiers=["clean-org"]))
        monkeypatch.setattr("znextscan.recon.backends.default_backends", lambda ctx: [])
        r = SourceExposureReconCheck().run(conn)
        assert r.status == CheckStatus.PASS

    def test_fail_when_exposure_found(
        self, conn: MockConnection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from znextscan.recon.engine import ReconFinding

        class FakeBackend:
            name = "fake"

            def search(self, context):
                return [
                    ReconFinding("fake", "acme: COBOL in acme/legacy", "http://x/1"),
                ]

        monkeypatch.setattr(
            "znextscan.recon.backends.default_backends", lambda ctx: [FakeBackend()]
        )
        set_context(ReconContext(enabled=True, authorized=True, identifiers=["acme"]))
        r = SourceExposureReconCheck().run(conn)
        assert r.status == CheckStatus.FAIL
        assert any("acme/legacy" in f for f in r.findings)


class TestGitHubBackendMocked:
    def test_parses_items_without_live_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from znextscan.recon.backends import GitHubCodeSearchBackend

        class FakeResp:
            status_code = 200
            headers: dict = {}

            def json(self):
                return {
                    "items": [
                        {
                            "html_url": "http://gh/acme/x",
                            "path": "src/PAY.cbl",
                            "repository": {"full_name": "acme/x"},
                        }
                    ]
                }

        class FakeClient:
            def __init__(self, *a, **k): ...
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def get(self, *a, **k):
                return FakeResp()

        monkeypatch.setattr("znextscan.recon.backends.httpx.Client", FakeClient)
        ctx = ReconContext(enabled=True, authorized=True, identifiers=["acme"])
        findings = GitHubCodeSearchBackend().search(ctx)
        assert findings and findings[0].source == "github-code-search"
        assert "acme/x" in findings[0].title
