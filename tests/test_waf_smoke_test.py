"""Tests for the single-request WAF smoke test."""

import sys
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import waf_smoke_test as smoke  # noqa: E402


class FakeResponse:
    """Minimal response object that records whether callers consume the body."""

    def __init__(self, status):
        self.status = status
        self.closed = False
        self.read_called = False

    def read(self):
        self.read_called = True
        raise AssertionError("the smoke test must not download the response body")

    def close(self):
        self.closed = True


class FakeOpener:
    """Record one request and return or raise a configured result."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_rejects_non_https_and_embedded_credentials():
    with pytest.raises(ValueError, match="https"):
        smoke.validate_url("http://example.com/health")

    with pytest.raises(ValueError, match="credentials"):
        smoke.validate_url("https://user:secret@example.com/health")


def test_sends_exactly_one_get_without_reading_body():
    response = FakeResponse(200)
    opener = FakeOpener(response)

    assert smoke.request_status("https://example.com/health", opener=opener) == 200

    assert len(opener.calls) == 1
    request, timeout = opener.calls[0]
    assert request.get_method() == "GET"
    assert request.get_header("User-agent") == smoke.USER_AGENT
    assert timeout == smoke.DEFAULT_TIMEOUT_SECONDS
    assert response.closed is True
    assert response.read_called is False


def test_redirect_handler_refuses_to_follow_redirects():
    handler = smoke.NoRedirectHandler()

    assert handler.redirect_request(None, None, 302, "Found", {}, "https://elsewhere.test") is None


def test_expected_status_passes_and_mismatch_fails(capsys):
    success = FakeOpener(FakeResponse(204))
    mismatch = FakeOpener(FakeResponse(403))

    assert smoke.main(["--url", "https://example.com/health", "--expected-status", "204"], success) == 0
    assert smoke.main(["--url", "https://example.com/health"], mismatch) == 1

    output = capsys.readouterr().out
    assert "smoke test passed" in output
    assert "unexpected status" in output


def test_http_error_status_can_be_expected():
    error = HTTPError("https://example.com/health", 403, "Forbidden", {}, None)
    opener = FakeOpener(error)

    assert smoke.main(["--url", "https://example.com/health", "--expected-status", "403"], opener) == 0
    assert len(opener.calls) == 1


def test_network_error_returns_usage_error(capsys):
    opener = FakeOpener(URLError("offline"))

    assert smoke.main(["--url", "https://example.com/health"], opener) == 2
    assert len(opener.calls) == 1
    assert "offline" in capsys.readouterr().err


def test_invalid_expected_status_and_timeout_do_not_send_requests():
    opener = FakeOpener(FakeResponse(200))

    assert smoke.main(["--url", "https://example.com", "--expected-status", "99"], opener) == 2
    assert smoke.main(["--url", "https://example.com", "--timeout-seconds", "0"], opener) == 2
    assert opener.calls == []
