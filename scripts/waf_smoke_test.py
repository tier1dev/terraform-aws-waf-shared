#!/usr/bin/env python3
"""Send one read-only HTTPS request through a WAF-protected endpoint."""

import argparse
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

USER_AGENT = "terraform-aws-waf-shared-smoke/v0.2.0"
DEFAULT_TIMEOUT_SECONDS = 10


class NoRedirectHandler(HTTPRedirectHandler):
    """Keep the smoke test on the exact host supplied by the operator."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Refuse redirects so a configured URL cannot forward the probe elsewhere."""
        return None


def validate_url(url):
    """Return a parsed, safe HTTPS target or raise ValueError."""
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError("the smoke-test URL must use https")
    if not parsed.hostname:
        raise ValueError("the smoke-test URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("the smoke-test URL must not contain embedded credentials")
    if parsed.fragment:
        raise ValueError("the smoke-test URL must not contain a fragment")
    return parsed


def request_status(url, timeout_seconds=DEFAULT_TIMEOUT_SECONDS, opener=None):
    """Return the status from exactly one GET without downloading its response body."""
    validate_url(url)
    request = Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    http = opener or build_opener(NoRedirectHandler())

    try:
        response = http.open(request, timeout=timeout_seconds)
        try:
            return response.status
        finally:
            response.close()
    except HTTPError as error:
        # HTTP errors are still valid responses from the protected endpoint.
        error.close()
        return error.code


def parse_args(argv=None):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Send one GET to an HTTPS endpoint you own. This checks reachability through "
            "the attached WAF; it does not exercise attack payloads or rate limits."
        )
    )
    parser.add_argument("--url", required=True, help="Owned HTTPS health or read-only URL")
    parser.add_argument(
        "--expected-status",
        type=int,
        default=200,
        help="Expected HTTP status (default: 200)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Single-request timeout (default: 10)",
    )
    return parser.parse_args(argv)


def main(argv=None, opener=None):
    """Run the smoke test and return a process exit code."""
    args = parse_args(argv)

    if not 100 <= args.expected_status <= 599:
        print("error: --expected-status must be between 100 and 599", file=sys.stderr)
        return 2
    if args.timeout_seconds <= 0:
        print("error: --timeout-seconds must be greater than zero", file=sys.stderr)
        return 2

    try:
        status = request_status(args.url, args.timeout_seconds, opener=opener)
    except (ValueError, URLError, TimeoutError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if status != args.expected_status:
        print(f"unexpected status: got {status}, expected {args.expected_status}")
        return 1

    print(f"smoke test passed: GET returned {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
