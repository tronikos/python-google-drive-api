"""Tests for Google Drive authentication and the resumable upload protocol."""

from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

import aiohttp
import pytest
from aiohttp import web

from google_drive_api.auth import (
    MAX_BACKOFF_SECONDS,
    RESUME_INCOMPLETE,
    AbstractAuth,
    _backoff_delay,
    _parse_range,
    _retry_after,
)
from google_drive_api.exceptions import ApiException, ApiForbiddenException, AuthException
from tests.conftest import FakeAuth, FakeDrive, open_bytes, open_iterator


def drive_error(status: int, reason: str | None = None, message: str = "boom") -> web.Response:
    """Return an error response in the format the Drive API uses."""
    # https://developers.google.com/drive/api/guides/handle-errors
    error: dict[str, Any] = {"code": status, "message": message}
    if reason is not None:
        error["errors"] = [{"domain": "global", "reason": reason, "message": message}]
    return web.json_response({"error": error}, status=status)


def resume_incomplete(received: int | None = None, **kwargs: Any) -> web.Response:
    """Return a 308 Resume Incomplete response."""
    headers = {} if received is None else {"Range": f"bytes=0-{received - 1}"}
    return web.Response(status=RESUME_INCOMPLETE, headers=headers, **kwargs)


def content_ranges(drive: FakeDrive) -> list[str | None]:
    """Return the Content-Range header of every recorded request."""
    return [req.headers.get("Content-Range") for req in drive.requests]


# --- request() ---------------------------------------------------------------


async def test_request_does_not_mutate_caller_headers(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test that a reused headers dict does not pin the first access token."""
    drive.queue(web.Response(), web.Response(), web.Response())
    headers = {"X-Custom": "1"}

    for _ in range(3):
        await auth.get(drive.url, headers=headers)

    assert headers == {"X-Custom": "1"}
    sent = [req.headers["Authorization"] for req in drive.requests]
    assert sent == ["Bearer token-1", "Bearer token-2", "Bearer token-3"]


async def test_request_keeps_caller_authorization(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test that an explicit Authorization header wins."""
    drive.queue(web.Response())

    await auth.get(drive.url, headers={"Authorization": "Bearer mine"})

    assert drive.requests[0].headers["Authorization"] == "Bearer mine"


async def test_request_access_token_failure(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test that a failure to refresh the token raises AuthException."""
    auth.error = aiohttp.ClientError("no token")

    with pytest.raises(AuthException, match="Access token failure"):
        await auth.get(drive.url)


async def test_request_connection_error(auth: FakeAuth) -> None:
    """Test that a connection failure raises ApiException."""
    with pytest.raises(ApiException, match="Error connecting to API"):
        await auth.get("http://127.0.0.1:1/nope")


# --- verbs and error mapping -------------------------------------------------


async def test_get_json(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test a get request returning json."""
    drive.queue(web.json_response({"a": 1}))

    assert await auth.get_json(drive.url) == {"a": 1}


async def test_post_json(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test a post request returning json."""
    drive.queue(web.json_response({"a": 1}))

    assert await auth.post_json(drive.url, json={"b": 2}) == {"a": 1}
    assert drive.requests[0].body == b'{"b": 2}'


async def test_delete(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test a delete request."""
    drive.queue(web.Response(status=204))

    assert (await auth.delete(drive.url)).status == 204


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (400, ApiException),
        (401, AuthException),
        (403, ApiForbiddenException),
        (404, ApiException),
        (500, ApiException),
    ],
)
async def test_error_status_mapping(auth: FakeAuth, drive: FakeDrive, status: int, expected: type[Exception]) -> None:
    """Test that each error status maps to the documented exception."""
    drive.queue(drive_error(status, message="nope"))

    with pytest.raises(expected, match="nope"):
        await auth.get(drive.url)


@pytest.mark.parametrize("body", ["<html>oops</html>", "null", "[]", '{"error": "text"}', ""])
async def test_error_detail_survives_malformed_body(auth: FakeAuth, drive: FakeDrive, body: str) -> None:
    """Test that an unparsable error body still raises the right exception."""
    drive.queue(web.Response(status=500, text=body))

    with pytest.raises(ApiException, match=r"\(500\)"):
        await auth.get(drive.url)


async def test_error_detail_includes_reasons(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test that the machine readable reason reaches the error message."""
    drive.queue(drive_error(403, "storageQuotaExceeded", "The user's Drive storage quota"))

    with pytest.raises(ApiForbiddenException, match="storageQuotaExceeded"):
        await auth.get(drive.url)


async def test_get_json_malformed_response(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test that a body that is not json raises ApiException."""
    drive.queue(web.Response(text="not json", content_type="application/json"))

    with pytest.raises(ApiException, match="malformed"):
        await auth.get_json(drive.url)


# --- multipart ---------------------------------------------------------------


async def test_multi_part_post_with_iterator(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test a multipart upload whose stream is an async iterator."""
    drive.queue(web.json_response({"id": "1"}))

    await auth.multi_part_post(drive.url, {"name": "b"}, open_iterator(b"hello world"))

    assert b"hello world" in drive.requests[0].body


async def test_multi_part_post_connection_error(auth: FakeAuth) -> None:
    """Test that a connection failure during a multipart upload raises ApiException."""
    with pytest.raises(ApiException, match="Error connecting to API"):
        await auth.multi_part_post("http://127.0.0.1:1/nope", {}, open_bytes(b"x"))


async def test_multi_part_post_keeps_boundary(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test that caller headers cannot break the multipart boundary."""
    drive.queue(web.json_response({"id": "1"}))

    await auth.multi_part_post(drive.url, {"name": "b"}, open_bytes(b"x"), headers={"Content-Type": "text/plain"})

    assert drive.requests[0].headers["Content-Type"].startswith("multipart/related; boundary=")


# --- resumable upload: arguments ---------------------------------------------


@pytest.mark.parametrize(("max_retries", "stream_size"), [(0, 1), (-1, 1), (1, -1)])
async def test_resumable_post_rejects_bad_arguments(
    auth: FakeAuth, drive: FakeDrive, max_retries: int, stream_size: int
) -> None:
    """Test that invalid arguments raise ValueError instead of asserting."""
    with pytest.raises(ValueError, match=r"max_retries|stream_size"):
        await auth.resumable_post(drive.url, {}, open_bytes(b"x"), stream_size, max_retries)


# --- resumable upload: happy paths -------------------------------------------


@pytest.mark.parametrize("open_stream", [open_bytes, open_iterator])
async def test_resumable_post(auth: FakeAuth, drive: FakeDrive, open_stream: Any) -> None:
    """Test a resumable upload that succeeds on the first attempt."""
    drive.queue(drive.session_started(), web.json_response({"id": "file-id"}))

    resp = await auth.resumable_post(drive.url, {"name": "b"}, open_stream(b"hello"), 5, 3)

    assert resp.status == 200
    initiate, upload = drive.requests
    assert initiate.query == {"uploadType": "resumable"}
    assert initiate.headers["X-Upload-Content-Length"] == "5"
    assert initiate.headers["Content-Type"] == "application/json; charset=UTF-8"
    assert upload.headers["Content-Range"] == "bytes 0-4/5"
    assert upload.headers["Content-Length"] == "5"
    assert upload.body == b"hello"


async def test_resumable_post_created(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test that 201 Created is also a success."""
    drive.queue(drive.session_started(), web.Response(status=201))

    assert (await auth.resumable_post(drive.url, {}, open_bytes(b"x"), 1, 3)).status == 201


async def test_resumable_post_empty_file(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test that an empty file does not send an invalid Content-Range."""
    # Sending "bytes 0--1/0" would be rejected, so the header is omitted.
    drive.queue(drive.session_started(), web.json_response({"id": "file-id"}))

    resp = await auth.resumable_post(drive.url, {}, open_bytes(b""), 0, 3)

    assert resp.status == 200
    upload = drive.requests[1]
    assert "Content-Range" not in upload.headers
    assert upload.headers["Content-Length"] == "0"
    assert upload.body == b""


async def test_resumable_post_caller_headers_apply_to_initiation_only(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test that caller headers do not leak onto the session URI."""
    drive.queue(drive.session_started(), web.Response(status=200))

    await auth.resumable_post(drive.url, {}, open_bytes(b"x"), 1, 3, headers={"X-Custom": "yes"})

    assert drive.requests[0].headers["X-Custom"] == "yes"
    assert "X-Custom" not in drive.requests[1].headers


# --- resumable upload: resuming ----------------------------------------------


async def test_resumable_post_resumes_from_range(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that an incomplete upload resumes from the byte the server reports."""
    drive.queue(
        drive.session_started(),
        resume_incomplete(),  # content PUT: only part of the file arrived
        resume_incomplete(received=3),  # status probe
        web.json_response({"id": "file-id"}),  # resumed content PUT
    )

    resp = await auth.resumable_post(drive.url, {}, open_iterator(b"hello"), 5, 3)

    assert resp.status == 200
    assert backoffs == [1]
    assert content_ranges(drive) == [None, "bytes 0-4/5", "bytes */5", "bytes 3-4/5"]
    assert drive.requests[3].body == b"lo"
    assert drive.requests[3].headers["Content-Length"] == "2"


async def test_resumable_post_does_not_follow_308_redirect(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test that a 308 carrying a Location is not treated as a redirect.

    aiohttp classifies 308 as a redirect and cannot replay a streamed body, so
    following it would fail the upload instead of resuming it.
    """
    drive.queue(
        drive.session_started(),
        web.Response(status=RESUME_INCOMPLETE, headers={"Location": "/elsewhere"}),
        resume_incomplete(received=5),
        web.json_response({"id": "file-id"}),
    )

    with pytest.MonkeyPatch.context():
        resp = await auth.resumable_post(drive.url, {}, open_bytes(b"hello"), 5, 4)

    assert resp.status == 200
    assert [req.path for req in drive.requests] == ["/", "/session", "/session", "/session"]


async def test_resumable_post_status_probe_reports_complete(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that a completed upload is detected by the status probe."""
    drive.queue(
        drive.session_started(),
        web.Response(status=503),
        web.json_response({"id": "file-id"}),  # status probe says it is already done
    )

    resp = await auth.resumable_post(drive.url, {}, open_bytes(b"hello"), 5, 3)

    assert resp.status == 200
    assert content_ranges(drive) == [None, "bytes 0-4/5", "bytes */5"]


async def test_resumable_post_ignores_malformed_range(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that a malformed Range header restarts from the first byte."""
    drive.queue(
        drive.session_started(),
        web.Response(status=503),
        web.Response(status=RESUME_INCOMPLETE, headers={"Range": "bytes=0"}),
        web.json_response({"id": "file-id"}),
    )

    resp = await auth.resumable_post(drive.url, {}, open_bytes(b"hello"), 5, 3)

    assert resp.status == 200
    assert drive.requests[3].headers["Content-Range"] == "bytes 0-4/5"


async def test_resumable_post_server_has_everything(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test the finalizing request when the server already has every byte."""
    drive.queue(
        drive.session_started(),
        web.Response(status=503),
        resume_incomplete(received=5),
        web.json_response({"id": "file-id"}),
    )

    resp = await auth.resumable_post(drive.url, {}, open_bytes(b"hello"), 5, 3)

    assert resp.status == 200
    final = drive.requests[3]
    assert "Content-Range" not in final.headers
    assert final.headers["Content-Length"] == "0"


# --- resumable upload: session expiry ----------------------------------------


@pytest.mark.parametrize("status", [404, 410])
async def test_resumable_post_restarts_expired_session(
    auth: FakeAuth, drive: FakeDrive, backoffs: list[int], status: int
) -> None:
    """Test that an expired session is replaced with a new one."""
    drive.queue(
        drive.session_started(),
        web.Response(status=status),  # content PUT: session is gone
        drive.session_started(),  # a new session is requested
        web.json_response({"id": "file-id"}),
    )

    resp = await auth.resumable_post(drive.url, {}, open_bytes(b"hello"), 5, 3)

    assert resp.status == 200
    # A brand new session has received nothing, so it is not probed for status.
    assert content_ranges(drive) == [None, "bytes 0-4/5", None, "bytes 0-4/5"]


async def test_resumable_post_expired_session_on_status_probe(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that the status probe also detects an expired session."""
    drive.queue(
        drive.session_started(),
        web.Response(status=503),
        web.Response(status=404),  # status probe: session is gone
        drive.session_started(),
        web.json_response({"id": "file-id"}),
    )

    resp = await auth.resumable_post(drive.url, {}, open_bytes(b"hello"), 5, 4)

    assert resp.status == 200


# --- resumable upload: retry policy ------------------------------------------


async def test_resumable_post_retries_5xx(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that a server error is retried with backoff."""
    drive.queue(
        web.Response(status=503),  # initiating the session failed
        drive.session_started(),
        web.json_response({"id": "file-id"}),
    )

    resp = await auth.resumable_post(drive.url, {}, open_bytes(b"x"), 1, 3)

    assert resp.status == 200
    assert backoffs == [1]


async def test_resumable_post_retries_rate_limit(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that a 403 rate limit is retried rather than raised."""
    drive.queue(
        drive.session_started(),
        drive_error(403, "userRateLimitExceeded"),
        resume_incomplete(),
        web.json_response({"id": "file-id"}),
    )

    resp = await auth.resumable_post(drive.url, {}, open_bytes(b"x"), 1, 4)

    assert resp.status == 200
    assert backoffs == [1]


async def test_resumable_post_retries_too_many_requests(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that 429 is retried."""
    drive.queue(
        drive.session_started(),
        drive_error(429, "rateLimitExceeded"),
        resume_incomplete(),
        web.json_response({"id": "file-id"}),
    )

    assert (await auth.resumable_post(drive.url, {}, open_bytes(b"x"), 1, 4)).status == 200


@pytest.mark.parametrize(
    "case",
    [
        (403, "storageQuotaExceeded", ApiForbiddenException),
        (403, None, ApiForbiddenException),
        (400, "badRequest", ApiException),
        (401, "authError", AuthException),
    ],
)
async def test_resumable_post_fails_fast(
    auth: FakeAuth,
    drive: FakeDrive,
    backoffs: list[int],
    case: tuple[int, str | None, type[Exception]],
) -> None:
    """Test that a permanent error is raised instead of exhausting the retries."""
    status, reason, expected = case
    drive.queue(drive.session_started(), drive_error(status, reason))

    with pytest.raises(expected, match="boom"):
        await auth.resumable_post(drive.url, {}, open_bytes(b"x"), 1, 20)

    assert len(drive.requests) == 2
    assert backoffs == []


async def test_resumable_post_fails_fast_on_initiation(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that a permanent error initiating the session is raised immediately."""
    drive.queue(drive_error(403, "storageQuotaExceeded"))

    with pytest.raises(ApiForbiddenException, match="storageQuotaExceeded"):
        await auth.resumable_post(drive.url, {}, open_bytes(b"x"), 1, 20)

    assert len(drive.requests) == 1


async def test_resumable_post_unexpected_success_status(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that an unusable non error response is reported rather than retried."""
    drive.queue(web.Response(status=204))

    with pytest.raises(ApiException, match=r"Unexpected response from API \(204\)"):
        await auth.resumable_post(drive.url, {}, open_bytes(b"x"), 1, 20)


# --- resumable upload: failure paths -----------------------------------------


async def test_resumable_post_never_returns_incomplete(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that exhausting the retries on a 308 raises instead of faking success."""
    drive.handler = lambda request: _always_incomplete(drive, request)

    with pytest.raises(ApiException, match="did not complete after 3 attempts"):
        await auth.resumable_post(drive.url, {}, open_bytes(b"hello"), 5, 3)


async def _always_incomplete(drive: FakeDrive, request: web.Request) -> web.StreamResponse:
    """Return a session that never finishes."""
    if request.path == "/":
        return drive.session_started()
    return resume_incomplete()


async def test_resumable_post_missing_location(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test that a session response without a Location header raises."""
    drive.queue(web.Response(status=200))

    with pytest.raises(ApiException, match="no Location header"):
        await auth.resumable_post(drive.url, {}, open_bytes(b"x"), 1, 3)


async def test_resumable_post_connection_error(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that a connection failure is retried and then reported."""
    with pytest.raises(ApiException, match="Error connecting to API"):
        await auth.resumable_post("http://127.0.0.1:1/nope", {}, open_bytes(b"x"), 1, 3)

    assert backoffs == [1, 2]


async def test_resumable_post_recovers_from_connection_error(
    auth: FakeAuth, drive: FakeDrive, backoffs: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that a timeout mid upload is retried against the same session."""
    drive.queue(
        drive.session_started(),
        resume_incomplete(received=2),
        web.json_response({"id": "file-id"}),
    )
    calls = {"n": 0}
    real_request = AbstractAuth.request

    async def flaky(self: AbstractAuth, method: str, url: str, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 2:
            raise TimeoutError
        return await real_request(self, method, url, **kwargs)

    monkeypatch.setattr(AbstractAuth, "request", flaky)

    resp = await auth.resumable_post(drive.url, {}, open_bytes(b"hello"), 5, 3)

    assert resp.status == 200
    assert drive.requests[-1].headers["Content-Range"] == "bytes 2-4/5"


# --- backoff helpers ---------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, 0), ("", 0), ("bytes=0-42", 43), ("bytes=0", 0), ("bytes=0-x", 0), ("garbage", 0)],
)
def test_parse_range(value: str | None, expected: int) -> None:
    """Test parsing the Range header of a 308 response."""
    assert _parse_range(value) == expected


def test_backoff_delay_is_exponential_and_jittered() -> None:
    """Test that the delay grows exponentially, is capped, and carries jitter."""
    # https://developers.google.com/drive/api/guides/limits#exponential
    assert 1 <= _backoff_delay(0) < 2
    assert 2 <= _backoff_delay(1) < 3
    assert 8 <= _backoff_delay(3) < 9
    assert MAX_BACKOFF_SECONDS <= _backoff_delay(30) < MAX_BACKOFF_SECONDS + 1
    assert len({_backoff_delay(1) for _ in range(20)}) > 1


class FakeResponse:
    """A stand in for a response carrying only headers."""

    def __init__(self, **headers: str) -> None:
        """Initialize FakeResponse."""
        self.headers = headers


def test_retry_after_seconds() -> None:
    """Test a Retry-After header expressed in seconds."""
    assert _retry_after(FakeResponse(**{"Retry-After": "120"})) == 120  # type: ignore[arg-type]
    assert _retry_after(FakeResponse(**{"Retry-After": "-5"})) == 0  # type: ignore[arg-type]


def test_retry_after_http_date() -> None:
    """Test a Retry-After header expressed as an HTTP date."""
    soon = datetime.now(timezone.utc) + timedelta(seconds=30)
    header = soon.strftime("%a, %d %b %Y %H:%M:%S GMT")

    delay = _retry_after(FakeResponse(**{"Retry-After": header}))  # type: ignore[arg-type]

    assert delay is not None
    assert 25 <= delay <= 31


def test_retry_after_past_date() -> None:
    """Test that a Retry-After date in the past does not go negative."""
    assert _retry_after(FakeResponse(**{"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"})) == 0  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["not a date", ""])
def test_retry_after_malformed(value: str) -> None:
    """Test that a malformed Retry-After header is ignored."""
    assert _retry_after(FakeResponse(**{"Retry-After": value})) is None  # type: ignore[arg-type]


def test_retry_after_absent() -> None:
    """Test that a missing Retry-After header is ignored."""
    assert _retry_after(None) is None
    assert _retry_after(FakeResponse()) is None  # type: ignore[arg-type]


def test_backoff_delay_honors_retry_after() -> None:
    """Test that a long Retry-After wins over the exponential delay."""
    resp = FakeResponse(**{"Retry-After": "300"})

    assert _backoff_delay(1, resp) == 300  # type: ignore[arg-type]
    # ... but a short one does not shorten the backoff.
    assert _backoff_delay(5, FakeResponse(**{"Retry-After": "1"})) >= 32  # type: ignore[arg-type]


# --- remaining error plumbing ------------------------------------------------


async def test_post_connection_error(auth: FakeAuth) -> None:
    """Test that a connection failure on post raises ApiException."""
    with pytest.raises(ApiException, match="Error connecting to API"):
        await auth.post("http://127.0.0.1:1/nope")


async def test_delete_connection_error(auth: FakeAuth) -> None:
    """Test that a connection failure on delete raises ApiException."""
    with pytest.raises(ApiException, match="Error connecting to API"):
        await auth.delete("http://127.0.0.1:1/nope")


async def test_post_json_malformed_response(auth: FakeAuth, drive: FakeDrive) -> None:
    """Test that a post returning a body that is not json raises ApiException."""
    drive.queue(web.Response(text="not json", content_type="application/json"))

    with pytest.raises(ApiException, match="malformed"):
        await auth.post_json(drive.url)


async def test_resumable_post_retries_failed_status_probe(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that a server error on the status probe is retried."""
    drive.queue(
        drive.session_started(),
        web.Response(status=503),  # content PUT
        web.Response(status=503),  # status probe
        resume_incomplete(received=2),  # status probe
        web.json_response({"id": "file-id"}),
    )

    resp = await auth.resumable_post(drive.url, {}, open_bytes(b"hello"), 5, 4)

    assert resp.status == 200
    assert backoffs == [1, 2]
    assert drive.requests[-1].headers["Content-Range"] == "bytes 2-4/5"


async def test_resumable_post_fails_fast_on_status_probe(auth: FakeAuth, drive: FakeDrive, backoffs: list[int]) -> None:
    """Test that a permanent error on the status probe is raised."""
    drive.queue(
        drive.session_started(),
        web.Response(status=503),
        drive_error(400, "badRequest"),  # status probe
    )

    with pytest.raises(ApiException, match="boom"):
        await auth.resumable_post(drive.url, {}, open_bytes(b"hello"), 5, 20)

    assert len(drive.requests) == 3


def test_retry_after_naive_http_date() -> None:
    """Test a Retry-After date that carries no timezone."""
    delay = _retry_after(FakeResponse(**{"Retry-After": "Wed, 21 Oct 2015 07:28:00"}))  # type: ignore[arg-type]

    assert delay == 0


class BrokenResponse:
    """A response whose body and status checks fail."""

    status = 500
    headers: ClassVar[dict[str, str]] = {}

    def raise_for_status(self) -> None:
        """Raise a client error that is not a response error."""
        raise aiohttp.ClientError("connection reset")

    async def text(self) -> str:
        """Fail to read the body."""
        raise aiohttp.ClientError("connection reset")


async def test_error_detail_unreadable_body() -> None:
    """Test that an unreadable error body is reported as a plain API error."""
    with pytest.raises(ApiException, match="Error from API: connection reset"):
        await AbstractAuth._raise_for_status(BrokenResponse())  # type: ignore[arg-type]
