"""Fixtures for Google Drive API tests."""

from collections.abc import AsyncIterator, Callable, Coroutine
from typing import Any

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient

from google_drive_api.api import GoogleDriveApi
from google_drive_api.auth import AbstractAuth

Handler = Callable[[web.Request], Coroutine[Any, Any, web.StreamResponse]]
Client = TestClient[web.Request, web.Application]


class FakeAuth(AbstractAuth):
    """Auth that hands out a new token on every request."""

    def __init__(self, websession: Any) -> None:
        """Initialize FakeAuth."""
        super().__init__(websession)
        self.tokens: list[str] = []
        self.error: Exception | None = None

    async def async_get_access_token(self) -> str:
        """Return a valid access token."""
        if self.error is not None:
            raise self.error
        self.tokens.append(f"token-{len(self.tokens) + 1}")
        return self.tokens[-1]


class RecordedRequest:
    """A request captured by the fake Google Drive server."""

    def __init__(self, request: web.Request, body: bytes) -> None:
        """Initialize RecordedRequest."""
        self.method = request.method
        self.path = request.path
        self.query = dict(request.query)
        self.headers = dict(request.headers)
        self.body = body

    def __repr__(self) -> str:
        """Return a readable representation, used when a test fails."""
        return f"<{self.method} {self.path} {self.query}>"


class FakeDrive:
    """A fake Google Drive server that replays queued responses."""

    def __init__(self) -> None:
        """Initialize FakeDrive."""
        self.requests: list[RecordedRequest] = []
        self.responses: list[web.StreamResponse] = []
        self.handler: Handler | None = None
        self.url = ""

    def queue(self, *responses: web.StreamResponse) -> None:
        """Queue responses to be returned in order."""
        self.responses.extend(responses)

    @property
    def session_url(self) -> str:
        """Return the URL of the resumable upload session."""
        return f"{self.url}/session"

    def session_started(self, **kwargs: Any) -> web.Response:
        """Return the response that initiates a resumable upload session."""
        return web.Response(status=200, headers={"Location": self.session_url}, **kwargs)

    async def handle(self, request: web.Request) -> web.StreamResponse:
        """Record a request and return the next queued response."""
        self.requests.append(RecordedRequest(request, await request.read()))
        if self.handler is not None:
            return await self.handler(request)
        assert self.responses, f"no response queued for {request.method} {request.path}"
        return self.responses.pop(0)


@pytest.fixture
def backoffs(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record the retry attempts and skip the backoff delay.

    Patching the calculation rather than asyncio.sleep keeps the test server
    running at full speed. The calculation itself is unit tested separately.
    """
    attempts: list[int] = []

    def fake_backoff(retry: int, resp: Any = None) -> float:
        attempts.append(retry)
        return 0.0

    monkeypatch.setattr("google_drive_api.auth._backoff_delay", fake_backoff)
    return attempts


@pytest.fixture
async def client(aiohttp_client: Any) -> Client:
    """Return a test client for the fake Google Drive server."""
    fake = FakeDrive()
    app = web.Application()
    app["fake"] = fake
    app.router.add_route("*", "/{tail:.*}", fake.handle)
    created: Client = await aiohttp_client(app)
    return created


@pytest.fixture
def drive(client: Client) -> FakeDrive:
    """Return the fake Google Drive server."""
    fake: FakeDrive = client.app["fake"]
    fake.url = str(client.make_url("")).rstrip("/")
    return fake


@pytest.fixture
def auth(client: Client, drive: FakeDrive) -> FakeAuth:
    """Return an AbstractAuth talking to the fake server."""
    return FakeAuth(client.session)


@pytest.fixture
def api(auth: FakeAuth) -> GoogleDriveApi:
    """Return a GoogleDriveApi talking to the fake server."""
    return GoogleDriveApi(auth)


async def read_stream(data: bytes) -> AsyncIterator[bytes]:
    """Yield the data in small chunks, like a real upload stream."""
    for i in range(0, len(data), 2):
        yield data[i : i + 2]


def open_bytes(data: bytes) -> Callable[[], Coroutine[Any, Any, bytes]]:
    """Return an open_stream that resolves to bytes."""

    async def _open() -> bytes:
        return data

    return _open


def open_iterator(data: bytes) -> Callable[[], Coroutine[Any, Any, AsyncIterator[bytes]]]:
    """Return an open_stream that resolves to an async iterator."""

    async def _open() -> AsyncIterator[bytes]:
        return read_stream(data)

    return _open
