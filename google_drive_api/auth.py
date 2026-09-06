"""API for Google Drive OAuth.

Callers subclass this to provide an asyncio implementation that refreshes
authentication tokens.
"""

import asyncio
import logging
import random
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import Enum, auto
from http import HTTPStatus
from typing import Any

import aiohttp

from .exceptions import ApiException, ApiForbiddenException, AuthException
from .model import Error, ErrorResponse

__all__ = ["AbstractAuth"]

_LOGGER = logging.getLogger(__name__)


AUTHORIZATION_HEADER = "Authorization"

# https://developers.google.com/drive/api/guides/manage-uploads#resumable
# "308 Resume Incomplete" means the upload is not done yet. It is not a redirect,
# even though aiohttp treats 308 as one.
RESUME_INCOMPLETE = 308

# https://developers.google.com/drive/api/guides/limits#exponential
MAX_BACKOFF_SECONDS = 64

# https://developers.google.com/drive/api/guides/handle-errors
# 403 reasons that are transient and worth retrying, unlike e.g. storageQuotaExceeded.
RATE_LIMIT_REASONS = frozenset({"rateLimitExceeded", "userRateLimitExceeded", "sharingRateLimitExceeded"})

# Statuses that mean the resumable session is gone and a new one must be requested.
SESSION_EXPIRED_STATUSES = frozenset({HTTPStatus.NOT_FOUND, HTTPStatus.GONE})

SUCCESS_STATUSES = frozenset({HTTPStatus.OK, HTTPStatus.CREATED})


def _merge(defaults: dict[str, Any], override: Any) -> dict[str, Any]:
    """Merge caller supplied values on top of the library defaults."""
    if not override:
        return dict(defaults)
    return {**defaults, **override}


def _is_retryable(status: int, error: Error | None) -> bool:
    """Return True if a failed request is worth retrying."""
    # https://developers.google.com/drive/api/guides/handle-errors#5xx-errors
    if status >= HTTPStatus.INTERNAL_SERVER_ERROR:
        return True
    if status == HTTPStatus.TOO_MANY_REQUESTS:
        return True
    # 403 is only transient for rate limits.
    if status == HTTPStatus.FORBIDDEN and error is not None:
        return bool(error.reasons & RATE_LIMIT_REASONS)
    return False


def _retry_after(resp: aiohttp.ClientResponse | None) -> float | None:
    """Return the delay in seconds requested by a Retry-After header, if any."""
    if resp is None or not (value := resp.headers.get("Retry-After")):
        return None
    try:
        return float(max(0, int(value)))
    except ValueError:
        pass
    try:
        retry_at = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        _LOGGER.debug("Ignoring malformed Retry-After header: %s", value)
        return None
    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=timezone.utc)
    return max(0.0, (retry_at - datetime.now(timezone.utc)).total_seconds())


def _backoff_delay(retry: int, resp: aiohttp.ClientResponse | None = None) -> float:
    """Return how long to wait before attempt number `retry`."""
    # https://developers.google.com/drive/api/guides/limits#exponential
    # The random jitter keeps many clients from retrying in lockstep.
    delay: float = min(2.0**retry, MAX_BACKOFF_SECONDS) + random.random()  # noqa: S311
    if (retry_after := _retry_after(resp)) is not None:
        return max(delay, retry_after)
    return delay


def _parse_range(value: str | None) -> int:
    """Return how many bytes the server has received.

    A Range header of bytes=0-42 indicates that the first 43 bytes of the file were
    received. If the response doesn't have a Range header, no bytes have been received.
    """
    if not value:
        return 0
    try:
        return int(value.split("-")[1]) + 1
    except (IndexError, ValueError):
        _LOGGER.debug("resumable: ignoring malformed Range header: %s", value)
        return 0


async def _async_skip_first_n_bytes(data: AsyncIterator[bytes] | bytes, n: int) -> AsyncIterator[bytes]:
    if isinstance(data, bytes):
        yield data[n:]
        return
    skipped = 0
    async for chunk in data:
        remaining_to_skip = n - skipped
        if remaining_to_skip > 0:
            if len(chunk) <= remaining_to_skip:
                skipped += len(chunk)
                continue
            chunk = chunk[remaining_to_skip:]  # noqa: PLW2901
            skipped = n
        yield chunk


class _Outcome(Enum):
    """What a response from a resumable upload session means."""

    COMPLETED = auto()
    """The upload finished and the response is the created file."""

    INCOMPLETE = auto()
    """The server wants more bytes."""

    EXPIRED = auto()
    """The session is gone and a new one has to be requested."""

    RETRY = auto()
    """A transient failure worth another attempt."""


@dataclass
class _Session:
    """State of a resumable upload session, carried across retries."""

    uri: str | None = None
    is_new: bool = False
    """True when the session was just created and has received nothing yet."""

    last_response: aiohttp.ClientResponse | None = None


class AbstractAuth(ABC):
    """Base class for Google Drive authentication library.

    Provides an asyncio interface around the blocking client library.
    """

    def __init__(self, websession: aiohttp.ClientSession) -> None:
        """Initialize the auth."""
        self._websession = websession

    @abstractmethod
    async def async_get_access_token(self) -> str:
        """Return a valid access token."""

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        """Make a request."""
        try:
            access_token = await self.async_get_access_token()
        except aiohttp.ClientError as err:
            raise AuthException(f"Access token failure: {err}") from err
        # Copy so that a headers dict reused by the caller doesn't get pinned to
        # the first access token, which would keep being sent after it expires.
        headers = dict(headers) if headers else {}
        if AUTHORIZATION_HEADER not in headers:
            headers[AUTHORIZATION_HEADER] = f"Bearer {access_token}"
        _LOGGER.debug("request[%s]=%s %s", method, url, kwargs.get("params"))
        if method != "get" and "json" in kwargs:
            _LOGGER.debug("request[post json]=%s", kwargs["json"])
        return await self._websession.request(method, url, **kwargs, headers=headers)

    async def get(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a get request."""
        try:
            resp = await self.request("get", url, **kwargs)
        except aiohttp.ClientError as err:
            raise ApiException(f"Error connecting to API: {err}") from err
        return await AbstractAuth._raise_for_status(resp)

    async def get_json(
        self,
        url: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make a get request and return json response."""
        resp = await self.get(url, **kwargs)
        try:
            result: dict[str, Any] = await resp.json()
        except (aiohttp.ClientError, ValueError) as err:
            # A body that is not json raises JSONDecodeError, which is a ValueError.
            raise ApiException(f"Server returned malformed response: {err}") from err
        _LOGGER.debug("response=%s", result)
        return result

    async def post(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a post request."""
        try:
            resp = await self.request("post", url, **kwargs)
        except aiohttp.ClientError as err:
            raise ApiException(f"Error connecting to API: {err}") from err
        return await AbstractAuth._raise_for_status(resp)

    async def post_json(self, url: str, **kwargs: Any) -> dict[str, Any]:
        """Make a post request and return a json response."""
        resp = await self.post(url, **kwargs)
        try:
            result: dict[str, Any] = await resp.json()
        except (aiohttp.ClientError, ValueError) as err:
            # A body that is not json raises JSONDecodeError, which is a ValueError.
            raise ApiException(f"Server returned malformed response: {err}") from err
        _LOGGER.debug("response=%s", result)
        return result

    async def multi_part_post(
        self,
        url: str,
        json: dict[str, Any],
        open_stream: Callable[[], Coroutine[Any, Any, AsyncIterator[bytes]] | Awaitable[bytes]],
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        """Make a multi part post request."""
        # https://developers.google.com/drive/api/guides/manage-uploads#multipart
        params = _merge({"uploadType": "multipart"}, kwargs.pop("params", None))
        with aiohttp.MultipartWriter() as mpwriter:
            mpwriter.append_json(json, {"Content-Type": "application/json; charset=UTF-8"})
            mpwriter.append(await open_stream())
            # The boundary has to match the writer, so it always wins over the caller.
            headers = {
                **(kwargs.pop("headers", None) or {}),
                "Content-Type": f"multipart/related; boundary={mpwriter.boundary}",
            }
            try:
                resp = await self.request(
                    "post",
                    url,
                    params=params,
                    data=mpwriter,
                    headers=headers,
                    **kwargs,
                )
            except aiohttp.ClientError as err:
                raise ApiException(f"Error connecting to API: {err}") from err
            return await AbstractAuth._raise_for_status(resp)

    async def resumable_post(
        self,
        url: str,
        json: dict[str, Any],
        open_stream: Callable[[], Coroutine[Any, Any, AsyncIterator[bytes]] | Awaitable[bytes]],
        stream_size: int,
        max_retries: int,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        """Make a resumable post request.

        `params` and `headers` apply to the request that initiates the upload session.
        The session URI returned by that request is opaque and takes neither.
        """
        # https://developers.google.com/drive/api/guides/manage-uploads#resumable
        if max_retries < 1:
            raise ValueError(f"max_retries must be at least 1, got {max_retries}")
        if stream_size < 0:
            raise ValueError(f"stream_size cannot be negative, got {stream_size}")
        init_params = _merge({"uploadType": "resumable"}, kwargs.pop("params", None))
        init_headers = _merge(
            {
                "X-Upload-Content-Length": str(stream_size),
                "Content-Type": "application/json; charset=UTF-8",
            },
            kwargs.pop("headers", None),
        )
        session = _Session()
        last_error: Exception | None = None
        for retry in range(max_retries):
            if retry > 0:
                # https://developers.google.com/drive/api/guides/limits#exponential
                delay = _backoff_delay(retry, session.last_response)
                _LOGGER.debug(
                    "resumable: retrying%s after %.1f seconds",
                    "" if session.uri else " from the beginning",
                    delay,
                )
                await asyncio.sleep(delay)
            last_error = None
            try:
                attempt = self._resumable_attempt(
                    session,
                    url=url,
                    json=json,
                    open_stream=open_stream,
                    stream_size=stream_size,
                    init_params=init_params,
                    init_headers=init_headers,
                    **kwargs,
                )
                if (resp := await attempt) is not None:
                    return resp
            except (aiohttp.ClientError, asyncio.TimeoutError, TimeoutError) as err:
                # Before Python 3.11 asyncio.TimeoutError is not the builtin one,
                # so a client timeout would otherwise escape the retry loop.
                last_error = err
                _LOGGER.debug("resumable: retrying: %s", err)
        if last_error is not None:
            raise ApiException(f"Error connecting to API: {last_error}") from last_error
        # Never return a non 2xx response: a 308 here means the upload is unfinished.
        raise ApiException(f"Upload did not complete after {max_retries} attempts")

    async def _resumable_attempt(
        self,
        session: _Session,
        *,
        url: str,
        json: dict[str, Any],
        open_stream: Callable[[], Coroutine[Any, Any, AsyncIterator[bytes]] | Awaitable[bytes]],
        stream_size: int,
        init_params: dict[str, Any],
        init_headers: dict[str, Any],
        **kwargs: Any,
    ) -> aiohttp.ClientResponse | None:
        """Make one attempt at the upload, returning the response once it completes."""
        if session.uri is None:
            await self._initiate_session(
                session,
                url=url,
                json=json,
                init_params=init_params,
                init_headers=init_headers,
                **kwargs,
            )
            if session.uri is None:
                return None

        bytes_received = 0
        if not session.is_new:
            if (resp := await self._request_upload_status(session, stream_size, **kwargs)) is not None:
                return resp
            if session.uri is None or session.last_response is None:
                return None
            if session.last_response.status != RESUME_INCOMPLETE:
                return None
            # If the response doesn't have a Range header, no bytes have been received.
            bytes_received = _parse_range(session.last_response.headers.get("Range"))
            _LOGGER.debug("resumable: bytes_received: %s", bytes_received)
        session.is_new = False

        # Upload content in a single request. This approach is best because it
        # requires fewer requests and results in better performance.
        resp = await self._put_content(
            session,
            open_stream=open_stream,
            bytes_received=bytes_received,
            stream_size=stream_size,
            **kwargs,
        )
        outcome = await self._outcome(resp)
        if outcome is _Outcome.COMPLETED:
            return resp
        _LOGGER.debug("resumable: upload incomplete: %s", resp.status)
        resp.release()
        if outcome is _Outcome.EXPIRED:
            session.uri = None
        return None

    async def _initiate_session(
        self,
        session: _Session,
        *,
        url: str,
        json: dict[str, Any],
        init_params: dict[str, Any],
        init_headers: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Send the initial request that starts a resumable upload session."""
        resp = await self.request(
            "post",
            url,
            params=init_params,
            # Add the metadata to the request body in JSON format
            json=json,
            headers=init_headers,
            **kwargs,
        )
        session.last_response = resp
        if resp.status != HTTPStatus.OK:
            await self._raise_if_not_retryable(resp)
            _LOGGER.debug("resumable: initiating upload failed: %s", resp.status)
            return
        uri = resp.headers.get("Location")
        resp.release()
        if uri is None:
            raise ApiException("Response initiating the upload has no Location header")
        session.uri = uri
        session.is_new = True

    async def _request_upload_status(
        self,
        session: _Session,
        stream_size: int,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse | None:
        """Ask how much of the file the server already has.

        Returns the response if the upload turns out to be complete.
        """
        assert session.uri is not None
        resp = await self._request_session(
            session.uri,
            {"Content-Range": f"bytes */{stream_size}", "Content-Length": "0"},
            **kwargs,
        )
        session.last_response = resp
        outcome = await self._outcome(resp)
        # A 200 OK or 201 Created response indicates that the upload was completed,
        # and no further action is necessary.
        if outcome is _Outcome.COMPLETED:
            return resp
        resp.release()
        if outcome is _Outcome.EXPIRED:
            # The upload must be restarted from the beginning.
            _LOGGER.debug("resumable: upload session expired: %s", resp.status)
            session.uri = None
        elif outcome is _Outcome.RETRY:
            _LOGGER.debug("resumable: upload status failed: %s", resp.status)
        return None

    async def _outcome(self, resp: aiohttp.ClientResponse) -> _Outcome:
        """Classify a response from a resumable upload session."""
        if resp.status in SUCCESS_STATUSES:
            return _Outcome.COMPLETED
        # A 404 Not Found response indicates the upload session has expired.
        if resp.status in SESSION_EXPIRED_STATUSES:
            return _Outcome.EXPIRED
        # A 308 Resume Incomplete response indicates that you must continue to upload.
        if resp.status == RESUME_INCOMPLETE:
            return _Outcome.INCOMPLETE
        await self._raise_if_not_retryable(resp)
        return _Outcome.RETRY

    async def _request_session(
        self,
        session_uri: str,
        headers: dict[str, Any],
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        """Make a request against a resumable upload session URI."""
        return await self.request(
            "put",
            session_uri,
            headers=headers,
            # 308 Resume Incomplete is not a redirect. Following it would fail anyway
            # because a streamed request body cannot be replayed.
            allow_redirects=False,
            **kwargs,
        )

    async def _put_content(
        self,
        session: _Session,
        *,
        open_stream: Callable[[], Coroutine[Any, Any, AsyncIterator[bytes]] | Awaitable[bytes]],
        bytes_received: int,
        stream_size: int,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        """Upload the bytes the server has not received yet."""
        assert session.uri is not None
        remaining = max(0, stream_size - bytes_received)
        headers: dict[str, Any] = {"Content-Length": str(remaining)}
        data = None
        if remaining:
            # For example, Content-Range: bytes 43-1999999 indicates that you send
            # bytes 44 through 2,000,000. An empty upload would produce the invalid
            # "bytes 0--1/0", so the header is only sent when there is content.
            headers["Content-Range"] = f"bytes {bytes_received}-{stream_size - 1}/{stream_size}"
            data = _async_skip_first_n_bytes(await open_stream(), bytes_received)
        resp = await self._request_session(session.uri, headers, data=data, **kwargs)
        session.last_response = resp
        return resp

    async def delete(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a delete request."""
        try:
            resp = await self.request("delete", url, **kwargs)
        except aiohttp.ClientError as err:
            raise ApiException(f"Error connecting to API: {err}") from err
        return await AbstractAuth._raise_for_status(resp)

    @classmethod
    async def _raise_if_not_retryable(cls, resp: aiohttp.ClientResponse) -> None:
        """Raise unless the response is a failure that is worth retrying."""
        error_detail = await cls._error_detail(resp)
        if _is_retryable(resp.status, error_detail):
            return
        cls._raise_error(resp, error_detail)
        # Not an error status, but not one this request can make progress with either.
        raise ApiException(f"Unexpected response from API ({resp.status})")

    @classmethod
    async def _raise_for_status(cls, resp: aiohttp.ClientResponse) -> aiohttp.ClientResponse:
        """Raise exceptions on failure methods."""
        cls._raise_error(resp, await cls._error_detail(resp))
        return resp

    @classmethod
    def _raise_error(cls, resp: aiohttp.ClientResponse, error_detail: Error | None) -> None:
        """Raise the exception that matches an error response."""
        try:
            resp.raise_for_status()
        except aiohttp.ClientResponseError as err:
            error_message = f"{err.message} response from API ({resp.status})"
            if error_detail:
                error_message += f": {error_detail}"
            if err.status == HTTPStatus.FORBIDDEN:
                raise ApiForbiddenException(error_message) from err
            if err.status == HTTPStatus.UNAUTHORIZED:
                raise AuthException(error_message) from err
            raise ApiException(error_message) from err
        except aiohttp.ClientError as err:
            raise ApiException(f"Error from API: {err}") from err

    @classmethod
    async def _error_detail(cls, resp: aiohttp.ClientResponse) -> Error | None:
        """Return an error message string from the API response."""
        if resp.status < 400:
            return None
        try:
            result = await resp.text()
        except aiohttp.ClientError:
            return None
        try:
            error_response = ErrorResponse.from_json(result)
        except (LookupError, ValueError):
            return None
        return error_response.error
