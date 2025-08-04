"""API for Google Drive OAuth.

Callers subclass this to provide an asyncio implementation that refreshes
authentication tokens.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from http import HTTPStatus
from typing import Any

import aiohttp

from .exceptions import ApiException, ApiForbiddenException, AuthException
from .model import Error, ErrorResponse

__all__ = ["AbstractAuth"]

_LOGGER = logging.getLogger(__name__)


AUTHORIZATION_HEADER = "Authorization"
ERROR = "error"
STATUS = "status"
MESSAGE = "message"


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
        if headers is None:
            headers = {}
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
        except aiohttp.ClientError as err:
            raise ApiException("Server returned malformed response") from err
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
        except aiohttp.ClientError as err:
            raise ApiException("Server returned malformed response") from err
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
        with aiohttp.MultipartWriter() as mpwriter:
            mpwriter.append_json(json)
            mpwriter.append(await open_stream())
            headers = {"Content-Type": f"multipart/related; boundary={mpwriter.boundary}"}
            try:
                resp = await self.request(
                    "post",
                    url,
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
        """Make a resumable post request."""
        # https://developers.google.com/drive/api/guides/manage-uploads#resumable
        resumable_session_uri = None
        resp: aiohttp.ClientResponse | None = None
        last_error: Exception | None = None
        for retry in range(max_retries):
            if last_error is not None or resp is not None:
                # https://developers.google.com/drive/api/guides/handle-errors#5xx-errors
                # https://developers.google.com/drive/api/guides/limits#exponential
                delay = (
                    min(2**retry, 64) if (last_error is not None or (resp is not None and (resp.status // 100) == 5)) else 0
                )
                _LOGGER.debug(
                    "resumable: retrying: %s%s after %s seconds",
                    last_error or (resp is not None and resp.status),
                    " from the beginning" if resumable_session_uri is None else "",
                    delay,
                )
                await asyncio.sleep(delay)
            last_error = None
            try:
                if resumable_session_uri is None:
                    # Send the initial request to initiate a resumable upload
                    resp = await self.request(
                        "post",
                        url,
                        params={"uploadType": "resumable"},
                        # Add the metadata to the request body in JSON format
                        json=json,
                        headers={"X-Upload-Content-Length": str(stream_size)},
                        **kwargs,
                    )
                    if resp.status != HTTPStatus.OK:
                        _LOGGER.debug("resumable: initiating upload failed: %s", resp.status)
                        continue
                    resumable_session_uri = resp.headers["Location"]

                bytes_received = 0
                if retry > 0:
                    # Request the upload status
                    resp = await self.request(
                        "put",
                        resumable_session_uri,
                        headers={"Content-Range": f"bytes */{stream_size}"},
                        **kwargs,
                    )
                    # A 200 OK or 201 Created response indicates that the upload was completed,
                    # and no further action is necessary.
                    if resp.status in [HTTPStatus.OK, HTTPStatus.CREATED]:
                        return resp
                    # A 404 Not Found response indicates the upload session has expired
                    # and the upload must be restarted from the beginning.
                    if resp.status == HTTPStatus.NOT_FOUND:
                        _LOGGER.debug("resumable: upload status not found")
                        resumable_session_uri = None
                        continue
                    # A 308 Resume Incomplete response indicates that you must continue to upload the file.
                    if resp.status != 308:
                        _LOGGER.debug("resumable: upload status failed: %s", resp.status)
                        continue
                    # If the response doesn't have a Range header, no bytes have been received.
                    # A Range header of bytes=0-42 indicates that the first 43 bytes of the file were received
                    # and that the next chunk to upload would start with byte 44.
                    if "Range" in resp.headers:
                        bytes_received = int(resp.headers["Range"].split("-")[1]) + 1
                        _LOGGER.debug("resumable: bytes_received: %s", bytes_received)

                # Upload content in a single request.
                # This approach is best because it requires fewer requests and results in better performance.
                resp = await self.request(
                    "put",
                    resumable_session_uri,
                    headers={
                        # For example, Content-Range: bytes 43-1999999 indicates that you send bytes 44 through 2,000,000.
                        "Content-Range": f"bytes {bytes_received}-{stream_size - 1}/{stream_size}",
                        "Content-Length": str(stream_size - bytes_received),
                    },
                    data=_async_skip_first_n_bytes(await open_stream(), bytes_received),
                    **kwargs,
                )
                if resp.status in [HTTPStatus.OK, HTTPStatus.CREATED]:
                    return resp
            except (aiohttp.ClientError, TimeoutError) as err:
                last_error = err
                _LOGGER.debug("resumable: retrying: %s", err)
                continue
        if last_error is not None:
            raise ApiException(f"Error connecting to API: {last_error}") from last_error
        assert resp
        return await AbstractAuth._raise_for_status(resp)

    async def delete(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a delete request."""
        try:
            resp = await self.request("delete", url, **kwargs)
        except aiohttp.ClientError as err:
            raise ApiException(f"Error connecting to API: {err}") from err
        return await AbstractAuth._raise_for_status(resp)

    @classmethod
    async def _raise_for_status(cls, resp: aiohttp.ClientResponse) -> aiohttp.ClientResponse:
        """Raise exceptions on failure methods."""
        error_detail = await cls._error_detail(resp)
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
        return resp

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
