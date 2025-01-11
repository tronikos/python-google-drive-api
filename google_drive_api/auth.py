"""API for Google Drive OAuth.

Callers subclass this to provide an asyncio implementation that refreshes
authentication tokens.
"""

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from http import HTTPStatus
import logging
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
        open_stream: Callable[
            [], Coroutine[Any, Any, AsyncIterator[bytes]] | Awaitable[bytes]
        ],
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        """Make a multi part post request."""
        with aiohttp.MultipartWriter() as mpwriter:
            mpwriter.append_json(json)
            mpwriter.append(await open_stream())
            headers = {
                "Content-Type": f"multipart/related; boundary={mpwriter.boundary}"
            }
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

    async def delete(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a delete request."""
        try:
            resp = await self.request("delete", url, **kwargs)
        except aiohttp.ClientError as err:
            raise ApiException(f"Error connecting to API: {err}") from err
        return await AbstractAuth._raise_for_status(resp)

    @classmethod
    async def _raise_for_status(
        cls, resp: aiohttp.ClientResponse
    ) -> aiohttp.ClientResponse:
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
