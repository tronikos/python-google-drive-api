"""API for Google Drive bound to Home Assistant OAuth."""

from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from typing import Any

import aiohttp

from .auth import AbstractAuth

__all__ = [
    "GoogleDriveApi",
]


# https://developers.google.com/drive/api/reference/rest/v3
DRIVE_API_ABOUT = "https://www.googleapis.com/drive/v3/about"
DRIVE_API_FILES = "https://www.googleapis.com/drive/v3/files"
DRIVE_API_UPLOAD_FILES = "https://www.googleapis.com/upload/drive/v3/files"


class GoogleDriveApi:
    """The Google Drive API client."""

    def __init__(self, auth: AbstractAuth) -> None:
        """Initialize GoogleDriveApi."""
        self._auth = auth

    async def get_user(self, **kwargs: Any) -> dict[str, Any]:
        """Get information about the user, the user's Drive, and system capabilities."""
        return await self._auth.get_json(DRIVE_API_ABOUT, **kwargs)

    async def create_file(self, **kwargs: Any) -> dict[str, Any]:
        """Create a new file (for metadata-only requests)."""
        return await self._auth.post_json(DRIVE_API_FILES, **kwargs)

    async def upload_file(
        self,
        file_metadata: dict[str, Any],
        open_stream: Callable[
            [], Coroutine[Any, Any, AsyncIterator[bytes]] | Awaitable[bytes]
        ],
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        """Upload a new file (for media upload requests)."""
        return await self._auth.multi_part_post(
            DRIVE_API_UPLOAD_FILES, file_metadata, open_stream, **kwargs
        )

    async def resumable_upload_file(
        self,
        file_metadata: dict[str, Any],
        open_stream: Callable[
            [], Coroutine[Any, Any, AsyncIterator[bytes]] | Awaitable[bytes]
        ],
        stream_size: int,
        max_retries: int = 10,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        """Resumable upload a new file (for media upload requests)."""
        return await self._auth.resumable_post(
            DRIVE_API_UPLOAD_FILES,
            file_metadata,
            open_stream,
            stream_size,
            max_retries,
            **kwargs,
        )

    async def get_file_content(
        self, file_id: str, **kwargs: Any
    ) -> aiohttp.ClientResponse:
        """Get a file's content by ID."""
        return await self._auth.get(
            f"{DRIVE_API_FILES}/{file_id}", params={"alt": "media"}, **kwargs
        )

    async def delete_file(self, file_id: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Permanently delete a file owned by the user without moving it to the trash."""
        return await self._auth.delete(f"{DRIVE_API_FILES}/{file_id}", **kwargs)

    async def list_files(self, **kwargs: Any) -> dict[str, Any]:
        """List the user's files."""
        return await self._auth.get_json(DRIVE_API_FILES, **kwargs)
