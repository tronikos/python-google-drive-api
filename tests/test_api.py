"""Tests for the Google Drive API client."""

import pytest
from aiohttp import web

from google_drive_api.api import GoogleDriveApi
from tests.conftest import FakeDrive, open_bytes


@pytest.fixture(autouse=True)
def _point_api_at_fake(monkeypatch: pytest.MonkeyPatch, drive: FakeDrive) -> None:
    """Point the API endpoints at the fake server."""
    monkeypatch.setattr("google_drive_api.api.DRIVE_API_ABOUT", f"{drive.url}/about")
    monkeypatch.setattr("google_drive_api.api.DRIVE_API_FILES", f"{drive.url}/files")
    monkeypatch.setattr("google_drive_api.api.DRIVE_API_UPLOAD_FILES", f"{drive.url}/upload")


async def test_get_user(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test getting information about the user."""
    drive.queue(web.json_response({"user": {"emailAddress": "a@b.com"}}))

    res = await api.get_user(params={"fields": "user(emailAddress)"})

    assert res == {"user": {"emailAddress": "a@b.com"}}
    assert drive.requests[0].path == "/about"
    assert drive.requests[0].query == {"fields": "user(emailAddress)"}


async def test_create_file(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test creating a metadata only file."""
    drive.queue(web.json_response({"id": "folder-id"}))

    res = await api.create_file(json={"name": "Home Assistant"})

    assert res == {"id": "folder-id"}
    assert drive.requests[0].method == "POST"
    assert drive.requests[0].path == "/files"


async def test_delete_file(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test deleting a file."""
    drive.queue(web.Response(status=204))

    await api.delete_file("file-id")

    assert drive.requests[0].method == "DELETE"
    assert drive.requests[0].path == "/files/file-id"


async def test_list_files(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test listing files."""
    drive.queue(web.json_response({"files": [{"id": "1"}]}))

    res = await api.list_files(params={"q": "trashed=false"})

    assert res == {"files": [{"id": "1"}]}
    assert drive.requests[0].query == {"q": "trashed=false"}


async def test_list_all_files_follows_page_token(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test that pagination follows nextPageToken until it is absent."""
    drive.queue(
        web.json_response({"files": [{"id": "1"}], "nextPageToken": "page-2"}),
        web.json_response({"files": [{"id": "2"}], "nextPageToken": "page-3"}),
        web.json_response({"files": [{"id": "3"}]}),
    )

    files = [file async for file in api.list_all_files(params={"q": "trashed=false"})]

    assert files == [{"id": "1"}, {"id": "2"}, {"id": "3"}]
    assert [req.query.get("pageToken") for req in drive.requests] == [None, "page-2", "page-3"]
    assert all(req.query["q"] == "trashed=false" for req in drive.requests)


async def test_list_all_files_without_files_key(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test that a response without a files key yields nothing."""
    drive.queue(web.json_response({}))

    assert [file async for file in api.list_all_files()] == []


async def test_get_file_content(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test that downloading a file asks for the media alt."""
    drive.queue(web.Response(body=b"backup"))

    resp = await api.get_file_content("file-id")

    assert await resp.read() == b"backup"
    assert drive.requests[0].query == {"alt": "media"}


async def test_get_file_content_merges_caller_params(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test that caller params do not collide with the alt=media param."""
    drive.queue(web.Response(body=b"backup"))

    await api.get_file_content("file-id", params={"acknowledgeAbuse": "true"})

    assert drive.requests[0].query == {"alt": "media", "acknowledgeAbuse": "true"}


async def test_upload_file(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test that a multipart upload sends metadata and content together."""
    drive.queue(web.json_response({"id": "file-id"}))

    await api.upload_file({"name": "backup.tar"}, open_bytes(b"hello"))

    request = drive.requests[0]
    assert request.path == "/upload"
    # https://developers.google.com/drive/api/guides/manage-uploads#multipart
    assert request.query == {"uploadType": "multipart"}
    assert request.headers["Content-Type"].startswith("multipart/related; boundary=")
    assert b'{"name": "backup.tar"}' in request.body
    assert b"application/json; charset=UTF-8" in request.body
    assert b"hello" in request.body


async def test_upload_file_merges_caller_params(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test that caller params are kept alongside the upload type."""
    drive.queue(web.json_response({"id": "file-id"}))

    await api.upload_file({"name": "b"}, open_bytes(b"x"), params={"fields": "id"})

    assert drive.requests[0].query == {"uploadType": "multipart", "fields": "id"}


async def test_upload_file_raises_on_error(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test that a failed multipart upload raises."""
    drive.queue(web.json_response({"error": {"code": 400, "message": "bad"}}, status=400))

    with pytest.raises(Exception, match="bad"):
        await api.upload_file({"name": "b"}, open_bytes(b"x"))


async def test_resumable_upload_file(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test a resumable upload through the public API."""
    drive.queue(drive.session_started(), web.json_response({"id": "file-id"}))

    resp = await api.resumable_upload_file({"name": "b"}, open_bytes(b"hello"), 5)

    assert resp.status == 200
    assert drive.requests[0].query == {"uploadType": "resumable"}


async def test_resumable_upload_file_merges_caller_params(api: GoogleDriveApi, drive: FakeDrive) -> None:
    """Test that caller params no longer collide with the upload type."""
    drive.queue(drive.session_started(), web.json_response({"id": "file-id"}))

    await api.resumable_upload_file({"name": "b"}, open_bytes(b"x"), 1, params={"fields": "id"})

    assert drive.requests[0].query == {"uploadType": "resumable", "fields": "id"}
    # The session URI is opaque and must not inherit the initiation params.
    assert drive.requests[1].query == {}
