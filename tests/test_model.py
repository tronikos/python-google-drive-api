"""Tests for the Google Drive API data model."""

import pytest

from google_drive_api.model import Error, ErrorResponse


def test_error_response_uses_drive_error_format() -> None:
    """Test that the machine readable reasons the Drive API sends are kept."""
    # https://developers.google.com/drive/api/guides/handle-errors
    body = """
    {"error": {"code": 403, "message": "Rate Limit Exceeded",
     "errors": [{"domain": "usageLimits", "reason": "rateLimitExceeded"}]}}
    """

    error = ErrorResponse.from_json(body).error

    assert error is not None
    assert error.code == 403
    assert error.reasons == {"rateLimitExceeded"}
    assert str(error) == (
        "403: Rate Limit Exceeded\nError details: ([{'domain': 'usageLimits', 'reason': 'rateLimitExceeded'}])"
    )


def test_error_response_without_error() -> None:
    """Test a body that carries no error."""
    assert ErrorResponse.from_json("{}").error is None


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (Error(), ""),
        (Error(code=404), "404"),
        (Error(status="NOT_FOUND"), "NOT_FOUND"),
        (Error(status="NOT_FOUND", code=404), "NOT_FOUND (404)"),
        (Error(message="nope"), "nope"),
        (Error(code=404, message="nope"), "404: nope"),
        (Error(status="NOT_FOUND", code=404, message="nope"), "NOT_FOUND (404): nope"),
        (Error(code=404, details=[{"a": 1}]), "404\nError details: ([{'a': 1}])"),
    ],
)
def test_error_str(error: Error, expected: str) -> None:
    """Test the human readable rendering of an error."""
    assert str(error) == expected


def test_error_reasons_ignores_entries_without_reason() -> None:
    """Test that error entries without a reason are skipped."""
    assert Error(errors=[{"domain": "global"}, {"reason": "notFound"}]).reasons == {"notFound"}
