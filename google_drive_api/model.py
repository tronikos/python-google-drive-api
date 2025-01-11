"""Google Drive API Data Model."""

from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any

from mashumaro.mixins.json import DataClassJSONMixin

__all__ = [
    "Status",
]


@dataclass
class Status(DataClassJSONMixin):
    """Status of the media item."""

    code: int = field(default=HTTPStatus.OK)
    """The status code, which should be an enum value of google.rpc.Code"""

    message: str | None = None
    """A developer-facing error message, which should be in English"""

    details: list[dict[str, Any]] = field(default_factory=list)
    """A list of messages that carry the error details"""


@dataclass
class Error:
    """Error details from the API response."""

    status: str | None = None
    code: int | None = None
    message: str | None = None
    details: list[dict[str, Any]] | None = field(default_factory=list)

    def __str__(self) -> str:
        """Return a string representation of the error details."""
        error_message = ""
        if self.status:
            error_message += self.status
        if self.code:
            if error_message:
                error_message += f" ({self.code})"
            else:
                error_message += str(self.code)
        if self.message:
            if error_message:
                error_message += ": "
            error_message += self.message
        if self.details:
            error_message += f"\nError details: ({self.details})"
        return error_message


@dataclass
class ErrorResponse(DataClassJSONMixin):
    """A response message that contains an error message."""

    error: Error | None = None
