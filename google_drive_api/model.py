"""Google Drive API Data Model."""

from dataclasses import dataclass, field
from typing import Any

from mashumaro.mixins.json import DataClassJSONMixin

__all__ = [
    "Error",
    "ErrorResponse",
]


@dataclass
class Error:
    """Error details from the API response."""

    status: str | None = None
    code: int | None = None
    message: str | None = None
    errors: list[dict[str, Any]] = field(default_factory=list)
    """Machine readable details, e.g. [{"domain": ..., "reason": "rateLimitExceeded"}]"""

    details: list[dict[str, Any]] = field(default_factory=list)
    """A list of messages that carry the error details"""

    @property
    def reasons(self) -> set[str]:
        """Return the machine readable reasons reported by the API."""
        # https://developers.google.com/drive/api/guides/handle-errors
        return {str(error["reason"]) for error in self.errors if "reason" in error}

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
        if details := self.errors or self.details:
            error_message += f"\nError details: ({details})"
        return error_message


@dataclass
class ErrorResponse(DataClassJSONMixin):
    """A response message that contains an error message."""

    error: Error | None = None
