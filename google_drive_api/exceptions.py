"""Exceptions for Google Drive API calls."""


class GoogleDriveApiError(Exception):
    """Error talking to the Google Drive API."""


class ApiException(GoogleDriveApiError):
    """Raised during problems talking to the API."""


class AuthException(GoogleDriveApiError):
    """Raised due to auth problems talking to API."""


class ApiForbiddenException(GoogleDriveApiError):
    """Raised due to permission errors talking to API."""
