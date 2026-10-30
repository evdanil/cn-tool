"""Credential interaction for callers which do not own a terminal."""
from dataclasses import dataclass, field
from typing import NoReturn, Optional, Protocol


class AuthenticationRequired(Exception):
    """Credentials are absent or the person canceled their entry."""

    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class AuthenticationFailed(AuthenticationRequired):
    """Configured credential sources are invalid or conflict."""


@dataclass(frozen=True)
class CredentialRequest:
    account: str
    username: str
    need_username: bool
    need_password: bool
    message: str


@dataclass(frozen=True)
class CredentialReply:
    username: str = field(repr=False)
    password: str = field(repr=False)


class CredentialInteraction(Protocol):
    def prompt(self, request: CredentialRequest) -> Optional[CredentialReply]:
        """Return missing credential values, or None to cancel."""
        ...

    def fail(self, code: int, message: str) -> NoReturn:
        """Raise AuthenticationRequired for an unsuccessful credential request."""
        ...
