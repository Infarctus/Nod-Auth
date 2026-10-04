"""Provider boundary: authenticate replies before exposing them to the service."""
from dataclasses import dataclass
from typing import Protocol


class BotError(RuntimeError):
    """Safe user-facing diagnostic, built only from fixed text and numeric codes.

    Never include upstream exception text, response bodies, URLs, or credentials.
    """


@dataclass(frozen=True)
class Reply:
    request_id: str | None
    text: str
    source_id: str | None = None


@dataclass(frozen=True)
class Update:
    cursor: str
    reply: Reply | None = None


class ApprovalBot(Protocol):
    name: str

    def check(self) -> None: ...
    def notify(self, text: str) -> None: ...
    def request(self, text: str, *, choices: list[str] | None = None) -> str: ...
    def update_request(self, request_id: str, text: str, *, status: str) -> None: ...
    def updates(self, cursor: str) -> list[Update]: ...


class BotProvider(Protocol):
    @staticmethod
    def validate_options(options: dict) -> None: ...
    @staticmethod
    def setup(options: dict) -> None: ...
    @staticmethod
    def load(options: dict) -> ApprovalBot: ...


def valid_callback(value):
    import re
    return isinstance(value, str) and re.fullmatch(r'approval:([0-9]{1,2}|APPROVE|DENY)', value) is not None
