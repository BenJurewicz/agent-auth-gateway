"""
Auth Proxy — Service Registry

Each service is a subclass of BaseService registered via the @service decorator.
The registry maps service names to their handler classes.
"""

import logging
from typing import Optional

log = logging.getLogger("auth-proxy.registry")

_registry: dict[str, type["BaseService"]] = {}


def service(name: str):
    """Decorator to register a service class."""
    def wrapper(cls):
        _registry[name] = cls
        cls.service_name = name
        log.info("Registered service: %s", name)
        return cls
    return wrapper


def get_service(name: str) -> Optional[type["BaseService"]]:
    return _registry.get(name)


def list_services() -> list[str]:
    return list(_registry.keys())


class BaseService:
    """Abstract base for all auth-proxy services.

    Subclasses must:
        - Decorate with @service("name")
        - Implement execute(action, data, config) -> dict
        - Implement validate(action, data) -> None (raise ValueError on bad input)
        - Implement approval_text(action, data, request_id) -> str
        - Optionally override context(action, data) -> str
    """

    service_name: str = ""

    @classmethod
    def validate(cls, action: str, data: dict) -> None:
        """Validate request parameters. Raise ValueError if invalid."""
        raise NotImplementedError

    @classmethod
    def execute(cls, action: str, data: dict, config: dict) -> dict:
        """Execute the action. Return dict with at least {success, output}."""
        raise NotImplementedError

    @classmethod
    def approval_text(cls, action: str, data: dict, request_id: str) -> str:
        """Build the Telegram approval prompt. Supports Markdown."""
        raise NotImplementedError

    @classmethod
    def context(cls, action: str, data: dict) -> str:
        """Optional: return additional context for the approval prompt."""
        return ""

    @classmethod
    def requires_approval(cls, action: str) -> bool:
        """Whether this action requires user approval.

        Override to return False for read-only or non-destructive actions.
        """
        return True

    @classmethod
    def redact_request_data(cls, action: str, data: dict) -> dict:
        """Return a safe-to-display copy of queued request data.

        Services can override this to hide action-specific fields. The default
        redacts commonly sensitive key names and large binary payload fields.
        """
        redacted = {}
        sensitive_markers = ("token", "secret", "password", "key", "credential", "bundle_b64")
        for key, value in (data or {}).items():
            if any(marker in key.lower() for marker in sensitive_markers):
                redacted[key] = f"<redacted {len(str(value))} chars>"
            else:
                redacted[key] = value
        return redacted


# Import services so they register themselves
from . import git       # noqa: E402, F811
from . import github    # noqa: E402, F811
from . import sudo      # noqa: E402, F811
# from . import calendar  # future — uncomment when implemented
