"""Application exceptions for controlled protocol errors."""

from __future__ import annotations


class EvotingError(Exception):
    """Base class for application-level errors."""


class ModelValidationError(EvotingError, ValueError):
    """Raised when a protocol model has invalid structure."""


class CanonicalSerializationError(EvotingError, TypeError):
    """Raised when a value cannot be represented canonically."""


__all__ = ["CanonicalSerializationError", "EvotingError", "ModelValidationError"]
