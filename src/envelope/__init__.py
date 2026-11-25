"""Tenant-scoped envelope encryption primitives."""

from .seal import (
    AuthenticationError,
    EnvelopeError,
    build_aad,
    check_version,
    derive_data_key,
    envelope_batch,
    open_sealed,
    rotate_master,
    seal,
    validate_header,
)

__all__ = [
    "EnvelopeError",
    "AuthenticationError",
    "derive_data_key",
    "build_aad",
    "seal",
    "open_sealed",
    "check_version",
    "validate_header",
    "rotate_master",
    "envelope_batch",
]