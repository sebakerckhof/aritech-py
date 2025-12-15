"""
Error classes for ATS panel communication.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """Error codes for common scenarios."""

    # Connection/Protocol errors
    CONNECTION_FAILED = "CONNECTION_FAILED"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    CRC_ERROR = "CRC_ERROR"
    DECRYPT_FAILED = "DECRYPT_FAILED"
    TIMEOUT = "TIMEOUT"

    # Authentication errors
    LOGIN_FAILED = "LOGIN_FAILED"
    KEY_EXCHANGE_FAILED = "KEY_EXCHANGE_FAILED"

    # Panel errors (from 0xF0 response)
    PANEL_ERROR = "PANEL_ERROR"

    # Arm/Disarm errors
    ARM_FAILED = "ARM_FAILED"
    ARM_FAULTS = "ARM_FAULTS"
    ARM_ACTIVE_ZONES = "ARM_ACTIVE_ZONES"
    ARM_INHIBITED = "ARM_INHIBITED"
    FORCE_ARM_FAILED = "FORCE_ARM_FAILED"
    DISARM_FAILED = "DISARM_FAILED"

    # Zone control errors
    ZONE_INHIBIT_FAILED = "ZONE_INHIBIT_FAILED"
    ZONE_UNINHIBIT_FAILED = "ZONE_UNINHIBIT_FAILED"

    # Output control errors
    OUTPUT_ACTIVATE_FAILED = "OUTPUT_ACTIVATE_FAILED"
    OUTPUT_DEACTIVATE_FAILED = "OUTPUT_DEACTIVATE_FAILED"

    # Trigger control errors
    TRIGGER_ACTIVATE_FAILED = "TRIGGER_ACTIVATE_FAILED"
    TRIGGER_DEACTIVATE_FAILED = "TRIGGER_DEACTIVATE_FAILED"

    # Control context errors
    CREATE_CC_FAILED = "CREATE_CC_FAILED"

    # Unknown
    UNKNOWN = "UNKNOWN"


class AritechError(Exception):
    """
    Custom exception for Aritech client operations.

    Provides structured error information for consistent error handling.
    """

    def __init__(
        self,
        message: str,
        *,
        code: ErrorCode | str = ErrorCode.UNKNOWN,
        status: int | None = None,
        panel_error: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize an AritechError.

        Args:
            message: Human-readable error message
            code: Error code (e.g., 'ARM_FAILED', 'ZONE_FAULT')
            status: Panel status code if applicable
            panel_error: Raw panel error code (from 0xF0 response)
            details: Additional structured details (e.g., faults, activeZones)
        """
        super().__init__(message)
        self.code = code if isinstance(code, ErrorCode) else ErrorCode(code)
        self.status = status
        self.panel_error = panel_error
        self.details = details or {}

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.code != ErrorCode.UNKNOWN:
            parts.append(f"code={self.code}")
        if self.status is not None:
            parts.append(f"status=0x{self.status:04x}")
        if self.panel_error is not None:
            parts.append(f"panel_error=0x{self.panel_error:02x}")
        if self.details:
            parts.append(f"details={self.details}")
        return " ".join(parts)

    def __repr__(self) -> str:
        return (
            f"AritechError({super().__str__()!r}, code={self.code!r}, "
            f"status={self.status!r}, panel_error={self.panel_error!r}, "
            f"details={self.details!r})"
        )
