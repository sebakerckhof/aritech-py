"""
Aritech ATS - Unofficial Python client for ATS alarm panels.

This library provides async communication with Aritech/UTC ATS alarm panels
using the ACE 2 ATS protocol version 6.
"""

from __future__ import annotations

from .client import AritechClient, AritechConfig
from .errors import AritechError, ErrorCode
from .event_parser import (
    EntityType,
    EventEntity,
    ParsedEvent,
    parse_event,
    parse_events,
)
from .event_types import (
    CLASS_ID_STRINGS,
    EVENT_TYPES,
    EventCategory,
    EventType,
    get_class_name,
    get_event_type,
)
from .message_helpers import (
    build_batch_stat_request,
    build_get_event_log_message,
    build_get_stat_request,
    build_get_valid_zones_message,
    construct_message,
    get_property,
)
from .messages import MESSAGE_TEMPLATES, MessageTemplate, PropertyDef
from .monitor import AritechMonitor, ChangeEvent, InitializedEvent
from .protocol import (
    aes_ctr,
    append_crc,
    calculate_protocol_version,
    crc16,
    decrypt_message,
    decode_serial,
    encrypt_message,
    make_encryption_key,
    slip_decode,
    slip_encode,
    verify_crc,
)
from .state import AreaState, DoorState, OutputState, TriggerState, ZoneState

__version__ = "0.4.0"

__all__ = [
    # Version
    "__version__",
    # Client
    "AritechClient",
    "AritechConfig",
    # Errors
    "AritechError",
    "ErrorCode",
    # Event parsing
    "EntityType",
    "EventEntity",
    "ParsedEvent",
    "parse_event",
    "parse_events",
    # Event types
    "CLASS_ID_STRINGS",
    "EVENT_TYPES",
    "EventCategory",
    "EventType",
    "get_class_name",
    "get_event_type",
    # Message helpers
    "build_batch_stat_request",
    "build_get_event_log_message",
    "build_get_stat_request",
    "build_get_valid_zones_message",
    "construct_message",
    "get_property",
    # Messages
    "MESSAGE_TEMPLATES",
    "MessageTemplate",
    "PropertyDef",
    # Monitor
    "AritechMonitor",
    "ChangeEvent",
    "InitializedEvent",
    # Protocol utilities
    "aes_ctr",
    "append_crc",
    "calculate_protocol_version",
    "crc16",
    "decrypt_message",
    "decode_serial",
    "encrypt_message",
    "make_encryption_key",
    "slip_decode",
    "slip_encode",
    "verify_crc",
    # State classes
    "AreaState",
    "DoorState",
    "OutputState",
    "TriggerState",
    "ZoneState",
]
