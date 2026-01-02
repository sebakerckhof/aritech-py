"""
Message construction and parsing helpers for ATS panel communication.
"""

from __future__ import annotations

import logging
from typing import Any

from .messages import MESSAGE_TEMPLATES, MessageTemplate

logger = logging.getLogger(__name__)

# Protocol header constants
HEADER_REQUEST = 0xC0
HEADER_RESPONSE = 0xA0
HEADER_ERROR = 0xF0

# Batch response payload lengths
BATCH_PAYLOAD_LENGTHS = {
    "areaStatus": 17,
    "doorStatus": 6,
    "zoneStatus": 7,
    "triggerStatus": 5,
    "outputStatus": 5,
}

# Status message name mapping
GET_STAT_MSG_NAMES = {
    "AREA": "areaStatus",
    "DOOR": "doorStatus",
    "ZONE": "zoneStatus",
    "TRIGGER": "triggerStatus",
    "OUTPUT": "outputStatus",
}


def construct_message(msg_name: str, properties: dict[str, Any] | None = None) -> bytes:
    """
    Construct a message buffer from a template and properties.

    Args:
        msg_name: Message name (e.g., 'inhibitZone')
        properties: Property values to set

    Returns:
        The constructed message payload (with header)
    """
    template = MESSAGE_TEMPLATES.get(msg_name)
    if not template:
        raise ValueError(f"Unknown message: {msg_name}")

    properties = properties or {}

    # Calculate total payload size: header (1) + msgIdBytes + templateBytes
    payload_length = 1 + len(template.msg_id_bytes) + len(template.template_bytes)
    buffer = bytearray(payload_length)

    offset = 0

    # Write header byte (0xC0 for requests)
    buffer[offset] = HEADER_REQUEST
    offset += 1

    # Write message ID bytes
    for b in template.msg_id_bytes:
        buffer[offset] = b
        offset += 1

    # Write template bytes (default values)
    for b in template.template_bytes:
        buffer[offset] = b
        offset += 1

    # Apply property values
    for prop_name, value in properties.items():
        prop_defs = template.properties.get(prop_name)
        if not prop_defs:
            logger.warning(f"Unknown property '{prop_name}' for message '{msg_name}'")
            continue

        # Handle multi-byte properties (array with multiple entries)
        if len(prop_defs) > 1 and all(p.mask == 0xFF for p in prop_defs):
            num_value = int(value) if value else 0
            for prop_def in prop_defs:
                buffer_index = prop_def.byte + 1  # +1 to skip header
                if 0 <= buffer_index < len(buffer):
                    buffer[buffer_index] = num_value & 0xFF
                    num_value >>= 8
            continue

        for prop_def in prop_defs:
            buffer_index = prop_def.byte + 1  # +1 to skip header
            mask = prop_def.mask
            length = prop_def.length
            prop_type = prop_def.prop_type

            if buffer_index < 0 or buffer_index >= len(buffer):
                logger.warning(f"Property '{prop_name}' byte offset out of range")
                continue

            # Handle bytes/bytearray values
            if isinstance(value, (bytes, bytearray)):
                max_len = length or len(value)
                for i in range(max_len):
                    if buffer_index + i < len(buffer):
                        buffer[buffer_index + i] = value[i] if i < len(value) else 0
                continue

            # Handle string values
            if isinstance(value, str):
                if prop_type == "string":
                    # Length-prefixed string
                    max_len = length or 16
                    str_bytes = value.encode("ascii", errors="ignore")
                    buffer[buffer_index] = min(len(str_bytes), max_len)
                    for i in range(max_len):
                        if buffer_index + 1 + i < len(buffer):
                            buffer[buffer_index + 1 + i] = (
                                str_bytes[i] if i < len(str_bytes) else 0
                            )
                elif length:
                    # Fixed-length null-padded string
                    str_bytes = value.encode("ascii", errors="ignore")
                    for i in range(length):
                        if buffer_index + i < len(buffer):
                            buffer[buffer_index + i] = (
                                str_bytes[i] if i < len(str_bytes) else 0
                            )
                continue

            # Handle numeric/boolean values
            if mask == 0xFF:
                num_value = int(value) if value else 0
                # Determine byte count from type or length, default to 2 bytes
                type_byte_counts = {"bool": 1, "byte": 1, "short": 2, "int": 4}
                if prop_type and prop_type in type_byte_counts:
                    byte_count = type_byte_counts[prop_type]
                elif length and length > 1:
                    byte_count = length
                else:
                    # Default to 2 bytes for numeric values (like JS)
                    byte_count = 2

                # Write value as little-endian
                for i in range(byte_count):
                    if buffer_index + i < len(buffer):
                        buffer[buffer_index + i] = (num_value >> (i * 8)) & 0xFF
            else:
                # Bitmask value
                if value:
                    buffer[buffer_index] |= mask
                else:
                    buffer[buffer_index] &= ~mask

    return bytes(buffer)


def get_property(msg_name: str, payload: bytes, property_name: str) -> Any:
    """
    Extract a property value from a response payload.

    Args:
        msg_name: Message name (e.g., 'zoneStatus')
        payload: The response payload buffer
        property_name: Property name to extract

    Returns:
        The property value
    """
    template = MESSAGE_TEMPLATES.get(msg_name)
    if not template:
        raise ValueError(f"Unknown message: {msg_name}")

    prop_defs = template.properties.get(property_name)
    if not prop_defs:
        raise ValueError(f"Unknown property '{property_name}' for message '{msg_name}'")

    prop_def = prop_defs[0]
    byte_offset = prop_def.byte
    mask = prop_def.mask
    length = prop_def.length
    prop_type = prop_def.prop_type

    if byte_offset < 0 or byte_offset >= len(payload):
        raise ValueError(f"Property byte offset {byte_offset} out of range")

    # Handle string type
    if prop_type == "string":
        str_len = payload[byte_offset]
        if str_len == 0 or byte_offset + 1 + str_len > len(payload):
            return ""
        return (
            payload[byte_offset + 1 : byte_offset + 1 + str_len]
            .decode("ascii", errors="ignore")
            .rstrip("\x00")
            .strip()
        )

    # Handle multi-byte properties
    if len(prop_defs) > 1 and all(p.mask == 0xFF for p in prop_defs):
        value = 0
        for i, pd in enumerate(prop_defs):
            if 0 <= pd.byte < len(payload):
                value |= payload[pd.byte] << (i * 8)
        return value

    if mask == 0xFF:
        if length and length > 1:
            value = 0
            for i in range(length):
                if byte_offset + i < len(payload):
                    value |= payload[byte_offset + i] << (i * 8)
            return value
        return payload[byte_offset]
    else:
        return (payload[byte_offset] & mask) != 0


def is_message_type(response: bytes, msg_name: str, header_offset: int = 0) -> bool:
    """
    Check if a response matches a message type.

    Args:
        response: Response bytes
        msg_name: Message name to check
        header_offset: Offset to skip before checking

    Returns:
        True if response matches the message type
    """
    template = MESSAGE_TEMPLATES.get(msg_name)
    if not template:
        return False

    msg_id_bytes = template.msg_id_bytes
    if len(response) < header_offset + len(msg_id_bytes):
        return False

    for i, b in enumerate(msg_id_bytes):
        if response[header_offset + i] != b:
            return False

    return True


def check_response_error(response: bytes) -> int | None:
    """
    Check if response is an error and return error code.

    Args:
        response: Response bytes

    Returns:
        Error code if error response, None otherwise
    """
    if response and len(response) >= 2 and response[0] == HEADER_ERROR:
        return response[1]
    return None


def parse_create_cc_response(response: bytes) -> dict[str, int] | None:
    """
    Parse a createCC response to extract sessionId.

    Args:
        response: Response bytes

    Returns:
        Dict with sessionId, or None if invalid
    """
    if not response or len(response) < 4:
        return None

    if response[0] != HEADER_RESPONSE:
        return None

    # shortResponse format: a0 00 03 XX YY (sessionId at bytes 3-4, little-endian)
    if response[1] == 0x00 and len(response) >= 5:
        session_id = response[3] | (response[4] << 8)
        return {"sessionId": session_id}

    return None


def parse_return_bool(response: bytes) -> bool | None:
    """
    Parse a booleanResponse.

    Args:
        response: Response bytes

    Returns:
        Boolean result, or None if invalid
    """
    if not response or len(response) < 3:
        return None

    if response[0] != HEADER_RESPONSE:
        return None

    # booleanResponse format: a0 00 01 XX
    if response[1] == 0x00 and response[2] == 0x01 and len(response) >= 4:
        return response[3] != 0

    return None


def build_get_stat_request(
    stat_type: str, object_id: int, with_header: bool = True
) -> bytes:
    """
    Build a getStatus request.

    Args:
        stat_type: Type ('AREA', 'ZONE', 'TRIGGER', 'OUTPUT')
        object_id: Object ID to query
        with_header: Whether to include 0xC0 header

    Returns:
        Request bytes
    """
    msg_name = f"get{stat_type.capitalize()}Status"
    template = MESSAGE_TEMPLATES.get(msg_name)
    if not template:
        raise ValueError(f"Unknown stat type: {stat_type}")

    if with_header:
        return construct_message(msg_name, {"objectId": object_id})
    else:
        msg = construct_message(msg_name, {"objectId": object_id})
        return msg[1:]  # Skip header


def build_batch_stat_request(stat_type: str, object_ids: list[int]) -> bytes:
    """
    Build a batch status request for multiple objects.

    Args:
        stat_type: Type ('AREA', 'ZONE', 'TRIGGER', 'OUTPUT')
        object_ids: List of object IDs to query

    Returns:
        Batch request bytes
    """
    # Build individual requests without headers
    requests = []
    for obj_id in object_ids:
        req = build_get_stat_request(stat_type, obj_id, with_header=False)
        requests.append(req)

    # Embedded message size (getStatus messages are 6 bytes without header)
    embedded_msg_size = 0x06

    # Build batch payload:
    # [c0 ee e0 ee ee] [06] [req1] 06 [req2] 06 ... [lastReq]
    # The 0x06 after header is the embedded message size
    # The 0x06 between requests acts as separator
    payload = bytearray([HEADER_REQUEST, 0xEE, 0xE0, 0xEE, 0xEE, embedded_msg_size])

    for i, req in enumerate(requests):
        payload.extend(req)
        # Add separator after each request except the last
        if i < len(requests) - 1:
            payload.append(embedded_msg_size)

    return bytes(payload)


def split_batch_response(
    response: bytes, expected_template: str
) -> list[dict[str, Any]]:
    """
    Split a batch response into individual messages.

    Args:
        response: Batch response bytes
        expected_template: Expected response template name

    Returns:
        List of parsed messages with template, bytes, and objectId
    """
    if not response or len(response) < 4:
        return []

    # Check for batch response header: a0 ee ee [typeIndicator]
    if response[0] != HEADER_RESPONSE or response[1] != 0xEE or response[2] != 0xEE:
        # Not a batch response - try single response
        template = MESSAGE_TEMPLATES.get(expected_template)
        if template and response[0] == HEADER_RESPONSE:
            msg_bytes = response[1:]
            object_id = msg_bytes[3] if len(msg_bytes) > 3 else 0
            return [
                {"template": expected_template, "bytes": msg_bytes, "objectId": object_id}
            ]
        return []

    messages = []
    payload_length = BATCH_PAYLOAD_LENGTHS.get(expected_template)

    if not payload_length:
        return []

    # Skip batch header (a0 ee ee XX)
    offset = 4

    while offset + payload_length <= len(response):
        msg_bytes = response[offset : offset + payload_length]

        # Extract objectId from byte 3 of each embedded message
        object_id = msg_bytes[3] if len(msg_bytes) > 3 else 0

        messages.append(
            {"template": expected_template, "bytes": msg_bytes, "objectId": object_id}
        )

        # Move to next message (payload + 1 byte separator)
        offset += payload_length + 1

    return messages


def build_get_valid_zones_message(area_numbers: list[int] | None = None) -> bytes:
    """
    Build a getZonesAssignedToAreas request.

    Args:
        area_numbers: List of area numbers to query (None for all areas)

    Returns:
        Request bytes
    """
    if area_numbers is None:
        # Query all 64 areas using 32-bit bitmasks
        return construct_message(
            "getZonesAssignedToAreas",
            {"areas-1-32": 0xFFFFFFFF, "areas-33-64": 0xFFFFFFFF},
        )

    # Build bitmasks for specific areas
    areas_1_32 = 0
    areas_33_64 = 0

    for area_num in area_numbers:
        if 1 <= area_num <= 32:
            areas_1_32 |= 1 << (area_num - 1)
        elif 33 <= area_num <= 64:
            areas_33_64 |= 1 << (area_num - 33)

    return construct_message(
        "getZonesAssignedToAreas",
        {"areas-1-32": areas_1_32, "areas-33-64": areas_33_64},
    )


def build_get_event_log_message(direction: int) -> bytes:
    """
    Build a selectLogEntry request.

    Args:
        direction: 0 for first, 3 for next

    Returns:
        Request bytes
    """
    return construct_message("selectLogEntry", {"logReadingDirection": direction})
