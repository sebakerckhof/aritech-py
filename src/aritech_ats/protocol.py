"""
Protocol utilities for ATS panel communication.

This module provides low-level utilities for:
- SLIP framing (RFC 1055)
- CRC-16 checksums
- AES-128-CTR encryption
- Key derivation and serial number decoding
"""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

from Crypto.Cipher import AES

if TYPE_CHECKING:
    pass

# SLIP framing constants (RFC 1055)
SLIP_END = 0xC0
SLIP_ESC = 0xDB
SLIP_ESC_END = 0xDC
SLIP_ESC_ESC = 0xDD


def slip_encode(data: bytes) -> bytes:
    """
    Encode data using SLIP framing.

    Args:
        data: Raw data to encode

    Returns:
        SLIP-encoded data with frame markers
    """
    result = bytearray([SLIP_END])
    for byte in data:
        if byte == SLIP_END:
            result.extend([SLIP_ESC, SLIP_ESC_END])
        elif byte == SLIP_ESC:
            result.extend([SLIP_ESC, SLIP_ESC_ESC])
        else:
            result.append(byte)
    result.append(SLIP_END)
    return bytes(result)


def slip_decode(data: bytes) -> bytes:
    """
    Decode SLIP-framed data.

    Args:
        data: SLIP-encoded data

    Returns:
        Decoded data without frame markers
    """
    result = bytearray()
    i = 1 if data and data[0] == SLIP_END else 0

    while i < len(data) and data[i] != SLIP_END:
        if data[i] == SLIP_ESC and i + 1 < len(data):
            i += 1
            if data[i] == SLIP_ESC_END:
                result.append(SLIP_END)
            elif data[i] == SLIP_ESC_ESC:
                result.append(SLIP_ESC)
            else:
                result.append(data[i])
        else:
            result.append(data[i])
        i += 1

    return bytes(result)


def crc16(data: bytes, offset: int = 0, length: int | None = None) -> int:
    """
    Calculate CRC-16 checksum.

    Uses polynomial 0xA001, initial value 0xFFFF.

    Args:
        data: Input data
        offset: Start offset in data
        length: Number of bytes to process (default: rest of data from offset)

    Returns:
        CRC-16 value
    """
    if length is None:
        length = len(data) - offset

    crc = 0xFFFF
    for i in range(length):
        crc = crc ^ data[offset + i]
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc = crc >> 1
    return crc


def append_crc(data: bytes) -> bytes:
    """
    Append CRC-16 checksum to data (big-endian).

    Args:
        data: Input data

    Returns:
        Data with CRC-16 appended
    """
    crc_val = crc16(data)
    return data + bytes([(crc_val >> 8) & 0xFF, crc_val & 0xFF])


def verify_crc(data: bytes) -> bool:
    """
    Verify CRC-16 checksum on data.

    Args:
        data: Data with CRC-16 appended

    Returns:
        True if CRC matches, False otherwise
    """
    if len(data) < 3:
        return False
    payload = data[:-2]
    frame_crc = (data[-2] << 8) | data[-1]
    calc_crc = crc16(payload)
    return frame_crc == calc_crc


def _gray_pack(value: int) -> int:
    """Gray code packing function used in key derivation."""
    num = value ^ (value >> 1)
    return ((num & 0x600) >> 3) | ((num & 0xC0) >> 2) | ((num & 0x18) >> 1) | (num & 3)


def make_encryption_key(password: str) -> bytes:
    """
    Derive 16-byte AES key from 24-character password.

    Args:
        password: 24-character hex password string

    Returns:
        16-byte encryption key
    """
    if not password or len(password) < 24:
        return bytes(16)

    result = bytearray(16)
    parts = [password[0:12], password[12:24]]

    for part_index, part in enumerate(parts):
        chars = part.encode("ascii")
        offset = part_index * 8

        result[offset + 0] = _gray_pack((chars[0] << 4) | (chars[1] >> 4))
        result[offset + 1] = _gray_pack(((chars[1] & 0xF) << 8) | chars[2])
        result[offset + 2] = _gray_pack((chars[3] << 4) | (chars[4] >> 4))
        result[offset + 3] = _gray_pack(((chars[4] & 0xF) << 8) | chars[5])
        result[offset + 4] = _gray_pack((chars[6] << 4) | (chars[7] >> 4))
        result[offset + 5] = _gray_pack(((chars[7] & 0xF) << 8) | chars[8])
        result[offset + 6] = _gray_pack((chars[9] << 4) | (chars[10] >> 4))
        result[offset + 7] = _gray_pack(((chars[10] & 0xF) << 8) | chars[11])

    return bytes(result)


def _base64_char_to_val(c: str) -> int:
    """Convert base64-like character to value."""
    code = ord(c)
    if 65 <= code <= 90:  # A-Z
        return code - 65
    if 97 <= code <= 122:  # a-z
        return code - 97 + 26
    if 48 <= code <= 57:  # 0-9
        return code - 48 + 52
    if c in ("+", "-"):
        return 62
    if c in ("_", "/"):
        return 63
    return -1


def decode_serial(serial: str) -> bytes:
    """
    Decode 16-character serial string to 6-byte serial bytes.

    Args:
        serial: 16-character serial string

    Returns:
        6-byte serial bytes
    """
    b_arr = bytearray(12)

    for i in range(4):
        i2 = i * 4
        val = _base64_char_to_val(serial[i2]) << 18
        val += _base64_char_to_val(serial[i2 + 1]) << 12
        val += _base64_char_to_val(serial[i2 + 2]) << 6
        val += _base64_char_to_val(serial[i2 + 3])

        i3 = i * 3
        b_arr[i3] = (val >> 16) & 0xFF
        b_arr[i3 + 1] = (val >> 8) & 0xFF
        b_arr[i3 + 2] = val & 0xFF

    result = bytearray(6)
    result[0] = b_arr[0] ^ b_arr[6]
    result[1] = b_arr[7] ^ b_arr[1]
    result[2] = b_arr[8] ^ b_arr[2]
    result[3] = b_arr[9] ^ b_arr[3]
    result[4] = b_arr[10] ^ b_arr[4]
    result[5] = b_arr[11] ^ b_arr[5]

    return bytes(result)


def aes_ctr(data: bytes, key: bytes, nonce: bytes, serial_bytes: bytes) -> bytes:
    """
    AES-128-CTR encryption/decryption.

    IV = [nonce 8 bytes][serial 6 bytes][padding 2 bytes]

    Args:
        data: Data to encrypt/decrypt
        key: 16-byte AES key
        nonce: 8-byte nonce
        serial_bytes: 6-byte serial

    Returns:
        Encrypted/decrypted data
    """
    # IV = [nonce 8 bytes][serial 6 bytes][padding 2 bytes]
    iv = bytearray(16)
    iv[0:8] = nonce[0:8]
    iv[8:14] = serial_bytes[0:6]
    # bytes 14-15 stay 0

    result = bytearray(len(data))
    block_size = 16

    block = 0
    while block * block_size < len(data):
        # Create AES-ECB cipher for keystream generation
        cipher = AES.new(key, AES.MODE_ECB)
        keystream = cipher.encrypt(bytes(iv))

        start = block * block_size
        end = min(start + block_size, len(data))
        for i in range(start, end):
            result[i] = data[i] ^ keystream[i - start]

        # Increment counter (big-endian from end)
        for i in range(len(iv) - 1, -1, -1):
            iv[i] = (iv[i] + 1) & 0xFF
            if iv[i] != 0:
                break

        block += 1

    return bytes(result)


def generate_nonce() -> bytes:
    """
    Generate random 8-byte nonce.

    Returns:
        8-byte random nonce
    """
    return os.urandom(8)


def encrypt_message(payload: bytes, key: bytes, serial_bytes: bytes) -> bytes:
    """
    Encrypt a message payload.

    Adds CRC, encrypts with AES-CTR, and prepends nonce.

    Args:
        payload: Message payload to encrypt
        key: 16-byte encryption key
        serial_bytes: 6-byte decoded serial

    Returns:
        Encrypted frame: [nonce][encrypted(payload + CRC)]
    """
    with_crc = append_crc(payload)
    nonce = generate_nonce()
    encrypted = aes_ctr(with_crc, key, nonce, serial_bytes)
    return nonce + encrypted


def decrypt_message(frame: bytes, key: bytes, serial_bytes: bytes) -> bytes | None:
    """
    Decrypt a received frame.

    Extracts nonce, decrypts with AES-CTR, and verifies CRC.

    Args:
        frame: SLIP-encoded frame to decrypt
        key: 16-byte encryption key
        serial_bytes: 6-byte decoded serial

    Returns:
        Decrypted payload (without CRC), or None if invalid
    """
    decoded = slip_decode(frame)
    if len(decoded) <= 10:
        return None

    nonce = decoded[0:8]
    encrypted = decoded[8:]
    decrypted = aes_ctr(encrypted, key, nonce, serial_bytes)

    if not verify_crc(decrypted):
        return None

    return decrypted[:-2]  # Strip CRC


def calculate_protocol_version(firmware: str) -> int | None:
    """
    Calculate protocol version from firmware string.

    Args:
        firmware: Firmware version string (e.g., "MR_4.1.38741")

    Returns:
        Protocol version number, or None if parse failed
    """
    if not firmware:
        return None

    # Split by underscore and dots: "MR_4.1.38741" -> ["MR", "4", "1", "38741"]
    parts = re.split(r"[_.]", firmware)

    if len(parts) < 3:
        return None

    try:
        num1 = int(parts[1])  # Major version
        num2 = int(parts[2])  # Minor version
    except (ValueError, IndexError):
        return None

    if num1 <= 21:
        return num1 * 1000 + num2
    else:
        return num1


def encode_varint(value: int) -> bytes:
    """
    Encode signed integer to zigzag varint.

    Args:
        value: Signed integer to encode

    Returns:
        Varint-encoded bytes
    """
    # Zigzag encoding for signed integers
    zigzag = (value << 1) ^ (value >> 31)
    zigzag = zigzag & 0xFFFFFFFF  # Ensure unsigned 32-bit

    result = bytearray()
    remaining = zigzag
    while remaining > 0x7F:
        result.append((remaining & 0x7F) | 0x80)
        remaining >>= 7
    result.append(remaining & 0x7F)

    return bytes(result)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Decode zigzag varint from bytes.

    Args:
        data: Input bytes
        offset: Start offset

    Returns:
        Tuple of (decoded value, bytes consumed)
    """
    result = 0
    shift = 0
    bytes_consumed = 0

    while offset + bytes_consumed < len(data):
        byte = data[offset + bytes_consumed]
        result |= (byte & 0x7F) << shift
        bytes_consumed += 1
        if not (byte & 0x80):
            break
        shift += 7

    # Zigzag decode
    value = (result >> 1) ^ -(result & 1)
    return value, bytes_consumed
