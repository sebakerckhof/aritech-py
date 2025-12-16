"""
Async client for ATS alarm panel communication.

This module provides the main AritechClient class for connecting to and
communicating with ATS alarm panels over TCP/IP.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .event_parser import ParsedEvent

from .errors import AritechError, ErrorCode
from .message_helpers import (
    HEADER_ERROR,
    HEADER_RESPONSE,
    build_batch_stat_request,
    build_get_event_log_message,
    build_get_stat_request,
    build_get_valid_zones_message,
    check_response_error,
    construct_message,
    get_property,
    is_message_type,
    parse_create_cc_response,
    parse_return_bool,
    split_batch_response,
)
from .protocol import (
    SLIP_END,
    append_crc,
    calculate_protocol_version,
    decrypt_message,
    decode_serial,
    encrypt_message,
    make_encryption_key,
    slip_decode,
    slip_encode,
    verify_crc,
)
from .state import AreaState, OutputState, TriggerState, ZoneState

logger = logging.getLogger(__name__)


def _debug_enabled() -> bool:
    """Check if debug logging is enabled."""
    return logger.isEnabledFor(logging.DEBUG)


@dataclass(slots=True)
class AritechConfig:
    """Configuration for AritechClient."""

    host: str
    port: int = 3001
    pin: str = ""
    encryption_password: str = ""
    serial: str | None = None


@dataclass(slots=True)
class NamedItem:
    """A named item (area, zone, output, or trigger)."""

    number: int
    name: str


@dataclass(slots=True)
class StateResult:
    """Result of a status query."""

    number: int
    state: Any
    raw_hex: str = ""


# Model configuration
MODEL_AREAS = {
    "ATS1000": 4,
    "ATS1500": 4,
    "ATS2000": 8,
    "ATS3500": 8,
    "ATS4500": 64,
}

MODEL_ZONES = {
    "ATS1000": 368,
    "ATS1500": 240,
    "ATS2000": 368,
    "ATS3500": 496,
    "ATS4500": 976,
}

# Response parsing constants
NAMES_START_OFFSET = 6  # Offset where names begin in getName responses
NAME_LENGTH = 16  # Each name is 16 bytes, null-padded
NAMES_PER_PAGE = 16  # Panel returns 16 names per request

# Event log direction constants
EVENT_LOG_FIRST = 0x00
EVENT_LOG_NEXT = 0x03

# Control context status codes for arm operations
CC_STATUS = {
    # Part set statuses (0x04xx)
    "PartSetFault": 0x0401,
    "PartSetActiveStates": 0x0402,
    "PartSetInhibited": 0x0403,
    "PartSetSetting": 0x0404,
    "PartSetSet": 0x0405,
    # Full set statuses (0x05xx)
    "FullSetFault": 0x0501,
    "FullSetActiveStates": 0x0502,
    "FullSetInhibited": 0x0503,
    "FullSetSetting": 0x0504,
    "FullSetSet": 0x0505,
    # Part set 2 statuses (0x10xx)
    "PartSet2Fault": 0x1001,
    "PartSet2ActiveStates": 0x1002,
    "PartSet2Inhibited": 0x1003,
    "PartSet2Setting": 0x1004,
    "PartSet2Set": 0x1005,
}


class AritechClient:
    """
    Async client for Aritech ATS alarm panels.

    Example usage:
        ```python
        async with AritechClient(config) as client:
            await client.initialize()
            areas = await client.get_area_names()
            states = await client.get_area_states([a.number for a in areas])
        ```
    """

    def __init__(self, config: dict[str, Any] | AritechConfig) -> None:
        """
        Initialize the Aritech client.

        Args:
            config: Configuration dict or AritechConfig instance
        """
        if isinstance(config, dict):
            self.config = AritechConfig(
                host=config.get("host", ""),
                port=config.get("port", 3001),
                pin=config.get("pin", ""),
                encryption_password=config.get(
                    "encryption_password", config.get("encryptionPassword", "")
                ),
                serial=config.get("serial"),
            )
        else:
            self.config = config

        # Connection state
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._receive_buffer = bytearray()

        # Event listeners for COS events
        self._event_listeners: list[Callable[[bytes], Coroutine[Any, Any, None]]] = []

        # Encryption keys
        self._initial_key = make_encryption_key(self.config.encryption_password)
        self._serial_bytes: bytes | None = None
        self._session_key: bytes | None = None

        # Panel info
        self._panel_model: str | None = None
        self._panel_name: str | None = None
        self._firmware_version: str | None = None
        self._protocol_version: int | None = None

        # Monitoring state
        self._monitoring_active = False
        self._processing_cos = False
        self._valid_area_numbers: list[int] | None = None
        self._zone_areas: dict[int, list[int]] = {}

        # Keep-alive task
        self._keepalive_task: asyncio.Task[None] | None = None

        # Background reader task - single reader that fans out messages
        self._reader_task: asyncio.Task[None] | None = None
        # Pending response future - commands wait on this for their response
        self._pending_response: asyncio.Future[bytes] | None = None

        # Command queue lock - ensures control operations are serialized
        # This prevents conflicts when:
        # 1. The same entity can only have one active control session
        # 2. Requests don't have unique IDs, so responses must be sequential
        self._command_lock: asyncio.Lock = asyncio.Lock()

    @property
    def panel_model(self) -> str | None:
        """Panel model (e.g., 'ATS1500')."""
        return self._panel_model

    @property
    def panel_name(self) -> str | None:
        """Panel name configured in the panel."""
        return self._panel_name

    @property
    def firmware_version(self) -> str | None:
        """Panel firmware version."""
        return self._firmware_version

    @property
    def is_connected(self) -> bool:
        """Check if connected to panel."""
        return self._writer is not None and not self._writer.is_closing()

    @property
    def max_area_count(self) -> int:
        """Maximum number of areas for this panel model."""
        return MODEL_AREAS.get(self._panel_model or "", 4)

    @property
    def max_zone_count(self) -> int:
        """Maximum number of zones for this panel model."""
        return MODEL_ZONES.get(self._panel_model or "", 240)

    async def __aenter__(self) -> AritechClient:
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit."""
        await self.disconnect()

    async def connect(self) -> None:
        """Connect to the panel."""
        logger.debug(f"Connecting to {self.config.host}:{self.config.port}...")

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.host, self.config.port),
                timeout=10.0,
            )
            logger.debug("Socket connected")
        except asyncio.TimeoutError as e:
            raise AritechError(
                "Connection timeout", code=ErrorCode.CONNECTION_FAILED
            ) from e
        except OSError as e:
            raise AritechError(
                f"Connection failed: {e}", code=ErrorCode.CONNECTION_FAILED
            ) from e

    async def disconnect(self) -> None:
        """Disconnect from the panel gracefully."""
        if not self._writer:
            return

        # Stop keep-alive
        self._stop_keepalive()

        try:
            if self._session_key:
                logger.debug("Sending logout...")
                msg = construct_message("logout", {})
                await self._call_encrypted(msg, self._session_key)
                self._session_key = None
        except Exception as e:
            logger.debug(f"Disconnect message failed: {e}")

        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

        logger.debug("Disconnected from panel")

    async def initialize(self) -> None:
        """
        Initialize the connection.

        Performs description query, key exchange, and login.
        """
        await self.get_description()
        await self._change_session_key()
        await self._login()
        self._start_keepalive()

    async def get_description(self) -> dict[str, Any]:
        """Get panel description (unencrypted)."""
        logger.debug("Getting panel description...")

        msg = construct_message("getDeviceInfo", {})
        decoded = await self._call_plain(msg)
        payload = decoded[:-2]  # Strip CRC

        # Parse panel info
        try:
            self._panel_name = get_property("deviceDescription", payload, "deviceName")
            product_name = get_property("deviceDescription", payload, "productName")
            match = re.search(r"ATS\d+", product_name or "")
            if match:
                self._panel_model = match.group(0)

            self._firmware_version = get_property(
                "deviceDescription", payload, "firmwareVersion"
            )
            if self._firmware_version:
                self._protocol_version = calculate_protocol_version(
                    self._firmware_version
                )

            serial = get_property("deviceDescription", payload, "serialNumber")
            if serial and re.match(r"^[A-Za-z0-9_+-]{16}$", serial):
                self.config.serial = serial
                self._serial_bytes = decode_serial(serial)

            logger.debug(f"Panel: {self._panel_name or 'unknown'}")
            logger.debug(f"Model: {self._panel_model or 'unknown'}")
            logger.debug(f"Firmware: {self._firmware_version or 'unknown'}")
        except Exception as e:
            logger.debug(f"Could not parse panel description: {e}")

        return {
            "panelName": self._panel_name,
            "panelModel": self._panel_model,
            "serial": self.config.serial,
            "firmwareVersion": self._firmware_version,
            "protocolVersion": self._protocol_version,
        }

    async def _change_session_key(self) -> None:
        """Perform key exchange."""
        logger.debug("Starting key exchange...")

        # 1. Send createSession with 8 zeros
        client_key = bytes(8)
        begin_payload = construct_message(
            "createSession",
            {"typeId": 0x09, "data": client_key + bytes(8)},
        )

        begin_response = await self._call_encrypted(begin_payload, self._initial_key)
        if not begin_response:
            raise AritechError(
                "Failed to decrypt createSession response",
                code=ErrorCode.KEY_EXCHANGE_FAILED,
            )

        # Extract panel's key portion
        panel_key = begin_response[3:11]
        logger.debug(f"Panel key bytes: {panel_key.hex()}")

        # Build session key
        self._session_key = client_key + panel_key
        logger.debug(f"Session key: {self._session_key.hex()}")

        # 2. Send enableEncryptionKey (still with initial key)
        end_payload = construct_message("enableEncryptionKey", {"typeId": 0x00})
        end_response = await self._call_encrypted(end_payload, self._initial_key)
        if not end_response:
            raise AritechError(
                "Failed to decrypt enableEncryptionKey response",
                code=ErrorCode.KEY_EXCHANGE_FAILED,
            )

        logger.debug("Key exchange complete")

    async def _login(self) -> None:
        """Login with PIN."""
        logger.debug(f"Logging in with PIN: {self.config.pin}")

        login_payload = construct_message(
            "login",
            {
                "canUpload": True,
                "canDownload": False,
                "canControl": True,
                "canMonitor": True,
                "canDiagnose": True,
                "canReadLogs": True,
                "pinCode": self.config.pin,
                "connectionMethod": 3,  # MobileApps
            },
        )

        response = await self._call_encrypted(login_payload, self._session_key)
        if not response:
            raise AritechError("Login failed - no response", code=ErrorCode.LOGIN_FAILED)

        # Check response: a0 00 00 means success (header + msgId 0 + status 0)
        if (
            len(response) >= 3
            and response[0] == HEADER_RESPONSE
            and response[2] == 0x00
        ):
            logger.debug("Login successful")
            self._start_keepalive()
            return

        # Login failed
        status_code = response[2] if len(response) >= 3 else 0xFF
        raise AritechError(
            f"Login failed - status code 0x{status_code:02x}",
            code=ErrorCode.LOGIN_FAILED,
            status=status_code,
        )

    def _start_keepalive(self) -> None:
        """Start keep-alive task."""
        if self._keepalive_task:
            return

        async def keepalive() -> None:
            while True:
                try:
                    await asyncio.sleep(30)
                    if self._session_key and self._writer:
                        msg = construct_message("ping", {})
                        await self._call_encrypted(msg, self._session_key)
                    else:
                        # No session/writer, stop keepalive
                        break
                except asyncio.CancelledError:
                    # Task was cancelled, exit cleanly
                    break
                except Exception as e:
                    # Log error but continue - don't break on transient errors
                    logger.debug(f"Keep-alive failed: {e}")

        self._keepalive_task = asyncio.create_task(keepalive())

    def _stop_keepalive(self) -> None:
        """Stop keep-alive task."""
        if self._keepalive_task:
            self._keepalive_task.cancel()
            self._keepalive_task = None

    def start_background_reader(self) -> None:
        """Start background reader task that fans out all incoming messages."""
        if self._reader_task:
            return

        async def reader_loop() -> None:
            """
            Single reader that handles ALL incoming frames.

            - COS events → queued and processed via callbacks
            - Command responses → delivered to waiting command via Future
            """
            logger.debug("Background reader started")
            frame_count = 0

            while self._monitoring_active and self._reader and self._session_key:
                try:
                    # Read next frame (with timeout so we can check _monitoring_active)
                    frame = await self._read_frame_direct(timeout=1.0)
                    if not frame:
                        continue

                    frame_count += 1
                    logger.debug(f"Background reader got frame #{frame_count}: {len(frame)} bytes")

                    # Check if it's a COS event
                    if self._is_cos_event(frame):
                        logger.debug("  -> COS event, processing...")
                        await self._handle_cos_frame(frame)
                    else:
                        # It's a command response - deliver to waiting command
                        logger.debug("  -> Command response")
                        if self._pending_response and not self._pending_response.done():
                            self._pending_response.set_result(frame)
                        else:
                            # No one waiting - this shouldn't happen normally
                            logger.debug("  -> No pending command, discarding")

                except asyncio.TimeoutError:
                    # No data available, continue polling
                    continue
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.debug(f"Background reader error: {e}")
                    await asyncio.sleep(0.1)

            logger.debug(f"Background reader stopped (read {frame_count} frames)")

        self._reader_task = asyncio.create_task(reader_loop())

    async def _read_frame_direct(self, timeout: float = 5.0) -> bytes | None:
        """Read a single SLIP frame directly from socket (no fan-out logic)."""
        if not self._reader:
            return None

        end_time = asyncio.get_event_loop().time() + timeout

        while True:
            # Check for complete frame in buffer
            if SLIP_END in self._receive_buffer:
                start = 0
                if self._receive_buffer[0] == SLIP_END:
                    start = 1
                end = self._receive_buffer.index(SLIP_END, start)
                if end > start:
                    frame = bytes(self._receive_buffer[: end + 1])
                    del self._receive_buffer[: end + 1]
                    return frame
                del self._receive_buffer[: end + 1]

            remaining = end_time - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError()

            try:
                data = await asyncio.wait_for(
                    self._reader.read(1024), timeout=min(remaining, 0.5)
                )
                if not data:
                    return None
                self._receive_buffer.extend(data)
            except asyncio.TimeoutError:
                if asyncio.get_event_loop().time() >= end_time:
                    raise
                # Short timeout for responsiveness, continue

    def _is_cos_event(self, frame: bytes) -> bool:
        """Check if frame is a COS event (without queueing it)."""
        if not self._session_key:
            return False

        try:
            decrypted = decrypt_message(frame, self._session_key, self._serial_bytes)
            if not decrypted or len(decrypted) < 3:
                return False

            # COS event format: [0xC0 header][0xCA 0x00 msgId 37][payload...]
            return decrypted[0] == 0xC0 and decrypted[1] == 0xCA and decrypted[2] == 0x00
        except Exception:
            return False

    async def _handle_cos_frame(self, frame: bytes) -> None:
        """Process a COS event frame by spawning listener tasks (non-blocking)."""
        try:
            decrypted = decrypt_message(frame, self._session_key, self._serial_bytes)
            if not decrypted:
                return

            payload = decrypted[3:]  # Skip C0 CA 00
            status_byte = payload[2] if len(payload) >= 3 else None

            # Spawn listener tasks - don't await them!
            # This prevents deadlock: listeners may send commands that need
            # responses from the background reader, so we can't block here.
            for listener in self._event_listeners:
                asyncio.create_task(self._run_cos_listener(listener, status_byte, payload))
        except Exception as e:
            logger.error(f"Error handling COS frame: {e}")

    async def _run_cos_listener(
        self,
        listener: Callable[[int | None, bytes], Coroutine[Any, Any, None]],
        status_byte: int | None,
        payload: bytes,
    ) -> None:
        """Run a COS listener in a separate task with error handling."""
        try:
            await listener(status_byte, payload)
        except Exception as e:
            logger.error(f"Error in COS listener: {e}")

    def stop_background_reader(self) -> None:
        """Stop background reader task."""
        if self._reader_task:
            self._reader_task.cancel()
            self._reader_task = None

    # ========================================================================
    # Low-level communication
    # ========================================================================

    @property
    def session_key(self) -> bytes | None:
        """Session key for encrypted communication."""
        return self._session_key

    @property
    def monitoring_active(self) -> bool:
        """Whether monitoring mode is active."""
        return self._monitoring_active

    @monitoring_active.setter
    def monitoring_active(self, value: bool) -> None:
        """Set monitoring mode state."""
        self._monitoring_active = value

    def on_cos_event(
        self, callback: Callable[[int | None, bytes], Coroutine[Any, Any, None]]
    ) -> None:
        """Register a callback for COS (Change of Status) events."""
        self._event_listeners.append(callback)

    async def _send_raw(self, data: bytes) -> None:
        """Send raw bytes."""
        if not self._writer:
            raise AritechError("Not connected", code=ErrorCode.CONNECTION_FAILED)
        self._writer.write(data)
        await self._writer.drain()

    async def _receive_frame(self, timeout: float = 5.0) -> bytes:
        """Receive a SLIP frame."""
        if not self._reader:
            raise AritechError("Not connected", code=ErrorCode.CONNECTION_FAILED)

        # If background reader is active, wait for it to deliver the response
        if self._monitoring_active and self._reader_task:
            return await self._receive_frame_via_reader(timeout)

        # Otherwise read directly (used during initialization before monitoring starts)
        return await self._receive_frame_direct(timeout)

    async def _receive_frame_via_reader(self, timeout: float) -> bytes:
        """Wait for background reader to deliver a response frame."""
        # Create a future for the background reader to resolve
        self._pending_response = asyncio.get_event_loop().create_future()

        try:
            frame = await asyncio.wait_for(self._pending_response, timeout=timeout)
            return frame
        except asyncio.TimeoutError:
            raise AritechError("Receive timeout", code=ErrorCode.TIMEOUT)
        finally:
            self._pending_response = None

    async def _receive_frame_direct(self, timeout: float) -> bytes:
        """Read a SLIP frame directly (when monitoring not active)."""
        end_time = asyncio.get_event_loop().time() + timeout

        while True:
            # Check for complete frame in buffer
            if SLIP_END in self._receive_buffer:
                start = 0
                if self._receive_buffer[0] == SLIP_END:
                    start = 1
                end = self._receive_buffer.index(SLIP_END, start)
                if end > start:
                    frame = bytes(self._receive_buffer[: end + 1])
                    del self._receive_buffer[: end + 1]
                    return frame
                del self._receive_buffer[: end + 1]

            remaining = end_time - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise AritechError("Receive timeout", code=ErrorCode.TIMEOUT)

            try:
                data = await asyncio.wait_for(
                    self._reader.read(1024), timeout=min(remaining, 0.5)
                )
                if not data:
                    raise AritechError(
                        "Connection closed", code=ErrorCode.CONNECTION_FAILED
                    )
                self._receive_buffer.extend(data)
            except asyncio.TimeoutError:
                if asyncio.get_event_loop().time() >= end_time:
                    raise AritechError("Receive timeout", code=ErrorCode.TIMEOUT)

    async def send_encrypted(self, payload: bytes, key: bytes | None = None) -> None:
        """Send an encrypted message without waiting for response."""
        if key is None:
            key = self._session_key
        if not key or not self._serial_bytes:
            raise AritechError("No encryption key", code=ErrorCode.PROTOCOL_ERROR)

        encrypted = encrypt_message(payload, key, self._serial_bytes)
        frame = slip_encode(encrypted)

        logger.debug(f"TX (enc, no-wait): {frame.hex()}")
        await self._send_raw(frame)

    async def _call_plain(self, payload: bytes) -> bytes:
        """Send unencrypted message and receive response."""
        with_crc = append_crc(payload)
        frame = slip_encode(with_crc)

        logger.debug(f"TX (plain): {frame.hex()}")
        await self._send_raw(frame)

        response = await self._receive_frame()
        logger.debug(f"RX (plain): {response.hex()}")

        decoded = slip_decode(response)
        if not verify_crc(decoded):
            raise AritechError("CRC error", code=ErrorCode.CRC_ERROR)

        return decoded

    async def _call_encrypted(
        self, payload: bytes, key: bytes | None = None, raise_on_error: bool = True
    ) -> bytes | None:
        """Send encrypted message and receive response."""
        if key is None:
            key = self._session_key
        if not key or not self._serial_bytes:
            raise AritechError("No encryption key", code=ErrorCode.PROTOCOL_ERROR)

        encrypted = encrypt_message(payload, key, self._serial_bytes)
        frame = slip_encode(encrypted)

        logger.debug(f"TX (enc): {frame.hex()}")
        await self._send_raw(frame)

        # If monitoring active, bg reader will deliver response via Future
        # Otherwise we read directly
        response = await self._receive_frame()
        logger.debug(f"RX (enc): {response.hex()}")

        decrypted = decrypt_message(response, key, self._serial_bytes)
        if not decrypted:
            # Check for error response
            decoded = slip_decode(response)
            if decoded and decoded[0] == HEADER_ERROR and raise_on_error:
                error_code = decoded[1] if len(decoded) > 1 else 0
                raise AritechError(
                    f"Panel error: 0x{error_code:02x}",
                    code=ErrorCode.PANEL_ERROR,
                    panel_error=error_code,
                )
            return None

        # Check for error in decrypted response
        if raise_on_error:
            err = check_response_error(decrypted)
            if err is not None:
                raise AritechError(
                    f"Panel error: 0x{err:02x}",
                    code=ErrorCode.PANEL_ERROR,
                    panel_error=err,
                )

        return decrypted

    async def call_encrypted(
        self, payload: bytes, key: bytes | None = None, raise_on_error: bool = True
    ) -> bytes | None:
        """
        Public method to send encrypted message and receive response.

        Used by AritechMonitor for COS handling. This delegates to the internal
        method which handles pausing the background reader.
        """
        return await self._call_encrypted(payload, key, raise_on_error)

    # ========================================================================
    # Generic name fetching helper
    # ========================================================================

    async def _get_names(
        self,
        msg_name: str,
        response_name: str,
        entity_name: str,
        *,
        max_count: int | None = None,
        valid_numbers: list[int] | None = None,
    ) -> list[NamedItem]:
        """
        Generic helper for fetching entity names from the panel.

        Args:
            msg_name: Message name for the request (e.g., 'getAreaNames')
            response_name: Response message name (e.g., 'areaNames')
            entity_name: Entity type name for logging (e.g., 'Area')
            max_count: Maximum entity count (stops pagination)
            valid_numbers: Only include these entity numbers

        Returns:
            List of NamedItem objects
        """
        logger.debug(f"Querying {entity_name} names...")

        results: list[NamedItem] = []

        # Determine which pages to request
        pages_to_request: list[int] = []
        if valid_numbers:
            # Only request pages containing valid numbers
            page_set: set[int] = set()
            for num in valid_numbers:
                page_start = ((num - 1) // NAMES_PER_PAGE) * NAMES_PER_PAGE + 1
                page_set.add(page_start)
            pages_to_request = sorted(page_set)
        elif max_count:
            # Request pages up to max_count
            pages_to_request = list(range(1, max_count + 1, NAMES_PER_PAGE))
        else:
            # Request pages until empty (output/trigger style)
            pages_to_request = list(range(1, 257, NAMES_PER_PAGE))

        for start_index in pages_to_request:
            payload = construct_message(msg_name, {"index": start_index})
            response = await self._call_encrypted(payload, self._session_key)

            if not response:
                logger.debug(f"No response for {entity_name} page at {start_index}")
                if not max_count and not valid_numbers:
                    break  # Stop pagination on no response
                continue

            if response[0] == HEADER_RESPONSE and is_message_type(
                response, response_name, 1
            ):
                found_any = False

                for i in range(NAMES_PER_PAGE):
                    offset = NAMES_START_OFFSET + i * NAME_LENGTH
                    if offset + NAME_LENGTH > len(response):
                        break

                    entity_num = start_index + i
                    if max_count and entity_num > max_count:
                        break

                    name_bytes = response[offset : offset + NAME_LENGTH]
                    name = (
                        name_bytes.decode("ascii", errors="ignore")
                        .rstrip("\x00")
                        .strip()
                    )

                    if name:
                        # Filter by valid_numbers if provided
                        if not valid_numbers or entity_num in valid_numbers:
                            results.append(NamedItem(number=entity_num, name=name))
                            found_any = True

                # Stop pagination if no entities found and not using valid_numbers/max_count
                if not found_any and not valid_numbers and not max_count:
                    logger.debug(
                        f"No {entity_name}s found at index {start_index}, stopping"
                    )
                    break
            else:
                logger.debug(f"Unexpected response format for {entity_name} page")
                if not max_count and not valid_numbers:
                    break

        logger.debug(f"Found {len(results)} {entity_name}s")
        return results

    # ========================================================================
    # Control session helper
    # ========================================================================

    @asynccontextmanager
    async def _with_control_session(
        self,
        create_msg_name: str,
        create_props: dict[str, Any],
        entity_type: str,
        entity_id: int,
    ) -> AsyncIterator[int]:
        """
        Async context manager for control session operations.

        Creates a control session, yields the session ID, and ensures
        cleanup (destroyControlSession) runs even on failure.

        Uses a lock to serialize all control operations, preventing conflicts when:
        1. The same entity can only have one active control session
        2. Requests don't have unique IDs, so responses must be sequential

        Args:
            create_msg_name: Message name for creating the session
            create_props: Properties for the create message
            entity_type: Entity type for error messages (e.g., 'zone')
            entity_id: Entity ID for error messages

        Yields:
            The session ID for use in action commands

        Raises:
            AritechError: If session creation fails
        """
        async with self._command_lock:
            create_payload = construct_message(create_msg_name, create_props)
            response = await self._call_encrypted(create_payload, self._session_key)

            cc = parse_create_cc_response(response)
            if not cc:
                raise AritechError(
                    f"Failed to create control context for {entity_type} {entity_id}",
                    code=ErrorCode.CREATE_CC_FAILED,
                )

            session_id = cc["sessionId"]
            try:
                yield session_id
            finally:
                await self._call_encrypted(
                    construct_message("destroyControlSession", {"sessionId": session_id}),
                    self._session_key,
                    raise_on_error=False,
                )

    # ========================================================================
    # Area operations
    # ========================================================================

    async def get_area_names(self) -> list[NamedItem]:
        """Get area names from the panel."""
        return await self._get_names(
            "getAreaNames",
            "areaNames",
            "Area",
            max_count=self.max_area_count,
        )

    async def get_area_states(
        self, area_numbers: list[int] | None = None
    ) -> list[StateResult]:
        """Get area states."""
        if area_numbers is None:
            area_numbers = list(range(1, self.max_area_count + 1))

        if not area_numbers:
            return []

        # Use batch request for efficiency
        payload = build_batch_stat_request("AREA", area_numbers)
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            return []

        messages = split_batch_response(response, "areaStatus")
        results: list[StateResult] = []

        for msg in messages:
            state = AreaState.from_bytes(msg["bytes"])
            results.append(
                StateResult(
                    number=msg["objectId"],
                    state=state,
                    raw_hex=msg["bytes"].hex(),
                )
            )

        return results

    async def get_valid_areas(self) -> list[int]:
        """Get list of valid/configured area numbers. Uses cached value if available."""
        # Return cached value if available
        if self._valid_area_numbers is not None:
            logger.debug(f"Using cached valid areas: {self._valid_area_numbers}")
            return self._valid_area_numbers

        payload = construct_message("getValidAreas", {})
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 3:
            return list(range(1, self.max_area_count + 1))

        if response[0] == HEADER_RESPONSE and is_message_type(
            response, "validAreas", 1
        ):
            # Parse bitmask - skip a0 1b 02 (header + msgId + typeId)
            bitset = response[3:]
            valid: list[int] = []
            for byte_idx, byte in enumerate(bitset):
                for bit in range(8):
                    if byte & (1 << bit):
                        valid.append(byte_idx * 8 + bit + 1)
            self._valid_area_numbers = valid
            return valid

        return list(range(1, self.max_area_count + 1))

    # ========================================================================
    # Zone operations
    # ========================================================================

    async def get_zone_names(self) -> list[NamedItem]:
        """Get zone names from the panel."""
        # First, get the list of valid zones from the panel
        valid_zone_numbers = await self.get_valid_zone_numbers()

        return await self._get_names(
            "getZoneNames",
            "zoneNames",
            "Zone",
            valid_numbers=valid_zone_numbers,
        )

    async def get_valid_zone_numbers(self) -> list[int] | None:
        """
        Get list of valid/configured zone numbers from the panel.

        This method also populates the zone-to-areas mapping (self._zone_areas),
        which maps each zone number to the list of areas it belongs to.

        Returns:
            List of valid zone numbers, or None if query fails
        """
        logger.debug("Querying valid zone numbers...")

        # Get valid areas first (from cache or query)
        if self._valid_area_numbers is None:
            self._valid_area_numbers = await self.get_valid_areas()

        valid_areas = self._valid_area_numbers
        if not valid_areas:
            logger.debug("No valid areas found")
            return None

        # Build batch request - one getZonesAssignedToAreas per area
        requests: list[bytes] = []
        for i, area_num in enumerate(valid_areas):
            msg = build_get_valid_zones_message([area_num])
            # Strip header for batch
            without_header = msg[1:]
            # Separator is the message length (0x0c = 12 bytes for getZonesAssignedToAreas)
            separator = len(without_header)
            # Add separator between requests (not after last one)
            if i < len(valid_areas) - 1:
                requests.append(without_header + bytes([separator]))
            else:
                requests.append(without_header)

        # Send batch request
        batch_msg = construct_message("batch", {})
        length_byte = bytes([0x0C])  # getZonesAssignedToAreas messages are 12 bytes
        payload = batch_msg + length_byte + b"".join(requests)

        logger.debug(f"Zone batch payload ({len(payload)} bytes)")
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            logger.debug("No valid batch response for zones")
            return await self._get_valid_zone_numbers_individual(valid_areas)

        # Response format: a0 [ee ee 20] [response1] [20] [response2] [20] ... [responseN]
        # 0x20 is the msgId for zonesAssignedToAreas
        if response[1] != 0xEE or response[2] != 0xEE or response[3] != 0x20:
            logger.debug(f"Unexpected response format: {response[:4].hex()}, falling back")
            return await self._get_valid_zone_numbers_individual(valid_areas)

        # Reset zone-to-areas mapping
        self._zone_areas = {}
        valid_zones_set: set[int] = set()

        # Each zone response is 32 bytes: 20 0a [30 bytes bitset]
        # Plus 0x20 separator between responses (not after last)
        ZONE_RESPONSE_LEN = 32
        offset = 4  # Skip a0 ee ee 20 header

        for i, area_num in enumerate(valid_areas):
            is_last = i == len(valid_areas) - 1
            response_len = ZONE_RESPONSE_LEN if is_last else ZONE_RESPONSE_LEN + 1

            if offset + ZONE_RESPONSE_LEN > len(response):
                logger.debug(f"Not enough data at offset {offset} for area {area_num}")
                break

            zone_response = response[offset : offset + ZONE_RESPONSE_LEN]
            offset += response_len

            # Parse: 20 0a [bitset...]
            if zone_response[0] != 0x20:
                logger.debug(
                    f"Unexpected zone response format for area {area_num}: {zone_response[:4].hex()}"
                )
                continue

            bitset_start = 2  # Skip 20 0a
            bitset = zone_response[bitset_start:]

            for byte_idx, byte_val in enumerate(bitset):
                for bit in range(8):
                    if byte_val & (1 << bit):
                        zone_num = byte_idx * 8 + bit + 1
                        valid_zones_set.add(zone_num)

                        # Add this area to zone's area list
                        if zone_num not in self._zone_areas:
                            self._zone_areas[zone_num] = []
                        self._zone_areas[zone_num].append(area_num)

        valid_zones = sorted(valid_zones_set)
        logger.debug(f"Found {len(valid_zones)} valid zones")
        logger.debug(f"Zone-to-areas mapping: {len(self._zone_areas)} entries")
        return valid_zones

    async def _get_valid_zone_numbers_individual(
        self, valid_areas: list[int]
    ) -> list[int] | None:
        """
        Fallback: query zones for each area individually (slower but more compatible).

        Args:
            valid_areas: List of valid area numbers

        Returns:
            List of valid zone numbers
        """
        logger.debug("Using individual zone queries (fallback)")

        self._zone_areas = {}
        valid_zones_set: set[int] = set()

        for area_num in valid_areas:
            payload = build_get_valid_zones_message([area_num])
            response = await self._call_encrypted(payload, self._session_key)

            if not response:
                logger.debug(f"No response for area {area_num}")
                continue

            if response[0] == HEADER_RESPONSE and is_message_type(
                response, "zonesAssignedToAreas", 1
            ):
                bitset_start = 3  # Skip a0 20 0a
                bitset = response[bitset_start:]

                for byte_idx, byte_val in enumerate(bitset):
                    for bit in range(8):
                        if byte_val & (1 << bit):
                            zone_num = byte_idx * 8 + bit + 1
                            valid_zones_set.add(zone_num)

                            if zone_num not in self._zone_areas:
                                self._zone_areas[zone_num] = []
                            self._zone_areas[zone_num].append(area_num)

        valid_zones = sorted(valid_zones_set)
        logger.debug(f"Found {len(valid_zones)} valid zones")
        return valid_zones

    def get_zone_areas(self, zone_num: int) -> list[int] | None:
        """
        Get the areas a zone belongs to.

        Args:
            zone_num: Zone number

        Returns:
            List of area numbers, or None if unknown
        """
        return self._zone_areas.get(zone_num)

    async def _get_zone_area_props(self, zone_num: int) -> dict[str, bool]:
        """
        Build area props dict for createZoneControlSession based on zone's assigned areas.

        Args:
            zone_num: Zone number

        Returns:
            Dictionary with area.N: True for each area the zone belongs to
        """
        # If zone-to-areas mapping is empty, populate it first
        if not self._zone_areas:
            logger.debug("Zone-to-areas mapping empty, querying...")
            await self.get_valid_zone_numbers()

        areas = self.get_zone_areas(zone_num)
        if areas:
            props = {f"area.{area_num}": True for area_num in areas}
            logger.debug(f"Zone {zone_num} is in areas: {areas}")
            return props

        # Fallback to all valid areas if zone mapping unknown
        if self._valid_area_numbers:
            props = {f"area.{area_num}": True for area_num in self._valid_area_numbers}
            logger.debug(
                f"Zone {zone_num} area unknown, using all valid areas: {self._valid_area_numbers}"
            )
            return props

        # Last resort fallback
        logger.debug(f"Zone {zone_num} area unknown, falling back to area 1")
        return {"area.1": True}

    async def get_zone_states(
        self, zone_numbers: list[int] | None = None
    ) -> list[StateResult]:
        """Get zone states using batch request."""
        if zone_numbers is None:
            zone_numbers = list(range(1, min(24, self.max_zone_count) + 1))

        if not zone_numbers:
            return []

        payload = build_batch_stat_request("ZONE", zone_numbers)
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            logger.debug("No valid batch response, falling back to individual queries")
            return await self._get_zone_states_individual(zone_numbers)

        messages = split_batch_response(response, "zoneStatus")

        if not messages:
            logger.debug("No messages parsed from batch, falling back to individual queries")
            return await self._get_zone_states_individual(zone_numbers)

        results: list[StateResult] = []

        for msg in messages:
            state = ZoneState.from_bytes(msg["bytes"])
            results.append(
                StateResult(
                    number=msg["objectId"],
                    state=state,
                    raw_hex=msg["bytes"].hex(),
                )
            )

        return results

    async def _get_zone_states_individual(
        self, zone_numbers: list[int]
    ) -> list[StateResult]:
        """
        Get zone states individually (fallback when batch fails).

        Args:
            zone_numbers: List of zone numbers to query

        Returns:
            List of zone state results
        """
        logger.debug("Using individual zone state queries")
        results: list[StateResult] = []

        for zone_num in zone_numbers:
            # Build individual getZoneStatus request
            payload = bytes([0xC0]) + build_get_stat_request("ZONE", zone_num, False)
            response = await self._call_encrypted(payload, self._session_key)

            if response and len(response) >= 7 and response[4] == zone_num:
                state = ZoneState.from_bytes(response)
                results.append(
                    StateResult(
                        number=zone_num,
                        state=state,
                        raw_hex=response.hex(),
                    )
                )

        return results

    async def inhibit_zone(self, zone_num: int) -> None:
        """Inhibit a zone."""
        logger.debug(f"Inhibiting zone {zone_num}...")

        area_props = await self._get_zone_area_props(zone_num)
        async with self._with_control_session(
            "createZoneControlSession", area_props, "zone", zone_num
        ) as session_id:
            payload = construct_message(
                "inhibitZone", {"sessionId": session_id, "objectId": zone_num}
            )
            response = await self._call_encrypted(
                payload, self._session_key, raise_on_error=False
            )

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to inhibit zone {zone_num}",
                    code=ErrorCode.ZONE_INHIBIT_FAILED,
                )

            logger.debug(f"Zone {zone_num} inhibited")

    async def uninhibit_zone(self, zone_num: int) -> None:
        """Uninhibit a zone."""
        logger.debug(f"Uninhibiting zone {zone_num}...")

        area_props = await self._get_zone_area_props(zone_num)
        async with self._with_control_session(
            "createZoneControlSession", area_props, "zone", zone_num
        ) as session_id:
            payload = construct_message(
                "uninhibitZone", {"sessionId": session_id, "objectId": zone_num}
            )
            response = await self._call_encrypted(
                payload, self._session_key, raise_on_error=False
            )

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to uninhibit zone {zone_num}",
                    code=ErrorCode.ZONE_UNINHIBIT_FAILED,
                )

            logger.debug(f"Zone {zone_num} uninhibited")

    # ========================================================================
    # Output operations
    # ========================================================================

    async def get_output_names(self) -> list[NamedItem]:
        """Get output names from the panel."""
        return await self._get_names("getOutputNames", "outputNames", "Output")

    async def get_output_states(
        self, output_numbers: list[int] | None = None
    ) -> list[StateResult]:
        """Get output states."""
        if output_numbers is None:
            output_numbers = list(range(1, 9))

        if not output_numbers:
            return []

        payload = build_batch_stat_request("OUTPUT", output_numbers)
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            return []

        messages = split_batch_response(response, "outputStatus")
        results: list[StateResult] = []

        for msg in messages:
            state = OutputState.from_bytes(msg["bytes"])
            results.append(
                StateResult(
                    number=msg["objectId"],
                    state=state,
                    raw_hex=msg["bytes"].hex(),
                )
            )

        return results

    async def activate_output(self, output_num: int) -> None:
        """Activate an output."""
        logger.debug(f"Activating output {output_num}...")

        async with self._with_control_session(
            "createOutputControlSession", {"area.1": True}, "output", output_num
        ) as session_id:
            payload = construct_message(
                "activateOutput", {"sessionId": session_id, "objectId": output_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to activate output {output_num}",
                    code=ErrorCode.OUTPUT_ACTIVATE_FAILED,
                )

            logger.debug(f"Output {output_num} activated")

    async def deactivate_output(self, output_num: int) -> None:
        """Deactivate an output."""
        logger.debug(f"Deactivating output {output_num}...")

        async with self._with_control_session(
            "createOutputControlSession", {"area.1": True}, "output", output_num
        ) as session_id:
            payload = construct_message(
                "deactivateOutput", {"sessionId": session_id, "objectId": output_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to deactivate output {output_num}",
                    code=ErrorCode.OUTPUT_DEACTIVATE_FAILED,
                )

            logger.debug(f"Output {output_num} deactivated")

    # ========================================================================
    # Trigger operations
    # ========================================================================

    async def get_trigger_names(self) -> list[NamedItem]:
        """Get trigger names from the panel."""
        return await self._get_names("getTriggerNames", "triggerNames", "Trigger")

    async def get_trigger_states(
        self, trigger_numbers: list[int] | None = None
    ) -> list[StateResult]:
        """Get trigger states."""
        if trigger_numbers is None:
            trigger_numbers = list(range(1, 9))

        if not trigger_numbers:
            return []

        payload = build_batch_stat_request("TRIGGER", trigger_numbers)
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            return []

        messages = split_batch_response(response, "triggerStatus")
        results: list[StateResult] = []

        for msg in messages:
            state = TriggerState.from_bytes(msg["bytes"])
            results.append(
                StateResult(
                    number=msg["objectId"],
                    state=state,
                    raw_hex=msg["bytes"].hex(),
                )
            )

        return results

    async def activate_trigger(self, trigger_num: int) -> None:
        """Activate a trigger."""
        logger.debug(f"Activating trigger {trigger_num}...")

        async with self._with_control_session(
            "createTriggerControlSession", {}, "trigger", trigger_num
        ) as session_id:
            payload = construct_message(
                "activateTrigger", {"sessionId": session_id, "objectId": trigger_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to activate trigger {trigger_num}",
                    code=ErrorCode.TRIGGER_ACTIVATE_FAILED,
                )

            logger.debug(f"Trigger {trigger_num} activated")

    async def deactivate_trigger(self, trigger_num: int) -> None:
        """Deactivate a trigger."""
        logger.debug(f"Deactivating trigger {trigger_num}...")

        async with self._with_control_session(
            "createTriggerControlSession", {}, "trigger", trigger_num
        ) as session_id:
            payload = construct_message(
                "deactivateTrigger", {"sessionId": session_id, "objectId": trigger_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to deactivate trigger {trigger_num}",
                    code=ErrorCode.TRIGGER_DEACTIVATE_FAILED,
                )

            logger.debug(f"Trigger {trigger_num} deactivated")

    # ========================================================================
    # Arm/Disarm operations
    # ========================================================================

    async def arm_area(
        self, areas: int | list[int], set_type: str = "full", force: bool = False
    ) -> None:
        """
        Arm one or more areas.

        Args:
            areas: Area number(s) to arm - single int or list of ints
            set_type: Arm type ('full', 'part1', 'part2')
            force: Force arm despite faults
        """
        async with self._command_lock:
            await self._arm_area_impl(areas, set_type, force)

    async def _arm_area_impl(
        self, areas: int | list[int], set_type: str = "full", force: bool = False
    ) -> None:
        """Internal implementation of arm_area (called with lock held)."""
        area_list = areas if isinstance(areas, list) else [areas]
        logger.debug(f"Arming area(s) {area_list} ({set_type}, force={force})...")

        # Map set_type to create message name
        create_messages = {
            "full": "createArmSession",
            "part1": "createPartArmSession",
            "part2": "createPartArm2Session",
        }
        create_msg_name = create_messages.get(set_type.lower(), "createArmSession")

        # Status mappings per set type
        success_statuses = {
            "full": [CC_STATUS["FullSetSetting"], CC_STATUS["FullSetSet"]],
            "part1": [CC_STATUS["PartSetSetting"], CC_STATUS["PartSetSet"]],
            "part2": [CC_STATUS["PartSet2Setting"], CC_STATUS["PartSet2Set"]],
        }
        fault_statuses = {
            "full": CC_STATUS["FullSetFault"],
            "part1": CC_STATUS["PartSetFault"],
            "part2": CC_STATUS["PartSet2Fault"],
        }
        active_statuses = {
            "full": CC_STATUS["FullSetActiveStates"],
            "part1": CC_STATUS["PartSetActiveStates"],
            "part2": CC_STATUS["PartSet2ActiveStates"],
        }
        inhibited_statuses = {
            "full": CC_STATUS["FullSetInhibited"],
            "part1": CC_STATUS["PartSetInhibited"],
            "part2": CC_STATUS["PartSet2Inhibited"],
        }

        # Step 1: Create control context
        area_props = {f"area.{area_num}": True for area_num in area_list}
        create_payload = construct_message(create_msg_name, area_props)
        logger.debug(f"Step 1: Sending {create_msg_name}")
        response = await self._call_encrypted(create_payload, self._session_key)

        cc = parse_create_cc_response(response)
        if not cc:
            raise AritechError(
                f"Failed to create control context for area(s) {area_list}",
                code=ErrorCode.CREATE_CC_FAILED,
            )

        session_id = cc["sessionId"]
        logger.debug(f"createArmSession succeeded, sessionId: 0x{session_id:x}")

        try:
            # Step 2: Start arm procedure
            logger.debug("Step 2: Starting arm procedure (armAreas)")
            arm_payload = construct_message("armAreas", {"sessionId": session_id})
            await self._call_encrypted(arm_payload, self._session_key, raise_on_error=False)
            logger.debug("armAreas sent")

            # Step 3: Poll status and handle force scenarios
            forced_once = False
            polls_after_force = 0
            last_status = 0

            for i in range(60):
                if i > 0:
                    await asyncio.sleep(0.3)

                # Read status
                status_payload = construct_message(
                    "getControlSessionStatus", {"sessionId": session_id}
                )
                status_response = await self._call_encrypted(
                    status_payload, self._session_key, raise_on_error=False
                )

                if not status_response or len(status_response) < 5:
                    logger.debug(f"Poll {i + 1}: Invalid response")
                    continue

                # Check if this is actually a controlSessionStatus (msgId 0x20)
                if not is_message_type(status_response, "controlSessionStatus", 1):
                    logger.debug(
                        f"Poll {i + 1}: Got different message (0x{status_response[1]:02x}), retrying..."
                    )
                    continue

                # Parse stateId (16-bit big-endian at bytes 2-3 after header)
                state_id = get_property(
                    "controlSessionStatus", status_response[1:], "stateId"
                )
                last_status = state_id
                logger.debug(f"Poll {i + 1}: Status 0x{state_id:04x}")

                # Check for success (Setting or Set)
                if state_id in success_statuses.get(set_type.lower(), []):
                    logger.debug(f"Arm operation complete - status: 0x{state_id:04x}")
                    return  # Success

                # Handle fault status
                if state_id == fault_statuses.get(set_type.lower()):
                    if not forced_once and force:
                        logger.debug("Fault detected, forcing arm...")
                        forced_once = True
                        polls_after_force = 0
                        force_payload = construct_message(
                            "setAreaForced", {"sessionId": session_id}
                        )
                        await self._call_encrypted(
                            force_payload, self._session_key, raise_on_error=False
                        )
                        continue
                    if forced_once:
                        polls_after_force += 1
                        if polls_after_force >= 10:
                            raise AritechError(
                                "Force arm failed - faults still present after forcing",
                                code=ErrorCode.FORCE_ARM_FAILED,
                                status=state_id,
                            )
                        continue
                    # Read fault zones and throw
                    faults = await self._read_arm_issues(session_id, "getFaultZones")
                    raise AritechError(
                        "Arm failed - zone faults detected",
                        code=ErrorCode.ARM_FAULTS,
                        status=state_id,
                        details={"faults": faults},
                    )

                # Handle active states status
                if state_id == active_statuses.get(set_type.lower()):
                    if not forced_once and force:
                        logger.debug("Active zones detected, forcing arm...")
                        forced_once = True
                        polls_after_force = 0
                        force_payload = construct_message(
                            "setAreaForced", {"sessionId": session_id}
                        )
                        await self._call_encrypted(
                            force_payload, self._session_key, raise_on_error=False
                        )
                        continue
                    if forced_once:
                        polls_after_force += 1
                        if polls_after_force >= 10:
                            raise AritechError(
                                "Force arm failed - active zones still present after forcing",
                                code=ErrorCode.FORCE_ARM_FAILED,
                                status=state_id,
                            )
                        continue
                    # Read active zones and throw
                    active_zones = await self._read_arm_issues(
                        session_id, "getActiveZones"
                    )
                    raise AritechError(
                        "Arm failed - active zones detected",
                        code=ErrorCode.ARM_ACTIVE_ZONES,
                        status=state_id,
                        details={"activeZones": active_zones},
                    )

                # Handle inhibited status
                if state_id == inhibited_statuses.get(set_type.lower()):
                    if not forced_once and force:
                        logger.debug("Inhibited zones detected, re-sending set command...")
                        forced_once = True
                        polls_after_force = 0
                        # For inhibited, re-send armAreas (not setAreaForced)
                        re_set_payload = construct_message(
                            "armAreas", {"sessionId": session_id}
                        )
                        await self._call_encrypted(
                            re_set_payload, self._session_key, raise_on_error=False
                        )
                        continue
                    if forced_once:
                        polls_after_force += 1
                        if polls_after_force >= 10:
                            raise AritechError(
                                "Force arm failed - inhibited zones still blocking after forcing",
                                code=ErrorCode.FORCE_ARM_FAILED,
                                status=state_id,
                            )
                        continue
                    # Read inhibited zones and throw
                    inhibited_zones = await self._read_arm_issues(
                        session_id, "getInhibitedZones"
                    )
                    raise AritechError(
                        "Arm failed - inhibited zones detected",
                        code=ErrorCode.ARM_INHIBITED,
                        status=state_id,
                        details={"inhibitedZones": inhibited_zones},
                    )

            # If we get here, polling timed out without success or clear failure
            raise AritechError(
                "Arm operation timed out",
                code=ErrorCode.ARM_FAILED,
                status=last_status,
            )

        finally:
            # Step 4: Cleanup - always destroy control context
            logger.debug("Step 4: Cleanup control context...")
            await self._call_encrypted(
                construct_message("destroyControlSession", {"sessionId": session_id}),
                self._session_key,
                raise_on_error=False,
            )
            logger.debug("Cleanup complete")

    async def _read_arm_issues(
        self, session_id: int, message_name: str
    ) -> list[dict[str, Any]]:
        """
        Read fault/active/inhibited zones during arm procedure.

        Args:
            session_id: Control session ID
            message_name: Message to send ('getFaultZones', 'getActiveZones', 'getInhibitedZones')

        Returns:
            List of issue dictionaries with raw data
        """
        issues: list[dict[str, Any]] = []
        next_val = 0

        for i in range(100):  # Safety limit
            payload = construct_message(
                message_name, {"sessionId": session_id, "next": next_val}
            )
            try:
                response = await self._call_encrypted(
                    payload, self._session_key, raise_on_error=False
                )
            except AritechError as err:
                # Panel may return error when no issues to report
                logger.debug(f"{message_name}: {err}")
                break

            if not response or len(response) < 3:
                break

            # Check if response is booleanResponse (end of list)
            if is_message_type(response, "booleanResponse", 1):
                break

            # Parse zone info from response
            if len(response) >= 5:
                issues.append({"raw": response.hex(), "index": i})

            next_val = 1  # Continue reading

        logger.debug(f"Read {len(issues)} {message_name} zones")
        return issues

    async def disarm_area(self, area_num: int) -> None:
        """Disarm an area."""
        async with self._command_lock:
            await self._disarm_area_impl(area_num)

    async def _disarm_area_impl(self, area_num: int) -> None:
        """Internal implementation of disarm_area (called with lock held)."""
        logger.debug(f"Disarming area {area_num}...")

        create_payload = construct_message(
            "createDisarmSession", {f"area.{area_num}": True}
        )
        response = await self._call_encrypted(create_payload, self._session_key)

        cc = parse_create_cc_response(response)
        if not cc:
            raise AritechError(
                f"Failed to create control context for area {area_num}",
                code=ErrorCode.CREATE_CC_FAILED,
            )

        session_id = cc["sessionId"]

        try:
            disarm_payload = construct_message(
                "disarmAreas", {"sessionId": session_id}
            )
            await self._call_encrypted(disarm_payload, self._session_key, raise_on_error=False)

            logger.debug(f"Area {area_num} disarmed")
        finally:
            await self._call_encrypted(
                construct_message("destroyControlSession", {"sessionId": session_id}),
                self._session_key,
                raise_on_error=False,
            )

    # ========================================================================
    # Event log operations
    # ========================================================================

    async def read_event_log(
        self, max_events: int = 100
    ) -> AsyncIterator["ParsedEvent"]:
        """
        Read events from the panel event log.

        This is an async generator that yields parsed events.

        Args:
            max_events: Maximum number of events to read (0 for unlimited)

        Yields:
            Parsed event dictionaries
        """
        from .event_parser import parse_event

        logger.debug("Reading event log...")

        # Open the log
        open_payload = construct_message("openLog", {})
        await self._call_encrypted(open_payload, self._session_key)

        event_count = 0
        direction = EVENT_LOG_FIRST
        last_sequence = None
        consecutive_errors = 0
        max_consecutive_errors = 3

        while max_events == 0 or event_count < max_events:
            payload = build_get_event_log_message(direction)

            try:
                response = await self._call_encrypted(payload, self._session_key)

                if not response:
                    logger.debug("No response received")
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        logger.debug("Max consecutive errors reached, stopping")
                        break
                    continue

                # Check for logEntry response (msgId 0x0D at byte 1)
                if not is_message_type(response, "logEntry", 1):
                    # Check for ack response (can happen as async COS message)
                    if len(response) > 1 and response[1] == 0x00:
                        logger.debug("Received ack, continuing...")
                        continue
                    logger.debug(
                        f"Unexpected response: {response[:10].hex() if response else 'empty'}"
                    )
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        break
                    continue

                # Response payload is 70 bytes starting at offset 2 (after header + msgId)
                event_data = response[2:]

                if len(event_data) < 70:
                    logger.debug(f"Event data too short: {len(event_data)} bytes")
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        break
                    continue

                # Parse the 70-byte event
                try:
                    event_buffer = event_data[:70]
                    parsed_event = parse_event(event_buffer)

                    # Use parsed sequence for end detection
                    sequence = parsed_event.sequence

                    # Check for end of log - when sequence wraps or stays at 0
                    if last_sequence is not None and last_sequence == 0 and sequence == 0:
                        logger.debug("Reached end of event log (oldest event)")
                        break

                    event_count += 1
                    consecutive_errors = 0
                    last_sequence = sequence

                    yield parsed_event

                except Exception as parse_error:
                    logger.debug(f"Failed to parse event: {parse_error}")
                    logger.debug(f"Raw event data: {event_data[:70].hex()}")
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        break

                # After first request, switch to "next" direction
                direction = EVENT_LOG_NEXT

            except Exception as err:
                logger.debug(f"Error reading event: {err}")
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    logger.debug("Max errors reached, stopping event log read")
                    break
