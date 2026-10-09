"""Connection robustness tests against a minimal local fake panel."""

from __future__ import annotations

import asyncio
import logging
import os

import pytest

from aritech_client.client import AritechClient
from aritech_client.errors import AritechError, ErrorCode
from aritech_client.message_helpers import parse_sys_event
from aritech_client.protocol import SLIP_END, decrypt_message, encrypt_message, slip_encode

KEY = os.urandom(16)
SERIAL = bytes.fromhex("010203040506")


class FakePanel:
    """Answers request n with `a0 n`; `delays[n]` delays that answer."""

    def __init__(self, delays: dict[int, float] | None = None) -> None:
        self.delays = delays or {}
        self.count = 0
        self.writer: asyncio.StreamWriter | None = None
        self.port = 0

    async def start(self) -> None:
        server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = server.sockets[0].getsockname()[1]

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.writer = writer
        buf = bytearray()
        try:
            while data := await reader.read(1024):
                buf.extend(data)
                while SLIP_END in buf[1:]:
                    end = buf.index(SLIP_END, 1)
                    frame = bytes(buf[: end + 1])
                    del buf[: end + 1]
                    payload = decrypt_message(frame, KEY, SERIAL)
                    if payload is None or payload[0] != 0xC0:
                        continue
                    self.count += 1
                    asyncio.create_task(self._respond(self.count))
        except ConnectionError:
            pass

    async def _respond(self, n: int) -> None:
        await asyncio.sleep(self.delays.get(n, 0))
        self.send(bytes([0xA0, n]))

    def send(self, payload: bytes) -> None:
        if self.writer and not self.writer.is_closing():
            self.writer.write(slip_encode(encrypt_message(payload, KEY, SERIAL)))

    def send_cos(self) -> None:
        self.send(bytes([0xC0, 0xCA, 0x00, 0x30, 0x00, 0x01, 0x00]))


async def _client(panel: FakePanel, *, reader: bool) -> AritechClient:
    client = AritechClient(
        {"host": "127.0.0.1", "port": panel.port, "pin": "1234", "encryption_key": "0" * 24}
    )
    await client.connect()
    client._session_key = KEY
    client._serial_bytes = SERIAL
    if reader:
        client.monitoring_active = True
        client.start_background_reader()
    return client


@pytest.mark.parametrize(
    ("reader", "delays"),
    [(False, {1: 6.0}), (True, {1: 6.0, 2: 2.0})],
    ids=["direct", "background-reader"],
)
async def test_late_response_is_never_given_to_the_next_request(reader, delays) -> None:
    panel = FakePanel(delays)
    await panel.start()
    client = await _client(panel, reader=reader)
    lost: list[int] = []
    client.on_connection_lost(lambda: lost.append(1))

    with pytest.raises(AritechError) as err:
        await client._call_encrypted(bytes([0xC0, 0x01]))
    assert err.value.code == ErrorCode.TIMEOUT

    # Before the fix the next call received the stale answer to call 1.
    with pytest.raises(AritechError) as err:
        await client._call_encrypted(bytes([0xC0, 0x02]))
    assert err.value.code == ErrorCode.CONNECTION_FAILED

    await asyncio.sleep(1.5)
    assert lost == [1]
    await client.disconnect()


async def test_cos_events_are_handled_one_at_a_time() -> None:
    panel = FakePanel()
    await panel.start()
    client = await _client(panel, reader=True)
    active = peak = calls = 0

    async def listener(status, payload) -> None:
        nonlocal active, peak, calls
        calls += 1
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.2)
        active -= 1

    client.on_cos_event(listener)
    await asyncio.sleep(0.1)
    for _ in range(5):
        panel.send_cos()
    await asyncio.sleep(1.5)

    assert peak == 1
    assert 1 <= calls <= 2  # identical waiting events are merged
    await client.disconnect()


async def test_disconnect_cleans_up_without_reporting_connection_lost() -> None:
    panel = FakePanel()
    await panel.start()
    client = await _client(panel, reader=True)
    lost: list[int] = []
    client.on_connection_lost(lambda: lost.append(1))
    await asyncio.sleep(0.1)
    client._receive_buffer.extend(b"\xc0leftover")
    client._session_key = None  # skip the logout round trip

    await client.disconnect()
    await asyncio.sleep(0.2)

    assert client._reader_task is None
    assert len(client._receive_buffer) == 0
    assert lost == []


async def test_secrets_are_not_logged(caplog) -> None:
    client = AritechClient(
        {"host": "127.0.0.1", "port": 1, "pin": "987654", "encryption_key": "0" * 24}
    )
    with caplog.at_level(logging.DEBUG, logger="aritech_client"):
        with pytest.raises(Exception):
            await client._login_with_pin()
    assert "987654" not in caplog.text


def test_parse_sys_event_active_zone() -> None:
    # Captured on an ATS1500: zone 22 active in area 1.
    event = parse_sys_event(bytes.fromhex("a02001019c01000000040000010016001f00000000"))
    assert event is not None
    assert event["objectNumber"] == 22
    assert event["areas"] == [1]
    assert event["categories"] == ["ACTZN"]
    assert parse_sys_event(bytes.fromhex("f000000003")) is None
