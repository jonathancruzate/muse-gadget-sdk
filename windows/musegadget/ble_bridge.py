# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Part of the Windows port of the Muse gadget SDK. Anything a person reads
# says Muse; the only other names here are the protocol's frozen UUIDs and
# the target PC's existing Bluetooth name, which is configuration, not code.

"""Name-translation bridge core for Muse Gadget setup.

The Muse app discovers gadgets by their advertised BLE name,
``MuseGadgetXXXXXX``. A Windows PC cannot advertise that name: Windows
reserves the Local Name section of custom advertisements, so the only
connectable advertisement a Windows gadget puts on air wears the PC's own
Bluetooth name (for example ``POWERSPEC-G757-``) next to the gadget service
UUID. The app therefore never lists the PC, even though the PC's GATT setup
service is complete and connectable.

This bridge translates between the two names. It runs on a separate
BLE-capable host in the same room (the platform driver lives in
:mod:`musegadget.ble_bridge_bluez`):

* Front (phone side): a BLE peripheral advertising the gadget's
  ``MuseGadgetXXXXXX`` name, the setup service UUID and the paired flag —
  indistinguishable from a native gadget to the app's scan.
* Back (PC side): a BLE central that finds the real gadget by its
  *existing* Bluetooth name and/or its service UUID, connects to its setup
  service, writes to its RX characteristic and subscribes to its TX
  characteristic.

The core in this module is the translation layer between those two links
and nothing else. It understands the SDK's chunk framing
(:mod:`musegadget.ble_framing`) only well enough to reassemble each
message on the incoming link and re-chunk it for the outgoing link's MTU;
message payloads are forwarded byte-for-byte, never parsed. The pairing
handshake (ECDH, encrypted records, the SDK token) therefore stays
end-to-end between the Muse app and the PC's own
:class:`musegadget.ble_setup.SetupController` — the bridge host never
sees a plaintext credential and holds no pairing state. When the window
closes, nothing about the pairing lives on the bridge: the PC's daemon
registers with Muse over WSS exactly as if it had paired directly.

The PC side needs no changes at all: it opens its normal pairing window
(``musegadget_win.py pair``) and serves whoever connects to its GATT
service — here, the bridge instead of the phone.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Iterable

try:
    from musegadget.ble_framing import ChunkAssembler, encode_chunks
    from musegadget.identity import Identity
except ImportError:  # loaded as a top-level module, with this directory on sys.path
    from ble_framing import ChunkAssembler, encode_chunks  # type: ignore[no-redef]
    from identity import Identity  # type: ignore[no-redef]

log = logging.getLogger(__name__)

# The setup GATT layout, identical in ble_server.py (BlueZ) and
# ble_server_windows.py (WinRT); duplicated here so this module imports
# without either platform stack.
SERVICE_UUID = "7fdd3d1c-38ea-46cf-8b46-314ecf5f240c"
RX_UUID = "4d593029-28a2-4a6e-a1f0-3c2d5e8f9b01"
TX_UUID = "d75dc4ca-7b2b-4e9c-8f0a-1d2e3f4a5b6c"

# Until a link reports its negotiated MTU, assume the same value both
# platform servers assume: one large enough for full 160-byte packets.
ASSUMED_MTU = 163

# App messages reassembled before the back link is up are held, in order,
# up to this many; pairing sends only a handful, so this is generous.
MAX_QUEUED_MESSAGES = 16

# A name match must share at least this many leading characters. PC
# Bluetooth names are themselves often truncated (a 15-character name
# ending in "-" is the signature of a cut-off longer name), and a scan
# can surface a shortened form, so exact matching alone is too strict.
MIN_NAME_PREFIX = 8


def _norm_address(address: str | None) -> str:
    return (address or "").replace("-", ":").upper()


def _name_matches(seen: str | None, wanted: str) -> bool:
    if not seen:
        return False
    if seen == wanted:
        return True
    shorter, longer = (seen, wanted) if len(seen) < len(wanted) else (wanted, seen)
    return len(shorter) >= MIN_NAME_PREFIX and longer.startswith(shorter)


@dataclass(frozen=True)
class BridgeConfig:
    """Which name the bridge advertises, and which existing device it feeds.

    ``front_name`` is the gadget's BLE name (``Identity.ble_name``).
    The back target is recognised by Bluetooth address when
    ``target_address`` is set, otherwise by any of ``target_names``
    (the PC's existing Bluetooth name) together with the setup service
    UUID whenever the scan reports UUIDs.
    """

    front_name: str
    target_names: tuple[str, ...] = ()
    target_address: str | None = None
    service_uuid: str = SERVICE_UUID

    @classmethod
    def for_identity(
        cls,
        identity: Identity,
        *,
        target_names: Iterable[str] = (),
        target_address: str | None = None,
    ) -> "BridgeConfig":
        return cls(
            front_name=identity.ble_name,
            target_names=tuple(target_names),
            target_address=target_address,
        )

    def target_matches(
        self,
        *,
        name: str | None = None,
        address: str | None = None,
        service_uuids: Iterable[str] = (),
    ) -> bool:
        """True if a scanned device is the gadget this bridge feeds."""
        uuids = {str(u).lower() for u in service_uuids}
        if uuids and self.service_uuid.lower() not in uuids:
            return False
        if self.target_address and address:
            return _norm_address(address) == _norm_address(self.target_address)
        if not self.target_names:
            return False
        return any(_name_matches(name, wanted) for wanted in self.target_names)


@dataclass
class BridgeStats:
    app_to_target_messages: int = 0
    target_to_app_messages: int = 0
    app_to_target_bytes: int = 0
    target_to_app_bytes: int = 0
    queued_messages: int = 0
    dropped_messages: int = 0


class NameBridge:
    """Reassembles, re-chunks and forwards setup messages between two links.

    All callbacks are supplied by the platform driver:

    * ``send_to_app(packets)`` / ``send_to_target(packets)`` deliver one
      framed message's packets on that link.
    * ``app_mtu()`` / ``target_mtu()`` report each link's current ATT MTU
      (the value :func:`musegadget.ble_framing.encode_chunks` expects).
    * ``disconnect_app(delay)`` / ``disconnect_target()`` tear a link down
      when the other side goes away, so session state clears at both ends
      exactly as it would on a direct connection.

    The driver calls :meth:`set_target_ready` once the back link is
    connected and subscribed; app messages completed before then are
    queued in order (see ``MAX_QUEUED_MESSAGES``). Every method is safe
    to call from the driver's own threads: each direction is serialised
    by its own lock, preserving the strict chunk order the framing and
    the encrypted record counters require.
    """

    def __init__(
        self,
        config: BridgeConfig,
        *,
        send_to_app: Callable[[list[bytes]], None],
        send_to_target: Callable[[list[bytes]], None],
        disconnect_app: Callable[[float], None] | None = None,
        disconnect_target: Callable[[], None] | None = None,
        app_mtu: Callable[[], int] | None = None,
        target_mtu: Callable[[], int] | None = None,
    ) -> None:
        self.config = config
        self.stats = BridgeStats()
        self._send_to_app = send_to_app
        self._send_to_target = send_to_target
        self._disconnect_app = disconnect_app or (lambda delay: None)
        self._disconnect_target = disconnect_target or (lambda: None)
        self._app_mtu = app_mtu or (lambda: ASSUMED_MTU)
        self._target_mtu = target_mtu or (lambda: ASSUMED_MTU)

        self._app_assembler = ChunkAssembler()
        self._target_assembler = ChunkAssembler()
        self._app_lock = threading.Lock()
        self._target_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._target_ready = False
        self._pending: deque[bytes] = deque()

    # -- Link state -------------------------------------------------------------

    @property
    def target_ready(self) -> bool:
        with self._state_lock:
            return self._target_ready

    def set_target_ready(self, ready: bool) -> None:
        """Mark the back link connected/subscribed (or gone); flush the queue."""
        flush: list[bytes] = []
        with self._state_lock:
            self._target_ready = ready
            if ready:
                flush = list(self._pending)
                self._pending.clear()
            if not ready:
                self._target_assembler.reset()
        for message in flush:
            self._forward_to_target(message)

    # -- Phone side (driver -> core) ---------------------------------------------

    def on_app_write(self, packet: bytes) -> None:
        """One RX write from the phone, exactly as the front GATT server got it."""
        with self._app_lock:
            message = self._app_assembler.feed(bytes(packet))
        if message is None:
            return
        with self._state_lock:
            ready = self._target_ready
            if not ready:
                if len(self._pending) >= MAX_QUEUED_MESSAGES:
                    self._pending.popleft()
                    self.stats.dropped_messages += 1
                    log.warning("bridge queue full; dropped the oldest app message")
                self._pending.append(message)
                self.stats.queued_messages += 1
        if ready:
            self._forward_to_target(message)

    def on_app_disconnect(self) -> None:
        """The phone left: clear front state and drop the back link too.

        Dropping the back link is what makes the PC's setup controller run
        its own disconnect path (clearing the pairing session), exactly as
        when a phone disconnects from a native gadget.
        """
        with self._app_lock:
            self._app_assembler.reset()
        with self._state_lock:
            self._pending.clear()
        self._disconnect_target()

    # -- PC side (driver -> core) -------------------------------------------------

    def on_target_notify(self, packet: bytes) -> None:
        """One TX notification from the PC, exactly as the back link got it."""
        with self._target_lock:
            message = self._target_assembler.feed(bytes(packet))
        if message is None:
            return
        self.stats.target_to_app_messages += 1
        self.stats.target_to_app_bytes += len(message)
        self._send_to_app(encode_chunks(message, self._app_mtu()))

    def on_target_disconnect(self) -> None:
        """The PC link went away: end the phone session the same way.

        This is also how a PC-initiated disconnect (the setup controller
        closes the session after a fatal pairing error, for example)
        reaches the phone.
        """
        self.set_target_ready(False)
        self._disconnect_app(0.0)

    # -- Internals ------------------------------------------------------------------

    def _forward_to_target(self, message: bytes) -> None:
        self.stats.app_to_target_messages += 1
        self.stats.app_to_target_bytes += len(message)
        self._send_to_target(encode_chunks(message, self._target_mtu()))
