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
# Part of the Windows port of the Muse gadget SDK.

"""Secondary-mode PC-resident BLE bridge driver using Google Bumble (`bumble`).

When the Windows PC's built-in Bluetooth stack cannot advertise the full
17-character `MuseGadgetXXXXXX` name (due to the 15-character NetBIOS limit or
driver refusal of `Device Parameters\\Local Name`), a USB BLE dongle (bound to
WinUSB via Zadig) or HCI-over-UART serial board plugged into the SAME PC acts
as the front radio.

Architecture on the PC:
* Front (peripheral on the USB dongle): advertises the full 17-character
  `MuseGadget-3855D8` name (`COMPLETE_LOCAL_NAME`), the paired flag (`0xFFFF:0x00`),
  and the setup service UUID (`7fdd3d1c-38ea-46cf-8b46-314ecf5f240c` in scan
  response), exposing RX and TX characteristics to the Muse phone app.
* Middle (`musegadget.ble_bridge.NameBridge`): reassembles and re-chunks framed
  setup messages opaquely between the two links.
* Back (central on the USB dongle): scans for and connects over the air
  (centimetres away) to the PC's built-in Realtek radio (`POWERSPEC-G757-`)
  where `musegadget_win.py pair` is serving the WinRT GATT peripheral.

Like `ble_bridge_bluez.py` and `ble_server_windows.py`, this module imports
cleanly even if `bumble` is not installed; constructing `BridgeBumble` without
`bumble` raises `RuntimeError`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

try:
    from musegadget.ble_bridge import (
        ASSUMED_MTU,
        RX_UUID,
        SERVICE_UUID,
        TX_UUID,
        BridgeConfig,
        NameBridge,
    )
    from musegadget.ble_framing import CHUNK_STAGGER_S
except ImportError:  # loaded with windows/musegadget on sys.path
    from ble_bridge import (  # type: ignore[no-redef]
        ASSUMED_MTU,
        RX_UUID,
        SERVICE_UUID,
        TX_UUID,
        BridgeConfig,
        NameBridge,
    )
    from ble_framing import CHUNK_STAGGER_S  # type: ignore[no-redef]

log = logging.getLogger(__name__)

try:
    from bumble.core import AdvertisingData, PhysicalTransport, UUID
    from bumble.device import Advertisement, Connection, Device, Peer
    from bumble.gatt import Characteristic, CharacteristicValue, Service
    from bumble.hci import Address, OwnAddressType
    from bumble.transport import open_transport
except (ImportError, OSError) as _exc:
    _BUMBLE_IMPORT_ERROR: BaseException | None = _exc
else:
    _BUMBLE_IMPORT_ERROR = None

PAIRED_FLAG_COMPANY_LE = b"\xff\xff"
PAIRED_FLAG_UNPAIRED = b"\x00"
DEFAULT_DONGLE_ADDRESS = "F0:38:55:D8:00:01"


def have_bumble() -> bool:
    """Return True if the `bumble` BLE stack is importable."""
    return _BUMBLE_IMPORT_ERROR is None


def build_advertising_data_bytes(front_name: str) -> bytes:
    """Build the 31-byte-compliant legacy Advertising Data PDU carrying:
    - Flags (0x06: LE General Discoverable + BR/EDR Not Supported) -> 3 bytes
    - Complete Local Name (`MuseGadget-3855D8`, 17 chars) -> 19 bytes
    - Manufacturer Specific Data (`0xFFFF` + `0x00`) -> 5 bytes
    Total: 27 bytes (fits inside the 31-byte legacy BLE advertising limit).
    """
    if _BUMBLE_IMPORT_ERROR is not None:
        raise RuntimeError(f"bumble is required ({_BUMBLE_IMPORT_ERROR})")
    name_bytes = front_name.encode("utf-8")
    adv = AdvertisingData(
        [
            (
                AdvertisingData.FLAGS,
                bytes(
                    [
                        AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE_FLAG
                        | AdvertisingData.BR_EDR_NOT_SUPPORTED_FLAG
                    ]
                ),
            ),
            (AdvertisingData.COMPLETE_LOCAL_NAME, name_bytes),
            (
                AdvertisingData.MANUFACTURER_SPECIFIC_DATA,
                PAIRED_FLAG_COMPANY_LE + PAIRED_FLAG_UNPAIRED,
            ),
        ]
    )
    raw = bytes(adv)
    if len(raw) > 31:
        raise ValueError(f"Advertising data ({len(raw)} B) exceeds 31-byte legacy PDU limit")
    return raw


def build_scan_response_data_bytes(service_uuid: str = SERVICE_UUID) -> bytes:
    """Build the 31-byte-compliant legacy Scan Response PDU carrying the
    128-bit setup service UUID (`7fdd3d1c-38ea-46cf-8b46-314ecf5f240c`, 18 bytes).
    """
    if _BUMBLE_IMPORT_ERROR is not None:
        raise RuntimeError(f"bumble is required ({_BUMBLE_IMPORT_ERROR})")
    sr = AdvertisingData(
        [
            (
                AdvertisingData.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
                UUID(service_uuid).to_pdu_bytes(),
            ),
        ]
    )
    raw = bytes(sr)
    if len(raw) > 31:
        raise ValueError(f"Scan response data ({len(raw)} B) exceeds 31-byte legacy PDU limit")
    return raw


def extract_advertisement_fields(advertisement: Any) -> tuple[str, str, list[str]]:
    """Extract `(local_name, address_str, service_uuid_strings)` from a Bumble Advertisement."""
    addr = str(getattr(advertisement, "address", "") or "")
    # Strip Bumble's '/P' or '/R' address-type suffix if present for matching
    if "/" in addr:
        addr = addr.split("/", 1)[0]
    ad_data = getattr(advertisement, "data", None)
    if ad_data is None:
        return "", addr, []

    name = (
        ad_data.get(AdvertisingData.COMPLETE_LOCAL_NAME)
        or ad_data.get(AdvertisingData.SHORTENED_LOCAL_NAME)
        or ""
    )
    if isinstance(name, bytes):
        name = name.decode("utf-8", errors="replace")

    uuids: list[str] = []
    for ad_type in (
        AdvertisingData.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
        AdvertisingData.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
    ):
        found = ad_data.get(ad_type) or []
        for u in found:
            uuids.append(str(u).lower())
    return str(name), addr, uuids


class BridgeBumble:
    """PC-hosted dual-radio BLE bridge driver backed by Google Bumble and `NameBridge`.

    Can be driven either:
    - Live on a Bumble `Device` (over `usb:0`, `serial:COMx`, or a virtual
      `LocalLink` controller in tests), or
    - Directly via its transport callbacks in synchronous unit simulations.
    """

    def __init__(
        self,
        bridge: NameBridge,
        *,
        stagger_s: float = CHUNK_STAGGER_S,
        low_level_send_app: Callable[[bytes], Any] | None = None,
        low_level_send_target: Callable[[bytes], Any] | None = None,
    ) -> None:
        if _BUMBLE_IMPORT_ERROR is not None:
            raise RuntimeError(
                "Secondary-mode PC dongle bridge needs the `bumble` package "
                f"(pip install bumble): {_BUMBLE_IMPORT_ERROR}"
            )
        self._bridge = bridge
        self._stagger_s = stagger_s
        self._low_level_send_app = low_level_send_app
        self._low_level_send_target = low_level_send_target

        self._device: Device | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._tx_char: Characteristic | None = None
        self._rx_char: Characteristic | None = None
        self._last_tx_value: bytes = b""

        self._app_connection: Connection | None = None
        self._app_mtu: int = ASSUMED_MTU

        self._target_connection: Connection | None = None
        self._target_peer: Peer | None = None
        self._target_rx_char: Any = None
        self._target_tx_char: Any = None
        self._target_mtu: int = ASSUMED_MTU
        self._target_connecting: bool = False
        self._tasks: set[asyncio.Task[Any]] = set()

    @property
    def bridge(self) -> NameBridge:
        return self._bridge

    # -- NameBridge Transport Callbacks -----------------------------------------

    def app_mtu(self) -> int:
        return self._app_mtu

    def target_mtu(self) -> int:
        return self._target_mtu

    def set_app_mtu(self, mtu: int) -> None:
        self._app_mtu = int(mtu)

    def set_target_mtu(self, mtu: int) -> None:
        self._target_mtu = int(mtu)

    def send_to_app(self, packets: list[bytes]) -> None:
        """Deliver framed packets to the phone (via TX notifications or injected sink)."""
        if self._low_level_send_app is not None:
            for packet in packets:
                self._last_tx_value = bytes(packet)
                self._low_level_send_app(bytes(packet))
            return
        if self._loop is not None and self._device is not None and self._tx_char is not None:
            self._schedule_coro(self._async_send_to_app(list(packets)))

    def send_to_target(self, packets: list[bytes]) -> None:
        """Deliver framed packets to the PC's GATT RX characteristic."""
        if self._low_level_send_target is not None:
            for packet in packets:
                self._low_level_send_target(bytes(packet))
            return
        if self._loop is not None and self._target_peer is not None and self._target_rx_char is not None:
            self._schedule_coro(self._async_send_to_target(list(packets)))

    def disconnect_app(self, delay: float) -> None:
        if self._loop is not None and self._app_connection is not None:
            self._schedule_coro(self._async_disconnect_app(delay))

    def disconnect_target(self) -> None:
        if self._loop is not None and self._target_connection is not None:
            self._schedule_coro(self._async_disconnect_target())

    # -- Event Handlers (callable from Bumble or tests) -------------------------

    def handle_front_write(self, connection: Any, value: bytes) -> None:
        """Handle an RX write from the Muse phone app on the front GATT peripheral."""
        if connection is not None:
            self._app_connection = connection
            att_mtu = getattr(connection, "att_mtu", None)
            if isinstance(att_mtu, int) and att_mtu >= 23:
                self._app_mtu = att_mtu
        self._bridge.on_app_write(bytes(value))

    def handle_front_read(self, _connection: Any) -> bytes:
        """Return the last TX packet when the phone reads TX directly."""
        return self._last_tx_value

    def handle_front_disconnect(self) -> None:
        """Handle phone disconnect on the front link."""
        self._app_connection = None
        self._bridge.on_app_disconnect()

    def handle_back_notify(self, value: bytes) -> None:
        """Handle a TX notification from the PC's WinRT GATT service."""
        self._bridge.on_target_notify(bytes(value))

    def handle_back_disconnect(self) -> None:
        """Handle a disconnect on the back link to the PC."""
        self._target_connection = None
        self._target_peer = None
        self._target_rx_char = None
        self._target_tx_char = None
        self._target_connecting = False
        self._bridge.on_target_disconnect()

    # -- Bumble Device Setup & Async Runtime ------------------------------------

    def _schedule_coro(self, coro: Any) -> None:
        loop = self._loop
        if loop is None:
            return

        def _spawn() -> None:
            task = loop.create_task(coro)
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            _spawn()
        else:
            loop.call_soon_threadsafe(_spawn)

    async def _async_send_to_app(self, packets: list[bytes]) -> None:
        if self._device is None or self._tx_char is None:
            return
        for i, packet in enumerate(packets):
            if i and self._stagger_s > 0:
                await asyncio.sleep(self._stagger_s)
            self._last_tx_value = bytes(packet)
            await self._device.notify_subscribers(self._tx_char, bytes(packet))

    async def _async_send_to_target(self, packets: list[bytes]) -> None:
        peer = self._target_peer
        rx_char = self._target_rx_char
        if peer is None or rx_char is None:
            log.warning("bumble bridge: write dropped, back link is down")
            return
        for i, packet in enumerate(packets):
            if i and self._stagger_s > 0:
                await asyncio.sleep(self._stagger_s)
            await peer.write_value(rx_char, bytes(packet), with_response=False)

    async def _async_disconnect_app(self, delay: float) -> None:
        if delay > 0:
            await asyncio.sleep(delay)
        conn = self._app_connection
        if conn is not None:
            try:
                await conn.disconnect()
            except Exception as exc:  # noqa: BLE001
                log.debug("bumble bridge: front disconnect error: %s", exc)

    async def _async_disconnect_target(self) -> None:
        conn = self._target_connection
        if conn is not None:
            try:
                await conn.disconnect()
            except Exception as exc:  # noqa: BLE001
                log.debug("bumble bridge: back disconnect error: %s", exc)

    def attach_front_gatt(self, device: Device) -> Service:
        """Register the Muse Gadget setup GATT service on `device`."""
        self._device = device
        self._rx_char = Characteristic(
            RX_UUID,
            Characteristic.Properties.WRITE | Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
            Characteristic.Permissions.WRITEABLE,
            CharacteristicValue(write=self.handle_front_write),
        )
        self._tx_char = Characteristic(
            TX_UUID,
            Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
            Characteristic.Permissions.READABLE,
            CharacteristicValue(read=self.handle_front_read),
        )
        service = Service(SERVICE_UUID, [self._rx_char, self._tx_char])
        device.add_service(service)
        return service

    async def start_on_device(
        self,
        device: Device,
        *,
        start_scanning: bool = True,
    ) -> None:
        """Power on `device`, configure front GATT + advertising, and optionally scan."""
        self._loop = asyncio.get_running_loop()
        self._device = device
        device.name = self._bridge.config.front_name
        self.attach_front_gatt(device)

        def _on_connection(connection: Connection) -> None:
            # Distinguish back-central connection (initiated by us) from front-peripheral
            if self._target_connecting or (
                self._target_connection is not None
                and connection.peer_address == self._target_connection.peer_address
            ):
                return
            self._app_connection = connection
            att_mtu = getattr(connection, "att_mtu", None)
            if isinstance(att_mtu, int) and att_mtu >= 23:
                self._app_mtu = att_mtu
            connection.on("disconnection", lambda *_a: self.handle_front_disconnect())

        device.on("connection", _on_connection)
        device.on("advertisement", self._on_advertisement)

        await device.power_on()
        adv_bytes = build_advertising_data_bytes(self._bridge.config.front_name)
        sr_bytes = build_scan_response_data_bytes(self._bridge.config.service_uuid)
        await device.start_advertising(
            advertising_data=adv_bytes,
            scan_response_data=sr_bytes,
            auto_restart=True,
        )
        log.info(
            "bumble bridge: advertising as %s (%d B adv, %d B scan_rsp)",
            self._bridge.config.front_name,
            len(adv_bytes),
            len(sr_bytes),
        )
        if start_scanning:
            await device.start_scanning(active=True)

    def _on_advertisement(self, advertisement: Advertisement) -> None:
        if self._target_connecting or self._bridge.target_ready:
            return
        name, addr, uuids = extract_advertisement_fields(advertisement)
        if not self._bridge.config.target_matches(
            name=name,
            address=addr,
            service_uuids=uuids,
        ):
            return
        if self._loop is not None and self._device is not None:
            self._target_connecting = True
            self._schedule_coro(self.connect_to_target(advertisement.address))

    async def connect_to_target(self, peer_address: Any) -> None:
        """Connect to the target PC GATT peripheral, discover RX/TX, and subscribe TX."""
        if self._device is None:
            raise RuntimeError("BridgeBumble device is not initialized")
        self._loop = asyncio.get_running_loop()
        self._target_connecting = True
        try:
            conn = await self._device.connect(peer_address)
            self._target_connection = conn
            conn.on("disconnection", lambda *_a: self.handle_back_disconnect())

            peer = Peer(conn)
            self._target_peer = peer
            await peer.discover_services()
            for service in peer.services:
                await service.discover_characteristics()

            rx_chars = peer.get_characteristics_by_uuid(UUID(RX_UUID))
            tx_chars = peer.get_characteristics_by_uuid(UUID(TX_UUID))
            if not rx_chars or not tx_chars:
                raise RuntimeError("Target PC GATT service missing RX or TX characteristic")

            self._target_rx_char = rx_chars[0]
            self._target_tx_char = tx_chars[0]
            await peer.subscribe(self._target_tx_char, self.handle_back_notify)

            att_mtu = getattr(conn, "att_mtu", None)
            if isinstance(att_mtu, int) and att_mtu >= 23:
                self._target_mtu = att_mtu
            self._target_connecting = False
            self._bridge.set_target_ready(True)
            log.info("bumble bridge: connected and subscribed to PC target %s", peer_address)
        except Exception:
            self._target_connecting = False
            raise

    async def stop(self) -> None:
        """Wait for pending tasks and stop advertising/scanning."""
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
        self._bridge.set_target_ready(False)
        if self._device is not None:
            try:
                await self._device.stop_advertising()
            except Exception:  # noqa: BLE001
                pass
            try:
                await self._device.stop_scanning()
            except Exception:  # noqa: BLE001
                pass

    async def serve_hci_transport(
        self,
        hci_transport: str,
        *,
        dongle_address: str = DEFAULT_DONGLE_ADDRESS,
    ) -> None:
        """Open `hci_transport` (e.g. `usb:0` or `serial:COM3,1000000`) and run until cancelled."""
        async with await open_transport(hci_transport) as (hci_source, hci_sink):
            device = Device.with_hci(
                self._bridge.config.front_name,
                Address(dongle_address),
                hci_source,
                hci_sink,
            )
            await self.start_on_device(device, start_scanning=True)
            stop_Ev = asyncio.Event()
            try:
                await stop_Ev.wait()
            finally:
                await self.stop()


def build_bumble_bridge(
    config: BridgeConfig,
    *,
    stagger_s: float = CHUNK_STAGGER_S,
    low_level_send_app: Callable[[bytes], Any] | None = None,
    low_level_send_target: Callable[[bytes], Any] | None = None,
) -> tuple[NameBridge, BridgeBumble]:
    """Wire a `NameBridge` to a `BridgeBumble` driver for `config`."""
    holder: dict[str, BridgeBumble] = {}

    def driver() -> BridgeBumble:
        return holder["driver"]

    bridge = NameBridge(
        config,
        send_to_app=lambda packets: driver().send_to_app(packets),
        send_to_target=lambda packets: driver().send_to_target(packets),
        disconnect_app=lambda delay: driver().disconnect_app(delay),
        disconnect_target=lambda: driver().disconnect_target(),
        app_mtu=lambda: driver().app_mtu(),
        target_mtu=lambda: driver().target_mtu(),
    )
    holder["driver"] = BridgeBumble(
        bridge,
        stagger_s=stagger_s,
        low_level_send_app=low_level_send_app,
        low_level_send_target=low_level_send_target,
    )
    return bridge, holder["driver"]
