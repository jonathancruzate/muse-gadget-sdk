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
# Part of the Windows port of the Muse gadget SDK. This module replaces the
# BlueZ/D-Bus peripheral in ble_server.py with the Windows Runtime (WinRT)
# Bluetooth LE APIs, through the PyPI ``winrt`` projections pinned in
# windows/requirements-win.txt. Anything a person reads says Muse; the only
# other names here are the protocol's frozen UUIDs.

"""WinRT GATT peripheral for Muse Gadget setup on Windows.

Mirrors :class:`musegadget.ble_server.BleServer`: advertises the setup
service and exposes two characteristics, RX (the phone writes commands) and
TX (the device notifies responses). :meth:`BleServerWinRT.run` runs an
asyncio loop on the calling thread; WinRT raises its events on its own
threads, and every one of them is marshalled onto that loop. As with the
BlueZ version, ``send_packets`` must be called from another thread because
it paces notifications.

Importing this module never needs WinRT, so it imports cleanly on Linux;
constructing :class:`BleServerWinRT` without the ``winrt`` packages raises
:class:`RuntimeError`.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
import uuid
from typing import Any, Callable

try:
    from musegadget.ble_framing import CHUNK_STAGGER_S, MAX_PACKET_BYTES
except ImportError:  # loaded as a top-level module, with this directory on sys.path
    from ble_framing import CHUNK_STAGGER_S, MAX_PACKET_BYTES  # type: ignore[no-redef]

log = logging.getLogger(__name__)

# All WinRT imports stay inside this guard: the module must import on
# machines without WinRT (the Linux CI and dev VMs import it in tests).
try:
    from winrt.windows.devices.bluetooth import BluetoothAdapter, BluetoothError
    from winrt.windows.devices.bluetooth.advertisement import (
        BluetoothLEAdvertisement,
        BluetoothLEAdvertisementPublisher,
        BluetoothLEAdvertisementPublisherStatus,
        BluetoothLEManufacturerData,
    )
    from winrt.windows.devices.bluetooth.genericattributeprofile import (
        GattCharacteristicProperties,
        GattCommunicationStatus,
        GattLocalCharacteristicParameters,
        GattProtectionLevel,
        GattServiceProvider,
        GattServiceProviderAdvertisementStatus,
        GattServiceProviderAdvertisingParameters,
        GattSessionStatus,
        GattWriteOption,
    )
    from winrt.windows.devices.radios import Radio, RadioAccessStatus, RadioState
    from winrt.windows.storage.streams import DataReader, DataWriter

    # Imported for their side effect: the projections can only hand back
    # IAsyncOperation / IVector objects (awaitables, service_uuids,
    # manufacturer_data, subscribed_clients) once these namespaces are loaded.
    import winrt.windows.foundation  # noqa: F401
    import winrt.windows.foundation.collections  # noqa: F401
except (ImportError, OSError) as _exc:  # OSError: a projection DLL failed to load
    _WINRT_IMPORT_ERROR: BaseException | None = _exc
else:
    _WINRT_IMPORT_ERROR = None

SERVICE_UUID = "7fdd3d1c-38ea-46cf-8b46-314ecf5f240c"
RX_UUID = "4d593029-28a2-4a6e-a1f0-3c2d5e8f9b01"
TX_UUID = "d75dc4ca-7b2b-4e9c-8f0a-1d2e3f4a5b6c"

# Manufacturer data the apps read as the device's paired flag. 0xFFFF is the
# unassigned company id; the value is informational, not authenticated.
PAIRED_FLAG_COMPANY_ID = 0xFFFF

# Until a GATT session reports its PDU size, assume one large enough for full
# 160-byte packets; phones running the Muse app negotiate at least that.
_ASSUMED_MTU = MAX_PACKET_BYTES + 3

# How long to wait for the advertisement publisher to report Started or
# Aborted before accepting whatever state it is in.
_PUBLISHER_START_TIMEOUT_S = 3.0


class _SetupFailed(Exception):
    """A step of opening the peripheral failed; logged, then run() returns."""

    def __init__(self, what: str, detail: object) -> None:
        super().__init__(f"{what}: {detail}")
        self.what = what
        self.detail = detail


def _name(value: object) -> str:
    """Readable name for a WinRT enum value (they arrive as IntEnum members)."""
    return getattr(value, "name", None) or str(value)


def _to_ibuffer(data: bytes) -> Any:
    writer = DataWriter()
    if data:
        writer.write_bytes(data)
    return writer.detach_buffer()


def _from_ibuffer(buffer: Any) -> bytes:
    if buffer is None:
        return b""
    reader = DataReader.from_buffer(buffer)
    # winrt 3.x fills a caller-supplied writable buffer rather than returning a list.
    out = bytearray(reader.unconsumed_buffer_length)
    if out:
        reader.read_bytes(out)
    return bytes(out)


def _session_key(session: Any) -> str:
    try:
        return str(session.device_id.id)
    except Exception:  # noqa: BLE001 - a closed session can refuse property reads
        return f"session-{id(session):x}"


class BleServerWinRT:
    """Owns the Bluetooth adapter while setup is open; implements the setup Transport.

    Drop-in for :class:`musegadget.ble_server.BleServer` with the same
    constructor, ``run`` / ``stop`` and Transport methods.
    """

    def __init__(
        self,
        local_name: str,
        on_write: Callable[[bytes], None],
        on_disconnect: Callable[[], None],
    ) -> None:
        if _WINRT_IMPORT_ERROR is not None:
            raise RuntimeError(
                "Bluetooth setup on Windows needs the Python winrt packages; "
                "install them with: pip install -r windows/requirements-win.txt "
                f"({_WINRT_IMPORT_ERROR})"
            )
        self._local_name = local_name
        self._on_write = on_write
        self._on_disconnect = on_disconnect
        # True while this server has lent the Bluetooth adapter the gadget's
        # BLE name for the setup window (see _apply_radio_name). Restored
        # when the window closes, whatever the outcome.
        self._name_bridge_active = False

        # Shared with other threads, under _lock.
        self._lock = threading.Lock()
        self._mtu = _ASSUMED_MTU
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: int | None = None
        self._stop_event: asyncio.Event | None = None
        self._stop_requested = False
        # Keeps writes in the order WinRT raised them while they cross threads.
        self._write_order = threading.Lock()

        # Loop-thread state.
        self._provider: Any = None
        self._tx: Any = None
        self._publisher: Any = None
        self._handlers: list[tuple[Callable[[Any], None], Any]] = []  # (remove_fn, token)
        self._session: Any = None
        self._session_key: str | None = None
        self._session_handlers: list[tuple[Callable[[Any], None], Any]] = []
        self._connected = False
        self._had_subscribers = False
        self._value = b""
        self._tx_queue: asyncio.Queue[bytes] | None = None
        self._rx_queue: asyncio.Queue[tuple[Any, Any]] | None = None
        self._tasks: set[asyncio.Task] = set()

    # -- Transport (any thread) -------------------------------------------------

    def mtu(self) -> int:
        with self._lock:
            return self._mtu

    def send_packets(self, packets: list[bytes]) -> None:
        """Notify each packet in order, CHUNK_STAGGER_S apart; returns once all are queued."""
        on_loop = threading.get_ident() == self._loop_thread
        for i, packet in enumerate(packets):
            # Never sleep on the loop thread; the TX pump paces packets anyway.
            if i and not on_loop:
                time.sleep(CHUNK_STAGGER_S)
            if not self._post(self._queue_notify, bytes(packet)):
                log.warning("TX dropped: Bluetooth setup is not running")
                return

    def disconnect(self, delay: float) -> None:
        self._post(self._schedule_disconnect, max(0.0, float(delay)))

    # -- Lifecycle --------------------------------------------------------------

    def run(self) -> None:
        """Start advertising and serve until :meth:`stop`. Blocks.

        Ctrl+C cancels the loop, tears down, then raises KeyboardInterrupt
        (asyncio.run's behaviour), which pair() already handles.
        """
        asyncio.run(self._serve())

    def stop(self) -> None:
        with self._lock:
            self._stop_requested = True
            loop, event = self._loop, self._stop_event
        if loop is not None and event is not None:
            try:
                loop.call_soon_threadsafe(event.set)
            except RuntimeError:  # the loop already closed
                pass

    # -- Thread marshalling -----------------------------------------------------

    def _post(self, fn: Callable[..., Any], *args: Any) -> bool:
        """Run ``fn(*args)`` on the server loop. False if the loop is not running."""
        with self._lock:
            loop = self._loop
        if loop is None:
            return False
        try:
            loop.call_soon_threadsafe(fn, *args)
        except RuntimeError:  # closed between the check and the call
            return False
        return True

    def _spawn(self, coro: Any) -> asyncio.Task:
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # -- Serving (loop thread) --------------------------------------------------

    async def _serve(self) -> None:
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()
        self._tx_queue = asyncio.Queue()
        self._rx_queue = asyncio.Queue()
        with self._lock:
            if self._stop_requested:
                return
            self._loop = loop
            self._loop_thread = threading.get_ident()
            self._stop_event = stop_event
        try:
            self._spawn(self._tx_pump())
            self._spawn(self._rx_pump())
            try:
                await loop.run_in_executor(None, self._apply_radio_name)
                await self._start()
            except _SetupFailed as err:
                log.error("%s: %s", err.what, err.detail)
                return
            await stop_event.wait()
        finally:
            with self._lock:
                self._loop = None
                self._loop_thread = None
                self._stop_event = None
            await self._teardown()
            await loop.run_in_executor(None, self._restore_radio_name)

    # -- Radio name bridge (executor thread; blocking, best effort) ------------
    #
    # Windows broadcasts only the system Bluetooth radio name in the GATT
    # service provider's advertisement, and the WinRT advertising API will
    # not carry a custom Local Name — so out of the box the Muse app, which
    # discovers gadgets by their MuseGadget BLE name, can never see a
    # Windows PC. The SDK therefore lends the adapter the gadget's BLE name
    # for the setup window only, through musegadget.pc_bridge (the adapter
    # Device Parameters "Local Name" value bthport prefers over the NetBIOS
    # name, plus its reload), and restores the original name when the
    # window closes. The bridge keeps a backup and registers a continuation
    # task, so even a hard kill leaves a restorer behind. Set
    # MUSEGADGET_NO_NAME_BRIDGE=1 to opt out (pairing then relies on the
    # standalone advertisement publisher alone, as before).

    def _apply_radio_name(self) -> None:
        if os.environ.get("MUSEGADGET_NO_NAME_BRIDGE"):
            log.info("radio name bridge disabled (MUSEGADGET_NO_NAME_BRIDGE)")
            return
        try:
            try:
                from musegadget import pc_bridge
            except ImportError:  # loaded as a top-level module
                import pc_bridge  # type: ignore[no-redef]
            pc_bridge.apply_translation(mode="adapter", dry_run=False)
            self._name_bridge_active = True
            radio = pc_bridge.probe_host().radio_name
            if radio == self._local_name:
                log.info("Bluetooth radio name is now %s for this setup window",
                         self._local_name)
            else:
                log.warning(
                    "adapter name translation applied but the radio still "
                    "reports %r (expected %r); the Muse app may not list "
                    "this PC", radio, self._local_name)
        except Exception as err:  # noqa: BLE001 - pairing continues regardless
            log.warning("could not lend the adapter the gadget name (%s); "
                        "continuing without it", err)

    def _restore_radio_name(self) -> None:
        if not self._name_bridge_active:
            return
        self._name_bridge_active = False
        try:
            try:
                from musegadget import pc_bridge
            except ImportError:  # loaded as a top-level module
                import pc_bridge  # type: ignore[no-redef]
            pc_bridge.restore_identity()
            log.info("Bluetooth radio name restored")
        except Exception as err:  # noqa: BLE001 - never fail shutdown on it
            log.warning("could not restore the Bluetooth radio name (%s); "
                        "run `musegadget_pc_bridge.py restore` to retry", err)

    async def _start(self) -> None:
        adapter = await BluetoothAdapter.get_default_async()
        if adapter is None:
            raise RuntimeError("no Bluetooth adapter found")
        await self._power_on(adapter)
        try:
            if not adapter.is_peripheral_role_supported:
                log.warning("this Bluetooth adapter reports no BLE peripheral support; "
                            "the Muse app may not be able to connect")
        except Exception as err:  # noqa: BLE001 - informational only
            log.debug("could not read the adapter's peripheral support: %s", err)

        result = await GattServiceProvider.create_async(uuid.UUID(SERVICE_UUID))
        if result.error != BluetoothError.SUCCESS or result.service_provider is None:
            raise _SetupFailed("GATT registration failed", _name(result.error))
        self._provider = provider = result.service_provider

        rx = await self._create_characteristic(
            RX_UUID,
            GattCharacteristicProperties.WRITE | GattCharacteristicProperties.WRITE_WITHOUT_RESPONSE,
        )
        self._tx = tx = await self._create_characteristic(
            TX_UUID,
            GattCharacteristicProperties.READ | GattCharacteristicProperties.NOTIFY,
        )
        self._handlers += [
            (rx.remove_write_requested, rx.add_write_requested(self._on_write_requested)),
            (tx.remove_read_requested, tx.add_read_requested(self._on_read_requested)),
            (tx.remove_subscribed_clients_changed,
             tx.add_subscribed_clients_changed(self._on_subscribers_changed)),
            (provider.remove_advertisement_status_changed,
             provider.add_advertisement_status_changed(self._on_provider_advertising_changed)),
        ]
        log.info("GATT service registered")

        # Two advertisements, both carrying SERVICE_UUID. The duplication is
        # deliberate and acceptable: the publisher carries the BLE name and
        # the paired flag the Muse app looks for, while the service provider's
        # own advertisement is the one Windows documents as connectable (it
        # carries this PC's Bluetooth name). Centrals may see both.
        self._start_provider_advertising()
        await self._start_publisher()

    async def _power_on(self, adapter: Any) -> None:
        """Turn the Bluetooth radio on if it is off. Logs; never fails run()."""
        try:
            radio = await adapter.get_radio_async()
            if radio is None:
                log.warning("could not find the Bluetooth radio; assuming it is on")
                return
            if radio.state == RadioState.ON:
                return
            log.info("Bluetooth radio is %s; turning it on", _name(radio.state).lower())
            access = await Radio.request_access_async()
            if access != RadioAccessStatus.ALLOWED:
                log.warning("not allowed to turn on Bluetooth (%s); turn it on in Settings",
                            _name(access))
                return
            outcome = await radio.set_state_async(RadioState.ON)
            if outcome == RadioAccessStatus.ALLOWED:
                log.info("Bluetooth radio turned on")
            else:
                log.warning("could not turn on Bluetooth (%s); turn it on in Settings",
                            _name(outcome))
        except Exception as err:  # noqa: BLE001 - mirror BlueZ: power is best effort
            log.warning("could not check the Bluetooth radio: %s", err)

    async def _create_characteristic(self, char_uuid: str, properties: Any) -> Any:
        params = GattLocalCharacteristicParameters()
        params.characteristic_properties = properties
        params.read_protection_level = GattProtectionLevel.PLAIN
        params.write_protection_level = GattProtectionLevel.PLAIN
        result = await self._provider.service.create_characteristic_async(uuid.UUID(char_uuid), params)
        if result.error != BluetoothError.SUCCESS or result.characteristic is None:
            raise _SetupFailed("GATT registration failed", f"characteristic {char_uuid}: {_name(result.error)}")
        return result.characteristic

    # -- Advertising (loop thread) ----------------------------------------------

    def _start_provider_advertising(self) -> None:
        # The projection has no start_advertising(discoverable, connectable)
        # overload: the parameters go through start_advertising_with_parameters,
        # with the parameterless start_advertising() as the fallback.
        try:
            params = GattServiceProviderAdvertisingParameters()
            params.is_discoverable = True
            params.is_connectable = True
            self._provider.start_advertising_with_parameters(params)
            log.info("GATT service advertising requested (connectable, discoverable)")
            return
        except Exception as err:  # noqa: BLE001
            log.warning("GATT service advertising with parameters failed: %s", err)
        try:
            self._provider.start_advertising()
            log.info("GATT service advertising requested")
        except Exception as err:  # noqa: BLE001
            log.warning("GATT service advertising unavailable (%s); "
                        "relying on the advertisement publisher", err)

    def _provider_advertising(self) -> bool:
        try:
            return self._provider.advertisement_status in (
                GattServiceProviderAdvertisementStatus.STARTED,
                GattServiceProviderAdvertisementStatus.STARTED_WITHOUT_ALL_ADVERTISEMENT_DATA,
            )
        except Exception:  # noqa: BLE001
            return False

    async def _start_publisher(self) -> None:
        # A legacy advertisement holds 31 bytes. Flags (3), the 128-bit service
        # UUID (18), "MuseGadgetXXXXXX" (18) and the paired flag (5) need 44,
        # and Windows may also reserve the name section, so fall back to
        # smaller advertisements if the full one is rejected. The paired flag
        # is always kept; the service UUID is also in the provider's
        # advertisement.
        variants = (
            ("name, service and paired flag", True, True),
            ("name and paired flag", True, False),
            ("service and paired flag", False, True),
            ("paired flag only", False, False),
        )
        why = ""
        for index, (label, with_name, with_service) in enumerate(variants):
            status, why = await self._try_publisher(with_name, with_service)
            if status == BluetoothLEAdvertisementPublisherStatus.STARTED:
                log.info("advertising as %s%s", self._local_name,
                         "" if index == 0 else f" ({label})")
                return
            if status == BluetoothLEAdvertisementPublisherStatus.WAITING:
                log.info("advertising as %s%s, waiting for the radio", self._local_name,
                         "" if index == 0 else f" ({label})")
                return
            more = index + 1 < len(variants)
            log.warning("advertisement with %s rejected: %s%s", label, why,
                        "; trying a smaller one" if more else "")
        if self._provider_advertising():
            log.warning("advertisement publisher unavailable; only the GATT service "
                        "advertisement (this PC's Bluetooth name) is running")
            return
        raise _SetupFailed("advertising failed", why)

    async def _try_publisher(self, with_name: bool, with_service: bool) -> tuple[Any, str]:
        """Start one publisher variant; returns (status, reason) once it settles."""
        loop = asyncio.get_running_loop()
        settled: asyncio.Future = loop.create_future()

        def on_status(status: Any, error: Any) -> None:  # loop thread
            if not settled.done():
                if status in (BluetoothLEAdvertisementPublisherStatus.STARTED,
                              BluetoothLEAdvertisementPublisherStatus.ABORTED):
                    settled.set_result((status, _name(error)))
                return
            if publisher is self._publisher and status == BluetoothLEAdvertisementPublisherStatus.ABORTED:
                log.warning("advertising stopped by Windows (%s)", _name(error))

        def on_status_winrt(sender: Any, args: Any) -> None:  # WinRT thread
            self._post(on_status, args.status, args.error)

        try:
            advertisement = BluetoothLEAdvertisement()
            if with_name:
                advertisement.local_name = self._local_name
            if with_service:
                advertisement.service_uuids.append(uuid.UUID(SERVICE_UUID))
            advertisement.manufacturer_data.append(
                BluetoothLEManufacturerData(PAIRED_FLAG_COMPANY_ID, _to_ibuffer(b"\x00"))
            )
            publisher = BluetoothLEAdvertisementPublisher(advertisement)
        except Exception as err:  # noqa: BLE001
            return BluetoothLEAdvertisementPublisherStatus.ABORTED, str(err)

        token = publisher.add_status_changed(on_status_winrt)
        try:
            publisher.start()
        except Exception as err:  # noqa: BLE001 - reserved or oversized data is refused here
            publisher.remove_status_changed(token)
            return BluetoothLEAdvertisementPublisherStatus.ABORTED, str(err)
        try:
            status, why = await asyncio.wait_for(
                asyncio.shield(settled), _PUBLISHER_START_TIMEOUT_S)
        except asyncio.TimeoutError:
            status, why = publisher.status, "no status change"
        if status in (BluetoothLEAdvertisementPublisherStatus.STARTED,
                      BluetoothLEAdvertisementPublisherStatus.WAITING):
            self._publisher = publisher
            self._handlers.append((publisher.remove_status_changed, token))
        else:
            publisher.remove_status_changed(token)
            try:
                publisher.stop()
            except Exception:  # noqa: BLE001
                pass
        return status, why

    def _on_provider_advertising_changed(self, sender: Any, args: Any) -> None:  # WinRT thread
        status, error = args.status, args.error
        if status == GattServiceProviderAdvertisementStatus.ABORTED:
            log.warning("GATT service advertising aborted (%s)", _name(error))
        else:
            log.info("GATT service advertising %s", _name(status).lower())

    # -- GATT requests ----------------------------------------------------------

    def _on_write_requested(self, sender: Any, args: Any) -> None:  # WinRT thread
        # The deferral must be taken before this handler returns; the request
        # itself only arrives through get_request_async(), on the loop.
        try:
            deferral = args.get_deferral()
        except Exception as err:  # noqa: BLE001
            log.warning("write request dropped: %s", err)
            return
        with self._write_order:
            if not self._post(self._queue_write, args, deferral):
                deferral.complete()

    def _queue_write(self, args: Any, deferral: Any) -> None:
        self._rx_queue.put_nowait((args, deferral))

    async def _rx_pump(self) -> None:
        # One write at a time, in arrival order: chunk reassembly is strictly ordered.
        while True:
            args, deferral = await self._rx_queue.get()
            try:
                await self._handle_write(args)
            except Exception:  # noqa: BLE001
                log.exception("write request failed")
            finally:
                try:
                    deferral.complete()
                except Exception:  # noqa: BLE001
                    pass

    async def _handle_write(self, args: Any) -> None:
        self._attach_session(self._request_session(args))
        request = await args.get_request_async()
        if request is None:  # the client went away before the request could be read
            return
        value = _from_ibuffer(request.value)
        try:
            self._on_write(value)
        finally:
            if request.option == GattWriteOption.WRITE_WITH_RESPONSE:
                request.respond()

    def _on_read_requested(self, sender: Any, args: Any) -> None:  # WinRT thread
        try:
            deferral = args.get_deferral()
        except Exception as err:  # noqa: BLE001
            log.warning("read request dropped: %s", err)
            return
        if not self._post(self._start_read, args, deferral):
            deferral.complete()

    def _start_read(self, args: Any, deferral: Any) -> None:
        self._spawn(self._handle_read(args, deferral))

    async def _handle_read(self, args: Any, deferral: Any) -> None:
        try:
            self._attach_session(self._request_session(args))
            request = await args.get_request_async()
            if request is not None:
                # The last notified value, as the BlueZ ReadValue returns.
                request.respond_with_value(_to_ibuffer(self._value))
        except Exception as err:  # noqa: BLE001
            log.warning("read request failed: %s", err)
        finally:
            try:
                deferral.complete()
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _request_session(args: Any) -> Any:
        try:
            return args.session
        except Exception:  # noqa: BLE001 - absent on old Windows builds
            return None

    # -- Notifications (loop thread) --------------------------------------------

    def _queue_notify(self, packet: bytes) -> None:
        self._tx_queue.put_nowait(packet)

    async def _tx_pump(self) -> None:
        loop = asyncio.get_running_loop()
        last = None
        while True:
            packet = await self._tx_queue.get()
            if last is not None:
                wait = CHUNK_STAGGER_S - (loop.time() - last)
                if wait > 0:
                    await asyncio.sleep(wait)
            last = loop.time()
            try:
                await self._notify(packet)
            except Exception:  # noqa: BLE001
                log.exception("notification failed")

    async def _notify(self, packet: bytes) -> None:
        self._value = packet
        tx = self._tx
        if tx is None or not len(tx.subscribed_clients):
            return  # kept for reads, as BlueZ does when nobody is subscribed
        results = await tx.notify_value_async(_to_ibuffer(packet))
        for result in results or ():
            if result.status != GattCommunicationStatus.SUCCESS:
                log.warning("notification not delivered: %s (protocol error %s)",
                            _name(result.status), result.protocol_error)

    # -- Sessions (loop thread) -------------------------------------------------

    def _on_subscribers_changed(self, sender: Any, _args: Any) -> None:  # WinRT thread
        self._post(self._subscribers_changed)

    def _subscribers_changed(self) -> None:
        tx = self._tx
        if tx is None:
            return
        try:
            clients = list(tx.subscribed_clients)
        except Exception as err:  # noqa: BLE001
            log.warning("could not read subscribed clients: %s", err)
            return
        if clients:
            if not self._had_subscribers:
                log.info("client subscribed to %s", TX_UUID)
            self._had_subscribers = True
            try:
                session = clients[-1].session
            except Exception:  # noqa: BLE001
                session = None
            self._attach_session(session)
        elif self._had_subscribers:
            self._had_subscribers = False
            log.info("client unsubscribed from %s", TX_UUID)
            self._mark_disconnected()

    def _attach_session(self, session: Any) -> None:
        if session is None:
            return
        key = _session_key(session)
        if self._session is not None and key == self._session_key:
            if not self._connected:
                self._connected = True
                log.info("device %s connected", key)
            return
        if self._session is not None:
            # As in BlueZ, the newest client becomes the one setup talks to.
            log.info("device %s replaces %s", key, self._session_key)
            self._detach_session()

        def on_status(sender: Any, args: Any) -> None:  # WinRT thread
            if args.status == GattSessionStatus.CLOSED:
                self._post(self._session_closed, key)

        def on_pdu(sender: Any, _args: Any) -> None:  # WinRT thread
            self._post(self._session_mtu_changed, key)

        self._session, self._session_key = session, key
        try:
            self._session_handlers = [
                (session.remove_session_status_changed, session.add_session_status_changed(on_status)),
                (session.remove_max_pdu_size_changed, session.add_max_pdu_size_changed(on_pdu)),
            ]
        except Exception as err:  # noqa: BLE001
            log.warning("could not watch device %s: %s", key, err)
        self._connected = True
        log.info("device %s connected", key)
        self._update_mtu()
        try:
            closed = session.session_status == GattSessionStatus.CLOSED
        except Exception:  # noqa: BLE001
            closed = True
        if closed:  # closed before the handler was registered
            self._session_closed(key)

    def _session_mtu_changed(self, key: str) -> None:
        if key == self._session_key:
            self._update_mtu()

    def _update_mtu(self) -> None:
        try:
            pdu = int(self._session.max_pdu_size)
        except Exception:  # noqa: BLE001
            return
        with self._lock:
            changed, self._mtu = pdu != self._mtu, pdu
        if changed:
            log.info("ATT MTU %d", pdu)

    def _session_closed(self, key: str) -> None:
        if key != self._session_key:
            return
        log.info("device %s disconnected", key)
        session = self._session
        self._detach_session()
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass
        self._mark_disconnected()

    def _detach_session(self) -> None:
        for remove, token in self._session_handlers:
            try:
                remove(token)
            except Exception:  # noqa: BLE001
                pass
        self._session_handlers = []
        self._session = None
        self._session_key = None
        with self._lock:
            self._mtu = _ASSUMED_MTU

    def _mark_disconnected(self) -> None:
        """Tell setup the client left; once per connection, like BlueZ."""
        if not self._connected:
            return
        self._connected = False
        try:
            self._on_disconnect()
        except Exception:  # noqa: BLE001
            log.exception("disconnect handler failed")

    def _schedule_disconnect(self, delay: float) -> None:
        asyncio.get_running_loop().call_later(delay, self._disconnect_now)

    def _disconnect_now(self) -> None:
        session, key = self._session, self._session_key
        if session is None:
            return
        log.info("disconnecting device %s", key)
        self._detach_session()
        try:
            session.close()
        except Exception as err:  # noqa: BLE001
            log.warning("disconnect failed: %s", err)
        self._mark_disconnected()

    # -- Teardown (loop thread) -------------------------------------------------

    async def _teardown(self) -> None:
        publisher, self._publisher = self._publisher, None
        if publisher is not None:
            try:
                publisher.stop()
            except Exception as err:  # noqa: BLE001
                log.debug("stopping the advertisement failed: %s", err)
        if self._provider is not None:
            try:
                self._provider.stop_advertising()
            except Exception as err:  # noqa: BLE001
                log.debug("stopping GATT service advertising failed: %s", err)
        for remove, token in self._handlers:
            try:
                remove(token)
            except Exception:  # noqa: BLE001
                pass
        self._handlers = []
        session = self._session
        self._detach_session()
        if session is not None:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        # Writes that arrived during shutdown still hold their deferrals.
        while self._rx_queue is not None and not self._rx_queue.empty():
            _args, deferral = self._rx_queue.get_nowait()
            try:
                deferral.complete()
            except Exception:  # noqa: BLE001
                pass
        # Dropping the last references releases the service; WinRT has no
        # explicit close for GattServiceProvider.
        self._tx = None
        self._provider = None
        log.info("Bluetooth setup closed")
