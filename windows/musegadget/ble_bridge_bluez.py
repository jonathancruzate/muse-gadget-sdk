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

"""BlueZ driver for the name-translation bridge (see ble_bridge.py).

One process on a Linux host in the same room as the phone and the PC,
holding both BLE links on one adapter:

* Peripheral (front): reuses the upstream BlueZ GATT application and
  advertisement classes from :mod:`musegadget.ble_server`, so the front
  advertisement is byte-for-byte the one a native Linux gadget emits —
  ``MuseGadgetXXXXXX`` name, setup service UUID, paired flag.
* Central (back): a D-Bus GATT client that discovers the Windows PC by
  the name it already advertises (and/or its address / the setup service
  UUID), connects, writes to RX and subscribes to TX.

Everything between the two links is the platform-independent
:class:`musegadget.ble_bridge.NameBridge`. This module imports cleanly
without BlueZ (construction then raises), mirroring ble_server_windows.

Status: written against the BlueZ D-Bus APIs the upstream server already
uses, but not yet run on a BLE adapter — see BRIDGE.md for what a first
hardware run must check.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

try:
    from musegadget.ble_bridge import NameBridge
    from musegadget.ble_framing import CHUNK_STAGGER_S
except ImportError:  # loaded as a top-level module, with this directory on sys.path
    from ble_bridge import NameBridge  # type: ignore[no-redef]
    from ble_framing import CHUNK_STAGGER_S  # type: ignore[no-redef]

log = logging.getLogger(__name__)

try:
    import dbus
    import dbus.exceptions
    import dbus.mainloop.glib
    from gi.repository import GLib

    from musegadget.ble_server import (
        ADAPTER_IFACE,
        ADV_PATH,
        APP_PATH,
        DBUS_OM_IFACE,
        DBUS_PROP_IFACE,
        DEVICE_IFACE,
        GATT_CHRC_IFACE,
        GATT_MANAGER_IFACE,
        GATT_SERVICE_IFACE,
        LE_ADV_MANAGER_IFACE,
        RX_UUID,
        SERVICE_UUID,
        TX_UUID,
        Advertisement,
        Application,
        Characteristic,
        Service,
        _find_adapter,
    )
except (ImportError, OSError) as _exc:
    _BLUEZ_IMPORT_ERROR: BaseException | None = _exc
else:
    _BLUEZ_IMPORT_ERROR = None

_ASSUMED_MTU = 163


class BridgeBluez:
    """Owns the adapter while the bridge is open; blocks in run() until stop()."""

    def __init__(self, bridge: NameBridge) -> None:
        if _BLUEZ_IMPORT_ERROR is not None:
            raise RuntimeError(
                "the bridge host needs BlueZ (python3-dbus and a BLE adapter); "
                f"({_BLUEZ_IMPORT_ERROR})"
            )
        self._bridge = bridge
        self._lock = threading.Lock()
        self._loop: Any = None
        self._bus: Any = None
        self._adapter_path = ""
        self._saved_alias: Any = None

        self._tx_char: Any = None  # front TX characteristic (notify the phone)
        self._app_device_path: str | None = None
        self._app_mtu = _ASSUMED_MTU

        self._target_path: str | None = None
        self._target_rx: Any = None  # back RX characteristic proxy
        self._target_tx_path: str | None = None
        self._target_mtu = _ASSUMED_MTU
        self._target_connecting = False

    # -- Transport wiring for NameBridge ------------------------------------

    def app_mtu(self) -> int:
        with self._lock:
            return self._app_mtu

    def target_mtu(self) -> int:
        with self._lock:
            return self._target_mtu

    def send_to_app(self, packets: list[bytes]) -> None:
        self._paced(lambda packet: GLib.idle_add(self._tx_char.notify, packet), packets)

    def send_to_target(self, packets: list[bytes]) -> None:
        def write(packet: bytes) -> None:
            with self._lock:
                rx = self._target_rx
            if rx is None:
                log.warning("bridge: write dropped, back link is down")
                return
            rx.WriteValue(
                dbus.Array([dbus.Byte(b) for b in packet], signature="y"),
                {"type": dbus.String("command")},
            )

        self._paced(write, packets)

    @staticmethod
    def _paced(send: Any, packets: list[bytes]) -> None:
        # Notifications / writes are paced like both platform servers pace
        # theirs; pacing sleeps, so it runs on its own short-lived thread
        # and never stalls the GLib loop that carries the other link.
        def run() -> None:
            for i, packet in enumerate(packets):
                if i:
                    time.sleep(CHUNK_STAGGER_S)
                send(packet)

        threading.Thread(target=run, name="ble-bridge-pace", daemon=True).start()

    def disconnect_app(self, delay: float) -> None:
        with self._lock:
            path = self._app_device_path
        if path:
            GLib.timeout_add(int(delay * 1000), self._disconnect_path, path)

    def disconnect_target(self) -> None:
        with self._lock:
            path = self._target_path
        if path:
            GLib.idle_add(self._disconnect_path, path)

    def _disconnect_path(self, path: str) -> bool:
        try:
            device = dbus.Interface(self._bus.get_object("org.bluez", path), DEVICE_IFACE)
            device.Disconnect(timeout=5)
        except dbus.exceptions.DBusException as err:
            log.warning("bridge: disconnect of %s failed: %s", path, err)
        return False

    # -- Lifecycle ------------------------------------------------------------

    def run(self) -> None:
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        bus = self._bus = dbus.SystemBus()
        self._adapter_path = _find_adapter(bus)
        adapter = dbus.Interface(bus.get_object("org.bluez", self._adapter_path), DBUS_PROP_IFACE)
        self._saved_alias = adapter.Get(ADAPTER_IFACE, "Alias")
        adapter.Set(ADAPTER_IFACE, "Powered", dbus.Boolean(True))
        # The phone reads the GAP name as well as the advertised one; the
        # upstream server sets it the same way.
        adapter.Set(ADAPTER_IFACE, "Alias", dbus.String(self._bridge.config.front_name))
        adapter.Set(ADAPTER_IFACE, "Pairable", dbus.Boolean(False))

        app = Application(bus)
        service = Service(bus, 0, SERVICE_UUID)
        service.characteristics.append(Characteristic(
            bus, service, 0, RX_UUID, ["write", "write-without-response"],
            on_write=self._on_front_write,
        ))
        self._tx_char = Characteristic(bus, service, 1, TX_UUID, ["read", "notify"])
        service.characteristics.append(self._tx_char)
        app.services.append(service)
        self._objects = (app, service, self._tx_char, Advertisement(bus, self._bridge.config.front_name))

        bus.add_signal_receiver(
            self._on_device_props,
            dbus_interface=DBUS_PROP_IFACE, signal_name="PropertiesChanged",
            arg0=DEVICE_IFACE, path_keyword="path",
        )
        bus.add_signal_receiver(
            self._on_interfaces_added,
            dbus_interface=DBUS_OM_IFACE, signal_name="InterfacesAdded",
        )
        bus.add_signal_receiver(
            self._on_tx_value,
            dbus_interface=DBUS_PROP_IFACE, signal_name="PropertiesChanged",
            arg0=GATT_CHRC_IFACE, path_keyword="path",
        )

        adapter_obj = bus.get_object("org.bluez", self._adapter_path)
        dbus.Interface(adapter_obj, GATT_MANAGER_IFACE).RegisterApplication(
            APP_PATH, {},
            reply_handler=lambda: log.info("bridge GATT service registered"),
            error_handler=lambda e: self._fatal("GATT registration failed", e),
        )
        dbus.Interface(adapter_obj, LE_ADV_MANAGER_IFACE).RegisterAdvertisement(
            ADV_PATH, {},
            reply_handler=lambda: log.info("bridge advertising as %s", self._bridge.config.front_name),
            error_handler=lambda e: self._fatal("advertising failed", e),
        )
        dbus.Interface(adapter_obj, ADAPTER_IFACE).StartDiscovery()
        log.info("bridge scanning for the target PC")

        self._loop = GLib.MainLoop()
        import signal as _signal

        for signum in (_signal.SIGTERM, _signal.SIGINT):
            GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signum, self._loop.quit)
        try:
            self._loop.run()
        finally:
            self._teardown()

    def stop(self) -> None:
        if self._loop:
            GLib.idle_add(self._loop.quit)

    def _fatal(self, what: str, err: Exception) -> None:
        log.error("bridge: %s: %s", what, err)
        self.stop()

    def _teardown(self) -> None:
        self._bridge.set_target_ready(False)
        try:
            adapter = dbus.Interface(
                self._bus.get_object("org.bluez", self._adapter_path), ADAPTER_IFACE)
            adapter.StopDiscovery()
        except Exception:  # noqa: BLE001 - teardown is best effort
            pass
        if self._saved_alias is not None:
            try:
                props = dbus.Interface(
                    self._bus.get_object("org.bluez", self._adapter_path), DBUS_PROP_IFACE)
                props.Set(ADAPTER_IFACE, "Alias", self._saved_alias)
            except Exception:  # noqa: BLE001
                pass
        log.info("bridge closed")

    # -- Front link (phone) ---------------------------------------------------

    def _on_front_write(self, value: bytes, options: dict) -> None:
        with self._lock:
            if "mtu" in options:
                self._app_mtu = int(options["mtu"])
            if "device" in options:
                self._app_device_path = str(options["device"])
        self._bridge.on_app_write(value)

    # -- Back link (PC) ---------------------------------------------------------

    def _on_interfaces_added(self, path: str, interfaces: dict) -> None:
        props = interfaces.get(DEVICE_IFACE)
        if props:
            self._maybe_connect(path, props)

    def _on_device_props(self, interface: str, changed: dict, invalidated: list, path: str = "") -> None:
        with self._lock:
            is_app = path and path == self._app_device_path
            is_target = path and path == self._target_path
        if "Connected" in changed and not changed["Connected"]:
            if is_app:
                log.info("bridge: phone disconnected")
                self._bridge.on_app_disconnect()
            elif is_target:
                log.info("bridge: PC disconnected")
                with self._lock:
                    self._target_rx = None
                    self._target_tx_path = None
                    self._target_connecting = False
                self._bridge.on_target_disconnect()
                GLib.timeout_add(1000, self._rediscover)
            return
        if is_target and changed.get("ServicesResolved"):
            self._resolve_characteristics(path)
        elif not is_target and not is_app:
            # A device updating (e.g. its UUIDs arriving) may be the target.
            try:
                props = dbus.Interface(
                    self._bus.get_object("org.bluez", path), DBUS_PROP_IFACE
                ).GetAll(DEVICE_IFACE)
            except dbus.exceptions.DBusException:
                return
            self._maybe_connect(path, props)

    def _rediscover(self) -> bool:
        try:
            objects = self._bus.get_object("org.bluez", "/").GetManagedObjects(
                dbus_interface=DBUS_OM_IFACE)
            for path, ifaces in objects.items():
                if DEVICE_IFACE in ifaces:
                    self._maybe_connect(path, ifaces[DEVICE_IFACE])
        except dbus.exceptions.DBusException as err:
            log.warning("bridge: rescan failed: %s", err)
        return False

    def _maybe_connect(self, path: str, props: dict) -> None:
        with self._lock:
            if self._target_connecting or self._target_path == path and self._target_rx is not None:
                return
        name = str(props.get("Alias") or props.get("Name") or "")
        address = str(props.get("Address") or "")
        uuids = [str(u) for u in props.get("UUIDs", [])]
        if not self._bridge.config.target_matches(name=name, address=address, service_uuids=uuids):
            return
        if props.get("Connected"):
            with self._lock:
                self._target_path = path
            if props.get("ServicesResolved"):
                self._resolve_characteristics(path)
            return
        with self._lock:
            self._target_connecting = True
            self._target_path = path
        log.info("bridge: connecting to %s (%s)", name or address, address)
        device = dbus.Interface(self._bus.get_object("org.bluez", path), DEVICE_IFACE)
        device.Connect(
            reply_handler=lambda: log.info("bridge: connected to the PC"),
            error_handler=lambda e: self._connect_failed(e),
        )

    def _connect_failed(self, err: Exception) -> None:
        log.warning("bridge: connect to the PC failed: %s", err)
        with self._lock:
            self._target_connecting = False
            self._target_path = None

    def _resolve_characteristics(self, device_path: str) -> None:
        try:
            objects = self._bus.get_object("org.bluez", "/").GetManagedObjects(
                dbus_interface=DBUS_OM_IFACE)
        except dbus.exceptions.DBusException as err:
            log.warning("bridge: could not enumerate GATT objects: %s", err)
            return
        services = {
            path: props[GATT_SERVICE_IFACE]
            for path, props in objects.items()
            if GATT_SERVICE_IFACE in props and str(props[GATT_SERVICE_IFACE].get("Device")) == device_path
        }
        rx_proxy = tx_path = None
        for path, props in objects.items():
            if GATT_CHRC_IFACE not in props:
                continue
            chrc = props[GATT_CHRC_IFACE]
            if str(chrc.get("Service")) not in services:
                continue
            if str(chrc.get("UUID")).lower() == RX_UUID.lower():
                rx_proxy = dbus.Interface(self._bus.get_object("org.bluez", path), GATT_CHRC_IFACE)
            elif str(chrc.get("UUID")).lower() == TX_UUID.lower():
                tx_path = path
        if rx_proxy is None or tx_path is None:
            log.warning("bridge: PC GATT service found but RX/TX characteristics missing")
            return
        tx_proxy = dbus.Interface(self._bus.get_object("org.bluez", tx_path), GATT_CHRC_IFACE)
        tx_proxy.StartNotify()
        with self._lock:
            self._target_rx = rx_proxy
            self._target_tx_path = tx_path
            self._target_connecting = False
            device_props = objects.get(device_path, {}).get(DEVICE_IFACE, {})
            if "MTU" in device_props:
                self._target_mtu = int(device_props["MTU"])
        log.info("bridge: PC setup service subscribed; bridge is live")
        self._bridge.set_target_ready(True)

    def _on_tx_value(self, interface: str, changed: dict, invalidated: list, path: str = "") -> None:
        with self._lock:
            is_tx = path and path == self._target_tx_path
        if is_tx and "Value" in changed:
            self._bridge.on_target_notify(bytes(bytearray(changed["Value"])))


def build_bridge(config, identity_note: str = "") -> tuple[NameBridge, BridgeBluez]:
    """Wire a NameBridge to a BridgeBluez driver for ``config``."""
    holder: dict[str, BridgeBluez] = {}

    def driver() -> BridgeBluez:
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
    holder["driver"] = BridgeBluez(bridge)
    return bridge, holder["driver"]
