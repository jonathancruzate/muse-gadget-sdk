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

"""Tests for the name-translation bridge (musegadget.ble_bridge).

The core tests run anywhere: two fake links with deliberately mismatched
MTUs stand in for the phone side and the PC side. The end-to-end test
goes further — it runs the real SetupController and pairing v5 crypto
(the upstream test vectors' mobile simulator, written from the protocol
contract) with the bridge in the middle, and completes a whole pairing
through it. That is the property the bridge exists for: the app thinks
it is talking to a device named MuseGadgetXXXXXX, the PC thinks a
normal setup client connected to its existing-name GATT service, and
neither side's protocol changes.
"""

from __future__ import annotations

import base64
import json
import sys
import threading
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

WINDOWS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WINDOWS_DIR))

from musegadget.ble_bridge import BridgeConfig, NameBridge  # noqa: E402
from musegadget.ble_framing import ChunkAssembler, encode_chunks  # noqa: E402
from musegadget.identity import Identity  # noqa: E402

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "link_pairing_v5.json").read_text()
)["vectors"]
APP = next(v for v in VECTORS if v["name"] == "community_app_v5")

PC_NAME = "POWERSPEC-G757-"
SERVICE_UUID = "7fdd3d1c-38ea-46cf-8b46-314ecf5f240c"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --- Name translation -------------------------------------------------------


def test_front_name_comes_from_the_pc_identity():
    config = BridgeConfig.for_identity(
        Identity("fe:35:a9:38:55:d8"), target_names=[PC_NAME])
    assert config.front_name == "MuseGadget-3855D8"


def test_target_matches_by_existing_name_and_service_uuid():
    config = BridgeConfig("MuseGadget-3855D8", target_names=(PC_NAME,))
    assert config.target_matches(
        name=PC_NAME, address="AA:BB:CC:DD:EE:FF", service_uuids=[SERVICE_UUID])
    # A scan may surface the name shortened; a prefix is enough.
    assert config.target_matches(name="POWERSPEC-G757", service_uuids=[SERVICE_UUID])
    # Same name but advertising a different service is not the gadget.
    assert not config.target_matches(
        name=PC_NAME, service_uuids=["0000180a-0000-1000-8000-00805f9b34fb"])
    # The service alone is not enough either: names disambiguate PCs.
    assert not config.target_matches(name="OTHER-PC", service_uuids=[SERVICE_UUID])
    # And an unconfigured bridge matches nothing.
    assert not BridgeConfig("MuseGadget-3855D8").target_matches(
        name=PC_NAME, service_uuids=[SERVICE_UUID])


def test_target_matches_by_address_regardless_of_name():
    config = BridgeConfig(
        "MuseGadget-3855D8", target_address="30:56:0f:29:c0:94")
    assert config.target_matches(name="anything", address="30-56-0F-29-C0-94")
    assert not config.target_matches(name="anything", address="30:56:0f:29:c0:95")


# --- Framing translation ------------------------------------------------------


class RecordingLink:
    """One fake link end: records packets, reassembles messages."""

    def __init__(self) -> None:
        self.packets: list[bytes] = []
        self._assembler = ChunkAssembler()

    def send(self, packets: list[bytes]) -> None:
        self.packets.extend(packets)

    def messages(self) -> list[bytes]:
        out = []
        for packet in self.packets:
            message = self._assembler.feed(packet)
            if message is not None:
                out.append(message)
        return out


def make_bridge(app_mtu=23, target_mtu=185):
    app_link, target_link = RecordingLink(), RecordingLink()
    disconnects = {"app": [], "target": 0}
    bridge = NameBridge(
        BridgeConfig("MuseGadget-3855D8", target_names=(PC_NAME,)),
        send_to_app=app_link.send,
        send_to_target=target_link.send,
        disconnect_app=lambda delay: disconnects["app"].append(delay),
        disconnect_target=lambda: disconnects.__setitem__("target", disconnects["target"] + 1),
        app_mtu=lambda: app_mtu,
        target_mtu=lambda: target_mtu,
    )
    bridge.set_target_ready(True)
    return bridge, app_link, target_link, disconnects


def feed(link_packets, sink) -> None:
    for packet in link_packets:
        sink(packet)


def test_messages_are_rechunked_across_mismatched_mtus():
    bridge, app_link, target_link, _ = make_bridge(app_mtu=23, target_mtu=185)
    payload = bytes(range(256)) * 3  # 768 bytes: many chunks in, few out
    feed(encode_chunks(payload, 23), bridge.on_app_write)
    assert target_link.messages() == [payload]
    assert all(len(p) <= 160 for p in target_link.packets)

    feed(encode_chunks(payload, 185), bridge.on_target_notify)
    assert app_link.messages() == [payload]
    assert all(len(p) <= 20 for p in app_link.packets)  # 23-byte ATT MTU


def test_unchunked_packet_arrives_byte_identical_as_a_message():
    # The app may send a short message as one unframed write; the bridge
    # forwards the *message* (re-framed for the back link, as every SDK
    # sender frames), and it must arrive byte-identical.
    bridge, _, target_link, _ = make_bridge()
    bridge.on_app_write(b'{"action":"get_device_info"}')
    assert target_link.messages() == [b'{"action":"get_device_info"}']


def test_messages_queue_until_the_back_link_is_ready():
    app_link, target_link = RecordingLink(), RecordingLink()
    bridge = NameBridge(
        BridgeConfig("MuseGadget-3855D8", target_names=(PC_NAME,)),
        send_to_app=app_link.send, send_to_target=target_link.send,
    )
    feed(encode_chunks(b"one", 185), bridge.on_app_write)
    feed(encode_chunks(b"two", 185), bridge.on_app_write)
    assert target_link.packets == []  # nothing leaks before the link is up
    bridge.set_target_ready(True)
    assert target_link.messages() == [b"one", b"two"]


def test_disconnect_propagates_both_ways():
    bridge, _, _, disconnects = make_bridge()
    bridge.on_app_disconnect()
    assert disconnects["target"] == 1  # PC sees its client leave

    bridge2, _, _, disconnects2 = make_bridge()
    bridge2.on_target_disconnect()
    assert disconnects2["app"] == [0.0]  # phone session ends too
    assert not bridge2.target_ready


# --- End to end: a real pairing through the bridge ----------------------------

# The mobile simulator below is the upstream SDK tests' contract client
# (linux/tests/test_pairing.py), reused under the same Apache-2.0 license.


class Mobile:
    """Mobile side of the record layer, written from the contract."""

    def __init__(self, vector: dict) -> None:
        self.tx = AESGCM(bytes.fromhex(vector["mobile_tx_key_hex"]))
        self.rx = AESGCM(bytes.fromhex(vector["mobile_rx_key_hex"]))
        self.session_id = vector["session_id"]
        self.tx_counter = 0

    def _nonce(self, direction: int, counter: int) -> bytes:
        return bytes([direction]) + b"\0\0\0" + counter.to_bytes(8, "big")

    def _aad(self, arrow: str, counter: int) -> bytes:
        return f"hatch-link ble setup v1|{self.session_id}|{arrow}|{counter}".encode()

    def seal(self, command: dict, counter: int | None = None) -> dict:
        if counter is None:
            counter = self.tx_counter
            self.tx_counter += 1
        sealed = self.tx.encrypt(
            self._nonce(0, counter), json.dumps(command).encode(), self._aad("m2d", counter)
        )
        return {
            "action": "pairing_encrypted",
            "session_id": self.session_id,
            "counter": str(counter),
            "ciphertext": b64(sealed[:-16]),
            "tag": b64(sealed[-16:]),
        }

    def open(self, envelope: dict) -> dict:
        assert envelope["type"] == "pairing_encrypted"
        assert envelope["session_id"] == self.session_id
        counter = int(envelope["counter"])
        plain = self.rx.decrypt(
            self._nonce(1, counter),
            unb64(envelope["ciphertext"]) + unb64(envelope["tag"]),
            self._aad("d2m", counter),
        )
        return json.loads(plain)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_device():
    from musegadget.pairing import PairingSession

    scalar = int(APP["device_private_scalar_hex"], 16)
    return PairingSession(
        node_id=APP["node_id"],
        device_id=APP["device_id"],
        mac=APP["mac"],
        firmware_version=APP["firmware_version"],
        sdk_token="mgst_test_token",
        clock=FakeClock(),
        generate_key=lambda: ec.derive_private_key(scalar, ec.SECP256R1()),
        random_bytes=lambda n: unb64(APP["device_nonce"]),
    )


def hello(**overrides) -> dict:
    message = {
        "action": "pairing_client_hello",
        "version": 5,
        "pairing_auth": "none",
        "pairing_policy": "confirm_app",
        "mobile_pub": APP["mobile_pub"],
        "mobile_nonce": APP["mobile_nonce"],
    }
    message.update(overrides)
    return message


def client_finished_record() -> dict:
    return {
        "action": "pairing_encrypted",
        "session_id": APP["session_id"],
        "counter": "0",
        "ciphertext": APP["client_finished_ciphertext"],
        "tag": APP["client_finished_tag"],
    }


class AppSide:
    """The phone end of the front link: collects what the bridge notifies."""

    def __init__(self) -> None:
        self._assembler = ChunkAssembler()
        self._lock = threading.Lock()
        self.messages: list = []

    def send_packets(self, packets: list[bytes]) -> None:
        with self._lock:
            for packet in packets:
                message = self._assembler.feed(packet)
                if message is None:
                    continue
                try:
                    self.messages.append(json.loads(message))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self.messages.append(message.decode())

    def wait_for(self, predicate, timeout: float = 3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                for message in self.messages:
                    if predicate(message):
                        return message
            time.sleep(0.01)
        raise AssertionError(f"timed out; got {self.messages!r}")

    def opened(self, mobile: Mobile) -> list:
        with self._lock:
            return [mobile.open(m) for m in self.messages
                    if isinstance(m, dict) and m.get("type") == "pairing_encrypted"]


class FakeNetwork:
    def is_online(self) -> bool:
        return True

    def current_connection_entry(self) -> dict:
        return {"ssid": "HomeNet", "rssi": -40, "secure": False}


APP_MTU = 64    # awkward on purpose: not the PC link's MTU, not a default
TARGET_MTU = 185


def test_full_pairing_flow_through_the_bridge():
    from musegadget.ble_setup import ProvisionFailed, SetupController

    app_side = AppSide()
    saved: list = []
    completed = threading.Event()

    def provision(credentials, commit):
        if not commit(lambda: saved.append(credentials) or True):
            raise ProvisionFailed("error_storage")

    class TargetTransport:
        """The PC end: the controller's Transport, fed by the bridge."""

        def mtu(self) -> int:
            return TARGET_MTU

        def send_packets(self, packets: list[bytes]) -> None:
            for packet in packets:
                bridge.on_target_notify(packet)

        def disconnect(self, delay: float) -> None:
            pass

    controller = SetupController(
        pairing=make_device(),
        identity=Identity(APP["mac"]),
        version=APP["firmware_version"],
        transport=TargetTransport(),
        network=FakeNetwork(),
        provision=provision,
        on_complete=completed.set,
    )
    bridge = NameBridge(
        BridgeConfig.for_identity(Identity(APP["mac"]), target_names=[PC_NAME]),
        send_to_app=app_side.send_packets,
        send_to_target=lambda packets: [controller.on_write(p) for p in packets],
        app_mtu=lambda: APP_MTU,
        target_mtu=lambda: TARGET_MTU,
    )
    assert bridge.config.front_name.startswith("MuseGadget")
    bridge.set_target_ready(True)
    controller.start()

    def app_send(obj: dict) -> None:
        data = json.dumps(obj).encode()
        for packet in encode_chunks(data, APP_MTU):
            bridge.on_app_write(packet)

    mobile = Mobile(APP)
    try:
        # Plaintext discovery exchange, as the app performs it.
        app_send({"action": "get_device_info"})
        info = app_side.wait_for(lambda m: isinstance(m, dict) and m.get("type") == "device_info")
        assert info["node_id"] == APP["node_id"]
        assert info["device_id"] == APP["device_id"]

        # Pairing v5 handshake: hello, encrypted client-finished, confirm.
        app_send(hello())
        ready = app_side.wait_for(lambda m: isinstance(m, dict) and m.get("type") == "pairing_ready")
        assert ready["node_id"] == APP["node_id"]
        app_send(client_finished_record())
        mobile.tx_counter = 1  # the finished record consumed counter 0
        app_side.wait_for(
            lambda m: isinstance(m, dict) and m.get("type") == "pairing_encrypted"
            and mobile_status(m, mobile) == "pairing_confirmed",
        )

        # Encrypted commands ride the bridge opaquely after pairing.
        app_send(mobile.seal({"action": "wifi_scan"}))
        app_side.wait_for(
            lambda m: isinstance(m, dict) and m.get("type") == "pairing_encrypted"
            and opened_type(m, mobile) == "wifi_scan_result",
        )
        app_send(mobile.seal({
            "action": "provision_v2",
            "ssid": "HomeNet",
            "password": "",
            "access_token": "device-access",
            "refresh_token": "device-refresh",
            "token_type": "device",
            "username": "someone",
            "api_url": "https://legacy-api.example",
            "api_url_v2": "https://api.example",
            "noise_host": "noise.example",
        }))
        app_side.wait_for(
            lambda m: isinstance(m, dict) and m.get("type") == "pairing_encrypted"
            and opened_status(m, mobile) == "auth_ok",
        )
        assert completed.is_set()
        assert saved and saved[0].access_token == "device-access"

        stats = bridge.stats
        assert stats.app_to_target_messages >= 5
        assert stats.target_to_app_messages >= 5
    finally:
        controller.stop()


def _opened_or_none(message, mobile: Mobile):
    if not (isinstance(message, dict) and message.get("type") == "pairing_encrypted"):
        return None
    try:
        return mobile.open(message)
    except Exception:
        return None


def mobile_status(message, mobile: Mobile):
    opened = _opened_or_none(message, mobile)
    return opened.get("status") if opened else None


def opened_type(message, mobile: Mobile):
    opened = _opened_or_none(message, mobile)
    return opened.get("type") if opened else None


def opened_status(message, mobile: Mobile):
    return mobile_status(message, mobile)
