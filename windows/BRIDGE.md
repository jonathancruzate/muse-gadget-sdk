# Name-translation bridge — pairing a Windows PC whose Bluetooth name Windows controls

Built 2026-11-08 at Jonathan's order: "create a bridge in our forked sdk
translating muse name to existing Bluetooth name."

## The problem, in one paragraph

The Muse app finds gadgets by advertised BLE name (`MuseGadgetXXXXXX`,
suffix matched against the node id). Windows reserves the Local Name and
Service UUID sections of any custom `BluetoothLEAdvertisementPublisher`
advertisement (`E_INVALIDARG` — OS policy, not a Realtek fault), so the
only connectable ad a Windows gadget emits is the GATT service provider's
own, wearing the PC's system Bluetooth name (`POWERSPEC-G757-`) beside
the setup service UUID. The GATT service behind it is complete; the app
simply never lists the PC, so nothing ever connects. (Full probe history:
README.md, "Windows advertisement finding" + 2026-11-03 root cause.)

## The bridge

A small host with a BLE stack that *can* advertise a custom name sits in
the same room and translates:

```
Muse app  --BLE, name MuseGadget3855D8-->  BRIDGE  --BLE, existing name
POWERSPEC-G757- + setup service UUID-->  Windows PC (unmodified pair window)
```

* **Front (peripheral):** advertises the PC's `MuseGadgetXXXXXX` name,
  the setup service UUID and the paired flag — reusing the upstream
  BlueZ `Advertisement`/`Application` classes, so the ad is identical to
  a native Linux gadget's.
* **Back (central):** scans for the target by its existing Bluetooth
  name (exact or truncated-prefix, ≥8 chars) and/or Bluetooth address,
  gated on the setup service UUID when the scan reports UUIDs; connects,
  writes RX, subscribes TX.
* **Middle (`musegadget/ble_bridge.py`):** reassembles each framed
  message on the incoming link (`ChunkAssembler`) and re-chunks it for
  the outgoing link's MTU (`encode_chunks`). Payloads are forwarded
  byte-for-byte and never parsed, so pairing v5 (ECDH + AES-GCM records
  + the SDK token inside `pairing_confirmed`) stays end-to-end between
  the app and the PC's own `SetupController`. The bridge holds no
  credentials and no pairing state; `pairing.json` is written by the PC,
  on the PC, and afterwards the PC's daemon talks to Muse over WSS as
  usual — the bridge is only needed for the pairing window.
* **Disconnects propagate both ways**, so session clearing matches a
  direct connection (phone leaves → back link drops → PC clears its
  pairing session; PC closes the session after a fatal error → phone
  session ends).
* The PC side is **unchanged**: `musegadget_win.py pair` opens its
  normal WinRT GATT window and serves the bridge as its setup client.

Files:

* `windows/musegadget/ble_bridge.py` — platform-independent core.
* `windows/musegadget/ble_bridge_bluez.py` — BlueZ driver (front
  peripheral + D-Bus GATT central on one adapter / one GLib loop).
* `windows/musegadget_bridge.py` — CLI: `--state-dir` (a copy of the
  PC's `identity.json`), `--target-name` / `--target-address`.
* `windows/tests/test_ble_bridge.py` — core tests + full pairing E2E;
  `windows/tests/vectors/link_pairing_v5.json` — upstream test vectors.

## Verified (2026-11-08, this VM, no BLE hardware)

* All bridge tests pass under real pytest 9.2.0 (13 passed together
  with the existing Windows-port suite, 2026-11-08):
  * name/address/UUID target matching, incl. truncated-name scans;
  * re-chunking across mismatched MTUs (23 ↔ 185) byte-identical both
    ways, unframed messages, queue-until-back-link-ready, disconnect
    propagation;
  * **full pairing E2E through the bridge core**: real `SetupController`
    + real pairing v5 crypto (upstream contract vectors' mobile
    simulator) at asymmetric MTUs (app 64, PC 185) — `get_device_info`,
    hello → `pairing_ready`, encrypted client-finished →
    `pairing_confirmed`, encrypted `wifi_scan`, `provision_v2` →
    `auth_ok`, credentials saved on the PC side, completion fired.
* Existing Windows-port tests still pass in the same run, including
  the executor test that needs pytest's `monkeypatch` fixture.
* Modules compile; the BlueZ driver imports cleanly without BlueZ and
  fails loudly at construction, same pattern as `BleServerWinRT`.

## Not yet verified — needs a first hardware run

1. **A bridge host.** This VM has no BLE adapter. **SUPERSEDED
   2026-11-08 ~20:14 EST (Jonathan's order): the bridge host is no longer
   an external board — the bridge now lives on the PC itself; see
   `PC-BRIDGE.md` / `PC-BRIDGE-REPORT.md`. The ESP32 plan below is the
   earlier record, kept for history. Chosen host (earlier, 2026-11-08):
   the ESP32-C5 Home Link board, kept whole as
   Muse Home Link. Bridge firmware BUILT the same day (build only,
   not flashed):** `ble_bridge.c/h` in the VPS tree
   `~/muse-gadget-sdk-bridge`; binaries + BUILD-REPORT.md in
   `~/workspace/muse-home-link/firmware-bridge/` (muse-gadget.bin
   1,773,568 B, +3.8% vs shipped; SHA-256 verified; shipped
   `firmware/` untouched). Commands `ble.bridge_start` /
   `ble.bridge_stop` / `ble.bridge_status`, off at boot,
   MAX_CONNECTIONS=3. Design notes: bridge mode takes over the BLE
   stack for the session (the board's own gadget BLE powers down,
   restored on stop; auto-stop default 30 min; Wi-Fi link, identity
   and pairing never touched), session MTU capped at 67, and this
   build enables upstream persistent-BLE mode (companion advertising
   after setup instead of BLE shutdown). Remaining candidates if the
   board path fails on hardware: a small Linux box / Pi with BLE
   (none on file), a USB BLE dongle on any always-on Linux host in
   range, or the Shield — where, per the 2026-11-08 coordination
   decision, the bridge would plug into the existing Muse Device
   Assistance app running its TV profile (runtime Shield detection),
   NOT a separate Shield TV app; the Shield's peripheral-mode
   support is unverified either way. The BlueZ driver is the
   reference implementation every one of those ports mirrors.
2. **BlueZ dual-role on one adapter** (peripheral + central at once) —
   standard, but the driver's D-Bus central path has never run.
3. **Windows accepting a central connection at all** — zero connection
   attempts have ever reached the PC's WinRT GATT service; its session
   handling is code-reviewed, not exercised. The first bridge run is
   also the first test of that path (if Windows refuses the connection,
   that is a PC-side finding, not a bridge finding).

## Run order (when a host exists)

1. PC: `musegadget_win.py pair` (normal window, 10 min).
2. Bridge host: `sudo python3 musegadget_bridge.py --state-dir <dir
   with the PC's identity.json> --target-name POWERSPEC-G757-`
3. Phone: Muse app → Settings > Devices → Developer mode → Add Device
   → `MuseGadget3855D8` → accept the warning → pick the offered network.
4. Verify on the PC: `musegadget_win.py info` → `paired: yes`, then the
   steady-state service registers (a real `system.run` returning the
   Windows hostname is the acceptance check).
