# Muse Gadget — Windows + Shield

Adapt the Muse gadget SDK (upstream: `~/workspace/muse-gadget-sdk`, Meta's
open-source `facebookincubator/muse-gadget-sdk`) so Jonathan's Windows PC and
then his NVIDIA Shield pair as Muse devices, the way a Linux/Pi gadget does.
Community reference: a Reddit post Jonathan found (someone had Codex adapt
the gadget SDK to run on a PC and pair over Bluetooth). The post itself was
not retrievable (checked the main chat, the Reddit bridge ingest, and web
search on 2026-11-01); this build follows the SDK's own documentation and
source, which fully specify the pairing protocol.

## SDK provenance

- Upstream repo already on this VM: `~/workspace/muse-gadget-sdk`
  (synced 2026-10-31), Apache-2.0. The Linux Device SDK is a Python package,
  `musegadget` (`linux/src/musegadget`), deps `cryptography>=3.3.2`,
  `websockets>=13`, Python >= 3.9.
- SDK token: generated 2026-10-31 on gadgets.muse.ai (1 active token,
  0 of 50 devices used). Value lives ONLY in
  `~/workspace/security/muse-gadget-sdk-token.txt` (0600) — never in this
  repo, chat, or git. The SDK reads it from `$MUSEGADGET_SDK_TOKEN` or a
  `sdk_token` file in the state dir (`MUSEGADGET_STATE_DIR`).

## Pairing protocol summary (from linux/AGENTS.md + source)

- Identity: persistent random locally-administered MAC-shaped value →
  node id `homelink-XXXXXX`, device id `hatch-link:<mac>`, BLE name
  `MuseGadgetXXXXXX` (uppercase suffix, no separator). Kept across
  unpairing (`identity.py`, `identity.json` in the state dir).
- BLE peripheral (only while the pair window is open, 600 s):
  - Service `7fdd3d1c-38ea-46cf-8b46-314ecf5f240c`
  - RX `4d593029-28a2-4a6e-a1f0-3c2d5e8f9b01` (write / write-without-response)
  - TX `d75dc4ca-7b2b-4e9c-8f0a-1d2e3f4a5b6c` (read / notify)
  - Advertisement: peripheral, local name = BLE name (GAP name too),
    service UUID above, manufacturer data company `0xFFFF` → `[0]`
    (paired flag).
  - Framing (`ble_framing.py`): chunks `0xFE, index, total, payload…`,
    max packet 160 B, notifications paced 50 ms apart; MTU learned from
    the phone's writes (assumed 163 until known).
- Setup protocol (`ble_setup.py`, transport-independent): JSON commands
  over the framed channel.
  - Plaintext any time: `get_device_info` → node id, version, device_id,
    mac, `model: "hatch_link"`, pairing_protocol 5, pairing_auth `none`,
    epoch 0, policy `confirm_app`, network_ready.
  - `pairing_client_hello` → community pairing v5 (`pairing.py`): P-256
    ECDH, canonical transcript `hatch-link-pairing-v5` (device/node ids,
    mac, model, firmware version, both ephemeral pubs + nonces),
    HKDF-SHA256 (salt = SHA256(mobile_nonce‖device_nonce‖transcript_hash),
    info `hatch-link ble setup v1`), HKDF-Expand `mobile->device` /
    `device->mobile` record keys, session id = SHA256(`hatch-link session
    id v1`‖transcript_hash‖ECDH secret)[:16]. Device replies
    `pairing_ready`.
  - Records: AES-256-GCM in `pairing_encrypted` envelopes
    `{session_id, counter, ciphertext, tag}`; nonce = direction byte
    (0 m2d / 1 d2m) + 3 zero bytes + u64be counter; AAD
    `hatch-link ble setup v1|<session_id>|<m2d|d2m>|<counter>`; strict
    per-direction counters.
  - First decrypted record must be `pairing_client_finished` (the app
    collected consent; policy `confirm_app`) → device sends encrypted
    status `pairing_confirmed`, which carries the **SDK token** to the
    app. That is what the token authenticates: the app presents it to
    Muse's backend when registering the device; Muse records a device's
    token only at pairing.
  - Encrypted `wifi_scan` → `wifi_scan_result` with one open entry, "the
    current connection" (real SSID if discoverable, rssi −40,
    secure false), when the host is already online.
  - Encrypted `provision_v2` {ssid, password (ignored), access_token,
    refresh_token, token_type "device", username, api_url, api_url_v2,
    noise_host} → statuses `wifi_connecting` → `wifi_connected`; the host
    verifies the device token by fetching the account's VMs from the API
    (must return ≥1, else `auth_failed`), saves `pairing.json`, sends
    `auth_ok`.
- Steady state (`service.py`, `link_client.py`, `muse_api.py`):
  fetch VMs with the device access token → per-VM bearer → WSS
  `<noise_host>/v1/noise?vm_id=…` → Noise XX handshake → `POST
  /link-control` held open → `link.register` as `platform: "linux"`,
  `device_family: "homehub"` (never family `link`, never advertise
  `device.ota`) → serves `link.invoke` for `system.run`, `file.read`,
  `file.write`, `device.health` plus owner commands from commands.d.
  Device-token refresh via the stored refresh token.
- Phone side (Jonathan's hands): Muse app → Settings > Devices →
  Developer mode ON → Add Device → pick `MuseGadgetXXXXXX` → accept the
  community-device warning → pick the offered network (no password).

## What a port must implement (the seam)

Everything above the BLE transport is platform-independent Python:
`SetupController` needs only a `Transport` (send_packets / mtu /
disconnect), a `Network` (is_online / current_connection_entry), a
`PairingSession`, an `Identity`, and a provision callback (`pair.py`).
Per platform, a port supplies:

1. A BLE peripheral for the GATT layout above (the upstream
   `ble_server.py` is BlueZ/D-Bus; Windows uses WinRT, Android uses
   BluetoothGattServer + BluetoothLeAdvertiser).
2. A network entry (online check is a plain TCP-443 probe — portable;
   SSID lookup is per-OS, with the "Use current connection" fallback).
3. An executor: `system.run` in the host shell (upstream is bash; Windows
   is cmd/PowerShell), file ops (portable), device.health fields.
4. A long-running service host (upstream: systemd; Windows: scheduled
   task/console process; Android: foreground service). The upstream local
   Unix socket (send-user-msg) does not exist on Windows/Android and is
   skipped there.

## Phase status

- Phase 1 (recon): done 2026-11-01 — this summary.
- Phase 2 (PC): built and deployed 2026-11-01; pairing window opened
  22:17 EST. Identity: node `homelink-3855d8`, device
  `hatch-link:fe:35:a9:38:55:d8`, BLE name `MuseGadget3855D8`.
  Display name renamed to **PC** at Jonathan's order 2026-11-03
  (`DISPLAY_NAME = "PC"` in `musegadget_win.py`, passed as the Service
  `display_name` — that is the name Muse shows once the device is
  online; verified on the PC via `info`). The BLE pairing name is NOT
  renamed: the app matches `MuseGadget<suffix>` against the node id
  suffix, so changing it would break discovery/pairing. Deployed
  at `C:\Users\jonat\musegadget` on the PC (venv, vendored package,
  `musegadget_win.py`); SDK token placed as `state\sdk_token` (48 bytes,
  size-verified; the value is never printed anywhere). Verified on the
  PC: WinRT imports, the BLE server constructs, the GATT service
  registers and its provider advertisement starts. Pairing completes
  when the device is picked in the Muse app (Developer mode > Add
  Device) and the offered network is accepted.
- Phase 2b (name-translation bridge, 2026-11-08, Jonathan's order): a
  bridge in the fork translates between the name the app scans for and
  the name Windows lets the PC advertise — a BLE host in the room
  advertises `MuseGadget3855D8`, connects to the PC's setup service
  under `POWERSPEC-G757-`, and relays framed setup messages between the
  links (payloads opaque; pairing crypto stays app↔PC end-to-end; PC
  side unchanged). Core + BlueZ driver + CLI built
  (`windows/musegadget/ble_bridge.py`, `ble_bridge_bluez.py`,
  `windows/musegadget_bridge.py`); all tests pass including a full
  pairing-v5 E2E through the core at mismatched MTUs. Hardware run
  still owed: no BLE adapter on this VM and no spare Linux BLE host in
  the apartment yet. Full design + honest status: `BRIDGE.md`.
- Phase 2c (PC-resident bridge, 2026-11-08, Jonathan's order — supersedes
  the Phase 2b external-host plan and the ESP32 bridge-host choice): the
  bridge now lives on the PC itself. Primary: temporary self-translation
  of the PC's Bluetooth identity (adapter `Local Name` override first,
  `SetComputerNameExW` DNS rename fallback, preflight-gated against the
  16-char vs 15-char NetBIOS truncation risk), restoring the original
  name once `pairing.json` exists. Secondary: a Bumble-driven USB BLE
  dongle on the PC reusing the Phase 2b `NameBridge` core. Built by agy,
  verified by Muse: full suite 32 passed, 1 documented skip (the Bumble
  virtual LocalLink relay hangs at connect). Not deployed. Design +
  runbook + honest gaps: `PC-BRIDGE.md`, `PC-BRIDGE-REPORT.md`.
- Phase 3 (Shield): pending.
- Windows advertisement finding (probed live on the PC, 2026-11-01):
  this Realtek/WinRT stack refuses to start ANY
  BluetoothLEAdvertisementPublisher advertisement that contains a local
  name or service UUIDs (E_INVALIDARG from start(), even for a 4-char
  name alone); manufacturer-data-only advertisements start fine. The
  BLE module's fallback chain therefore lands on the paired-flag-only
  publisher, and the connectable/discoverable advertisement carrying
  the setup service UUID comes from the GATT service provider —
  proven started. Consequence: the phone's list shows the PC's
  Bluetooth (GAP) name, not `MuseGadgetXXXXXX`; discovery is by
  service UUID. The remaining lever, if the app ever insists on the
  name, is renaming the PC's Bluetooth adapter (needs elevation; not
  attempted).
- Discovery root cause CONFIRMED 2026-11-03 (live pairing attempts,
  02:07–03:52 EST; Jonathan parked the pairing to tomorrow): the app
  DOES insist on the name — per the SDK README it scans for the
  `MuseGadget` name prefix, so the nameless on-air advertisements are
  never listed ("No devices found" in the app; Android Bluetooth
  settings showed only the old classic pairing `POWERSPEC-G757-`).
  Extended advertising does not save it either: probes the same night
  (`adv_probe_ext.py`, `adv2.py` on the PC) — the adapter reports
  extended advertising supported, but every publisher variant carrying
  a local name or a service UUID still raises E_INVALIDARG at start,
  legacy and extended alike; manufacturer-data-only starts (status
  Started). Renaming the gadget *server* to match the PC (Jonathan's
  suggestion) cannot work: the BLE name is the discovery key and is
  derived from the identity (see the display-name note above).
  TOMORROW'S FIX (agreed 2026-11-03): rename the PC's Bluetooth
  identity to `MuseGadget3855D8` + reboot, Jonathan unlocks once,
  then pair (window open, Add Device) and start the service.
  Ops notes from the same night: pair windows launched over SSH die
  with their SSH session (~35 s) — launch detached instead (WMI
  `Win32_Process.Create` with output to `pair.log`, or a scheduled
  task in his session; both proven); kill stray `python.exe` pair
  chains before opening a fresh window so exactly one advertiser runs.
- Phase 4 (docs): this file, updated as phases land.
