# PC-BRIDGE report — PC-resident Muse Gadget bridge (built 2026-11-08)

Brief: `PC-BRIDGE-AGY-BRIEF.md` (Jonathan's order 2026-11-08 ~20:14 EST:
instead of relaxing/using the ESP32 Home Link board, build the bridge as a
program on the PC itself, translating the Bluetooth ID). Design: `PC-BRIDGE.md`.

## How this run went (honest)

- Executed by agy (frontier ladder, Opus 5.5 High first) under
  `agy_route.py`, launched 20:17 EST. agy produced the design doc, all code,
  PowerShell helpers, and the full test file, updating
  `PC-BRIDGE-CHECKPOINT.md` as it went.
- The outer 1500 s timeout killed the run at 20:42 EST, after the last code
  file landed but before agy ran the suite or wrote this report (its final
  stdout is empty; the run log is empty). Nothing was deployed, renamed,
  rebooted, paired, or flashed; the Home Link board was never touched.
- Muse (coordinator) then verified everything below independently and
  finished this report + the checkpoint. Two verification fixes are Muse's,
  marked where they live: one test-assertion correction, one test converted
  to a documented skip (details under Verification).

## What was built

| File | Bytes | What it is |
|---|---|---|
| `PC-BRIDGE.md` | 17,611 | Design: primary self-translation (Paths 1A/1B), secondary Bumble dual-radio, rejected WinRT loopback, UNVERIFIED table U1–U4 |
| `windows/musegadget/pc_bridge.py` | 44,641 | State machine, preflight, backup, apply/continue/restore/status logic (plain Python, importable on Linux) |
| `windows/musegadget/pc_bridge_bumble.py` | 20,767 | Secondary-mode Bumble driver reusing the existing `NameBridge` core |
| `windows/musegadget_pc_bridge.py` | 14,803 | CLI: `preflight`, `apply` (dry-run default), `continue`, `restore`, `status`, `secondary-run` |
| `windows/pc_bridge/adapter-name.ps1` | 6,825 | Path 1A: adapter `Device Parameters\Local Name` Query/Set/Restore, `-WhatIf` |
| `windows/pc_bridge/rename-computer.ps1` | 4,281 | Path 1B: `SetComputerNameExW` DNS-hostname Query/Set/Restore, `-WhatIf` |
| `windows/pc_bridge/scheduled-task.ps1` | 2,747 | Post-reboot continuation task `MuseGadgetPcBridgeContinue` Register/Unregister/Status |
| `windows/tests/test_pc_bridge.py` | ~23,500 | 20 tests (see below) |

Design decisions (full reasoning in `PC-BRIDGE.md`):
- **Primary, Path 1A first:** write the radio's adapter-level `Local Name`
  (registry, up to 248 bytes — no 15-char NetBIOS limit) and bounce the PnP
  device; no computer rename, no reboot. Read back the live radio name via
  `BluetoothGetRadioInfo` to prove all 16 chars of `MuseGadget3855D8` are
  on air.
- **Primary, Path 1B fallback:** `SetComputerNameExW(ComputerNamePhysicalDnsHostname)`
  stores the full 16-char DNS hostname while NetBIOS truncates to
  `MuseGadget3855D`. Preflight gates this: if today's DNS hostname is
  already >15 chars while the radio name is the 15-char `POWERSPEC-G757-`,
  preflight proves the radio name comes from NetBIOS and marks 1B NO-GO
  (unless `--allow-truncation-risk`).
- **Secondary (if neither path puts 16 chars on air):** Google Bumble on a
  USB BLE dongle plugged into the PC (WinUSB bound to the dongle only, via
  Zadig; the built-in Realtek stays on the Windows driver for the WinRT
  GATT target). Front advertises `MuseGadget3855D8` (26 B adv + 18 B scan
  response, both ≤31 B legacy), back connects centimetres over the air to
  the PC's own `POWERSPEC-G757-` GATT service; `NameBridge` forwards
  payloads opaquely, pairing v5 crypto stays app↔PC end-to-end.
- **Rejected:** in-process WinRT publisher loopback (proven `E_INVALIDARG` /
  system-reserved Local Name + Service UUID sections).

## Verification (Muse, 2026-11-08 evening, this VM, no BLE hardware)

Environment: fresh venv, Python 3.12, pytest 9.2.0, cryptography, websockets,
bumble 0.0.236 (same set agy used).

- Full suite: `python -m pytest windows/tests/ -q` → **32 passed, 1 skipped**
  in 1.35 s (13 pre-existing bridge/windows-port tests + 19 of the 20 new
  PC-bridge tests; 1 skip below).
- Included in the pass: full pairing v5 E2E through the Bumble secondary
  driver + `NameBridge` + real `SetupController` (asymmetric MTUs), the
  advertising/scan-response PDU test (26 B / 18 B, name + 0xFFFF flag +
  service UUID parse back correctly), backup-never-overwritten, dry-run
  changes nothing, restore idempotent from all five phases × both modes,
  preflight strictly read-only.
- CLI smoke: `musegadget_pc_bridge.py --help` lists all six subcommands.
- Muse fix 1 (test bug, not code): the PDU test asserted Bumble's
  manufacturer-data parse as raw bytes; Bumble returns `(company_id, data)`.
  Assertion corrected to `(0xFFFF, b"\x00")` with a comment.
- Muse fix 2 (documented skip): `test_bumble_virtual_locallink_three_device_over_the_air_relay`
  **hangs** — the dongle's central connect never completes on Bumble's
  virtual `LocalLink` (>120 s, event loop idle). Reproduced three ways
  (target advertising on/off-paused, literal peer addresses); the virtual
  controllers report address `00:00:00:00:00:00` before power-on and the
  connection is never routed. Converted to `pytest.mark.skip` with the
  full reason in the test file. The driver-level E2E above is the
  verification that stands; the virtual over-the-air relay is UNVERIFIED.

## Deploy to the PC (next step, gated — not done)

1. Copy the updated `windows\` tree to `C:\Users\jonat\musegadget\` on the PC
   (same lane as the Phase 2 deployment; keep `state\` untouched — it holds
   `identity.json` + `sdk_token`).
2. In the PC venv: `pip install -r windows\requirements-win.txt` (existing)
   plus `bumble` only if Secondary Mode is ever used.
3. Read-only first contact: `python windows\musegadget_pc_bridge.py preflight`
   — settles U1 (today's DNS vs NetBIOS vs radio names) and prints the
   GO / GO-WITH-RISK / NO-GO verdict per path. Nothing changes.

## Pairing-day runbook (Jonathan present, phone in hand)

1. `preflight` → confirm verdicts.
2. `apply` (dry-run) → review the exact steps → `apply --no-dry-run`
   (Path 1A first; reboot only if Path 1B is the chosen path, with the
   continuation task registered before rebooting).
3. Continuation (auto, or `continue` manually): verifies the live radio
   name is exactly `MuseGadget3855D8`, opens `musegadget_win.py pair`.
4. Phone: Muse app → Settings > Devices → Developer mode → Add Device →
   `MuseGadget3855D8` → accept the community warning → pick the offered
   network.
5. On `pairing.json`: the bridge restores the original identity
   (`POWERSPEC-G757-…`) and unregisters the continuation task; verify with
   `musegadget_win.py info` → `paired: yes`, then a real `system.run`
   returning the Windows hostname via the steady-state service.
6. Anything goes sideways at any point: `musegadget_pc_bridge.py restore`
   is standalone and idempotent from every state.

## Honest gaps — NOT hardware-verified

- U1–U4 in `PC-BRIDGE.md`: preflight readings on the real PC, whether the
  Realtek/Windows stack honours the adapter `Local Name` override with all
  16 chars, which name source `bthport.sys` uses after a 1B rename, and
  whether the PC's WinRT GATT service accepts a connection at all (zero
  connections have ever reached it — the first pairing attempt is also
  that test).
- The Bumble virtual over-the-air relay test (skipped, above); a real
  dongle run is the secondary mode's first hardware test, and needs a
  dongle from the list in `PC-BRIDGE.md` (none on hand on file).
- The ESP32 bridge firmware built earlier today
  (`~/workspace/muse-home-link/firmware-bridge/`) is superseded by this
  plan and stays unflashed; the Home Link board is untouched.

## Deployment + preflight — DONE 2026-11-08 ~22:40 EST (Jonathan's "Go")

Deployed to `C:\Users\jonat\musegadget\` over the tailnet SSH lane,
byte-size verified: `musegadget\pc_bridge.py`, `musegadget\pc_bridge_bumble.py`,
`musegadget_pc_bridge.py`, `pc_bridge\{adapter-name,rename-computer,scheduled-task}.ps1`,
plus the Phase 2b core the PC copy was missing (`musegadget\ble_bridge.py`,
`ble_bridge_bluez.py`, `musegadget_bridge.py`). PC `state\` untouched.
Note: the fleet naming ruling changed the same evening (hyphen everywhere,
ESP32 firmware form) — the PC's identity already reads `MuseGadget-3855D8`
(17 chars, verified by `musegadget_win.py info` read-back) and the bridge
derives its target from `identity.py`, so it targets the hyphenated name.

**Preflight verdicts on the real PC (read-only, nothing changed — status
afterwards: phase idle, no backup, no continuation task):**

- **U1 SETTLED — truncation PROVEN:** DNS hostname `PowerSpec-G757-5640`
  (19 chars) vs Bluetooth radio name `POWERSPEC-G757-` (15 chars, trailing
  hyphen) proves `bthport.sys` sources the radio name from the 15-char
  NetBIOS name on this stack.
- **Path 1B (rename): NO-GO** — a rename would truncate the BLE name to
  `MuseGadget-3855` and fail the app's suffix match. Deterministically
  excluded, exactly as the gate was designed to do.
- **Path 1A (adapter Local Name): GO-WITH-RISK** — Realtek adapter
  `USB\VID_0BDA&PID_B850`, registry `Local Name` currently unset, session
  is admin. U2 (does Realtek honour the override across a PnP bounce) is
  tested by the apply step itself, with immediate
  `BluetoothGetRadioInfo` read-back and automatic restore on failure.
- **Secondary (dongle): NO-GO for now** — `bumble` not installed in the PC
  venv and no dongle on hand; install-only if 1A fails.
- **OVERALL: GO-WITH-RISK via primary-adapter.**

Next step (gated, Jonathan present with phone): 
`musegadget_pc_bridge.py apply --mode adapter --execute`, then the
pairing-day runbook above from step 3.
