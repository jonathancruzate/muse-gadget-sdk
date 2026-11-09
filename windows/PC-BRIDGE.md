# PC-Resident Muse Gadget BLE Bridge (`PC-BRIDGE.md`)

> **ADDENDUM 2026-11-08 ~22:30 EST — fleet naming ruling changed the target name.**
> Jonathan's final ruling (Shield chat, same night): hyphen everywhere, matching
> the ESP32 firmware as shipped. The PC's BLE name is now **`MuseGadget-3855D8`**
> (**17 characters**: 11-char prefix `MuseGadget-` + 6-char suffix `3855D8`),
> already patched on the PC and in the shared SDK source; this repo's Windows
> `identity.py` was aligned to match in the same handling, and the bridge code
> derives the name from `identity.py` dynamically (tests re-verified:
> 32 passed, 1 skipped). Everywhere below, read `MuseGadget3855D8` (16 chars)
> as `MuseGadget-3855D8` (17 chars) and the 15-char NetBIOS truncation as
> `MuseGadget-3855` (suffix `3855`, which still fails suffix validation).
> The design, gates, and UNVERIFIED table are unchanged — the truncation
> risk is strictly worse by one character, which changes no decision.

## Purpose and Scope

Pair the Windows 11 Home desktop PC (`PowerSpec-G757`, user `jonat`, deployment tree `C:\Users\jonat\musegadget\`) as a Muse Gadget **entirely from the PC itself**, without touching or relaxing the ESP32-C5 Muse Home Link board and without requiring a separate Linux host.

### Proven Ground Truth

1. **Identity and target BLE name (`windows/musegadget/identity.py`):**
   - Device ID: `hatch-link:fe:35:a9:38:55:d8`
   - Node ID: `homelink-3855d8`
   - Required BLE pairing name: `MuseGadget3855D8` (**16 ASCII characters**: 10-char prefix `MuseGadget` + 6-char uppercase hex suffix `3855D8`).
   - Steady-state display name (`windows/musegadget_win.py`): `"PC"`. Once `state\pairing.json` is written, BLE is never used again; steady state dials out over WSS/Noise (`link.register`).
2. **WinRT GATT peripheral works; custom BLE name does not (`README.md`):**
   - `BleServerWinRT` (`windows/musegadget/ble_server_windows.py`) registers the setup GATT service (`7fdd3d1c-38ea-46cf-8b46-314ecf5f240c`) with RX (`4d593029-28a2-4a6e-a1f0-3c2d5e8f9b01`) and TX (`d75dc4ca-7b2b-4e9c-8f0a-1d2e3f4a5b6c`), and its `GattServiceProvider` connectable advertisement starts cleanly.
   - However, `GattServiceProvider` advertises the **system Bluetooth (GAP) name** (`POWERSPEC-G757-`), not `MuseGadget3855D8`.
   - The Muse phone app scans by the `MuseGadget` name prefix and matches the 6-character suffix against the node ID suffix (`homelink-3855d8`). Because the on-air advertisement carries `POWERSPEC-G757-`, the app displays `"No devices found"` and zero connections ever reach the PC's GATT server.

---

## 1. Primary Mode — Self-Translation by Temporary Identity Override (No New Hardware)

### Concept

Because BLE is only needed during the one-time setup window (up to 600 seconds) that produces `state\pairing.json`, a PC-resident controller (`windows/musegadget_pc_bridge.py`) temporarily translates the PC's own advertised Bluetooth identity to `MuseGadget3855D8`, runs `musegadget_win.py pair`, watches for `state\pairing.json`, and immediately restores the original PC/adapter identity.

### The 16-Character NetBIOS Risk (First-Class Design Constraint)

`MuseGadget3855D8` is **16 characters**, which collides with Windows' legacy **15-byte NetBIOS computer name limit** (`MAX_COMPUTERNAME_LENGTH = 15`):

1. **Empirical evidence from this PC:** The PC's current advertised Bluetooth name is `POWERSPEC-G757-` — **exactly 15 characters**, ending in a trailing hyphen (`-`). A trailing hyphen is invalid in a DNS hostname label (RFC 952 / RFC 1123), which indicates that the machine's full DNS hostname is longer (e.g., `POWERSPEC-G757-<suffix>`) and `POWERSPEC-G757-` is its 15-character NetBIOS truncation (`ComputerNamePhysicalNetBios`).
2. **PowerShell `Rename-Computer` vs Win32 `SetComputerNameExW`:**
   - PowerShell's `Rename-Computer -NewName` validates against the 15-character NetBIOS limit and rejects a 16-character string outright.
   - Win32 `SetComputerNameExW(ComputerNamePhysicalDnsHostname, "MuseGadget3855D8")` (info level `5`) accepts names longer than 15 characters: per Microsoft documentation, it sets the physical DNS hostname to the full 16-character string (`MuseGadget3855D8`) while **automatically truncating the NetBIOS name to the first 15 characters** (`MuseGadget3855D`).
3. **What happens if the on-air BLE name truncates to `MuseGadget3855D` (15 chars):**
   - **Discovery (prefix match):** The 10-character prefix `MuseGadget` is intact, so a prefix scan in the Muse app may list the device (**UNVERIFIED** whether the app's scanner checks prefix-only at list time or full regex `^MuseGadget[0-9A-Fa-f]{6}$`).
   - **Pairing validation (suffix match):** Per `identity.py` (`"the apps compare the text after the prefix with the text after 'homelink-' in the node id"`), the app compares the advertised suffix (`3855D`, 5 chars) against the node ID suffix (`3855d8`, 6 chars) returned in `get_device_info` / `pairing_ready`. A 15-character truncated name (`MuseGadget3855D`) drops the final hex digit (`8`) and is predicted to **fail suffix validation**.

### Two Primary Sub-Paths: Adapter Local-Name Override vs Full Computer Rename

To avoid an unnecessary reboot or a truncated NetBIOS rename if the driver supports an adapter-level override, Primary Mode implements two distinct mechanisms under `windows/pc_bridge/` and tests the less-invasive path first:

#### Path 1A — Adapter `Local Name` Override (`windows/pc_bridge/adapter-name.ps1`, No Reboot)
- **Mechanism:** Windows' Bluetooth port driver (`bthport.sys`) stores radio-specific parameters under the active USB/PCI enumerator instance key:
  `HKLM\SYSTEM\CurrentControlSet\Enum\<RadioInstanceId>\Device Parameters`
  (and `HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters`).
  Writing `Local Name` (`REG_BINARY`, UTF-8 bytes of `MuseGadget3855D8` with NUL terminator, up to 248 bytes per Bluetooth spec `BLUETOOTH_MAX_NAME_SIZE`) and cycling the Bluetooth PnP device (`Disable-PnpDevice` / `Enable-PnpDevice`) asks `bthport.sys` to reload the local radio name without renaming the OS computer or rebooting.
- **Verification on the PC:** Immediately after cycling the radio, read back the live stack radio name via `BluetoothApis.dll!BluetoothGetRadioInfo` (`BLUETOOTH_RADIO_INFO.szName`, `WCHAR[248]`).
- **UNVERIFIED hardware fact:** Whether Windows 11 23H2/24H2 + the Realtek Bluetooth driver on `PowerSpec-G757` honours `Device Parameters\Local Name` across a PnP bounce (and propagates all 16 characters of `MuseGadget3855D8` into `BluetoothGetRadioInfo.szName` and `GattServiceProvider`'s on-air AD/ScanRsp packet) without overwritten re-initialization from `GetComputerNameW` is **UNVERIFIED**. The first run of `preflight` + `apply` tests this directly via `BluetoothGetRadioInfo`.

#### Path 1B — DNS Hostname Rename via `SetComputerNameExW` (`windows/pc_bridge/rename-computer.ps1`, Two Reboots)
- **Mechanism:** Calls `kernel32.dll!SetComputerNameExW(ComputerNamePhysicalDnsHostname, "MuseGadget3855D8")` (info level `5`) so Windows stores the full 16-character string in `NV Hostname` (`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NV Hostname`), while `ComputerName` (NetBIOS) receives `MuseGadget3855D`.
- **UNVERIFIED hardware fact:** Whether `bthport.sys` initializes `BLUETOOTH_RADIO_INFO.szName` at boot from `ComputerNamePhysicalNetBios` (15-char `MuseGadget3855D`) or `ComputerNamePhysicalDnsHostname` (16-char `MuseGadget3855D8`).
- **Preflight Gate:** `preflight` compares the PC's current **DNS hostname** (`GetComputerNameExW(ComputerNamePhysicalDnsHostname)`), **NetBIOS name** (`GetComputerNameExW(ComputerNamePhysicalNetBios)`), and **live Bluetooth radio name** (`BluetoothGetRadioInfo.szName`):
  - If the current DNS hostname is already `> 15` characters (e.g., `POWERSPEC-G757-XXXX`) while `BluetoothGetRadioInfo.szName` is the 15-character `POWERSPEC-G757-`, **preflight proves deterministically before touching anything** that `bthport.sys` on this PC sources its default name from the 15-character NetBIOS name, so Path 1B will truncate `MuseGadget3855D8` to `MuseGadget3855D` (`NO-GO` for Path 1B unless `--allow-truncation-risk` is explicitly passed; fallback to Path 1A or Secondary Mode).
  - If the current DNS hostname is also 15 characters (`POWERSPEC-G757-`), preflight marks Path 1B as `GO-WITH-RISK` (truncation unknown until measured post-rename via `BluetoothGetRadioInfo.szName`).

### Primary Mode State Machine & Backup Safety (`windows/musegadget/pc_bridge.py`)

State files live in `<state_dir>/pc_bridge/`:
- `backup.json` — immutable backup of original names (`netbios_name`, `dns_hostname`, `radio_name`, `adapter_instance_id`, `adapter_reg_local_name_hex`, `created_at`). **Rule: never overwrite an existing `backup.json`**; if `backup.json` already exists, `apply` reuses it so an interrupted run can never clobber the true original name (`POWERSPEC-G757-`) with a translated intermediate name.
- `state.json` — current state machine phase:
  1. `idle` — no translation active; `pairing.json` absent (or `--force`).
  2. `renamed-awaiting-reboot` — translation applied (Path 1B or Path 1A requiring reboot); continuation task registered (`MuseGadgetPcBridgeContinue`); waiting for reboot.
  3. `pairing-window` — post-reboot (or post-adapter-bounce) continuation active; verifies live `BluetoothGetRadioInfo.szName`, opens `musegadget_win.py pair`, and polls for `<state_dir>/pairing.json`.
  4. `paired-restore-pending` — `<state_dir>/pairing.json` detected; ready to restore original identity and remove continuation task.
  5. `restored` — original name restored from `backup.json` and continuation task removed (`backup.json` retained as an audit record until explicitly cleared).
- **Idempotent `restore`:** Can be invoked from **any** state (`idle`, `renamed-awaiting-reboot`, `pairing-window`, `paired-restore-pending`, `restored`), whether or not pairing succeeded. Reads `backup.json`, restores the original adapter registry `Local Name` and/or `SetComputerNameExW` hostname, unregisters the scheduled task, and transitions to `restored`.

---

## 2. Secondary Mode — Dual-Radio Bridge Hosted on the PC (Fallback)

### When Secondary Mode Is Used

If `preflight` (or live post-apply readback of `BluetoothGetRadioInfo.szName`) shows that neither Path 1A (`adapter-name.ps1`) nor Path 1B (`rename-computer.ps1`) can put the full 16-character `MuseGadget3855D8` on air via the Microsoft WinRT stack, the PC switches to **Secondary Mode**: a dual-radio BLE bridge running **on the PC itself** (`windows/musegadget/pc_bridge_bumble.py`, invoked via `musegadget_pc_bridge.py secondary-run`).

### Concrete Stack Selected: Google Bumble (`bumble`) + Dedicated USB BLE Dongle on the PC

Among the candidate stacks (Bumble + WinUSB dongle, BleuIO AT-serial, BLED112 BGAPI, WSL2 + `usbipd-win` + BlueZ), **Google Bumble (`bumble`, pure-Python BLE host stack speaking raw HCI)** is selected and implemented for the PC-resident secondary driver:

- **Why Bumble over WSL2/BlueZ or proprietary AT/BGAPI:**
  - Runs natively in the PC's Python environment (no Linux VM, no custom WSL2 kernel with `CONFIG_BT`, no `usbipd` attach loop).
  - Full raw control over the 31-byte Legacy Advertising PDU and 31-byte Scan Response PDU, plus the GAP `0x2A00` Device Name attribute — completely bypassing `bthport.sys` and WinRT's `E_INVALIDARG` restriction.
  - Supports both **USB HCI dongles** (`usb:0` or `usb:<vid>:<pid>` via `pyusb`/`libusb` + Zadig WinUSB driver bound to that specific USB dongle only) and **HCI-over-UART serial boards** (`serial:COMx,1000000` — zero driver changes on Windows).
  - Includes an in-process virtual radio (`bumble.link.LocalLink` + `bumble.controller.Controller`) that allows the entire dual-role peripheral+central bridge and `NameBridge` packet forwarding to be tested end-to-end in pytest on Linux without hardware.

### Architecture: PC Talks to Itself Over the Air (Centimetres Apart)

```
Muse Phone App
   │
   │  BLE Link 1 (Front): advertises Complete Local Name "MuseGadget3855D8" (16 chars)
   │  + Manufacturer Data 0xFFFF=0x00 (AdvData, 26 B)
   │  + Complete 128-bit UUID 7fdd3d1c-38ea-46cf-8b46-314ecf5f240c (ScanRsp, 18 B)
   ▼
[USB BLE Dongle on PC — driven by Bumble (pc_bridge_bumble.py)]
   │  Front role: GATT Peripheral (Service 7fdd3d1c…, RX 4d59…, TX d75d…)
   │  Core:       musegadget.ble_bridge.NameBridge (reassembles & re-chunks; opaque payload)
   │  Back role:  GATT Central (scans for "POWERSPEC-G757-" + Service 7fdd3d1c…)
   │
   │  BLE Link 2 (Back, ~10 cm in-room RF): connects to PC's built-in radio
   ▼
[Built-in Realtek Radio on PC — driven by WinRT (musegadget_win.py pair)]
      GattServiceProvider advertising "POWERSPEC-G757-" + 7fdd3d1c…
      SetupController -> PairingSession (v5 ECDH + AES-GCM) -> writes state\pairing.json
```

1. **Built-in Realtek radio stays untouched on the Microsoft WinRT stack:** `python musegadget_win.py pair` runs normally on the PC, opening its WinRT `GattServiceProvider` under `POWERSPEC-G757-`.
2. **USB BLE dongle runs `pc_bridge_bumble.py` on the same PC:**
   - **Front (peripheral):** Configures `device.name = "MuseGadget3855D8"`, registers the setup GATT service (`SERVICE_UUID`, `RX_UUID`, `TX_UUID`), sets `advertising_data` (26 bytes: Flags + Complete Local Name `MuseGadget3855D8` + Manufacturer Data `0xFFFF: 0x00`) and `scan_response_data` (18 bytes: 128-bit setup `SERVICE_UUID`), and starts connectable advertising.
   - **Back (central):** Scans for the PC's built-in radio using `BridgeConfig.target_matches(name=..., address=..., service_uuids=...)` (`POWERSPEC-G757-`), connects over BLE, discovers `SERVICE_UUID`, subscribes to `TX_UUID`, and resolves `RX_UUID`.
   - **Middle (`NameBridge` from `windows/musegadget/ble_bridge.py`):** Unmodified `NameBridge` reassembles incoming framed chunks from the phone (`on_app_write`) and re-chunks them for the back link (`send_to_target`), and vice versa (`on_target_notify` -> `send_to_app`). Disconnects propagate both ways (`on_app_disconnect` / `on_target_disconnect`). Pairing v5 crypto and the SDK token remain strictly end-to-end between the phone and `musegadget_win.py pair`.

### Hardware & Driver Requirements for Secondary Mode

- **Supported USB BLE Dongles:**
  1. **CSR8510 A10 USB dongle** (VID `0A12`, PID `0001`, e.g. Hideez / generic CSR 4.0 dongle): No firmware upload needed; works out of the box with Bumble `usb:0a12:0001` once bound to WinUSB via Zadig.
  2. **Realtek RTL8761B / RTL8761BUV USB 5.0/5.1 dongle** (e.g. ASUS USB-BT500, TP-Link UB500, ZEXMTE): Supported by Bumble's built-in `rtk` driver (`bumble` auto-loads `rtl8761bu_fw.bin` / `rtl8761bu_config.bin` when present in Bumble's firmware dir).
  3. **Any HCI-over-UART USB-serial board (`serial:COMx,1000000`)**: e.g. an nRF52840 USB dongle or Zephyr/ESP-IDF `hci_uart` controller — appears as a standard Windows `COM` port (`usbser.sys`) and needs **no Zadig driver swap**.
- **CRITICAL Windows Zadig Rule (USB HCI dongles only):**
  - Bind **WinUSB** (via Zadig) **ONLY to the external USB dongle's VID:PID**, never to the PC's built-in Realtek adapter. The built-in Realtek adapter must stay on the Windows `BTHUSB` driver so `musegadget_win.py pair` can serve the WinRT GATT peripheral simultaneously.

---

## 3. Rejected Architecture — In-Process WinRT Publisher Loopback

An in-process or second-process WinRT `BluetoothLEAdvertisementPublisher` running on the PC's built-in radio to broadcast `MuseGadget3855D8` alongside `GattServiceProvider` is **rejected and not rebuilt**:

1. **Proven OS policy (`README.md`, live probes 2026-11-01 and 2026-11-03):**
   - Calling `BluetoothLEAdvertisementPublisher.start()` with **any** `advertisement.local_name` (even a 4-character string) or **any** `advertisement.service_uuids` raises `E_INVALIDARG` (`WinError -2147024809`), in both legacy advertising and extended advertising (`adv_probe_ext.py`).
   - Microsoft's `BluetoothLEAdvertisement` documentation explicitly states that Local Name (`0x08` / `0x09`) and Service UUID (`0x02`–`0x07`) AD sections are **system-reserved** and forbidden to `BluetoothLEAdvertisementPublisher`.
2. **Only `GattServiceProvider` can emit the connectable setup service advertisement under WinRT**, and `GattServiceProvider` always populates its Local Name from the Windows Bluetooth stack's local radio name (`IOCTL_BTH_GET_LOCAL_INFO` / `BluetoothGetRadioInfo.szName`). Therefore, on the built-in radio under WinRT, the only way to change the advertised name is to change the local radio/system name (Primary Mode), and the only way to advertise `MuseGadget3855D8` without changing the system/radio name is a second HCI controller bypassing WinRT (Secondary Mode).

---

## Summary of `UNVERIFIED` Hardware Facts (To Be Settled by First PC Run)

| # | Item | Status | How the First Run on the PC Checks It |
|---|---|---|---|
| U1 | Does `PowerSpec-G757`'s current DNS hostname exceed 15 chars while `BluetoothGetRadioInfo.szName` is `POWERSPEC-G757-` (15 chars)? | **UNVERIFIED** (strongly suspected from trailing `-`) | `python windows\musegadget_pc_bridge.py preflight` reads and compares `netbios_name`, `dns_hostname`, and `radio_name` (`BluetoothGetRadioInfo.szName`). |
| U2 | Does Windows 11 + the Realtek driver honour `HKLM\...\Enum\<InstanceId>\Device Parameters\Local Name` (`REG_BINARY`) for a 16-char `MuseGadget3855D8` after a PnP radio bounce (`adapter-name.ps1`), without a reboot? | **UNVERIFIED** | `apply --mode adapter` writes `Local Name`, cycles the radio, and immediately checks `BluetoothGetRadioInfo.szName == "MuseGadget3855D8"`. |
| U3 | If Path 1B (`SetComputerNameExW(ComputerNamePhysicalDnsHostname, "MuseGadget3855D8")` + reboot) is used, does `bthport.sys` advertise the 16-char DNS hostname or the 15-char NetBIOS name (`MuseGadget3855D`)? | **UNVERIFIED** | Checked pre-rename by U1 (if DNS > 15 chars today) and post-reboot by `musegadget_pc_bridge.py status` / `preflight` reading `BluetoothGetRadioInfo.szName`. |
| U4 | Does the PC's WinRT `GattServiceProvider` accept an incoming BLE GATT connection and complete `SetupController` pairing? | **UNVERIFIED** (zero connections have ever reached the PC) | Exercised on pairing day as soon as either Primary Mode (phone connects directly) or Secondary Mode (Bumble dongle connects as back-central) connects to `7fdd3d1c-38ea-46cf-8b46-314ecf5f240c`. |
