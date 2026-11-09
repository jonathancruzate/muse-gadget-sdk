# `BROADCAST-RE.md` — Windows 11 BLE Local-Name Runtime Broadcast Reverse-Engineering Dossier

## 1. Investigation Scope & Target Environment

- **Target PC:** `PowerSpec-G757-5640` (Windows 11 x64, build 26100 / 24H2 family, user `jonat`, local administrator session)
- **Target Bluetooth Adapter:** Realtek Bluetooth 5.4 USB Adapter
  - PnP Instance ID: `USB\VID_0BDA&PID_B850\00E04C000001`
  - Service / Filter Driver: `BTHUSB` + upper filter `RtkBtFilter` (`RtkBtfilter2.sys`)
- **Target Broadcast Identity:**
  - Pairing BLE Local Name: `MuseGadget-3855D8` (17 ASCII bytes, derived from BD_ADDR `38:55:D8` suffix)
  - Setup Primary Service UUID: `7fdd3d1c-38ea-46cf-8b46-314ecf5f240c`
  - Setup RX Characteristic UUID: `4d593029-28a2-4a6e-a1f0-3c2d5e8f9b01`
  - Setup TX Characteristic UUID: `d75dc4ca-7b2b-4e9c-8f0a-1d2e3f4a5b6c`
- **Hard Operational Bounds (`BROADCAST-AGY-BRIEF.md`):**
  1. **No computer rename** (`Rename-Computer`, `SetComputerNameEx`, `NV Hostname`, `Hostname` are forbidden).
  2. **No persistent registry identity writes** (the `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_0BDA&PID_B850\00E04C000001\Device Parameters\Local Name` registry path documented in `PC-BRIDGE.md` is the already-built persistent fallback and is **out of scope** for this runtime-only investigation).
  3. **No driver swap / Zadig / WinUSB replacement** (`BTHUSB` + `BTHport.sys` must remain bound so the Windows Bluetooth stack stays operational).
  4. **No reboot, no ESP32 reflash.**

---

## 2. Quarantined Binary Inventory

All target binaries were pulled from `C:\Windows\System32\` and `C:\Windows\System32\drivers\` on `PowerSpec-G757-5640` into `hidden_files/rea-quarantine/bins/` and disassembled into `hidden_files/rea-quarantine/*.asm` and `*.rdata`.

| Binary | Original Windows Path | Size (Bytes) | ImageBase | SHA-256 |
|---|---|---:|---|---|
| `BTHport.sys` | `C:\Windows\System32\drivers\BTHport.sys` | 2,326,528 | `0x140000000` | `c71802406150c2b4c8f73904d16780bf6a47ee84149f1c16d9e83d8ebd98dc53` |
| `BTHUSB.sys` | `C:\Windows\System32\drivers\BTHUSB.sys` | 143,360 | `0x140000000` | `48cdc1d7b42207c59d096946577ae9d37adf806bf9cc7cc9acf2f8a3e2739342` |
| `BthEnum.sys` | `C:\Windows\System32\drivers\BthEnum.sys` | 147,456 | `0x140000000` | `c283ce9d50983d011d6263dfc087617854ae978748f5ffc8c89eb583577daa7e` |
| `Microsoft.Bluetooth.Legacy.LEEnumerator.sys` | `C:\Windows\System32\drivers\Microsoft.Bluetooth.Legacy.LEEnumerator.sys` | 159,744 | `0x140000000` | `e64d6e809ed0d425efcf6c17dadfb3f29f1538e730c64a9c4e19030190cd0009` |
| `RtkBtfilter2.sys` | `C:\Windows\System32\drivers\RtkBtfilter2.sys` | 200,520 | `0x140000000` | `dd7e986e5c06a1536a9169d2b126ba0cf595ac6497d0da79caa5b4505a015b5b` |
| `RtkBtManServ.exe` | `C:\Windows\System32\RtkBtManServ.exe` | 300,624 | `0x140000000` | `4f8a5fea79353620a32644183799351485ca9d169df0941154f637ab984de680` |
| `bthserv.dll` | `C:\Windows\System32\bthserv.dll` | 311,296 | `0x180000000` | `de7ced84d3bad48f0e472349c7810615054af823f2afe8832f76770841b6954e` |
| `BluetoothApis.dll` | `C:\Windows\System32\BluetoothApis.dll` | 241,664 | `0x180000000` | `8b1738e6e6a13425a7994c362d975b0cbce706e79dce5e3598db29dde6eff9cd` |
| `bthci.dll` | `C:\Windows\System32\bthci.dll` | 122,880 | `0x180000000` | `453ad1963cf0e69d8cf7e1aaf23160c22dd095f8f998fcd08d47c9e99b8d18cb` |
| `Windows.Devices.Bluetooth.dll` | `C:\Windows\System32\Windows.Devices.Bluetooth.dll` | 1,986,560 | `0x180000000` | `278054e325c6ce3832a75c774c8c6d9108b1a8f7a57b98e063cf8d881d9ededa` |
| `Windows.Internal.Devices.Bluetooth.dll` | `C:\Windows\System32\Windows.Internal.Devices.Bluetooth.dll` | 540,672 | `0x180000000` | `919058745a6051a39f0eff17d2e83a4841f1b9981b76ff88750bb42f60cce846` |
| `Microsoft.Bluetooth.Service.dll` | `C:\Windows\System32\Microsoft.Bluetooth.Service.dll` | 3,780,608 | `0x180000000` | `5f6d195b5ebf593299198bcfa4d12c8a689d4cad8be85d8782aa7d38b2d48827` |
| `Microsoft.Bluetooth.UserService.dll` | `C:\Windows\System32\Microsoft.Bluetooth.UserService.dll` | 577,536 | `0x180000000` | `051c9d50868b2d58a8afae1018e3f8ead7bd8a53b170e96284e48b1876903786` |
| `Microsoft.Bluetooth.Proxy.dll` | `C:\Windows\System32\Microsoft.Bluetooth.Proxy.dll` | 307,200 | `0x180000000` | `09777dcb9f0b16a406b010df5411381c736717a814cdc4beb84edce5144e815c` |
| `BthRadioMedia.dll` | `C:\Windows\System32\BthRadioMedia.dll` | 139,264 | `0x180000000` | `838bc44cdfac5a171cecd377da89b2d1fe766febd10fb41d815aada15035dbbc` |
| `dafBth.dll` | `C:\Windows\System32\dafBth.dll` | 434,176 | `0x180000000` | `50e274cf82e5257db1ef321b2253a65c2f0e01d0ad67f8ea1b2012ef37e9bf00` |
| `wshbth.dll` | `C:\Windows\System32\wshbth.dll` | 90,112 | `0x180000000` | `0901e63e200fd5d28aded604e65f0a7456a8d96757dbe7efa5ea8c69be771fe5` |

---

## 3. Lane-by-Lane Reverse-Engineering Evidence

### Lane 1 (L1) — `bthport.sys` / `bthserv.dll` IOCTL & BRB Surface

#### Hypothesis
Can a user-mode process open the Bluetooth radio device interface (`GUID_BTHPORT_DEVICE_INTERFACE` / `\\.\BthPort` / radio symbolic link) and issue a user-mode `DeviceIoControl` or BRB (`IOCTL_INTERNAL_BTH_SUBMIT_BRB`) or call a `bthserv.dll` RPC/service routine that sets the controller or BLE GAP Local Name **purely in memory at runtime** without writing to the registry?

#### Static Evidence (`BTHport.sys`, `bthserv.dll`, `bthci.dll`)

1. **User-mode `IRP_MJ_DEVICE_CONTROL` vs. Kernel-only `IRP_MJ_INTERNAL_DEVICE_CONTROL` (`BTHport.sys`):**
   - In `BTHport.sys` (SHA-256 `c7180240...`), IRP dispatch distinguishes `IRP_MJ_DEVICE_CONTROL` (`MajorFunction == 0x0E`) from `IRP_MJ_INTERNAL_DEVICE_CONTROL` (`MajorFunction == 0x0F`, see check at VA `0x14002994b`–`0x140029965`: `cmp al, 0xe` vs `cmp al, 0xf; cmp DWORD PTR [rdx+0x18], 0x410003`).
   - `IOCTL_INTERNAL_BTH_SUBMIT_BRB` (`0x00410003`) and `0x00411003` are **only** dispatched inside the `IRP_MJ_INTERNAL_DEVICE_CONTROL` handler at VA `0x14001e5c6`–`0x14001e61a` (file offset `0x01d9c6`–`0x01da1a`):
     ```
     14001e5c6: mov rdx, QWORD PTR [rdi+0xb8]   ; CurrentStackLocation
     14001e5cd: mov eax, DWORD PTR [rdx+0x18]   ; IoControlCode
     14001e5d0: cmp eax, 0x410003               ; IOCTL_INTERNAL_BTH_SUBMIT_BRB
     14001e5d5: je  0x14001e611
     14001e5d7: cmp eax, 0x411003
     14001e5dc: je  0x14001e5e5
     14001e5de: mov ebx, 0xc0000010             ; STATUS_INVALID_DEVICE_REQUEST
     ```
   - User-mode `DeviceIoControl` generates `IRP_MJ_DEVICE_CONTROL` (`0x0E`), which enters `BTHport.sys` at VA `0x14001d2a0` (file offset `0x01c6a0`). Passing `0x00410003` via user-mode `DeviceIoControl` hits the `< 0x00410410` branch (`0x14001d358`) and is rejected with `STATUS_INVALID_DEVICE_REQUEST` (`0xC0000010`) at VA `0x14001e35b`.

2. **Full Audit of `BTHport.sys` User-Mode `IRP_MJ_DEVICE_CONTROL` Dispatch Table (`0x14001d2a0`–`0x14001e500`):**
   - `0x00410000` (`IOCTL_BTH_GET_LOCAL_INFO`, VA `0x14001d47e` -> `0x14011ff60`): **Read-only.** Copies `0x124` (292) bytes of cached local radio info (`BTH_LOCAL_RADIO_INFO`, including the cached 248-byte UTF-8 name at controller offset `+0x130`) to `Irp->AssociatedIrp.SystemBuffer`.
   - `0x00410940` (`IOCTL_BTH_HCI_VENDOR_COMMAND`, VA `0x14001d35f` -> `0x14001d3ee` -> `0x1400b4564`, file offset `0x0b3964`):
     - Checks `SeLoadDriverPrivilege` (`call 0x14001ceb8` at VA `0x1400b458f`; returns `0xC0000061` `STATUS_PRIVILEGE_NOT_HELD` if not enabled).
     - Checks `Manufacturer` and `LmpSubVersion` header fields (`0x1400b466e`–`0x1400b4688`).
     - **Enforces Vendor-Specific OGF (`0x3F`) mask (`0xFC00`)** at VA `0x1400b4702`–`0x1400b471d` (file offset `0x0b3b02`–`0x0b3b1d`):
       ```
       1400b4702: movzx r8d, WORD PTR [r14+0x6]  ; HCI command opcode
       1400b470e: mov   ecx, 0xfc00              ; OGF == 0x3F mask
       1400b4713: movzx eax, r8w
       1400b4717: and   ax, cx
       1400b471a: cmp   ax, cx
       1400b471d: je    0x1400b476a              ; allow ONLY if (opcode & 0xFC00) == 0xFC00
       ```
     - Any non-vendor HCI opcode (such as `HCI_Write_Local_Name` `0x0C13` or `HCI_LE_Set_Advertising_Data` `0x2008`) fails `(opcode & 0xFC00) == 0xFC00` and is rejected with `STATUS_INVALID_PARAMETER` (`0xC000000D`).
   - `0x00411008` (Undocumented Radio Registry Reload IOCTL, VA `0x14001d672` -> `0x1401d4844`, file offset `0x1d3c44`):
     - Accepts **only** a 4-byte `DWORD` bitmask in `Irp->AssociatedIrp.SystemBuffer` (`[r14+0x18]` at VA `0x14001d67b`), validating `(flags | 0x3fff) == 0x3fff` (`0x14001d6d1`).
     - In `0x1401d4844`, opens the adapter's PnP `Device Parameters` registry key (`call 0x1401baf8c` at VA `0x1401d490d`) and iterates the handler table at VA `0x14016fdd0`–`0x14016fe70` (file offset `0x16f1d0`).
     - Flag bit `0x4` (table entry at VA `0x14016fde0`) invokes `0x1401d0730` (file offset `0x1cfb30`), which queries `L"Local Name"` (string at VA `0x140181818`, loaded at VA `0x1401d07f4`) from the adapter's `Device Parameters` registry key (`call 0x14020b5a4` at VA `0x1401d07fe`, max `0xf8` = 248 bytes).
     - If `Device Parameters\Local Name` is absent (`eax < 0` at VA `0x1401d0803`), `0x1401d0730` falls back to the cached NetBIOS computer name at `[rdi+0x24]`.
     - If `r15b == 1` (runtime reload via `IOCTL 0x00411008`), `0x1401d0730` calls `0x1401d51a4` at VA `0x1401d08e1`, which sends `HCI_Write_Local_Name` (`0x0C13`) to the controller.
     - **Why this cannot satisfy the non-persistent bound:** `IOCTL 0x00411008` does **not** accept a name string in its input buffer; its input buffer is strictly a 4-byte flag mask (`0x00000004`), and `0x1401d0730` unconditionally reads the name from the persistent `Device Parameters\Local Name` registry value.
   - `0x0041104c` (`BluetoothSetLocalServiceInfo` IOCTL, VA `0x14001db13` -> `0x140120f20` -> `0x1401e7fbc`):
     - Creates/updates a child PnP PDO (`BTHENUM\{ServiceGuid}...`) for a registered host service driver. Never modifies `[rdi+0x130]` (radio local name), EIR, or BLE GAP advertising data.

3. **`bthserv.dll` Surface (`de7ced84...`):**
   - Disassembly of `bthserv.dll` shows it issues `IOCTL_BTH_GET_LOCAL_INFO` (`0x00410000`) at VAs `0x18000c062`, `0x18001cc93`, and `0x180024269` to read local radio state, and never calls `0x00411008` or any local-name-setting IOCTL. Its RPC handlers manage pairing/SDP cache/inquiry state, not the local adapter name.

#### Verdict for Lane 1: **`not viable` (under runtime-only non-persistent bounds)**
- **Why:** `BTHport.sys` has **no** user-mode IOCTL that accepts an in-memory local name string. The only IOCTL that triggers a runtime `Local Name` update (`IOCTL 0x00411008` with `flags = 0x4`) takes only a 4-byte bitmask and forces `BTHport.sys` (`0x1401d0730`) to read `Device Parameters\Local Name` from the registry. `IOCTL_INTERNAL_BTH_SUBMIT_BRB` (`0x00410003`) is blocked from user mode (`IRP_MJ_INTERNAL_DEVICE_CONTROL` only), and `IOCTL_BTH_HCI_VENDOR_COMMAND` (`0x00410940`) enforces `(opcode & 0xFC00) == 0xFC00` at VA `0x1400b470e`.

---

### Lane 2 (L2) — `BluetoothApis.dll` Exports & `Local Name` Reader/Writer (`bthci.dll`)

#### Hypothesis
Does `BluetoothApis.dll` (or its companion class installer `bthci.dll`) expose any documented or undocumented Win32 API (`BluetoothSetLocalServiceInfo`, `BluetoothUpdateDeviceRecord`, etc.) that sets the local radio name or BLE GAP name at runtime without persistent registry writes?

#### Static Evidence (`BluetoothApis.dll`, `bthci.dll`)

1. **Exhaustive Export & IOCTL Audit of `BluetoothApis.dll` (SHA-256 `8b1738e6...`):**
   - `BluetoothGetRadioInfo` (RVA `0x8d80`, VA `0x180008d80`): Calls `DeviceIoControl(hRadio, 0x00410000, ...)` (`IOCTL_BTH_GET_LOCAL_INFO`) and converts the returned UTF-8 radio name at offset `+0x10` of `BTH_RADIO_INFO` into UTF-16 `BLUETOOTH_RADIO_INFO.szName`. Read-only.
   - `BluetoothSetLocalServiceInfo` (RVA `0x1c1a0`, VA `0x18001c1a0`, file offset `0x1b5a0`):
     - Calls helper `0x180018f20` (`0x18001c24b`), which opens `HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Services\{ServiceGuid}` (`0x18002c0a0` / `0x180019003`) to verify the service GUID is registered in `HKLM`.
     - Sends `IOCTL 0x0041104c` (`mov edx, 0x41104c` at VA `0x18001c27a`, input size `0x422` = 1,058 bytes) to `hRadio`.
     - As proven in L1 (`BTHport.sys` VA `0x140120f20` -> `0x1401e7fbc`), `0x0041104c` requires `SeLoadDriverPrivilege` (`0xC0000061`) for arbitrary GUIDs, requires a pre-existing `HKLM\...\Services\{GUID}` registry key, and only sets the PnP PDO description on a `BTHENUM` child devnode—not the radio or BLE local name.
   - `BluetoothUpdateDeviceRecord` (RVA `0x1c510`, VA `0x18001c510`): Calls `IOCTL 0x0041002c` (`0x18001c59c`), which updates the cached friendly name of a **remote** peer `BTH_ADDR` in `BTHport.sys`, not the local radio.
   - `BluetoothEnableDiscovery` (VA `0x1800014b0` -> `IOCTL 0x00410018`) and `BluetoothEnableIncomingConnections` (VA `0x180019f90` -> `IOCTL 0x00410014`): Toggle BR/EDR inquiry scan and page scan (`HCI_Write_Scan_Enable`).
   - There is **no** `BluetoothSetRadioInfo` or `BluetoothSetLocalName` export in `BluetoothApis.dll`.

2. **How Windows Actually Sets `Local Name` (`bthci.dll`, SHA-256 `453ad196...`):**
   - `bthci.dll` (`drivers\wdm\bluetooth\user\bthci\proppage.cpp`, string at VA `0x18000bfc0`) implements the Device Manager "Advanced" property page for the Bluetooth radio at VA `0x180005e00`–`0x180006044` (file offset `0x05200`–`0x05444`):
     - Reads the user-edited radio name from dialog control ID `0x961` (`GetDlgItem` at VA `0x180005e55`, `GetWindowTextW` at VA `0x180005e98`).
     - Compares it against `GetComputerNameW` (`0x180005eb6`).
     - Writes `L"Local Name"` (VA `0x18000bfe0`) as `REG_BINARY` (`r9d = 3`) UTF-8 bytes into the adapter's PnP `Device Parameters` registry key via `RegSetValueExW` at VA `0x180005f78` (or deletes it via `RegDeleteValueW` at VA `0x180005efb` if equal to `GetComputerNameW`).
     - Sets `DWORD [rsp+0x40] |= 0x4` (`0x180005f84`) and calls `DeviceIoControl(hRadio, 0x00411008, &flags, 4, NULL, 0, &bytesRet, NULL)` at VA `0x180005ffe`–`0x180006006`:
       ```
       180005ffe: lea r8, [rsp+0x40]              ; &flags (0x00000004)
       180006003: mov edx, 0x411008               ; IOCTL 0x00411008
       180006008: mov rcx, rdi                    ; hRadio
       18000600b: call QWORD PTR [rip+0x83cf]     ; DeviceIoControl
       ```
   - This proves that even Microsoft's own first-party UI (`bthci.dll`) has no in-memory API to set the radio name: it **must** write `Device Parameters\Local Name` to the registry first and then send `IOCTL 0x00411008` (`flags = 0x4`) so `BTHport.sys` reloads the registry value.

#### Verdict for Lane 2: **`not viable` (under runtime-only non-persistent bounds)**
- **Why:** `BluetoothApis.dll` has no function that sets the local radio or BLE GAP name, and `bthci.dll` (`0x180005e00`) proves that Windows' own mechanism requires writing `Device Parameters\Local Name` to the registry before invoking `IOCTL 0x00411008` (`flags = 0x4`).
