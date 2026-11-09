# Broadcast-Only PC Bridge — Investigation Checkpoint

**Started:** 2026-11-08 22:50 EST  
**Resumed:** 2026-11-09 00:30 EST

## Status Overview
- [x] Read `BROADCAST-AGY-BRIEF.md` & `BROADCAST-RESUME-BRIEF.md`
- [x] Read `PC-BRIDGE-REPORT.md`, `PC-BRIDGE.md`, `local-rea` skill
- [x] Verify PC SSH lane & copy target Windows binaries into `hidden_files/rea-quarantine/` (completed 2026-11-08 22:51–23:08 EST)
  - Original binaries in `hidden_files/rea-quarantine/bins/`: `BTHport.sys`, `BTHUSB.sys`, `BthEnum.sys`, `Microsoft.Bluetooth.Legacy.LEEnumerator.sys`, `bthserv.dll`, `BluetoothApis.dll`, `Windows.Devices.Bluetooth.dll`, `Windows.Internal.Devices.Bluetooth.dll`, `Microsoft.Bluetooth.Service.dll`, `Microsoft.Bluetooth.UserService.dll`, `Microsoft.Bluetooth.Proxy.dll`, `BthRadioMedia.dll`, `dafBth.dll`, `bthci.dll`, `wshbth.dll`, `RtkBtfilter2.sys`, `RtkBtManServ.exe`, `rtkfilter.inf`, `sha256sums.txt`
  - Existing PC probes in `hidden_files/rea-quarantine/probes/`: `adv2.py`, `adv_probe.py`, `adv_probe2.py`, `adv_probe3.py`, `adv_probe_ext.py`, `btname.py`
  - Disassembly & `.rdata` dumps in `hidden_files/rea-quarantine/`: `BTHport.asm`, `BluetoothApis.asm` (+ `.rdata`), `LEEnumerator.asm`, `Microsoft.Bluetooth.Service.asm`, `Windows.Devices.Bluetooth.asm`, `Windows.Internal.Devices.Bluetooth.asm`, `RtkBtManServ.asm` (+ `.rdata`), `RtkBtfilter2.asm` (+ `.rdata`), `bthci.asm` (+ `.rdata`), `bthserv.asm`, `pe_inventory.json`, `lanes_summary.txt`
- [x] L1 — `bthport.sys` / `bthserv.dll` IOCTL & BRB surface analysis (verdict: `not viable` under runtime-only non-persistent bounds — documented in `BROADCAST-RE.md`)
- [x] L2 — `bluetoothapis.dll` exports & `Local Name` reader analysis (verdict: `not viable` under runtime-only non-persistent bounds — documented in `BROADCAST-RE.md`)
- [ ] L3 — `Windows.Devices.Bluetooth.dll` WinRT internals & RPC/BthServ boundary analysis
- [ ] L4 — Realtek `VID_0BDA&PID_B850` vendor driver & service (`RtkBtManServ` / `RtkBtfilter2`) surface
- [ ] L5 — Runtime HCI Write Local Name / LE Advertising Data assessment
- [ ] L6 — Additional binary surfaces (BthLEEnum, BthServ RPC endpoints, etc.)
- [ ] Write `BROADCAST-RE.md` (REA evidence dossier — incrementally per lane)
- [ ] If viable lane found: Craft Anything loop + `windows/broadcast/` + live runtime-only probe
- [ ] Write `BROADCAST-REPORT.md`

## CLOSED 2026-11-09 01:20 EST — superseded by owner order
Jonathan: "Wait just modify the sdk." L3–L6 not pursued. The name
translation was folded into the Windows SDK port itself
(`ble_server_windows.py` applies/restores the adapter Local Name around
the setup window via `pc_bridge`); a full live window cycle on the real
PC (apply + radio read-back `MuseGadget-3855D8` + advertising + timeout
+ verified restore) passed 2026-11-09 01:27–01:38 EST. L1/L2 verdicts in
`BROADCAST-RE.md` stand as the evidence base. No BROADCAST-REPORT.md
will be written; this note replaces it.
