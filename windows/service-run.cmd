@echo off
rem Muse Gadget service runner — launched by the MuseGadgetService
rem scheduled task (see install-service.ps1). Runs the paired gadget in
rem steady state and appends its log to service.log beside this file.
cd /d "%~dp0.."
"%~dp0..\venv\Scripts\python.exe" -u musegadget_win.py run >> "%~dp0..\service.log" 2>&1
