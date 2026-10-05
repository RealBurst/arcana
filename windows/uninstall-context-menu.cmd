@echo off
rem Removes the Arcana entries from the Explorer context menu (current user).
for %%K in (Arcana1Unpack Arcana2List Arcana3Info) do reg delete "HKCU\Software\Classes\*\shell\%%K" /f >nul 2>&1
echo Arcana entries removed from the Explorer context menu.
pause
