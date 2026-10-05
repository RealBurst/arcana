@echo off
rem Adds "Arcana Unpack ...", "Arcana List ..." and "Arcana Info ..." to the
rem context menu of every file in Windows Explorer (current user only, no
rem administrator rights needed). Run it again after moving the Arcana folder.
rem On Windows 11 the entries are under "Show more options" (or Shift+F10).
setlocal
set "LAUNCHER=%~dp0arcana-explorer.cmd"
if not exist "%LAUNCHER%" (
    echo "%LAUNCHER%" not found: keep this script next to arcana-explorer.cmd.
    pause
    exit /b 1
)
call :add Arcana1Unpack "Arcana Unpack ..." x || goto failed
call :add Arcana2List "Arcana List ..." l || goto failed
call :add Arcana3Info "Arcana Info ..." i || goto failed
echo Arcana entries added to the Explorer context menu.
pause
exit /b 0

:failed
echo Could not write the registry entries.
pause
exit /b 1

:add
reg add "HKCU\Software\Classes\*\shell\%~1" /v MUIVerb /d "%~2" /f >nul || exit /b 1
reg add "HKCU\Software\Classes\*\shell\%~1\command" /ve /d "\"%LAUNCHER%\" %~3 \"%%1\"" /f >nul || exit /b 1
exit /b 0
