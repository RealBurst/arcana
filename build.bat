@echo off
setlocal

if "%~1"=="" goto :usage

set "ROOT=%~dp0"
if not exist "%ROOT%VERSION" goto :no_version
set "ARCANA_VERSION="
set /p ARCANA_VERSION=<"%ROOT%VERSION"
for /f "tokens=* delims= " %%V in ("%ARCANA_VERSION%") do set "ARCANA_VERSION=%%V"
if not defined ARCANA_VERSION goto :no_version
set "ARCANA_JAR=%ROOT%jar\Arcana-v%ARCANA_VERSION%.jar"

if /i "%~1"=="arcana" goto :build_arcana
if /i "%~1"=="all" goto :build_all
goto :build_plugin

:no_version
echo ERROR: file "%ROOT%VERSION" missing or empty (expected content: 1.0.0)
exit /b 1

:usage
echo Usage: build.bat [arcana ^| plugin-pak ^| plugin-upx ^| all]
exit /b 1

:build_plugin
set "PLUGIN_NAME=arcana-%~1"
set "PLUGIN_DIR=%ROOT%plugins\%PLUGIN_NAME%"
if not exist "%PLUGIN_DIR%" goto :plugin_not_found
call :do_build_plugin "%PLUGIN_DIR%" "%PLUGIN_NAME%"
goto :end

:plugin_not_found
echo ERROR: plugin directory not found: %PLUGIN_DIR%
exit /b 1

:build_all
call :do_build_arcana
if errorlevel 1 goto :end
for /d %%D in ("%ROOT%plugins\arcana-plugin-*") do call :do_build_plugin "%%D" "%%~nxD"
goto :end

:build_arcana
call :do_build_arcana
goto :end

rem ---------------------------------------------------------------------------
rem Build arcana.jar from src\ into bin\
rem ---------------------------------------------------------------------------
:do_build_arcana
echo Building Arcana v%ARCANA_VERSION%...
set "BIN=%ROOT%bin"
if exist "%BIN%" rmdir /s /q "%BIN%"
mkdir "%BIN%"
set "SRCLIST=%TEMP%\arcana_sources.txt"
if exist "%SRCLIST%" del /f /q "%SRCLIST%"
for /r "%ROOT%src" %%F in (*.java) do call :write_path "%%F" "%SRCLIST%"
javac -Xlint:-options -source 8 -target 8 -d "%BIN%" @"%SRCLIST%"
if errorlevel 1 exit /b 1
del /f /q "%SRCLIST%"
if not exist "%ROOT%jar" mkdir "%ROOT%jar"
echo Main-Class: be.stef.arcana.Arcana> "%TEMP%\arcana_manifest.txt"
echo Implementation-Title: Arcana>> "%TEMP%\arcana_manifest.txt"
echo Implementation-Version: %ARCANA_VERSION%>> "%TEMP%\arcana_manifest.txt"
echo Implementation-Vendor: Stephane Bury>> "%TEMP%\arcana_manifest.txt"
jar cfm "%ARCANA_JAR%" "%TEMP%\arcana_manifest.txt" -C "%BIN%" .
if errorlevel 1 exit /b 1
del /f /q "%TEMP%\arcana_manifest.txt"
echo Done: %ARCANA_JAR%
exit /b 0

rem ---------------------------------------------------------------------------
rem Build one plugin: %1 = plugin directory, %2 = plugin name
rem ---------------------------------------------------------------------------
:do_build_plugin
set "PDIR=%~1"
set "PNAME=%~2"
set "PBIN=%PDIR%\bin"
set "PJAR=%PDIR%\jar\%PNAME%.jar"
echo Building %PNAME%...

set "ARCANA_CP="
if exist "%ROOT%bin\be\stef\arcana\Arcana.class" set "ARCANA_CP=%ROOT%bin"
if not defined ARCANA_CP if exist "%ARCANA_JAR%" set "ARCANA_CP=%ARCANA_JAR%"
if not defined ARCANA_CP goto :no_arcana
echo Classpath: %ARCANA_CP%

if exist "%PBIN%" rmdir /s /q "%PBIN%"
mkdir "%PBIN%"
set "SRCLIST=%TEMP%\plugin_sources.txt"
if exist "%SRCLIST%" del /f /q "%SRCLIST%"
for /r "%PDIR%\src" %%F in (*.java) do call :write_path "%%F" "%SRCLIST%"
javac -Xlint:-options -source 8 -target 8 -cp "%ARCANA_CP%" -d "%PBIN%" @"%SRCLIST%"
if errorlevel 1 exit /b 1
del /f /q "%SRCLIST%"

xcopy /e /q /y "%PDIR%\src\." "%PBIN%\" >nul
if exist "%PDIR%\META-INF" xcopy /e /q /y "%PDIR%\META-INF\." "%PBIN%\META-INF\" >nul
if not exist "%PDIR%\jar" mkdir "%PDIR%\jar"
if exist "%PBIN%\META-INF\MANIFEST.MF" (jar cfm "%PJAR%" "%PBIN%\META-INF\MANIFEST.MF" -C "%PBIN%" .) else (jar cf "%PJAR%" -C "%PBIN%" .)
if errorlevel 1 exit /b 1
echo Done: %PJAR%
exit /b 0

:no_arcana
echo ERROR: Arcana classes not found. Expected "%ROOT%bin" or "%ARCANA_JAR%".
exit /b 1

rem ---------------------------------------------------------------------------
rem Append one source path to the javac @file: quoted, with forward slashes
rem (inside quotes javac treats backslash as an escape character)
rem ---------------------------------------------------------------------------
:write_path
set "FPATH=%~1"
set "FPATH=%FPATH:\=/%"
echo "%FPATH%">> "%~2"
exit /b 0

:end
endlocal
