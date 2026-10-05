@echo off
rem Arcana - launcher used by the Windows Explorer context menu.
rem Usage: arcana-explorer.cmd <x|l|i> <file>
rem   x: extracts <file> into "<folder of file>\<name without extension>_extracted"
rem      (then _extracted_2, _extracted_3... if the folder already exists)
rem   l: lists the content of <file>
rem   i: identifies <file>
rem The Arcana jar (Arcana-v*.jar) must be in the same folder as this script;
rem plugins go in the "plugins" folder next to it or in %USERPROFILE%\.arcana\plugins.
setlocal
title Arcana
set "ARCANA_HOME=%~dp0"
set "JAR="
for %%J in ("%ARCANA_HOME%Arcana-v*.jar") do set "JAR=%%~fJ"
if not defined JAR (
    echo Arcana jar not found in "%ARCANA_HOME%"
    pause
    exit /b 1
)
set "JAVA=java"
if defined JAVA_HOME if exist "%JAVA_HOME%\bin\java.exe" set "JAVA=%JAVA_HOME%\bin\java.exe"
if "%~2"=="" (
    echo Usage: %~nx0 ^<x^|l^|i^> ^<file^>
    pause
    exit /b 1
)
if /i "%~1"=="x" goto unpack

rem The output goes through a file so that an empty result still shows a message
set "OUTFILE=%TEMP%\arcana-%RANDOM%%RANDOM%.txt"
"%JAVA%" -jar "%JAR%" %~1 "%~f2" > "%OUTFILE%" 2>&1
chcp 1252 >nul
for %%A in ("%OUTFILE%") do if %%~zA==0 echo Nothing here: Arcana has nothing to show for "%~nx2".
type "%OUTFILE%"
del /f /q "%OUTFILE%" >nul 2>&1
echo.
pause
exit /b

:unpack
set "BASE=%~dp2%~n2_extracted"
set "DEST=%BASE%"
set N=1
:check
if not exist "%DEST%" goto run
set /a N+=1
set "DEST=%BASE%_%N%"
goto check
:run
"%JAVA%" -jar "%JAR%" x "%~f2" -o "%DEST%"
if errorlevel 1 (
    echo.
    echo Extraction failed.
    pause
    exit /b 1
)
echo.
echo Extracted to "%DEST%"
timeout /t 5
exit /b 0
