@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Lists the most frequent strings in a JFR recording as a table.
rem Usage: scripts\demo.bat [recording.jfr^|-] [number of strings, default 30] [occurrences^|references^|inlined^|length]
rem        scripts\demo.bat [number of strings, default 30] [occurrences^|references^|inlined^|length]
rem Defaults to the included WebLogic (WLDF) MedRec recording, sorted by occurrences.
rem Use - to select the included recording explicitly.
rem Uses target\jfr-redact.exe if built, otherwise the jar, building it if missing.

if not "%~4"=="" goto usage
rem Check for a quoted empty fourth argument too.
if not "%4"=="" goto usage

for %%I in ("%~dp0..") do set "PROJECT_DIR=%%~fI"
set "RECORDING=%~1"
set "TOP=%~2"
set "SORT=%~3"
if not defined RECORDING goto recording_args
if exist "%RECORDING%" goto recording_args
if not "%~3"=="" goto recording_args
if not "%3"=="" goto recording_args
set RECORDING | "%SystemRoot%\System32\findstr.exe" /r /x /c:"RECORDING=[0-9][0-9]*" >nul
if errorlevel 1 goto recording_args
set "TOP=%~1"
set "SORT=%~2"
set "RECORDING="

:recording_args
if "%RECORDING%"=="-" set "RECORDING="
if not defined RECORDING set "RECORDING=%PROJECT_DIR%\src\test\resources\recordings\jdk9-weblogic-medrec.jfr"
if not defined TOP set "TOP=30"
if not defined SORT set "SORT=occurrences"
set "NATIVE=%PROJECT_DIR%\target\jfr-redact.exe"

if exist "%NATIVE%" goto run_native

call :find_jar
if defined JAR goto run_jar

echo No native image or jar found, building the jar... 1>&2
call mvn -q -B -f "%PROJECT_DIR%\pom.xml" -DskipTests package 1>&2
if errorlevel 1 exit /b %errorlevel%
call :find_jar
if defined JAR goto run_jar
echo No jfr-redact jar found after building. 1>&2
exit /b 1

:run_native
"%NATIVE%" scan --table --top "%TOP%" --sort "%SORT%" "%RECORDING%"
exit /b %errorlevel%

:run_jar
java -jar "%JAR%" scan --table --top "%TOP%" --sort "%SORT%" "%RECORDING%"
exit /b %errorlevel%

:find_jar
set "JAR="
for %%J in ("%PROJECT_DIR%\target\jfr-redact-*.jar") do if not defined JAR if exist "%%~fJ" set "JAR=%%~fJ"
exit /b 0

:usage
echo Usage: %~nx0 [recording.jfr^|-] [number of strings, default 30] [occurrences^|references^|inlined^|length] 1>&2
echo        %~nx0 [number of strings, default 30] [occurrences^|references^|inlined^|length] 1>&2
exit /b 2
