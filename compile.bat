@echo off
REM ============================================================================
REM  DisasmStudio -- one-click recompile of the app (release + debug).
REM  Run from anywhere: double-click, or `compile.bat` in a terminal.
REM ============================================================================
setlocal EnableExtensions
cd /d "%~dp0"

echo(
echo === DisasmStudio recompile ===
echo(

REM --- libclang for the C++ analysis bridge (engine/analysis/*.cpp) ---
set "LIBCLANG_PATH=%LOCALAPPDATA%\disasmstudio-tools\LLVM\bin"
if not exist "%LIBCLANG_PATH%\libclang.dll" (
    echo [!] libclang.dll not found at %LIBCLANG_PATH%
    echo     The C++ bridge will fail to build. Adjust LIBCLANG_PATH in this file.
    echo(
)

REM --- cargo on PATH ---
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
where cargo >nul 2>&1 || (
    echo [x] cargo not found. Install Rust from https://rustup.rs and re-run.
    exit /b 1
)

REM --- kill stale processes that lock the .exe (else silent LNK1104 / stale build) ---
taskkill /F /IM disasmstudio.exe          >nul 2>&1
taskkill /F /FI "IMAGENAME eq dump_pairs*" >nul 2>&1

REM --- force the C++ engine TU to recompile: cc does not track the #included
REM     decomp/*.inc files, so bump build.rs's timestamp to invalidate the cache ---
powershell -NoProfile -Command "(Get-Item 'crates\bridge\build.rs').LastWriteTime = Get-Date" >nul 2>&1

echo Building release ...
cargo build --release -p disasmstudio
if errorlevel 1 goto :fail

echo(
echo Building debug ...
cargo build -p disasmstudio
if errorlevel 1 goto :fail

echo(
echo === BUILD OK ===
echo   release: target\release\disasmstudio.exe
echo   debug  : target\debug\disasmstudio.exe
endlocal
exit /b 0

:fail
echo(
echo === BUILD FAILED (see the cargo errors above^) ===
endlocal
exit /b 1
