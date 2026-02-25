@echo off
setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%

if "%IDASDK%"=="" set IDASDK=%SCRIPT_DIR%\idasdk\src
set BUILD_DIR=%SCRIPT_DIR%\build
set JOBS=%NUMBER_OF_PROCESSORS%

echo === Building tests ===
cmake -S "%SCRIPT_DIR%" -B "%BUILD_DIR%\tests" -DBUILD_PLUGIN=OFF -DBUILD_TESTS=ON
if errorlevel 1 goto :error
cmake --build "%BUILD_DIR%\tests" --config Release -j %JOBS%
if errorlevel 1 goto :error

echo.
echo === Running tests ===
"%BUILD_DIR%\tests\Release\ida_mcp_tests.exe"
if errorlevel 1 goto :error

echo.
echo === Building plugin (IDASDK=%IDASDK%) ===
cmake -S "%SCRIPT_DIR%" -B "%BUILD_DIR%\plugin" -DBUILD_PLUGIN=ON -DBUILD_TESTS=OFF -DIDASDK="%IDASDK%"
if errorlevel 1 goto :error
cmake --build "%BUILD_DIR%\plugin" --config Release -j %JOBS%
if errorlevel 1 goto :error

set PLUGINS_DIR=%USERPROFILE%\ida-free-9.3\plugins
echo.
echo === Installing plugin to %PLUGINS_DIR% ===
if not exist "%PLUGINS_DIR%" mkdir "%PLUGINS_DIR%"
copy /Y "%BUILD_DIR%\plugin\Release\ida_mcp.dll" "%PLUGINS_DIR%\ida_mcp.dll"
if errorlevel 1 goto :error

echo.
echo === Done ===
echo Plugin: %PLUGINS_DIR%\ida_mcp.dll
goto :eof

:error
echo.
echo === Build failed ===
exit /b 1
