@echo off
REM Build script for AmcacheForensics
REM Author: Ayi NEDJIMI

echo ========================================
echo Building AmcacheForensics
echo Author: Ayi NEDJIMI
echo ========================================

set COMPILER=cl.exe
set OUTPUT=AmcacheForensics.exe
set SOURCE=AmcacheForensics.cpp

REM Check for Visual Studio environment
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: cl.exe not found. Please run from Visual Studio Developer Command Prompt.
    pause
    exit /b 1
)

echo.
echo Compiling %SOURCE%...
%COMPILER% /nologo /W4 /EHsc /O2 /D_UNICODE /DUNICODE /Fe%OUTPUT% %SOURCE% ^
    kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib shlwapi.lib advapi32.lib

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Compilation failed!
    pause
    exit /b 1
)

echo.
echo Cleaning up intermediate files...
del *.obj 2>nul

echo.
echo ========================================
echo Build completed successfully!
echo Output: %OUTPUT%
echo ========================================
echo.
echo Run %OUTPUT% with Administrator privileges to load Amcache.hve.
echo.
pause
