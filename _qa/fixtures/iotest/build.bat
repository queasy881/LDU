@echo off
call "%VCVARS%" >nul 2>&1
cd /d "%~dp0"
cl /nologo /O2 /EHsc /LD iotest.cpp /Fe:iotest.dll >build_O2.log 2>&1
cl /nologo /Od /EHsc /LD iotest.cpp /Fe:iotest_od.dll >build_Od.log 2>&1
