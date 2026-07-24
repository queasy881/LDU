@echo off
setlocal
set VC=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build
call "%VC%\vcvars64.bat" >nul 2>&1
cl /nologo /O2 /LD /TC feat_c.c /link /OUT:feat_c.dll
cl /nologo /O2 /EHsc /LD /TP feat_cpp.cpp /link /OUT:feat_cpp.dll
call "%VC%\vcvars32.bat" >nul 2>&1
cl /nologo /O2 /LD /TC /arch:IA32 feat_x87.c /link /OUT:feat_x87.dll
