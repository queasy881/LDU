@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "C:\Users\User\Downloads\sd\_qa\corpus"
cl /nologo /LD /Od /W3 torture.cpp
