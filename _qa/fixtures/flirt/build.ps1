$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath
cmd /c "`"$vs\VC\Auxiliary\Build\vcvars64.bat`" >NUL 2>&1 && cl /nologo /MT /O2 /EHsc /Fe:scratch_flirt\t.exe scratch_flirt\t.cpp /link /OUT:scratch_flirt\t.exe 2>&1" | Select-Object -Last 3
