call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
for %%F in (math_ops array_ops string_ops control_flow struct_ops) do (
  cl /nologo /LD /Od /W3 %%F.cpp >> build_corpus.log 2>&1
  echo %%F EXIT=!errorlevel!
)
