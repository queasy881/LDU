call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /LD /Od /W3 array_ops.cpp >> compile_all.log 2>&1 && echo OK array_ops || echo FAIL array_ops
cl /nologo /LD /Od /W3 bitops2.cpp >> compile_all.log 2>&1 && echo OK bitops2 || echo FAIL bitops2
cl /nologo /LD /Od /W3 board.cpp >> compile_all.log 2>&1 && echo OK board || echo FAIL board
cl /nologo /LD /Od /W3 checksums.cpp >> compile_all.log 2>&1 && echo OK checksums || echo FAIL checksums
cl /nologo /LD /Od /W3 cipher.cpp >> compile_all.log 2>&1 && echo OK cipher || echo FAIL cipher
cl /nologo /LD /Od /W3 control_flow.cpp >> compile_all.log 2>&1 && echo OK control_flow || echo FAIL control_flow
cl /nologo /LD /Od /W3 encoding.cpp >> compile_all.log 2>&1 && echo OK encoding || echo FAIL encoding
cl /nologo /LD /Od /W3 fixedpt.cpp >> compile_all.log 2>&1 && echo OK fixedpt || echo FAIL fixedpt
cl /nologo /LD /Od /W3 geometry.cpp >> compile_all.log 2>&1 && echo OK geometry || echo FAIL geometry
cl /nologo /LD /Od /W3 heaps.cpp >> compile_all.log 2>&1 && echo OK heaps || echo FAIL heaps
cl /nologo /LD /Od /W3 linklist.cpp >> compile_all.log 2>&1 && echo OK linklist || echo FAIL linklist
cl /nologo /LD /Od /W3 math_ops.cpp >> compile_all.log 2>&1 && echo OK math_ops || echo FAIL math_ops
cl /nologo /LD /Od /W3 matrix.cpp >> compile_all.log 2>&1 && echo OK matrix || echo FAIL matrix
cl /nologo /LD /Od /W3 parsing.cpp >> compile_all.log 2>&1 && echo OK parsing || echo FAIL parsing
cl /nologo /LD /Od /W3 ringbuf.cpp >> compile_all.log 2>&1 && echo OK ringbuf || echo FAIL ringbuf
cl /nologo /LD /Od /W3 sorting2.cpp >> compile_all.log 2>&1 && echo OK sorting2 || echo FAIL sorting2
cl /nologo /LD /Od /W3 stats.cpp >> compile_all.log 2>&1 && echo OK stats || echo FAIL stats
cl /nologo /LD /Od /W3 string_ops.cpp >> compile_all.log 2>&1 && echo OK string_ops || echo FAIL string_ops
cl /nologo /LD /Od /W3 struct_ops.cpp >> compile_all.log 2>&1 && echo OK struct_ops || echo FAIL struct_ops
cl /nologo /LD /Od /W3 validate.cpp >> compile_all.log 2>&1 && echo OK validate || echo FAIL validate

