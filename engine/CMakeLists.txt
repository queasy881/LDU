cmake_minimum_required(VERSION 3.20)
project(disasmengine C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Assembly is optional: only enable an assembler if the engine actually shipped
# .asm sources, so the common pure-C build configures with no assembler present.
file(GLOB DS_ASM_PROBE "${CMAKE_CURRENT_SOURCE_DIR}/src/*.asm")
if(DS_ASM_PROBE)
    if(MSVC)
        enable_language(ASM_MASM)
    else()
        enable_language(ASM_NASM)
    endif()
endif()

# capstone is optional and OFF by default so the project builds fully offline.
# When ON, capstone 5.x is fetched and statically linked and the engine uses it
# as the decode backend; when OFF the built-in x86-64 decoder is used.
option(DS_USE_CAPSTONE "Use capstone as the disassembly backend" OFF)

# ---- engine sources -------------------------------------------------------
# Globbing keeps this in sync with whatever the implementation agents write
# under src/ and analysis/.
file(GLOB DS_C_SOURCES   CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
file(GLOB DS_CXX_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/analysis/*.cpp")
file(GLOB DS_ASM_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.asm")

add_library(disasmengine STATIC ${DS_C_SOURCES} ${DS_CXX_SOURCES} ${DS_ASM_SOURCES})

target_include_directories(disasmengine
    PUBLIC  "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src"
            "${CMAKE_CURRENT_SOURCE_DIR}/analysis")

set_target_properties(disasmengine PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(MSVC)
    target_compile_options(disasmengine PRIVATE /W3 /wd4244 /wd4267)
else()
    target_compile_options(disasmengine PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

# ---- capstone backend (VENDORED in-tree, no network) ----------------------
# The capstone 5.0.1 source lives IN-TREE under third_party/capstone (x86 only)
# and is built via add_subdirectory, so the build is fully OFFLINE and never
# fetches capstone. To refresh, re-vendor from the upstream 5.0.1 tag.
if(DS_USE_CAPSTONE)
    set(CAPSTONE_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_CSTOOL   OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_SHARED   OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_STATIC   ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_INSTALL        OFF CACHE BOOL "" FORCE)
    # Only the x86 architecture is vendored, so disable all the others.
    set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_X86_SUPPORT    ON  CACHE BOOL "" FORCE)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone" EXCLUDE_FROM_ALL)
    target_compile_definitions(disasmengine PRIVATE DS_USE_CAPSTONE=1)
    target_link_libraries(disasmengine PUBLIC capstone)
    target_include_directories(disasmengine PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone/include")
endif()

# ---- install (the `cmake` Rust crate drives the `install` target) ---------
# Without this rule the default `cmake --build . --target install` fails. The
# bridge crate's build.rs searches <out>/lib for disasmengine.lib.
install(TARGETS disasmengine
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)
