# ============================================================================
# MasterKey Derivator (C++, airgapped) — derivador de claves maestras PQC-grade
#
# Reescritura en C++ de MasterKey Derivator v4.0 (Python) con paridad
# criptografica bit a bit:
#   - Scrypt   N=65536, r=8, p=2
#   - PBKDF2   HMAC-SHA512, 1,000,000 iteraciones
#   - SHA3-512 iterativo, 500,000 pasadas
#   - Salt fijo HMAC-SHA256(contexto, frase de salt)
#
# Build reproducible SIN red (todo vendored en third_party/):
#   cmake -S . -B build
#   cmake --build build -j
#   ctest --test-dir build
# ============================================================================
cmake_minimum_required(VERSION 3.20)
project(master_key_derivator VERSION 4.0.0 LANGUAGES C CXX)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(MKD_BUILD_TESTS "Build the self-test suite" ON)
option(MKD_ENABLE_CLANG_TIDY "Run clang-tidy checks on our sources" ON)

# ----------------------------------------------------------------------------
# Hardening (applied to every target of this project)
# ----------------------------------------------------------------------------
add_compile_options(-Wall -Wextra -Wpedantic -fstack-protector-strong)
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions(_FORTIFY_SOURCE=2)
endif()
add_link_options(-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack)

# ----------------------------------------------------------------------------
# libsodium (vendored, compiled statically via autotools) — third_party/
# ----------------------------------------------------------------------------
include(ExternalProject)

set(LIBSODIUM_ROOT ${CMAKE_BINARY_DIR}/_deps/libsodium/prefix)
set(LIBSODIUM_LIB ${LIBSODIUM_ROOT}/lib/libsodium.a)
set(LIBSODIUM_INCLUDE ${LIBSODIUM_ROOT}/include)

find_program(NPROC NAMES nproc)
if(NPROC)
  execute_process(COMMAND ${NPROC} OUTPUT_VARIABLE MKD_JOBS)
  string(STRIP "${MKD_JOBS}" MKD_JOBS)
else()
  set(MKD_JOBS 4)
endif()

ExternalProject_Add(libsodium_ext
  PREFIX ${CMAKE_BINARY_DIR}/_deps/libsodium
  SOURCE_DIR ${CMAKE_SOURCE_DIR}/third_party/libsodium
  CONFIGURE_COMMAND ${CMAKE_SOURCE_DIR}/third_party/libsodium/configure
      --prefix=${LIBSODIUM_ROOT}
      --disable-shared
      --enable-static
      --disable-tests
  BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} -j${MKD_JOBS}
  INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
  INSTALL_DIR ${LIBSODIUM_ROOT}
  BUILD_IN_SOURCE 0
  BUILD_BYPRODUCTS ${LIBSODIUM_LIB} ${LIBSODIUM_INCLUDE}/sodium.h
)

# ----------------------------------------------------------------------------
# Core (no GUI) static library: secure_mem + crypto.
# This library MUST NOT include any Dear ImGui header (checked by the
# crypto_no_imgui CTest). It is built and tested in isolation.
# ----------------------------------------------------------------------------
add_library(mkd_core STATIC
  src/secure_mem/secure_buffer.hpp
  src/secure_mem/secure_buffer.cpp
  src/crypto/base64.hpp
  src/crypto/base64.cpp
  src/crypto/sha3.hpp
  src/crypto/sha3.cpp
  src/crypto/pbkdf2.hpp
  src/crypto/pbkdf2.cpp
  src/crypto/kdf.hpp
  src/crypto/kdf.cpp
)
target_include_directories(mkd_core PUBLIC
  ${CMAKE_SOURCE_DIR}/src
  ${LIBSODIUM_INCLUDE}
)
target_include_directories(mkd_core SYSTEM PUBLIC ${LIBSODIUM_INCLUDE})
target_link_libraries(mkd_core PUBLIC ${LIBSODIUM_LIB} pthread)
add_dependencies(mkd_core libsodium_ext)

# ----------------------------------------------------------------------------
# Application (Dear ImGui + GLFW + OpenGL3, same backend as the reference apps)
# ----------------------------------------------------------------------------
find_package(OpenGL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLFW REQUIRED IMPORTED_TARGET glfw3)
pkg_check_modules(X11 REQUIRED IMPORTED_TARGET x11)

set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui)

add_executable(masterkey_derivator
  src/main.cpp
  src/clipboard/secure_clipboard.cpp
  src/clipboard/secure_clipboard.hpp
  src/security/seccomp.cpp
  src/security/seccomp.hpp
  src/ui/app.cpp
  src/ui/app.hpp
  src/ui/screen_derive.cpp
  src/ui/screen_verify.cpp
  ${IMGUI_DIR}/imgui.cpp
  ${IMGUI_DIR}/imgui_draw.cpp
  ${IMGUI_DIR}/imgui_tables.cpp
  ${IMGUI_DIR}/imgui_widgets.cpp
  ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
  ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)
target_include_directories(masterkey_derivator PRIVATE
  ${IMGUI_DIR}
  ${IMGUI_DIR}/backends
)
# ImGui vendored and patched for the airgapped profile:
#  - IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS removes the default "open in shell"
#    (fork/execvp) implementation.
#  - The GL loader resolves entry points through glfwGetProcAddress() instead
#    of dlopen() (see IMGL3W_DYNLOAD guard in imgui_impl_opengl3_loader.h).
target_compile_definitions(masterkey_derivator PRIVATE
  IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS
)
target_link_libraries(masterkey_derivator PRIVATE
  mkd_core
  OpenGL::GL
  PkgConfig::GLFW
  PkgConfig::X11
)

if(MKD_CLANG_TIDY_CMD)
  set_property(TARGET mkd_core masterkey_derivator
               PROPERTY CXX_CLANG_TIDY "${MKD_CLANG_TIDY_CMD}")
endif()

# clang-tidy on our own sources (only the app+core, not vendored code and not
# the test harness). Applied per-target (mkd_core + masterkey_derivator).
if(MKD_ENABLE_CLANG_TIDY)
  find_program(CLANG_TIDY_BIN clang-tidy)
  if(CLANG_TIDY_BIN)
    set(MKD_CLANG_TIDY_CMD
        ${CLANG_TIDY_BIN}
        --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy)
  endif()
endif()

# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------
if(MKD_BUILD_TESTS)
  enable_testing()

  add_executable(mkd_tests
    tests/test_main.cpp
    tests/test_secure_mem.cpp
    tests/test_sha3.cpp
    tests/test_pbkdf2.cpp
    tests/test_base64.cpp
    tests/test_kdf.cpp
    tests/kdf_vectors.generated.hpp
  )
  target_include_directories(mkd_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/tests
  )
  target_link_libraries(mkd_tests PRIVATE mkd_core)
  # Deterministic zeroization check: intercept sodium_malloc/sodium_free, and
  # force deterministic mlock failures (ASan makes RLIMIT_MEMLOCK unreliable).
  target_link_options(mkd_tests PRIVATE
    "-Wl,--wrap=sodium_malloc,--wrap=sodium_free,--wrap=sodium_mlock")

  add_test(NAME mkd_tests COMMAND mkd_tests)

  add_test(
    NAME no_network_symbols
    COMMAND ${CMAKE_COMMAND}
      -DBIN=$<TARGET_FILE:masterkey_derivator>
      -DSCRIPT_DIR=${CMAKE_SOURCE_DIR}/scripts
      -P ${CMAKE_SOURCE_DIR}/scripts/check_no_network.cmake
  )

  add_test(
    NAME no_sensitive_test_strings_in_binary
    COMMAND ${CMAKE_COMMAND}
      -DBIN=$<TARGET_FILE:masterkey_derivator>
      -DSCRIPT_DIR=${CMAKE_SOURCE_DIR}/scripts
      -P ${CMAKE_SOURCE_DIR}/scripts/check_no_sensitive_strings.cmake
  )

  add_test(
    NAME crypto_layer_has_no_imgui
    COMMAND ${CMAKE_COMMAND}
      -DSRC_DIR=${CMAKE_SOURCE_DIR}/src
      -P ${CMAKE_SOURCE_DIR}/scripts/check_crypto_no_imgui.cmake
  )
endif()
