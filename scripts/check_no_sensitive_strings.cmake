# Script: check_no_sensitive_strings.cmake
# Verifies that the shipped binary does not contain residual test secrets
# (passwords, salt phrases, contexts, plaintexts) as string literals.
#
# Invoked by CTest as:
#   cmake -DBIN=... -DSCRIPT_DIR=... -P check_no_sensitive_strings.cmake
#
# The test suite (separate binary) obviously contains these values; the
# application binary must NOT, even after a test run. `strings` output is
# scanned for each known test value (case-insensitive substring).

if(NOT EXISTS "${BIN}")
  message(FATAL_ERROR "binary not found: ${BIN}")
endif()

execute_process(
  COMMAND strings "${BIN}"
  OUTPUT_VARIABLE STRINGS_OUTPUT
  RESULT_VARIABLE STRINGS_RESULT
)
if(NOT STRINGS_RESULT EQUAL 0)
  message(FATAL_ERROR "strings failed")
endif()

# Values used by the unit tests / vectores de paridad (tests/). Keep in sync
# with tests/test_kdf.cpp and tests/kdf_vectors.generated.hpp. Only distinctive
# values are listed (common words like "password" can legitimately appear in
# vendored/UI strings).
set(FORBIDDEN
  "P@ssw0rd#Fuerte"
  "MiClaveSecreta#2026"
  "contrase\u00f1a-acentuada-123"
  "frase-salt-ejemplo-1"
  "segunda-frase-secreta"
  "salt-acentos-2026"
  "wallet-bitcoin"
  "servidor-ssh"
  "mi-salt-de-prueba"
)

foreach(v IN LISTS FORBIDDEN)
  string(TOLOWER "${STRINGS_OUTPUT}" lower_output)
  string(TOLOWER "${v}" lower_v)
  string(FIND "${lower_output}" "${lower_v}" pos)
  if(NOT pos EQUAL -1)
    message(FATAL_ERROR "FAIL: binary contains test secret string: '${v}'")
  endif()
endforeach()

message(STATUS "OK: no residual test secrets in ${BIN}")
