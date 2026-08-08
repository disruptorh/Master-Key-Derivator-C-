#ifndef MASTERKEY_CRYPTO_KDF_HPP_
#define MASTERKEY_CRYPTO_KDF_HPP_

#include <cstddef>
#include <cstdint>
#include <string>

#include "secure_mem/secure_buffer.hpp"

namespace crypto {

// Paridad bit a bit con dos referencias del stack:
//   - kdf_version::v2_apk -> Master-key-Creator-apk (MasterKey Derivator v2.0):
//       Scrypt N=32768, r=8, p=1 | PBKDF2 600,000 iters | SHA3-512 200,000
//       pasadas | contexto por defecto "masterkey-derivator-v2".
//   - kdf_version::v3_pqc  -> crypto_core/kdf.py (Master-Key-Creator-Linux /
//       app Python v4.0, PQC-grade):
//       Scrypt N=65536, r=8, p=2 | PBKDF2 1,000,000 iters | SHA3-512 500,000
//       pasadas | contexto por defecto "masterkey-derivator-v3-pqc-grade".
//
// Regla de oro: NO romper las salidas de ninguna de las dos; los salts,
// iteradores y parametros deben generar exactamente los mismos bytes que su
// referencia.
//
// El salt fijo (para los tres algoritmos y ambas versiones) es:
//   HMAC-SHA256(key = salt_phrase_utf8, msg = context_utf8 o el contexto por
//               defecto de la version si el contexto esta vacio).
enum class kdf_algo { scrypt_pqc, pbkdf2_sha512_pqc, sha3_512_iterative };
enum class kdf_version { v2_apk, v3_pqc };

// V3 (PQC-grade, Python/Linux v4.0).
inline constexpr std::uint64_t kScryptN = 65536;
inline constexpr std::uint32_t kScryptR = 8;
inline constexpr std::uint32_t kScryptP = 2;
inline constexpr std::uint32_t kPbkdf2Iterations = 1'000'000;
inline constexpr std::uint32_t kSha3Iterations = 500'000;
inline constexpr const char kDefaultContextV3[] =
    "masterkey-derivator-v3-pqc-grade";

// V2 (APK, MasterKey Derivator v2.0).
inline constexpr std::uint64_t kScryptNv2 = 32768;
inline constexpr std::uint32_t kScryptRv2 = 8;
inline constexpr std::uint32_t kScryptPv2 = 1;
inline constexpr std::uint32_t kPbkdf2IterationsV2 = 600'000;
inline constexpr std::uint32_t kSha3IterationsV2 = 200'000;
inline constexpr const char kDefaultContextV2[] = "masterkey-derivator-v2";

// HMAC-SHA256 de 32 bytes descrito arriba.
secure_mem::byte_buffer fixed_salt(const secure_mem::secure_string& salt_phrase,
                                   const secure_mem::secure_string& context,
                                   kdf_version version = kdf_version::v3_pqc);

secure_mem::byte_buffer derive_scrypt_pqc(
    const secure_mem::secure_string& password,
    const secure_mem::secure_string& salt_phrase,
    const secure_mem::secure_string& context, std::size_t length,
    kdf_version version = kdf_version::v3_pqc);

secure_mem::byte_buffer derive_pbkdf2_sha512_pqc(
    const secure_mem::secure_string& password,
    const secure_mem::secure_string& salt_phrase,
    const secure_mem::secure_string& context, std::size_t length,
    kdf_version version = kdf_version::v3_pqc);

secure_mem::byte_buffer derive_sha3_512_iterative(
    const secure_mem::secure_string& password,
    const secure_mem::secure_string& salt_phrase,
    const secure_mem::secure_string& context, std::size_t length,
    kdf_version version = kdf_version::v3_pqc);

// Dispatcher de los tres algoritmos (mapeo ALGORITHMS de Python).
secure_mem::byte_buffer derive_key(kdf_algo algo,
                                   const secure_mem::secure_string& password,
                                   const secure_mem::secure_string& salt_phrase,
                                   const secure_mem::secure_string& context,
                                   std::size_t length,
                                   kdf_version version = kdf_version::v3_pqc);

// Fingerprint SHA-256 de la clave RAW (hex en minusculas, 40 caracteres),
// igual que hashlib.sha256(key).hexdigest()[:40].
std::string fingerprint(const secure_mem::byte_buffer& key);

}  // namespace crypto

#endif  // MASTERKEY_CRYPTO_KDF_HPP_
