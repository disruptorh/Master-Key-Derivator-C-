#include "crypto/kdf.hpp"

#include <cstring>
#include <stdexcept>

#include <sodium.h>

#include "crypto/base64.hpp"
#include "crypto/pbkdf2.hpp"
#include "crypto/sha3.hpp"

namespace crypto {
namespace {

// Convierte una secure_string en un buffer de bytes: simplemente son los bytes
// UTF-8 del contenido (la app trabaja con texto; la codificacion coincide con
// str.encode("utf-8") en Python para todo el rango de caracteres ASCII y los
// acentos que se guardan como UTF-8).
const std::uint8_t* as_bytes(const secure_mem::secure_string& s) {
  return reinterpret_cast<const std::uint8_t*>(s.data());
}

const char* default_context(kdf_version version) {
  return version == kdf_version::v2_apk ? kDefaultContextV2
                                        : kDefaultContextV3;
}

std::uint64_t scrypt_n(kdf_version version) {
  return version == kdf_version::v2_apk ? kScryptNv2 : kScryptN;
}

std::uint32_t scrypt_p(kdf_version version) {
  return version == kdf_version::v2_apk ? kScryptPv2 : kScryptP;
}

std::uint32_t pbkdf2_iterations(kdf_version version) {
  return version == kdf_version::v2_apk ? kPbkdf2IterationsV2
                                        : kPbkdf2Iterations;
}

std::uint32_t sha3_iterations(kdf_version version) {
  return version == kdf_version::v2_apk ? kSha3IterationsV2 : kSha3Iterations;
}

}  // namespace

secure_mem::byte_buffer fixed_salt(const secure_mem::secure_string& salt_phrase,
                                   const secure_mem::secure_string& context,
                                   kdf_version version) {
  const char* msg = context.empty() ? default_context(version) : context.data();
  const std::size_t msg_len = context.empty()
                                  ? std::strlen(default_context(version))
                                  : context.size();

  secure_mem::byte_buffer salt(crypto_auth_hmacsha256_BYTES);  // 32
  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, as_bytes(salt_phrase), salt_phrase.size());
  crypto_auth_hmacsha256_update(&st, reinterpret_cast<const std::uint8_t*>(msg),
                                msg_len);
  crypto_auth_hmacsha256_final(&st, salt.data());
  sodium_memzero(&st, sizeof(st));
  return salt;
}

secure_mem::byte_buffer derive_scrypt_pqc(
    const secure_mem::secure_string& password,
    const secure_mem::secure_string& salt_phrase,
    const secure_mem::secure_string& context, std::size_t length,
    kdf_version version) {
  secure_mem::byte_buffer salt = fixed_salt(salt_phrase, context, version);
  secure_mem::byte_buffer key(length);
  if (crypto_pwhash_scryptsalsa208sha256_ll(
          as_bytes(password), password.size(), salt.data(), salt.size(),
          scrypt_n(version), kScryptR, scrypt_p(version), key.data(),
          key.size()) != 0) {
    throw std::runtime_error("kdf: crypto_pwhash_scryptsalsa208sha256_ll fallo");
  }
  return key;
}

secure_mem::byte_buffer derive_pbkdf2_sha512_pqc(
    const secure_mem::secure_string& password,
    const secure_mem::secure_string& salt_phrase,
    const secure_mem::secure_string& context, std::size_t length,
    kdf_version version) {
  secure_mem::byte_buffer salt = fixed_salt(salt_phrase, context, version);
  secure_mem::byte_buffer key(length);
  pbkdf2_hmac_sha512(as_bytes(password), password.size(), salt.data(),
                     salt.size(), pbkdf2_iterations(version), key.data(),
                     key.size());
  return key;
}

secure_mem::byte_buffer derive_sha3_512_iterative(
    const secure_mem::secure_string& password,
    const secure_mem::secure_string& salt_phrase,
    const secure_mem::secure_string& context, std::size_t length,
    kdf_version version) {
  secure_mem::byte_buffer salt = fixed_salt(salt_phrase, context, version);

  // data = password || salt, despues (200k en V2 / 500k en V3) SHA3-512
  // encadenados. El buffer se pre-dimensiona a su tamano maximo (longitud
  // inicial o 64 bytes) para no reasignar memoria mlock'ed en cada iteracion.
  const std::size_t initial_len = password.size() + salt.size();
  secure_mem::byte_buffer data(initial_len > 64 ? initial_len : 64);
  if (password.size() != 0) {
    std::memcpy(data.data(), as_bytes(password), password.size());
  }
  std::memcpy(data.data() + password.size(), salt.data(), salt.size());

  std::size_t data_len = initial_len;
  std::uint8_t digest[64];
  const std::uint32_t iterations = sha3_iterations(version);
  for (std::uint32_t i = 0; i < iterations; ++i) {
    sha3_512(digest, data.data(), data_len);
    std::memcpy(data.data(), digest, 64);
    data_len = 64;
  }
  sodium_memzero(digest, sizeof(digest));

  secure_mem::byte_buffer key(length);
  const std::size_t copy = (length <= data_len) ? length : data_len;
  std::memcpy(key.data(), data.data(), copy);
  return key;
}

secure_mem::byte_buffer derive_key(kdf_algo algo,
                                   const secure_mem::secure_string& password,
                                   const secure_mem::secure_string& salt_phrase,
                                   const secure_mem::secure_string& context,
                                   std::size_t length, kdf_version version) {
  switch (algo) {
    case kdf_algo::scrypt_pqc:
      return derive_scrypt_pqc(password, salt_phrase, context, length, version);
    case kdf_algo::pbkdf2_sha512_pqc:
      return derive_pbkdf2_sha512_pqc(password, salt_phrase, context, length,
                                      version);
    case kdf_algo::sha3_512_iterative:
      return derive_sha3_512_iterative(password, salt_phrase, context, length,
                                       version);
  }
  throw std::invalid_argument("kdf: algoritmo desconocido");
}

std::string fingerprint(const secure_mem::byte_buffer& key) {
  std::uint8_t digest[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(digest, key.data(), key.size());

  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(40);
  for (std::size_t i = 0; i < 20; ++i) {
    out.push_back(kHex[digest[i] >> 4]);
    out.push_back(kHex[digest[i] & 0x0f]);
  }
  sodium_memzero(digest, sizeof(digest));
  return out;
}

}  // namespace crypto
