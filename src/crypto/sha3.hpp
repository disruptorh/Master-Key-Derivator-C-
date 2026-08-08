#ifndef MASTERKEY_CRYPTO_SHA3_HPP_
#define MASTERKEY_CRYPTO_SHA3_HPP_

#include <cstddef>
#include <cstdint>

namespace crypto {

// SHA3-512 puro (FIPS 202) sobre Keccak-p[1600,24], rate 72 bytes, padding
// 0x06||...||0x80. Es la primitiva usada por la derivacion iterativa de la app
// Python de referencia (`hashlib.sha3_512`), con la que se garantiza paridad
// bit a bit. No depende de libsodium (que no implementa SHA3).
void sha3_512(std::uint8_t out[64], const std::uint8_t* data,
              std::size_t len);

}  // namespace crypto

#endif  // MASTERKEY_CRYPTO_SHA3_HPP_
