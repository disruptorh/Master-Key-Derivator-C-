#ifndef MASTERKEY_CRYPTO_BASE64_HPP_
#define MASTERKEY_CRYPTO_BASE64_HPP_

#include <cstddef>
#include <cstdint>
#include <string>

namespace crypto {

// Encoders Base64 con padding, byte-identicos a los de la app Python:
//   - base64_encode: alfabeto estandar RFC 4648 SS4 ('+' y '/'), igual a
//     base64.b64encode().
//   - base64_urlsafe_encode: alfabeto URL-safe ('-' y '_') CON padding,
//     igual a base64.urlsafe_b64encode().
// Nota deliberada frente al plan (seccion 3.3): el plan pedia URL-safe sin
// padding, pero la app Python de referencia SI emite padding, y la regla de
// oro exige no romper las salidas existentes. Se mantiene el padding.
std::string base64_encode(const std::uint8_t* data, std::size_t len);
std::string base64_urlsafe_encode(const std::uint8_t* data, std::size_t len);

}  // namespace crypto

#endif  // MASTERKEY_CRYPTO_BASE64_HPP_
