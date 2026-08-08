#include "crypto/base64.hpp"

#include <array>

namespace crypto {

namespace {

constexpr char kStdAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char kUrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void encode_to(const std::uint8_t* data, std::size_t len, const char* alphabet,
               char pad_char, std::string& out) {
  const std::size_t chunks = len / 3;
  const std::size_t rem = len % 3;
  std::size_t i = 0;
  for (std::size_t c = 0; c < chunks; ++c) {
    const std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                            (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                            static_cast<std::uint32_t>(data[i + 2]);
    out.push_back(alphabet[(v >> 18) & 0x3f]);
    out.push_back(alphabet[(v >> 12) & 0x3f]);
    out.push_back(alphabet[(v >> 6) & 0x3f]);
    out.push_back(alphabet[v & 0x3f]);
    i += 3;
  }
  if (rem == 1) {
    const std::uint32_t v = static_cast<std::uint32_t>(data[i]);
    out.push_back(alphabet[(v >> 2) & 0x3f]);
    out.push_back(alphabet[(v << 4) & 0x3f]);
    out.push_back(pad_char);
    out.push_back(pad_char);
  } else if (rem == 2) {
    const std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 8) |
                            static_cast<std::uint32_t>(data[i + 1]);
    out.push_back(alphabet[(v >> 10) & 0x3f]);
    out.push_back(alphabet[(v >> 4) & 0x3f]);
    out.push_back(alphabet[(v << 2) & 0x3f]);
    out.push_back(pad_char);
  }
}

}  // namespace

std::string base64_encode(const std::uint8_t* data, std::size_t len) {
  std::string out;
  out.reserve((len + 2) / 3 * 4);
  encode_to(data, len, kStdAlphabet, '=', out);
  return out;
}

std::string base64_urlsafe_encode(const std::uint8_t* data, std::size_t len) {
  std::string out;
  out.reserve((len + 2) / 3 * 4);
  encode_to(data, len, kUrlAlphabet, '=', out);
  return out;
}

}  // namespace crypto
