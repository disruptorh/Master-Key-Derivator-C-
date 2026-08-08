#ifndef MASTERKEY_UI_APP_HPP_
#define MASTERKEY_UI_APP_HPP_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

#include "clipboard/secure_clipboard.hpp"
#include "crypto/kdf.hpp"
#include "secure_mem/secure_buffer.hpp"

namespace ui {

// Opciones de la UI (mismos nombres que ALGORITHMS / KEY_LENGTHS /
// OUTPUT_FORMATS de la app Python). Viven aqui para que app.cpp (logica) y
// las pantallas las compartan sin duplicar.
inline constexpr const char* kAlgorithmLabels[] = {
    "Scrypt (Recomendado PQC-grade)",
    "PBKDF2-SHA512 (1M Iteraciones)",
    "SHA3-512 Iterativo (500k)",
};
inline constexpr crypto::kdf_algo kAlgorithmValues[] = {
    crypto::kdf_algo::scrypt_pqc,
    crypto::kdf_algo::pbkdf2_sha512_pqc,
    crypto::kdf_algo::sha3_512_iterative,
};
inline constexpr const char* kAlgorithmBadge[] = {"Scrypt", "PBKDF2-SHA512",
                                                  "SHA3-512"};
inline constexpr const char* kLengthLabels[] = {
    "128 bits (16 B - Clásico)",
    "192 bits (24 B - Clásico)",
    "256 bits (32 B - Nivel PQC 1)",
    "512 bits (64 B - Nivel PQC 5)",
};
inline constexpr std::size_t kLengthValues[] = {16, 24, 32, 64};
inline constexpr const char* kFormatLabels[] = {"Base64", "Hexadecimal",
                                                "Base64 URL-safe"};
inline constexpr const char* kVersionLabels[] = {"V2 (APK)", "V3 (PQC-grade)"};
inline constexpr int kAlgorithmCount = 3;
inline constexpr int kLengthCount = 4;
inline constexpr int kFormatCount = 3;
inline constexpr int kVersionCount = 2;

// Estado global de la aplicacion. Todo material sensible vive en buffers
// mlock'ed, auto-zeroed (RAII); el destructor y reset() lo barren.
//
// Dos modos (Derivar Clave / Verificar). La derivacion (Scrypt 64 MiB /
// PBKDF2 1M iter / SHA3 500k pasadas) corre en un worker thread; los inputs
// se deshabilitan mientras deriva y el resultado llega a traves de un buffer
// seguro protegido por un mutex.
class app {
 public:
  app() = default;
  ~app();

  app(const app&) = delete;
  app& operator=(const app&) = delete;

  // Inicializa el portapapeles seguro (sin servidor X -> desactivado, la app
  // sigue funcionando). Devuelve true salvo error fatal de inicializacion.
  bool init();
  void shutdown();

  // Renderiza un frame del modo activo.
  void frame();

  // Ultimo error de la operacion mas reciente (vacio en caso de exito).
  const std::string& last_error() const { return last_error_; }

 private:
  enum class mode { derive, verify };
  mode mode_ = mode::derive;

  // Combo de configuracion (indices en los arreglos de app.cpp).
  int algo_idx_ = 0;     // Scrypt por defecto (Recomendado PQC-grade)
  int length_idx_ = 2;   // 256 bits (32 B - Nivel PQC 1)
  int format_idx_ = 0;   // Base64 (igual que el APK)
  crypto::kdf_version version_ = crypto::kdf_version::v2_apk;  // igual que APK

  // Buffers de edicion (NUL-terminados, secure_mem).
  secure_mem::secure_string password_;
  secure_mem::secure_string salt_;
  secure_mem::secure_string context_;

  // Resultado de la ultima derivacion.
  bool has_key_ = false;
  secure_mem::byte_buffer last_key_;
  secure_mem::secure_string formatted_key_;
  std::string fingerprint_;

  // Modo Verificar.
  secure_mem::secure_string verify_input_;
  bool verify_checked_ = false;
  bool verify_ok_ = false;
  std::string verify_result_;

  // Worker de derivacion.
  bool deriving_ = false;
  std::thread worker_;
  std::mutex result_mu_;
  secure_mem::byte_buffer result_key_;
  bool result_error_ = false;
  std::string result_error_msg_;
  std::atomic<bool> result_ready_{false};
  std::string job_password_;
  std::string job_salt_;
  std::string job_context_;

  std::string last_error_;
  std::string status_;

  clipboard::secure_clipboard clipboard_;

  struct copy_state {
    bool active = false;
    std::uint64_t expires_at_ms = 0;
  };
  copy_state copy_output_;

  static constexpr std::size_t kPasswordCapacity = 512;
  static constexpr std::size_t kSaltCapacity = 512;
  static constexpr std::size_t kContextCapacity = 512;
  static constexpr std::size_t kVerifyCapacity = 4096;

  void render_mode_switch();
  void render_derive_screen();
  void render_verify_screen();
  void render_result_panel();
  void render_status();
  void render_copy_status(std::uint64_t now);

  std::string format_last_key() const;
  void switch_mode(mode next);
  void start_derivation();
  void poll_derivation();
  void finalize_key_output();
  void do_copy();
  void do_verify();
  void reset_all();
  void wipe_secret_jobs();

  static std::uint64_t now_ms();
};

}  // namespace ui

#endif  // MASTERKEY_UI_APP_HPP_
