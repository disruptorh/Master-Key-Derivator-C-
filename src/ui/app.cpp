#include "ui/app.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>

#include <imgui.h>

#include "crypto/base64.hpp"

namespace ui {

namespace {

constexpr std::uint64_t kClipboardTimeoutMs =
    clipboard::secure_clipboard::kDefaultTimeoutMs;

std::string to_hex(const std::uint8_t* data, std::size_t len) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    out.push_back(kHex[data[i] >> 4]);
    out.push_back(kHex[data[i] & 0x0f]);
  }
  return out;
}

}  // namespace

std::uint64_t app::now_ms() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

app::~app() { shutdown(); }

bool app::init() {
  password_.reserve(kPasswordCapacity);
  salt_.reserve(kSaltCapacity);
  context_.reserve(kContextCapacity);
  verify_input_.reserve(kVerifyCapacity);

  if (!clipboard_.init()) {
    last_error_ =
        "No hay servidor X disponible; el portapapeles estará desactivado.";
  } else {
    if (const char* env = std::getenv("MKD_CLIPBOARD_TIMEOUT_MS")) {
      const long v = std::strtol(env, nullptr, 10);
      if (v > 0) clipboard_.set_timeout_ms(static_cast<std::uint64_t>(v));
    }
  }
  return true;
}

void app::shutdown() {
  // Esperar a que el worker termine antes de tocar cualquier buffer seguro.
  if (deriving_) {
    worker_.join();
    deriving_ = false;
  }
  wipe_secret_jobs();
  clipboard_.shutdown();
  password_.wipe();
  salt_.wipe();
  context_.wipe();
  verify_input_.wipe();
  formatted_key_.wipe();
  last_key_.release_and_zero();
  result_key_.release_and_zero();
}

void app::frame() {
  const std::uint64_t now = now_ms();
  clipboard_.poll(now);
  poll_derivation();

  const ImGuiViewport* vp = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(vp->WorkPos, ImGuiCond_Always);
  ImGui::SetNextWindowSize(vp->WorkSize, ImGuiCond_Always);

  if (ImGui::Begin("MasterKey Derivator - Derivador de claves maestras "
                   "(airgapped)",
                   nullptr, ImGuiWindowFlags_NoMove |
                                ImGuiWindowFlags_NoResize |
                                ImGuiWindowFlags_NoCollapse)) {
    ImGui::TextUnformatted("MasterKey Derivator (C++)");
    ImGui::Separator();
    ImGui::Spacing();

    render_mode_switch();

    if (mode_ == mode::derive) {
      render_derive_screen();
    } else {
      render_verify_screen();
    }
  }
  ImGui::End();
}

void app::render_mode_switch() {
  ImGui::TextUnformatted("Modo:");
  ImGui::SameLine();
  if (ImGui::RadioButton("Derivar", mode_ == mode::derive)) {
    switch_mode(mode::derive);
  }
  ImGui::SameLine();
  if (ImGui::RadioButton("Verificar", mode_ == mode::verify)) {
    switch_mode(mode::verify);
  }
  ImGui::Separator();
  ImGui::Spacing();
}

void app::switch_mode(mode next) {
  if (next == mode_) return;
  // El material de verificación es sensible y se barren al cambiar de modo.
  // La última clave derivada se conserva (es el objetivo de la verificación).
  verify_input_.wipe();
  verify_checked_ = false;
  verify_ok_ = false;
  verify_result_.clear();
  last_error_.clear();
  status_.clear();
  mode_ = next;
}

void app::render_status() {
  if (!last_error_.empty()) {
    ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f), "%s",
                       last_error_.c_str());
  }
  if (!status_.empty()) {
    ImGui::TextColored(ImVec4(0.42f, 0.88f, 0.52f, 1.0f), "%s",
                       status_.c_str());
  }
}

void app::render_copy_status(std::uint64_t now) {
  if (copy_output_.active) {
    const std::uint64_t remaining =
        (copy_output_.expires_at_ms > now) ? copy_output_.expires_at_ms - now
                                           : 0;
    ImGui::TextColored(ImVec4(0.42f, 0.88f, 0.52f, 1.0f),
                       "En el portapapeles por ~%llu s.",
                       static_cast<unsigned long long>(remaining / 1000));
  }
}

std::string app::format_last_key() const {
  switch (format_idx_) {
    case 0:
      return crypto::base64_encode(last_key_.data(), last_key_.size());
    case 2:
      return crypto::base64_urlsafe_encode(last_key_.data(), last_key_.size());
    default:
      return to_hex(last_key_.data(), last_key_.size());
  }
}

void app::start_derivation() {
  if (deriving_) return;
  if (password_.size() == 0 || salt_.size() == 0) {
    last_error_ =
        "La contraseña principal y la frase de salt son obligatorias.";
    return;
  }

  const crypto::kdf_algo algo = kAlgorithmValues[algo_idx_];
  const std::size_t length = kLengthValues[length_idx_];

  // Snapshots del trabajo (strings efimeras; se barren en finalize).
  job_password_.assign(password_.data(), password_.size());
  job_salt_.assign(salt_.data(), salt_.size());
  const char* ctx = context_.data();
  std::size_t ctx_len = context_.size();
  while (ctx_len != 0 && (ctx[ctx_len - 1] == ' ' || ctx[ctx_len - 1] == '\t' ||
                          ctx[ctx_len - 1] == '\n' || ctx[ctx_len - 1] == '\r')) {
    --ctx_len;
  }
  while (ctx_len != 0 && (ctx[0] == ' ' || ctx[0] == '\t' || ctx[0] == '\n' ||
                          ctx[0] == '\r')) {
    ++ctx;
    --ctx_len;
  }
  job_context_.assign(ctx, ctx_len);

  last_error_.clear();
  status_ = "Procesando criptografía intensiva...";
  deriving_ = true;
  result_ready_.store(false, std::memory_order_release);

  worker_ = std::thread([this, algo, length] {
    std::string err;
    secure_mem::byte_buffer key;
    try {
      secure_mem::secure_string pw;
      secure_mem::secure_string sp;
      secure_mem::secure_string cx;
      pw.assign(job_password_.data(), job_password_.size());
      sp.assign(job_salt_.data(), job_salt_.size());
      cx.assign(job_context_.data(), job_context_.size());
      key = crypto::derive_key(algo, pw, sp, cx, length, version_);
    } catch (const std::exception& e) {
      err = e.what();
    }
    {
      std::lock_guard<std::mutex> lk(result_mu_);
      if (err.empty()) {
        result_key_ = std::move(key);
        result_error_ = false;
        result_error_msg_.clear();
      } else {
        result_error_ = true;
        result_error_msg_ = std::move(err);
      }
    }
    result_ready_.store(true, std::memory_order_release);
  });
}

void app::poll_derivation() {
  if (!deriving_) return;
  if (!result_ready_.load(std::memory_order_acquire)) return;

  worker_.join();
  deriving_ = false;
  wipe_secret_jobs();

  std::lock_guard<std::mutex> lk(result_mu_);
  if (result_error_) {
    last_error_ = "Error criptográfico: " + result_error_msg_;
    result_error_msg_.clear();
    status_.clear();
    result_ready_.store(false, std::memory_order_release);
    return;
  }
  last_key_ = std::move(result_key_);
  has_key_ = true;
  finalize_key_output();
  status_ = "Clave generada exitosamente.";
  result_ready_.store(false, std::memory_order_release);
}

void app::finalize_key_output() {
  const std::string formatted = format_last_key();
  formatted_key_.assign(formatted.data(), formatted.size());
  fingerprint_ = crypto::fingerprint(last_key_);
  verify_checked_ = false;
  verify_result_.clear();
}

void app::do_copy() {
  if (!has_key_ || formatted_key_.size() == 0) return;
  const std::uint64_t now = now_ms();
  last_error_.clear();
  status_.clear();
  clipboard_.set_text(formatted_key_.data(), formatted_key_.size());
  if (clipboard_.is_active()) {
    copy_output_.active = true;
    copy_output_.expires_at_ms = now + kClipboardTimeoutMs;
    status_ = "Clave copiada. El portapapeles se autolimpia en unos segundos.";
  } else {
    last_error_ = "No hay servidor X; no se pudo copiar.";
  }
}

void app::do_verify() {
  if (!has_key_) {
    verify_checked_ = true;
    verify_ok_ = false;
    verify_result_ = "Deriva una clave primero.";
    return;
  }
  const std::string expected = format_last_key();
  const std::string candidate(verify_input_.data(), verify_input_.size());
  verify_checked_ = true;
  if (candidate == expected) {
    verify_ok_ = true;
    verify_result_ = "LAS CLAVES COINCIDEN";
  } else {
    verify_ok_ = false;
    verify_result_ = "LAS CLAVES NO COINCIDEN";
  }
}

void app::reset_all() {
  if (deriving_) return;
  clipboard_.clear_now();
  copy_output_.active = false;
  password_.wipe();
  salt_.wipe();
  context_.wipe();
  formatted_key_.wipe();
  last_key_.release_and_zero();
  has_key_ = false;
  fingerprint_.clear();
  verify_input_.wipe();
  verify_checked_ = false;
  verify_ok_ = false;
  verify_result_.clear();
  last_error_.clear();
  status_ = "Campos limpiados.";
}

void app::wipe_secret_jobs() {
  if (!job_password_.empty()) {
    std::fill(job_password_.begin(), job_password_.end(), '\0');
    job_password_.clear();
  }
  if (!job_salt_.empty()) {
    std::fill(job_salt_.begin(), job_salt_.end(), '\0');
    job_salt_.clear();
  }
  if (!job_context_.empty()) {
    std::fill(job_context_.begin(), job_context_.end(), '\0');
    job_context_.clear();
  }
}

}  // namespace ui
