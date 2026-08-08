#include "ui/app.hpp"

#include <cstring>

#include <imgui.h>

namespace ui {

void app::render_derive_screen() {
  ImGui::TextWrapped(
      "Deriva una clave maestra con criptografía intensiva (Scrypt / PBKDF2 / "
      "SHA3-512). Nada se escribe a disco.");
  ImGui::Spacing();

  ImGui::BeginDisabled(deriving_);

  ImGui::TextUnformatted("Contraseña principal:");
  ImGui::SetNextItemWidth(-1.0f);
  if (ImGui::InputText("##password_derive", password_.data(),
                       static_cast<int>(kPasswordCapacity),
                       ImGuiInputTextFlags_Password)) {
    password_.set_len(std::strlen(password_.data()));
  }

  ImGui::Spacing();
  ImGui::TextUnformatted("Frase de salt (segunda contraseña):");
  ImGui::SetNextItemWidth(-1.0f);
  if (ImGui::InputText("##salt_derive", salt_.data(),
                       static_cast<int>(kSaltCapacity),
                       ImGuiInputTextFlags_Password)) {
    salt_.set_len(std::strlen(salt_.data()));
  }

  ImGui::Spacing();
  ImGui::TextUnformatted("Contexto (opcional):");
  ImGui::SetNextItemWidth(-1.0f);
  if (ImGui::InputText("##context_derive", context_.data(),
                       static_cast<int>(kContextCapacity))) {
    context_.set_len(std::strlen(context_.data()));
  }

  ImGui::Spacing();
  ImGui::TextUnformatted("Algoritmo:");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::Combo("##algo", &algo_idx_, kAlgorithmLabels, kAlgorithmCount);

  ImGui::Spacing();
  ImGui::TextUnformatted("Longitud:");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::Combo("##length", &length_idx_, kLengthLabels, kLengthCount);

  ImGui::Spacing();
  ImGui::TextUnformatted("Formato:");
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::Combo("##format", &format_idx_, kFormatLabels, kFormatCount);

  ImGui::Spacing();
  ImGui::TextUnformatted("Versión (compatibilidad):");
  const bool v2 = version_ == crypto::kdf_version::v2_apk;
  if (ImGui::RadioButton("V2 (igual que Master-key-Creator APK)", v2)) {
    version_ = crypto::kdf_version::v2_apk;
  }
  ImGui::SameLine();
  if (ImGui::RadioButton("V3 (PQC-grade, igual que Python/Linux)",
                         !v2)) {
    version_ = crypto::kdf_version::v3_pqc;
  }

  ImGui::EndDisabled();

  ImGui::Spacing();
  if (deriving_) {
    ImGui::BeginDisabled(true);
    ImGui::Button("Derivando... (esto toma tiempo)", ImVec2(-1.0f, 0.0f));
    ImGui::EndDisabled();
  } else if (ImGui::Button("Generar clave maestra", ImVec2(-1.0f, 0.0f))) {
    start_derivation();
  }

  ImGui::Spacing();
  if (ImGui::Button("Limpiar campos", ImVec2(-1.0f, 0.0f))) {
    reset_all();
  }

  render_status();

  if (has_key_) {
    render_result_panel();
  }
}

void app::render_result_panel() {
  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  const int bits = 8 * static_cast<int>(kLengthValues[length_idx_]);
  const char* ver =
      version_ == crypto::kdf_version::v2_apk ? "V2 (APK)" : "V3 (PQC-grade)";
  ImGui::TextDisabled("%s | %d bits | %s", kAlgorithmBadge[algo_idx_], bits,
                      ver);

  ImGui::Spacing();
  if (ImGui::BeginChild("##key_display", ImVec2(-1.0f, 120.0f),
                        ImGuiChildFlags_Border,
                        ImGuiWindowFlags_HorizontalScrollbar)) {
    ImGui::TextWrapped("%s", formatted_key_.data());
  }
  ImGui::EndChild();

  ImGui::TextDisabled("SHA-256 Fingerprint: %s...", fingerprint_.c_str());

  const std::uint64_t now = now_ms();
  if (ImGui::Button("Copiar clave", ImVec2(-1.0f, 0.0f))) {
    do_copy();
  }
  render_copy_status(now);
}

}  // namespace ui
