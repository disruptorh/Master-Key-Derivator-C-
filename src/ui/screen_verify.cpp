#include "ui/app.hpp"

#include <cstring>

#include <imgui.h>

namespace ui {

void app::render_verify_screen() {
  ImGui::TextWrapped(
      "Pega aquí la clave que quieres verificar contra la última derivada "
      "(usando el algoritmo y formato seleccionados).");
  ImGui::Spacing();

  ImGui::SetNextItemWidth(-1.0f);
  if (ImGui::InputTextMultiline("##verify_input", verify_input_.data(),
                                static_cast<int>(kVerifyCapacity),
                                ImVec2(-1.0f, 96.0f))) {
    verify_input_.set_len(std::strlen(verify_input_.data()));
  }

  ImGui::Spacing();
  if (ImGui::Button("Verificar coincidencia", ImVec2(-1.0f, 0.0f))) {
    do_verify();
  }

  ImGui::Spacing();
  if (!verify_checked_) {
    ImGui::TextDisabled(
        "La verificación se hará contra la clave generada más reciente.");
  } else {
    const ImVec4 ok(0.13f, 0.77f, 0.37f, 1.0f);
    const ImVec4 bad(0.95f, 0.35f, 0.35f, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, verify_ok_ ? ok : bad);
    ImGui::TextWrapped("%s", verify_result_.c_str());
    ImGui::PopStyleColor();
  }
}

}  // namespace ui
