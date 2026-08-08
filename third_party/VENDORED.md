# third_party: dependencias vendored (build 100% offline)

Todas las dependencias del proyecto están vendored en este directorio y se
compilan como parte del build. El build **no descarga nada**: ni en configuración
ni en compilación. Cada árbol incluye su propia licencia.

## libsodium

- Directorio: `third_party/libsodium/`
- Upstream: https://github.com/jedisct1/libsodium
- Versión: **1.0.22** (`1.0.22-RELEASE`)
- Licencia: ISC (`LICENSE` dentro del árbol).
- Build: autotools vía `ExternalProject` (estático, `--disable-shared
  --disable-tests`). Mismo procedimiento que la app de referencia (BIP-39 /
  Encrypt C++).
- Uso criptográfico en este proyecto:
  - `crypto_pwhash_scryptsalsa208sha256_ll` → Scrypt (RFC 7914) con
    `N=65536, r=8, p=2`, byte-idéntico al `Scrypt` de la app Python
    (`cryptography`).
  - `crypto_auth_hmacsha256` → HMAC-SHA256 para la derivación de salt fija.
  - `crypto_auth_hmacsha512` → HMAC-SHA512, base de PBKDF2 (RFC 2898).
  - `crypto_hash_sha256` → fingerprint SHA-256 de la clave.
  - `crypto_pwhash_SALTBYTES` no se usa; el salt es el HMAC-SHA256 de 32 bytes.

## Dear ImGui

- Directorio: `third_party/imgui/`
- Upstream: https://github.com/ocornut/imgui
- Versión: **1.91.9** (`IMGUI_VERSION "1.91.9"`)
- Licencia: MIT (`LICENSE.txt` dentro del árbol).
- Uso: fuente compilada directamente en el target de la app (sin submodulo, sin
  descarga). Backend GLFW + OpenGL3.
- No se utiliza el loader dinámico de OpenGL: se compila con
  `IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS` y el backend OpenGL3 resuelve sus
  símbolos vía `glfwGetProcAddress()` (ver `imgui_impl_opengl3_loader.h`),
  evitando `dlopen`.
