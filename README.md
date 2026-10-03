# MasterKey Derivator (C++)

Derivador de claves maestras para escritorio Linux, 100% airgapped. Deriva una
clave criptográfica a partir de una contraseña usando KDF de coste alto, con
**paridad criptográfica bit a bit** con dos referencias del stack: la app
Android v2.0 y la app Python/Linux v4.0 (PQC-grade). Dear ImGui + GLFW +
OpenGL3, ~2.7k líneas propias.

Dos modos:

- **Derivar** — contraseña + frase de salt + contexto → clave de 128 a
  512 bits, formateada en Base64, hexadecimal o Base64 URL-safe, con su
  fingerprint SHA-256.
- **Verificar** — pega una clave ya derivada y contrasta (**Verificar
  coincidencia**) contra la última derivada, sin volver a derivar.

<p align="center">
  <a href="https://github.com/disruptorh/Master-Key-Derivator-C-/releases/latest/download/masterkey_derivator">
    <img alt="Descargar" src="https://img.shields.io/badge/%E2%AC%87%20Download-latest%20release-2f6feb?style=for-the-badge&logo=github&logoColor=white">
  </a>
  <a href="https://github.com/disruptorh/Master-Key-Derivator-C-/releases/latest">
    <img alt="Versiones" src="https://img.shields.io/github/v/release/disruptorh/Master-Key-Derivator-C-?label=release&style=flat&logo=github&logoColor=white">
  </a>
  <a href="./LICENSE">
    <img alt="Licencia" src="https://img.shields.io/badge/licencia-Apache--2.0-blue?style=flat">
  </a>
</p>

## 📥 Descarga rápida

El botón de arriba descarga el asset `masterkey_derivator` de la release más
reciente publicada: un ejecutable **Linux x86-64 sin extensión de fichero**. Es un
único binario, no un instalador ni un `.tar.gz`.

Para usarlo desde una terminal, o para fijarte en una versión concreta:

```bash
curl -L -o masterkey_derivator https://github.com/disruptorh/Master-Key-Derivator-C-/releases/latest/download/masterkey_derivator && chmod +x masterkey_derivator && ./masterkey_derivator
```

No es un binario estático: enlaza dinámicamente contra `libOpenGL.so.0`,
`libglfw.so.3` y `libX11.so.6`. En Debian/Ubuntu se resuelven con:

```bash
sudo apt update && sudo apt install -y libopengl-dev libglfw3-dev libx11-dev libgl1
```

Para ejecutarlo sin pantalla (CI, contenedores, SSH sin X11):

```bash
sudo apt install -y xvfb && xvfb-run -a ./masterkey_derivator
```

## 🚀 Uso rápido

1. Elige **Algoritmo** (scrypt por defecto), **Longitud** (256 bits por
   defecto), **Formato** (Base64) y **Versión (compatibilidad)** (v2 APK por
   defecto, v3 PQC-grade).
2. Escribe la **Contraseña principal** y la **Frase de salt**. El campo
   *Contexto (opcional)* va vacío por defecto: vacío usa el contexto por defecto
   de la versión elegida.
3. Pulsa **Derivar**. Al terminar verás la clave formateada, su longitud y su
   fingerprint SHA-256 (40 hex), y podrás copiarla al portapapeles — que se
   auto-limpia a los 15 s (configurable con la variable de entorno
   `MKD_CLIPBOARD_TIMEOUT_MS`, en milisegundos).
4. En modo **Verificar**, pega la clave que quieres comprobar y pulsa
   **Verificar coincidencia**: la contrasta contra la última derivada sin volver
   a pagar el coste del KDF.

### Algoritmos y versiones

La versión fija los parámetros del KDF; el contexto solo cambia si lo escribes.

| | **v2 (APK)** | **v3 (PQC-grade)** |
|---|---|---|
| Scrypt | N=32768, r=8, p=1 | N=65536, r=8, p=2 |
| PBKDF2 | HMAC-SHA512, 600.000 iteraciones | HMAC-SHA512, 1.000.000 iteraciones |
| SHA3-512 iterativo | 200.000 pasadas | 500.000 pasadas |
| Contexto por defecto | `masterkey-derivator-v2` | `masterkey-derivator-v3-pqc-grade` |

Salt (los tres algoritmos, ambas versiones): `HMAC-SHA256(clave = frase de salt,
mensaje = contexto)` → 32 bytes.

Longitudes: 128, 192, 256 (por defecto) o 512 bits.

> La derivación es cara a propósito (Scrypt de 64 MiB, PBKDF2 de 1M iteraciones,
> SHA3-512 de 500k pasadas), así que corre en un **hilo worker**: la UI no se
> congela y el resultado se entrega a través de un buffer seguro protegido por
> mutex.

## 📦 Compilar desde código

### Requisitos

- CMake ≥ 3.20, compilador C++20 (GCC ≥ 10 o clang ≥ 12), pkg-config, make.
- Sistema: development headers de GLFW3, X11 y OpenGL.
- Opcionales: `clang-tidy` (activo por defecto), `clang-format`, `xvfb`.

### Clonar

Este repo **no tiene submódulos**: las dos dependencias están versionadas dentro
del propio repositorio, así que un `git clone` normal basta.

```bash
# 1. Clonar el repositorio
git clone https://github.com/disruptorh/Master-Key-Derivator-C-.git
cd Master-Key-Derivator-C--
```

### Dependencias

**Ya vendored en el repo, no hay que instalarlas** (el build no descarga nada de
la red; ver `third_party/VENDORED.md`):

| Dependencia | Dónde vive | Nota |
|---|---|---|
| libsodium 1.0.22 | `third_party/libsodium` | se compila estático vía autotools (`ExternalProject`) |
| Dear ImGui | `third_party/imgui` | parcheado para el perfil airgapped |

**Hay que instalarlas del sistema** (son las que pide el `CMakeLists.txt` vía
`find_package(OpenGL)` y `pkg_check_modules(glfw3, x11)`):

| Paquete Debian/Ubuntu | Para qué lo pide CMake |
|---|---|
| `build-essential` | g++, make |
| `cmake` | el propio build |
| `pkg-config` | `pkg_check_modules` |
| `libglfw3-dev` | `glfw3` (ventana, contexto GL, portapapeles) |
| `libx11-dev` | `x11` (portapapeles y display) |
| `libopengl-dev` | `find_package(OpenGL)` → `OpenGL::GL` |
| `libgl-dev` | cabeceras y `libGL.so` de Mesa |

```bash
# 2. Instalar las dependencias de compilación (Debian/Ubuntu)
sudo apt update && sudo apt install -y build-essential cmake pkg-config libglfw3-dev libx11-dev libopengl-dev libgl-dev
```

Para los chequeos estáticos (`MKD_ENABLE_CLANG_TIDY` viene en `ON`; si no
encuentra `clang-tidy` simplemente los salta):

```bash
# 2b. Herramientas de análisis estático (Debian/Ubuntu)
sudo apt update && sudo apt install -y clang-tidy clang-format
```

### Compilar

```bash
# 3. Configurar y compilar
cmake -S . -B build && cmake --build build -j
```

El ejecutable queda **directamente en `build/`**: `./build/masterkey_derivator`.
Nada de `build/Release/`. La primera build tarda bastante más que las siguientes,
porque libsodium se compila con autotools como `ExternalProject`.

### Ejecutar los tests

```bash
# 4. Suite de tests (requiere el binario ya compilado)
ctest --test-dir build --output-on-failure
```

| Target CTest | Qué cubre |
|---|---|
| `mkd_tests` | Paridad bit a bit con los vectores de las dos referencias (18 vectores × hex/Base64/Base64url/fingerprint), PBKDF2, SHA3-512, Base64, buffers seguros |
| `no_network_symbols` | `nm -D` sobre el binario: ninguna tabla dinámica con símbolos de red/DNS/shell/`dlopen` |
| `no_sensitive_test_strings_in_binary` | `strings` sobre el binario: las contraseñas/salts de los vectores de test no aparecen compilados |
| `crypto_layer_has_no_imgui` | La capa criptográfica no incluye Dear ImGui (el core es testeable aislado) |

`mkd_tests` se compila con
`-Wl,--wrap=sodium_malloc,--wrap=sodium_free,--wrap=sodium_mlock` para poder
comprobar de forma determinista que la zeroización ocurre. Los dos últimos no son
tests de comportamiento: son guardas de invariantes sobre el binario y las
fuentes.

### Ejecutar la aplicación

```bash
# 5. Lanzar la GUI
./build/masterkey_derivator
```

La app usa `mlock` para fijar el material sensible en RAM. Si el límite de
memoria bloqueada es bajo, los buffers no se pueden fijar: el ruido viene de
`ulimit -l`. Se recomienda devolverlo a `unlimited` en tu shell antes de lanzar
la app:

```bash
# 6. Recomendado: sin límite de memoria bloqueada
ulimit -l unlimited && ./build/masterkey_derivator
```

## 🧰 Comandos útiles / Opciones

Opciones de CMake:

| Opción | Por defecto | Qué hace |
|---|---|---|
| `MKD_BUILD_TESTS` | `ON` | Compila `mkd_tests` y registra los tests de CTest |
| `MKD_ENABLE_CLANG_TIDY` | `ON` | Aplica `clang-tidy` con el `.clang-tidy` del repo sobre `mkd_core` y `masterkey_derivator` (se salta si no está instalado) |
| `CMAKE_BUILD_TYPE` | `Release` | Se fuerza a `Release` si no lo pasas |

```bash
# Build sin suite de tests ni clang-tidy (más rápido)
cmake -S . -B build -DMKD_BUILD_TESTS=OFF -DMKD_ENABLE_CLANG_TIDY=OFF && cmake --build build -j
```

Variables de entorno que la app lee:

| Variable | Por defecto | Efecto |
|---|---|---|
| `MKD_CLIPBOARD_TIMEOUT_MS` | `15000` | Milisegundos hasta el auto-clear del portapapeles |
| `MKD_SMOKE_MS` | `0` | *Test seam*: cierra el bucle de eventos tras N ms, para CI y valgrind |

### Humo de la GUI sin pantalla

`MKD_SMOKE_MS` es un *test seam* de `src/main.cpp`: cierra el bucle de eventos
limpiamente tras N ms para que CI y valgrind puedan ejercitar el ciclo
init → frame → teardown completo y dar un resumen de fugas fiable. No se usa en
producción.

```bash
# Humo: abrir y cerrar la ventana limpiamente tras 1,5 s
MKD_SMOKE_MS=1500 xvfb-run -a ./build/masterkey_derivator
```

Este repo **no trae script e2e de GUI**: no hay `scripts/e2e_gui_test.sh`. Lo
más cercano es el humo de arriba, que comprueba el arranque y el apagado pero no
navega por los widgets.

### Regenerar los vectores de paridad

Los vectores de `tests/` no se editan a mano: se generan ejecutando el código de
la app Python de referencia. El script **exige** `--kdf-src` con la ruta al
directorio `src/` de la app Python v4.0 (`Master-Key-Creator-Linux`), que es un
repo externo a este, así que el comando no se puede dar listo para pegar sin esa
ruta. La forma es:

```text
python3 scripts/gen_kdf_vectors.py --kdf-src <ruta a Master-Key-Creator-Linux/src> -o tests/kdf_vectors.generated.hpp
```

Ambos argumentos son obligatorios. Emite un `.hpp` (el que consume
`tests/test_kdf.cpp`) y un `.json` (`tests/kdf_vectors.generated.json`) para
inspección humana.

## 🗂️ Estructura del proyecto

```text
.
├── CMakeLists.txt          # targets, vendored, guardas de CTest
├── .clang-tidy             # checks estáticos sobre las fuentes propias
├── .clang-format
├── scripts/
│   ├── check_no_network.cmake            # nm -D: sin símbolos de red/exec/dlopen
│   ├── check_no_sensitive_strings.cmake  # strings: sin secretos de test compilados
│   ├── check_crypto_no_imgui.cmake       # el core no puede referenciar ImGui
│   └── gen_kdf_vectors.py                # regenera los vectores desde la app Python
├── src/
│   ├── main.cpp            # init GLFW/ImGui + hardening de runtime
│   ├── secure_mem/         # buffers mlock'ed, secure_string, byte_buffer
│   ├── crypto/
│   │   ├── kdf.cpp               # scrypt / pbkdf2 / sha3-512 + salt fija + dispatcher
│   │   └── pbkdf2.cpp, sha3.cpp, base64.cpp   # implementación propia (paridad Python)
│   ├── clipboard/          # portapapeles X11 con auto-clear
│   ├── security/           # seccomp-BPF (bloquea sockets de red)
│   └── ui/                 # app (estado + worker) + pantallas derive/verify
├── tests/                  # suite propia + vectores de paridad generados
└── third_party/            # libsodium 1.0.22 + imgui (vendored, ver VENDORED.md)
```

El core (`mkd_core` = todo `src/` salvo `ui/`, `clipboard/` y `security/`) es
independiente de la GUI: lo comparten la app y la suite de tests, y un test de
CTest lo verifica.

## 🔐 Seguridad

### Modelo de seguridad

- **Paridad, no diseño propio.** Los parámetros, salts y contextos están
  fijados por compatibilidad con las dos apps de referencia: cambiarlos rompe la
  derivación de claves ya derivadas en ellas. Si hay que subirlos de nuevo, crear
  una v4.
- **Airegap**: sin símbolos de red en el binario y filtro seccomp que rechaza
  `AF_INET`/`AF_INET6` en el kernel (los sockets `AF_UNIX` siguen permitidos
  para X11/Wayland). Si el kernel rechaza el filtro la app **arranca igual**
  (fail-open) y avisa por stderr: pierde el refuerzo, no la función.
- **Confidencialidad en memoria**: buffers `mlock`'ed que se ponen a cero con
  `sodium_memzero` al destruirse; `RLIMIT_CORE=0` evita que un dump core escriba
  la clave a disco.
- **La contraseña y la frase de salt no son la clave.** Son la entrada del KDF:
  la seguridad de la clave derivada depende del coste del KDF elegido y de la
  entropía de la contraseña. El contexto es un dominio de separación, no un
  secreto.
- **Sin escritura a disco**: ni estado de ventana de ImGui, ni caches de shaders,
  ni core dumps. La app no escribe archivos en absoluto.

### Sobre la versión

El `project()` del `CMakeLists.txt` declara `VERSION 4.0.0`, que es la versión del
**algoritmo** (la de la app Python de referencia que replica), no el número de la
release de GitHub. La release publicada es la 1.0.

### Endurecimiento de compilación

Todos los targets se compilan con `-Wall -Wextra -Wpedantic
-fstack-protector-strong`, `_FORTIFY_SOURCE=2` (salvo en `Debug`) y las opciones
de enlace `-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack`. Dear ImGui se compila con
`IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS` (elimina el "open in shell" con
`fork`/`execvp`) y su loader de OpenGL resuelve los entry points con
`glfwGetProcAddress()` en vez de `dlopen()`.

Este repo no trae perfil AppArmor ni script de instalación de ninguno: el
endurecimiento se queda en seccomp + las guardas de CTest.

## 📄 Licencia

Apache-2.0 (ver `LICENSE`). Las dependencias vendored conservan sus propias
licencias: libsodium 1.0.22 (ISC) y Dear ImGui (MIT).