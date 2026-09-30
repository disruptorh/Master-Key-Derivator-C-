# MasterKey Derivator (C++)

Derivador de claves maestras para escritorio Linux, 100% airgapped. Deriva una
clave criptográfica a partir de una contraseña usando KDF de coste alto, con
**paridad criptográfica bit a bit** con dos referencias del stack: la app
Android v2.0 y la app Python/Linux v4.0 (PQC-grade). Dear ImGui + GLFW +
OpenGL3, ~2.7k líneas propias.

Dos modos:

- **Derivar Clave** — contraseña + frase de salt + contexto → clave de 128 a
  512 bits, formateada en Base64, hexadecimal o Base64 URL-safe, con su
  fingerprint SHA-256.
- **Verificar** — pega una clave ya derivada y la contrasta contra la última
  derivada (mismo algoritmo y formato), sin volver a derivar.

- Sin red: todo vendored en `third_party/`, filtro seccomp-BPF que bloquea
  `socket()` AF_INET/AF_INET6, y tres tests de CTest que auditan el binario y las
  fuentes.
- Sin escritura automática a disco: ni estado de ventana, ni caches de shaders,
  ni core dumps. La app no escribe archivos en absoluto.
- Material sensible en memoria `mlock`'ed y auto-zeroed (RAII), incluidos los
  buffers de trabajo del worker thread.
- La derivación (Scrypt 64 MiB, PBKDF2 1M iteraciones, SHA3-512 500k pasadas)
  corre en un **hilo worker**: la UI no se congela y el resultado se entrega a
  través de un buffer seguro protegido por mutex.
- `clang-tidy` activo por defecto sobre las fuentes propias.

## Algoritmos y versiones

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

## Requisitos

- CMake ≥ 3.20, compilador C++20 (GCC ≥ 10 o clang ≥ 12), pkg-config, make.
- libsodium 1.0.22 y Dear ImGui: **ya vendored** en `third_party/` (ver
  `third_party/VENDORED.md`); no se descarga nada.
- libsodium se compila estático vía autotools como `ExternalProject` (la primera
  build tarda bastante más).
- GLFW3, X11 y OpenGL (dev headers) del sistema: `pkg-config glfw3 x11`.
- `clang-tidy` si quieres los chequeos estáticos (o `-DMKD_ENABLE_CLANG_TIDY=OFF`).
- `ulimit -l unlimited` recomendado (los buffers se bloquean en RAM con `mlock`).

## Build y tests

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/masterkey_derivator        # GUI (puede usarse con xvfb-run)
```

Opciones:

```sh
cmake -S . -B build -DMKD_ENABLE_CLANG_TIDY=OFF   # sin chequeos estáticos
cmake -S . -B build -DMKD_BUILD_TESTS=OFF         # sin suite de tests
MKD_SMOKE_MS=1500 xvfb-run -a ./build/masterkey_derivator   # humo de la GUI
```

`MKD_SMOKE_MS` es un *test seam*: cierra el bucle de eventos limpiamente tras N
ms para que CI y valgrind puedan ejercitar el ciclo init → frame → teardown
completo y dar un resumen de fugas fiable.

### Tests incluidos

| Target CTest | Qué cubre |
|---|---|
| `mkd_tests` | Paridad bit a bit con los vectores de las dos referencias (18 vectores × hex/Base64/Base64url/fingerprint), PBKDF2, SHA3-512, Base64, buffers seguros |
| `no_network_symbols` | `nm -D` sobre el binario: ninguna tabla dinámica con símbolos de red/DNS/shell/`dlopen` |
| `no_sensitive_test_strings_in_binary` | Las contraseñas/salts de los vectores de test no aparecen compilados en el binario |
| `crypto_layer_has_no_imgui` | La capa criptográfica no incluye Dear ImGui (el core es testeable aislado) |

### Regenerar los vectores de paridad

Los vectores no se editan a mano: se generan ejecutando el código de la app
Python de referencia.

```sh
python3 scripts/gen_kdf_vectors.py \
    --kdf-src /ruta/Master-Key-Creator-Linux/src \
    -o tests/kdf_vectors.generated.hpp
```

Emite un `.hpp` (el que consume `tests/test_kdf.cpp`) y un `.json` para inspección
humana.

## Uso

1. Elige **algoritmo** (scrypt por defecto), **longitud** (256 bits por
   defecto), **formato de salida** (Base64) y **versión** (v2 APK por defecto,
   v3 PQC-grade).
2. Escribe la **contraseña** y la **frase de salt**. El campo *contexto* es
   opcional: vacío usa el contexto por defecto de la versión elegida.
3. Pulsa **Derivar**. Al terminar verás la clave formateada, su longitud y su
   fingerprint SHA-256 (40 hex), y podrás copiarla al portapapeles — que se
   auto-limpia a los 15 s (configurable con `BIP39_CLIPBOARD_TIMEOUT_MS`).
4. En modo **Verificar**, pega la clave que quieres comprobar y pulsa
   **Verificar coincidencia**: la contrasta contra la última derivada sin volver
   a pagar el coste del KDF.

## Estructura

```
src/
  main.cpp            # init GLFW/ImGui + hardening de runtime
  secure_mem/         # buffers mlock'ed, secure_string, byte_buffer
  crypto/
    kdf.cpp           # scrypt / pbkdf2 / sha3-512 + salt fija + dispatcher
    pbkdf2.cpp, sha3.cpp, base64.cpp   # implementación propia (paridad Python)
  clipboard/          # portapapeles X11 con auto-clear
  security/           # seccomp-BPF (bloquea sockets de red)
  ui/                 # app (estado + worker) + pantallas derive/verify
tests/                # suite propia + vectores de paridad generados
scripts/              # checks de CTest + gen_kdf_vectors.py
third_party/          # libsodium 1.0.22 + imgui (vendored, ver VENDORED.md)
```

El core (`mkd_core` = todo `src/` salvo `ui/`, `clipboard/` y `security/`) es
independiente de la GUI: lo comparten la app y la suite de tests, y un test de
CTest lo verifica.

## Modelo de seguridad

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

## Licencia

Apache-2.0 (ver `LICENSE`). Las dependencias vendored conservan sus propias
licencias: libsodium 1.0.22 (ISC) y Dear ImGui (MIT).
