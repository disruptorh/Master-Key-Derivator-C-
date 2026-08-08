 # Plan de Implementación: Master-Key-Creator-Linux en C++ (Air-Gapped & PQC-Grade)

## 1. Resumen Ejecutivo
El objetivo es reescribir la aplicación **MasterKey Derivator v4.0** de Python a C++ de alto rendimiento y seguridad, igualando el stack tecnológico y estético de los proyectos de referencia (`Bip39-Generator-C++` y `Encrypt-C++`). 

**Regla de Oro:** **NO SE DEBEN ROMPER LAS SALIDAS.** Los algoritmos, los salts y los iteradores deben generar **exactamente los mismos bytes** para garantizar que las contraseñas actuales del usuario sigan siendo válidas. La aplicación será 100% offline, "air-gapped", con protecciones de memoria y restricciones de sistema (seccomp).

---

## 2. Stack Tecnológico Objetivo

| Componente | Tecnología (C++) | Justificación |
| :--- | :--- | :--- |
| **Sistema de Build** | CMake (>= 3.20) | Compilación modular, integración estática de dependencias. |
| **UI Framework** | Dear ImGui + GLFW + OpenGL3 | Renderizado de interfaz rápido, sin dependencias complejas del sistema y estéticamente idéntico a los proyectos de referencia. |
| **Criptografía** | OpenSSL (libcrypto estático) o Botan/libsodium | Se requiere acceso de bajo nivel a Scrypt, PBKDF2-SHA512 y SHA3-512 puro. |
| **Seguridad Memoria** | `sodium_memzero` / Allocators seguros | Prevención de filtrado de memoria RAM (cold-boot attacks). |
| **Aislamiento** | Seccomp-BPF (Linux) | Bloqueo estricto a nivel de kernel para evitar llamadas de red (`socket()`, `connect()`). |

---

## 3. Paridad Criptográfica (CRÍTICO)

Para mantener la compatibilidad con las llaves derivadas previamente, la capa criptográfica en C++ (`crypto_core`) deberá replicar *bit a bit* la lógica de `kdf.py`.

### 3.1. Generación de Salt (HMAC-SHA256)
*   **Python:** `hmac.new(salt_phrase.encode(), context.encode() or b"masterkey-derivator-v3-pqc-grade", sha256)`
*   **C++:** Utilizar `HMAC(EVP_sha256(), ...)` asegurando que si el contexto está vacío, se use la cadena hardcodeada `"masterkey-derivator-v3-pqc-grade"`.

### 3.2. Algoritmos de Derivación
1.  **Scrypt (Recomendado PQC-grade):**
    *   **Parámetros:** `N = 65536`, `r = 8`, `p = 2`.
    *   **Implementación:** Usar `EVP_PBE_scrypt` de OpenSSL o la primitiva de bajo nivel de libsodium (`crypto_pwhash_scryptsalsa208sha256_ll`).
2.  **PBKDF2-SHA512 (1M Iteraciones):**
    *   **Parámetros:** Algoritmo SHA-512, 1,000,000 iteraciones.
    *   **Implementación:** `PKCS5_PBKDF2_HMAC` con `EVP_sha512()`.
3.  **SHA3-512 Iterativo (500k):**
    *   **Lógica exactita:** `data = password + salt`, iterar 500,000 veces aplicando `SHA3-512(data)`.
    *   **Implementación:** Bucle estricto usando `EVP_MD_CTX` de `EVP_sha3_512()`. El truncado final debe ser `data[:length]`.

### 3.3. Formatos de Salida
*   **Hexadecimal:** Representación en minúsculas.
*   **Base64:** Base64 estándar (`+` y `/`).
*   **Base64 URL-safe:** Base64 sin padding (`-` y `_`).

---

## 4. Prácticas de Seguridad y Aislamiento (Air-Gapped)

El nivel de seguridad debe equipararse a `/home/reimen/Escritorio/Projects/Bip39-Generator-C++`.

### 4.1. Prevención de Ataques en Memoria
*   **Secure Allocator:** Implementar una clase `SecureBuffer<T>` que utilice `mlock()` al ser creada y `munlock()` junto con borrado seguro (`explicit_bzero` o `sodium_memzero`) en su destructor. Todos los inputs de contraseñas y claves derivadas en la memoria de la app usarán este allocator.
*   **Ocultación UI:** El input de ImGui de la contraseña debe estar enmascarado por defecto (`ImGuiInputTextFlags_Password`).

### 4.2. Aislamiento del Sistema (Sandbox)
*   **Seccomp-BPF:** Integrar un filtro de syscalls. Permitir solo: `read`, `write`, `poll`, `mmap` (necesarios para ImGui/X11), y *DENEGAR* rotundamente `socket`, `connect`, `sendto`, `execve`.
*   **Red Auditada:** El script de CMake `check_no_network.cmake` del proyecto Bip39 será reutilizado en la etapa de Test/CI para asegurar que el binario final no contenga símbolos como `getaddrinfo` o dependencias de red.

### 4.3. Gestión del Portapapeles X11 / Wayland
*   Replicar la lógica estilo KeePass de `clipboard.py`.
*   Usar GLFW (`glfwSetClipboardString`) combinado con un thread/temporizador en C++ que borre el portapapeles exactamente a los **15 segundos**.
*   **Verificación Previa:** Antes de borrar el portapapeles a los 15s, leer el contenido; si el contenido difiere de la clave generada, no borrar (el usuario copió algo más).

### 4.4. Hardening de Compilación
Añadir las siguientes banderas al `CMakeLists.txt`:
```cmake
add_compile_options(-Wall -Wextra -Wpedantic -fstack-protector-strong)
add_compile_definitions(_FORTIFY_SOURCE=2)
add_link_options(-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack)
```

---

## 5. UI y Experiencia de Usuario (Estilo Moderno)

Se implementará una arquitectura basada en **ImGui** con tema oscuro moderno, idéntica a `Encrypt-C++`.
*   **Estructura de Vistas:** `src/ui/app.cpp` manejará las "Pestañas" (Derivar Clave / Verificar).
*   **Componentes Custom ImGui:** 
    *   Barras de progreso de entropía con interpolación de color (Rojo -> Naranja -> Verde).
    *   Badges descriptivas ("PQC-Grade") renderizadas con colores de acento verde brillante.
*   **Fuente:** Se embeberá en binario la fuente Inter o Segoe UI a través de ImGui para una apariencia premium.

---

## 6. Fases de Implementación

*   **Fase 1: Infraestructura y CMake.** Crear la estructura de carpetas (`src`, `tests`, `third_party`), vendimiar Dear ImGui, GLFW y OpenSSL/libsodium (compilados de forma estática pura).
*   **Fase 2: Motor Criptográfico.** Escribir `crypto_core.cpp`. **Hito crítico:** Implementar pruebas unitarias (`tests/test_kdf.cpp`) comparando vectores de prueba conocidos generados por la app de Python contra las salidas de C++ para asegurar 100% de paridad.
*   **Fase 3: Seguridad de Memoria y Sistema.** Desarrollar el `SecureBuffer` y el módulo `seccomp.cpp`. Integrar el borrado automático de portapapeles temporizado.
*   **Fase 4: Interfaz de Usuario.** Construir los widgets ImGui, calcular entropía visualmente, e interconectar los inputs del usuario con el backend criptográfico.
*   **Fase 5: Build Final y Hardening.** Configuración del ejecutable para perfiles `Release` y `Release-Asan`, validando la ausencia de funciones de red (Air-Gapped Audit).

