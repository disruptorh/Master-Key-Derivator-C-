#!/usr/bin/env python3
"""Genera vectores de prueba de paridad criptografica.

Emite vectores para las DOS versiones soportadas por la app C++:

  - version "v3" -> crypto_core/kdf.py (app Python de referencia,
                    MasterKey Derivator v4.0 / Master-Key-Creator-Linux):
      Scrypt N=65536,r=8,p=2 | PBKDF2 1M | SHA3-512 500k
      contexto por defecto "masterkey-derivator-v3-pqc-grade"
  - version "v2" -> Master-key-Creator-apk (MasterKey Derivator v2.0):
      Scrypt N=32768,r=8,p=1 | PBKDF2 600k | SHA3-512 200k
      contexto por defecto "masterkey-derivator-v2"

El test C++ (tests/test_kdf.cpp) compara sus salidas contra estos valores.

Uso:
  python3 scripts/gen_kdf_vectors.py \
      --kdf-src /ruta/Master-Key-Creator-Linux/src \
      -o tests/kdf_vectors.generated.hpp
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def load_kdf(kdf_src):
    sys.path.insert(0, os.path.abspath(kdf_src))
    from crypto_core.kdf import (
        derive_pbkdf2_sha512_pqc,
        derive_scrypt_pqc,
        derive_sha3_512_iterative,
    )
    return derive_scrypt_pqc, derive_pbkdf2_sha512_pqc, derive_sha3_512_iterative


def derive_v2(algo, password, salt_phrase, context, length):
    """Reproduce la app APK v2.0 (BouncyCastle/JCE) con primitivas Python."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend

    msg = context.encode("utf-8") if context else b"masterkey-derivator-v2"
    salt = hmac.new(salt_phrase.encode("utf-8"), msg, hashlib.sha256).digest()
    if algo == "scrypt":
        kdf = Scrypt(
            salt=salt,
            length=length,
            n=32768,
            r=8,
            p=1,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))
    if algo == "pbkdf2":
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=length,
            salt=salt,
            iterations=600_000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))
    # sha3: cadena pura de SHA3-512, 200k pasadas.
    data = password.encode("utf-8") + salt
    for _ in range(200_000):
        data = hashlib.sha3_512(data).digest()
    return data[:length]


VECTORS = [
    # (algoritmo, password, salt_phrase, context, length)
    ("scrypt", "P@ssw0rd#Fuerte", "frase-salt-ejemplo-1", "wallet-bitcoin", 32),
    ("scrypt", "MiClaveSecreta#2026", "segunda-frase-secreta", "", 64),
    ("scrypt", "contrase\u00f1a-acentuada-123", "salt-acentos-2026", "servidor-ssh", 48),
    ("pbkdf2", "P@ssw0rd#Fuerte", "frase-salt-ejemplo-1", "wallet-bitcoin", 32),
    ("pbkdf2", "MiClaveSecreta#2026", "segunda-frase-secreta", "", 64),
    ("pbkdf2", "contrase\u00f1a-acentuada-123", "salt-acentos-2026", "servidor-ssh", 16),
    ("sha3", "P@ssw0rd#Fuerte", "frase-salt-ejemplo-1", "wallet-bitcoin", 64),
    ("sha3", "MiClaveSecreta#2026", "segunda-frase-secreta", "", 32),
    ("sha3", "contrase\u00f1a-acentuada-123", "salt-acentos-2026", "servidor-ssh", 17),
]


def make_entry(version, algo, pw, salt, ctx, length, key):
    fingerprint = hashlib.sha256(key).hexdigest()[:40]
    return {
        "version": version,
        "algo": algo,
        "password": pw,
        "salt_phrase": salt,
        "context": ctx,
        "length": length,
        "key_hex": key.hex(),
        "key_b64": base64.b64encode(key).decode(),
        "key_b64url": base64.urlsafe_b64encode(key).decode(),
        "fingerprint": fingerprint,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kdf-src", required=True)
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args()

    scrypt_f, pbkdf2_f, sha3_f = load_kdf(args.kdf_src)
    funcs = {
        "scrypt": scrypt_f,
        "pbkdf2": pbkdf2_f,
        "sha3": sha3_f,
    }

    entries = []
    for algo, pw, salt, ctx, length in VECTORS:
        key_v3 = funcs[algo](pw, salt, ctx, length)
        entries.append(make_entry("v3", algo, pw, salt, ctx, length, key_v3))
        key_v2 = derive_v2(algo, pw, salt, ctx, length)
        entries.append(make_entry("v2", algo, pw, salt, ctx, length, key_v2))

    lines = []
    lines.append("// kdf_vectors.generated.hpp - GENERADO POR scripts/gen_kdf_vectors.py")
    lines.append("// Vectores de paridad bit-a-bit con MasterKey Derivator v2.0 (APK)")
    lines.append("// y v4.0/v3-pqc-grade (Python/Linux).")
    lines.append("// NO editar a mano: modificar el generador y volver a ejecutarlo.")
    lines.append("#pragma once")
    lines.append("#include <cstddef>")
    lines.append("#include <cstdint>")
    lines.append("#include <string>")
    lines.append("")
    lines.append("namespace test_vectors {")
    lines.append("struct kdf_vector {")
    lines.append("  const char* version;")
    lines.append("  const char* algorithm;")
    lines.append("  const char* password;")
    lines.append("  const char* salt_phrase;")
    lines.append("  const char* context;")
    lines.append("  std::size_t length;")
    lines.append("  const char* key_hex;")
    lines.append("  const char* key_b64;")
    lines.append("  const char* key_b64url;")
    lines.append("  const char* fingerprint;")
    lines.append("};")
    lines.append("inline constexpr kdf_vector kVectors[] = {")
    for e in entries:
        def cstr(s):
            return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
        lines.append(
            "  {%s, %s, %s, %s, %s, %d, %s, %s, %s, %s},"
            % (cstr(e["version"]), cstr(e["algo"]), cstr(e["password"]),
               cstr(e["salt_phrase"]), cstr(e["context"]), e["length"],
               cstr(e["key_hex"]), cstr(e["key_b64"]),
               cstr(e["key_b64url"]), cstr(e["fingerprint"])))
    lines.append("};")
    lines.append("inline constexpr std::size_t kVectorCount = "
                 + str(len(entries)) + ";")
    lines.append("}  // namespace test_vectors")
    lines.append("")

    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # Resumen tambien en JSON para inspeccion humana.
    json_out = os.path.splitext(args.output)[0] + ".json"
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)

    print("Generados %d vectores -> %s / %s" % (len(entries), args.output, json_out))


if __name__ == "__main__":
    main()
