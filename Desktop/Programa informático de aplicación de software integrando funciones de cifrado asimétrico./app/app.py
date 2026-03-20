# -*- coding: utf-8 -*-
"""
Flipobook — aplicación web educativa que simula una red social y demuestra ECC/ECDH/HKDF.

Al registrarse un usuario válido se generan sus claves y se simula un chat seguro
con otro usuario ficticio para ilustrar la comunicación privada entre pares.
"""

from __future__ import annotations

import os
import re

from flask import Flask, flash, redirect, render_template, request, session, url_for

from crypto_ecc import comunicar_entre_dos_usuarios, generar_claves

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    root_path=_BASE_DIR,
    template_folder=os.path.join(_BASE_DIR, "templates"),
)
app.secret_key = os.environ.get("FLIPBOOK_SECRET", "dev-cambiar-en-produccion")

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
PHONE_RE = re.compile(r"^\d{10}$")


def validar_nombre(v: str) -> str | None:
    if not v or not str(v).strip():
        return "El nombre no puede estar vacío."
    return None


def validar_correo(v: str) -> str | None:
    if not v or not str(v).strip():
        return "El correo no puede estar vacío."
    if not EMAIL_RE.match(v.strip()):
        return "El formato del correo electrónico no es válido."
    return None


def validar_celular(v: str) -> str | None:
    if not v or not str(v).strip():
        return "El celular no puede estar vacío."
    digitos = re.sub(r"\D", "", v)
    if len(digitos) != 10 or not PHONE_RE.match(digitos):
        return "El celular debe tener exactamente 10 dígitos."
    return None


def validar_contrasena(v: str) -> str | None:
    if not v:
        return "La contraseña no puede estar vacía."
    if len(v) < 10:
        return "La contraseña debe tener al menos 10 caracteres."
    if not re.search(r"[A-ZÁÉÍÓÚÑ]", v):
        return "Debe incluir al menos una letra mayúscula."
    if not re.search(r"\d", v):
        return "Debe incluir al menos un número."
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', v):
        return "Debe incluir al menos un carácter especial."
    return None


def validar_registro(datos) -> list[str]:
    errores: list[str] = []
    for f in (
        validar_nombre(datos.get("nombre", "")),
        validar_correo(datos.get("correo", "")),
        validar_celular(datos.get("celular", "")),
        validar_contrasena(datos.get("contrasena", "")),
    ):
        if f:
            errores.append(f)
    return errores


@app.route("/", methods=["GET"])
def index():
    """Página principal Flipobook: formulario o bienvenida si hay sesión reciente."""
    return render_template(
        "index.html",
        old={},
        registrado=session.get("flipobook_ok"),
        nombre=session.get("flipobook_nombre"),
        ecc=session.get("flipobook_ecc"),
    )


@app.route("/registro", methods=["POST"])
def registro():
    """Registro: valida, genera claves del usuario y simula canal seguro con otro usuario."""
    errores = validar_registro(request.form)
    if errores:
        for e in errores:
            flash(e, "error")
        return render_template("index.html", old=request.form, registrado=False)

    nombre = request.form.get("nombre", "").strip()
    correo = request.form.get("correo", "").strip()

    # Claves del usuario que se acaba de registrar (en producción la privada no se almacena en claro).
    par_registrado = generar_claves()

    otro = "Usuario_Flipobook_B"
    ecc = comunicar_entre_dos_usuarios(nombre, otro, par_a=par_registrado)

    print("\n=== Flipobook — claves ECC (educativo) ===")
    print(f"Nuevo usuario: {nombre} <{correo}>")
    print("Clave privada del registrado (PEM, solo en consola):")
    print(ecc["pem_privada_a"])
    print("Clave pública (usuario A):")
    print(ecc["pem_publica_a"])
    print("Clave pública (usuario B simulado):")
    print(ecc["pem_publica_b"])
    print("Derivada A (hex):", ecc["derivada_a_hex"])
    print("Derivada B (hex):", ecc["derivada_b_hex"])
    print("¿Coinciden las claves derivadas?", ecc["claves_coinciden"])
    print("Mensaje cifrado (hex):", ecc["mensaje_cifrado_hex"][:80] + "...")
    print("=== Fin consola ===\n")

    session["flipobook_ok"] = True
    session["flipobook_nombre"] = nombre
    session["flipobook_ecc"] = {
        "mensaje_exito": (
            "Usuario registrado en Flipobook con conexión segura mediante ECC"
        ),
        "otro_usuario": otro,
        "clave_derivada_coincide": ecc["claves_coinciden"],
        "mensaje_plano": ecc["mensaje_plano"],
        "mensaje_cifrado_hex_corto": ecc["mensaje_cifrado_hex"][:64] + "…",
    }

    flash(session["flipobook_ecc"]["mensaje_exito"], "success")
    return redirect(url_for("index"))


@app.route("/salir", methods=["GET"])
def salir():
    """Limpia la sesión para volver a probar el registro."""
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    puerto = int(os.environ.get("PORT", "5050"))
    print(f"Flipobook → http://127.0.0.1:{puerto}\n")
    app.run(debug=True, host="127.0.0.1", port=puerto)
