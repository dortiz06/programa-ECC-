# -*- coding: utf-8 -*-
"""
Módulo ECC para Flipobook (educativo).

¿Qué es ECC (Elliptic Curve Cryptography)?
-----------------------------------------
Es criptografía asimétrica basada en curvas elípticas sobre campos finitos. Cada
usuario tiene una clave privada (secreta) y una pública (compartible). La curva
SECP256R1 (NIST P-256) es un estándar muy usado en TLS y dispositivos móviles.

¿Qué es ECDH (Elliptic Curve Diffie-Hellman)?
---------------------------------------------
Protocolo de acuerdo de claves: dos partes intercambian solo sus claves públicas
y, cada una con su propia clave privada, calculan el mismo valor compartido sin
enviar ese secreto por la red. Aquí se simula un segundo usuario para mostrar el
intercambio antes de derivar una clave simétrica con HKDF-SHA256.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVA = ec.SECP256R1()


def generar_claves() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Genera un par de claves ECC en la curva SECP256R1.

    Returns:
        (clave_privada, clave_publica): la privada debe protegerse; la pública
        puede publicarse (p. ej. en un directorio de la red social).
    """
    privada = ec.generate_private_key(CURVA)
    publica = privada.public_key()
    return privada, publica


def generar_secreto(
    clave_privada_local: ec.EllipticCurvePrivateKey,
    clave_publica_remota: ec.EllipticCurvePublicKey,
    *,
    info: bytes = b"flipobook-ecdh",
) -> bytes:
    """
    Realiza ECDH entre la clave privada local y la clave pública del otro usuario,
    y deriva una clave simétrica con HKDF usando SHA-256.

    Args:
        clave_privada_local: clave privada del usuario que inicia el acuerdo.
        clave_publica_remota: clave pública del otro extremo (p. ej. del amigo).
        info: etiqueta de contexto para HKDF (evita mezclar usos de la misma clave).

    Returns:
        Bytes de clave simétrica derivada (32 bytes con la configuración por defecto).
    """
    secreto_crudo = clave_privada_local.exchange(ec.ECDH(), clave_publica_remota)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(secreto_crudo)


def clave_publica_a_pem(publica: ec.EllipticCurvePublicKey) -> str:
    """Serializa una clave pública a PEM (texto) para depuración o registro en consola."""
    return publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def clave_privada_a_pem(privada: ec.EllipticCurvePrivateKey) -> str:
    """Serializa la clave privada a PEM (solo para pruebas; en producción, nunca exponer)."""
    return privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def simular_mensaje_cifrado(clave_derivada: bytes, texto_plano: str) -> str:
    """
    Simula el envío de un mensaje privado: cifra con AES-256-GCM usando los primeros
    32 bytes de la clave derivada (material típico tras HKDF). Devuelve hex legible.
    """
    clave_aes = clave_derivada[:32]
    aes = AESGCM(clave_aes)
    nonce = os.urandom(12)
    datos = aes.encrypt(nonce, texto_plano.encode("utf-8"), associated_data=None)
    return (nonce + datos).hex()


def comunicar_entre_dos_usuarios(
    nombre_a: str,
    nombre_b: str,
    mensaje_privado: str = "Hola, mensaje privado en Flipobook",
    par_a: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey] | None = None,
) -> dict:
    """
    Simula dos miembros de Flipobook con sus claves, verifica ECDH y muestra un
    mensaje cifrado de ejemplo entre ellos.

    Si ``par_a`` se omite, se genera un nuevo par para el usuario A (registrado).

    Returns:
        Diccionario con PEMs, hex de clave derivada, texto cifrado simulado y flags.
    """
    if par_a is None:
        priv_a, pub_a = generar_claves()
    else:
        priv_a, pub_a = par_a
    priv_b, pub_b = generar_claves()

    derivada_desde_a = generar_secreto(priv_a, pub_b)
    derivada_desde_b = generar_secreto(priv_b, pub_a)

    return {
        "usuario_a": nombre_a,
        "usuario_b": nombre_b,
        "pem_publica_a": clave_publica_a_pem(pub_a),
        "pem_publica_b": clave_publica_a_pem(pub_b),
        "pem_privada_a": clave_privada_a_pem(priv_a),
        "pem_privada_b": clave_privada_a_pem(priv_b),
        "derivada_a_hex": derivada_desde_a.hex(),
        "derivada_b_hex": derivada_desde_b.hex(),
        "claves_coinciden": derivada_desde_a == derivada_desde_b,
        "mensaje_plano": mensaje_privado,
        "mensaje_cifrado_hex": simular_mensaje_cifrado(derivada_desde_a, mensaje_privado),
    }
