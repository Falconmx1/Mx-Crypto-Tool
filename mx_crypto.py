#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import getpass

# Banner bien chingón
def show_banner():
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║     ███╗   ███╗ ██╗  ██╗                      ║
    ║     ████╗ ████║ ╚██╗██╔╝                      ║
    ║     ██╔████╔██║  ╚███╔╝                       ║
    ║     ██║╚██╔╝██║  ██╔██╗                       ║
    ║     ██║ ╚═╝ ██║ ██╔╝ ██╗                      ║
    ║     ╚═╝     ╚═╝ ╚═╝  ╚═╝                      ║
    ║                                               ║
    ║         M X   C R Y P T O   T O O L          ║
    ║            Cifrado para la banda             ║
    ║                   v1.0                        ║
    ╚═══════════════════════════════════════════════╝
    """
    print(banner)

# AES-256-CBC
def pad(data):
    return data + b"\x00" * (16 - len(data) % 16)

def unpad(data):
    return data.rstrip(b"\x00")

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad(plaintext.encode())) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(key, ciphertext_b64):
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = unpad(decryptor.update(ciphertext) + decryptor.finalize())
    return plaintext.decode()

# RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("private_key.pem", "wb") as f:
        f.write(pem_private)
    with open("public_key.pem", "wb") as f:
        f.write(pem_public)

    print("[✓] Llaves RSA guardadas como private_key.pem y public_key.pem")

def rsa_encrypt(public_key_path, message):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(private_key_path, ciphertext_b64):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return plaintext.decode()

# Hashes
def get_hash(text, algo="sha256"):
    h = hashlib.new(algo)
    h.update(text.encode())
    return h.hexdigest()

def hash_file(filepath, algo="sha256"):
    h = hashlib.new(algo)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# Base64
def b64_encode(text):
    return base64.b64encode(text.encode()).decode()

def b64_decode(text):
    return base64.b64decode(text.encode()).decode()

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        show_banner()
        print("\n   MENÚ PRINCIPAL\n")
        print("   1. Cifrar texto (AES-256)")
        print("   2. Descifrar texto (AES-256)")
        print("   3. Generar llaves RSA")
        print("   4. Cifrar con RSA")
        print("   5. Descifrar con RSA")
        print("   6. Generar hash de texto")
        print("   7. Hash de archivo")
        print("   8. Base64 Encode/Decode")
        print("   9. Salir")
        
        opcion = input("\n   Elige una opción: ")
        
        if opcion == "1":
            key = getpass.getpass("   Clave AES (32 caracteres): ").encode()
            if len(key) != 32:
                print("   [!] La clave debe ser de 32 bytes")
                input()
                continue
            texto = input("   Texto a cifrar: ")
            res = aes_encrypt(key, texto)
            print(f"\n   [✓] Cifrado: {res}")
            input()
        
        elif opcion == "2":
            key = getpass.getpass("   Clave AES (32 caracteres): ").encode()
            if len(key) != 32:
                print("   [!] La clave debe ser de 32 bytes")
                input()
                continue
            cifrado = input("   Texto cifrado (base64): ")
            try:
                res = aes_decrypt(key, cifrado)
                print(f"\n   [✓] Descifrado: {res}")
            except Exception as e:
                print(f"   [!] Error: {e}")
            input()
        
        elif opcion == "3":
            generate_rsa_keys()
            input()
        
        elif opcion == "4":
            texto = input("   Texto a cifrar: ")
            try:
                res = rsa_encrypt("public_key.pem", texto)
                print(f"\n   [✓] Cifrado RSA: {res}")
            except:
                print("   [!] Genera llaves RSA primero (opción 3)")
            input()
        
        elif opcion == "5":
            cifrado = input("   Texto cifrado RSA (base64): ")
            try:
                res = rsa_decrypt("private_key.pem", cifrado)
                print(f"\n   [✓] Descifrado: {res}")
            except:
                print("   [!] Error al descifrar")
            input()
        
        elif opcion == "6":
            texto = input("   Texto: ")
            print("\n   MD5:", get_hash(texto, "md5"))
            print("   SHA1:", get_hash(texto, "sha1"))
            print("   SHA256:", get_hash(texto, "sha256"))
            print("   SHA512:", get_hash(texto, "sha512"))
            input()
        
        elif opcion == "7":
            archivo = input("   Ruta del archivo: ")
            if os.path.exists(archivo):
                print("\n   SHA256:", hash_file(archivo, "sha256"))
                print("   MD5:", hash_file(archivo, "md5"))
            else:
                print("   [!] Archivo no encontrado")
            input()
        
        elif opcion == "8":
            modo = input("   1. Encode | 2. Decode: ")
            texto = input("   Texto: ")
            if modo == "1":
                print(f"\n   [✓] {b64_encode(texto)}")
            else:
                try:
                    print(f"\n   [✓] {b64_decode(texto)}")
                except:
                    print("   [!] Base64 inválido")
            input()
        
        elif opcion == "9":
            print("\n   Bye bye, compa 🤘")
            sys.exit()
        
        else:
            print("   Opción no válida")
            input()

if __name__ == "__main__":
    main()
