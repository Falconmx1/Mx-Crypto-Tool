#!/bin/bash

echo "Instalando Mx Crypto Tool..."

if ! command -v python3 &> /dev/null; then
    echo "Python3 no encontrado. Instálalo primero."
    exit 1
fi

pip3 install cryptography pycryptodome

echo "Instalación completa. Corre con: python3 mx_crypto.py"
