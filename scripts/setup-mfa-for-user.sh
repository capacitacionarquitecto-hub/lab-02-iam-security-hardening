#!/bin/bash
# Script para que los usuarios configuren su MFA

USERNAME=$1

if [ -z "$USERNAME" ]; then
  echo "Uso: ./setup-mfa-for-user.sh <username>"
  exit 1
fi

echo "Configurando MFA para $USERNAME..."

# Crear dispositivo virtual MFA
SERIAL=$(aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name "${USERNAME}-mfa" \
  --outfile /tmp/${USERNAME}-qr.png \
  --bootstrap-method QRCodePNG \
  --query 'VirtualMFADevice.SerialNumber' \
  --output text)

echo "✅ Dispositivo MFA creado: $SERIAL"
echo "📱 Código QR guardado en: /tmp/${USERNAME}-qr.png"
echo ""
echo "INSTRUCCIONES:"
echo "1. Abre Google Authenticator o Authy en tu teléfono"
echo "2. Escanea el código QR en /tmp/${USERNAME}-qr.png"
echo "3. Ingresa dos códigos consecutivos cuando se te solicite"
echo ""
read -p "Código 1: " CODE1
read -p "Código 2: " CODE2

# Habilitar MFA
aws iam enable-mfa-device \
  --user-name $USERNAME \
  --serial-number $SERIAL \
  --authentication-code1 $CODE1 \
  --authentication-code2 $CODE2

echo "✅ MFA habilitado exitosamente para $USERNAME"
rm /tmp/${USERNAME}-qr.png
