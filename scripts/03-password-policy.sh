#!/bin/bash
set -e
source ./scripts/env-vars.sh

echo "🔑 Configurando política de contraseñas enterprise-grade..."

# Configurar política de contraseñas
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 5 \
  --hard-expiry

echo "✅ Política de contraseñas configurada:"
echo "   • Mínimo 14 caracteres"
echo "   • Símbolos, números, mayúsculas y minúsculas requeridos"
echo "   • Expira cada 90 días"
echo "   • No reutilizar las últimas 5 contraseñas"

# ─── CREAR USUARIO DE PRUEBA CON MFA ─────────────────────────────

echo ""
echo "👤 Creando usuario de prueba..."

TEST_USER="test-developer"

aws iam create-user --user-name $TEST_USER 2>/dev/null || echo "Usuario ya existe"

# Agregar a grupo Developers
aws iam add-user-to-group \
  --group-name Developers \
  --user-name $TEST_USER

# Crear contraseña inicial
INITIAL_PASSWORD=$(openssl rand -base64 16)

aws iam create-login-profile \
  --user-name $TEST_USER \
  --password "$INITIAL_PASSWORD" \
  --password-reset-required 2>/dev/null || echo "Login profile ya existe"

echo "✅ Usuario creado: $TEST_USER"
echo "   Contraseña temporal: $INITIAL_PASSWORD"
echo "   (Debe cambiarla en el primer login)"

# ─── POLÍTICA PARA FORZAR MFA ─────────────────────────────────────

echo ""
echo "🔐 Creando política para forzar MFA..."

cat > policies/enforce-mfa-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowViewAccountInfo",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountPasswordPolicy",
        "iam:ListVirtualMFADevices"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowManageOwnPasswords",
      "Effect": "Allow",
      "Action": [
        "iam:ChangePassword",
        "iam:GetUser"
      ],
      "Resource": "arn:aws:iam::*:user/${aws:username}"
    },
    {
      "Sid": "AllowManageOwnMFA",
      "Effect": "Allow",
      "Action": [
        "iam:CreateVirtualMFADevice",
        "iam:DeleteVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ListMFADevices",
        "iam:ResyncMFADevice"
      ],
      "Resource": [
        "arn:aws:iam::*:mfa/${aws:username}",
        "arn:aws:iam::*:user/${aws:username}"
      ]
    },
    {
      "Sid": "DenyAllExceptListedIfNoMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken",
        "iam:ChangePassword"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
EOF

# Crear política
ENFORCE_MFA_ARN=$(aws iam create-policy \
  --policy-name "${PROJECT_NAME}-enforce-mfa" \
  --policy-document file://policies/enforce-mfa-policy.json \
  --query 'Policy.Arn' \
  --output text 2>/dev/null || \
  aws iam list-policies --query "Policies[?PolicyName=='${PROJECT_NAME}-enforce-mfa'].Arn" --output text)

# Aplicar a todos los grupos
for group in Developers DevOps ReadOnly; do
  aws iam attach-group-policy \
    --group-name $group \
    --policy-arn $ENFORCE_MFA_ARN 2>/dev/null || true
done

echo "✅ Política MFA aplicada a todos los grupos"

# ─── CREAR SCRIPT DE CONFIGURACIÓN MFA PARA USUARIOS ─────────────

cat > scripts/setup-mfa-for-user.sh << 'MFASCRIPT'
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
MFASCRIPT

chmod +x scripts/setup-mfa-for-user.sh

echo ""
echo "═══════════════════════════════════════════"
echo "✅ Política de contraseñas y MFA configurada"
echo "═══════════════════════════════════════════"
echo "Usuario de prueba: $TEST_USER"
echo "Para configurar MFA: ./scripts/setup-mfa-for-user.sh $TEST_USER"
echo "═══════════════════════════════════════════"