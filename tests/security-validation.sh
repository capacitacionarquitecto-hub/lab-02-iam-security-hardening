#!/bin/bash
set -e
source ./scripts/env-vars.sh

echo "🧪 Ejecutando tests de seguridad..."

PASS=0
FAIL=0

# Test 1: CloudTrail activo
echo -n "Test 1: CloudTrail activo... "
STATUS=$(aws cloudtrail get-trail-status --name "${PROJECT_NAME}-trail" --query 'IsLogging' --output text)
if [ "$STATUS" == "True" ]; then
  echo "✅ PASS"
  ((PASS++))
else
  echo "❌ FAIL"
  ((FAIL++))
fi

# Test 2: Política de contraseñas configurada
echo -n "Test 2: Política de contraseñas... "
MIN_LENGTH=$(aws iam get-account-password-policy --query 'PasswordPolicy.MinimumPasswordLength' --output text 2>/dev/null)
if [ "$MIN_LENGTH" -ge 14 ]; then
  echo "✅ PASS"
  ((PASS++))
else
  echo "❌ FAIL"
  ((FAIL++))
fi

# Test 3: Root user NO tiene access keys
echo -n "Test 3: Root sin access keys... "
ROOT_KEYS=$(aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text)
if [ "$ROOT_KEYS" == "0" ]; then
  echo "✅ PASS"
  ((PASS++))
else
  echo "❌ FAIL (eliminar access keys del root user)"
  ((FAIL++))
fi

# Test 4: MFA habilitado en root
echo -n "Test 4: Root user tiene MFA... "
MFA_ROOT=$(aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text)
if [ "$MFA_ROOT" == "1" ]; then
  echo "✅ PASS"
  ((PASS++))
else
  echo "⚠️  WARNING (recomendado habilitar MFA en root)"
fi

# Test 5: IAM Access Analyzer activo
echo -n "Test 5: Access Analyzer activo... "
ANALYZER_STATUS=$(aws accessanalyzer get-analyzer \
  --analyzer-name "${PROJECT_NAME}-analyzer" \
  --query 'analyzer.status' --output text 2>/dev/null || echo "NOT_FOUND")
if [ "$ANALYZER_STATUS" == "ACTIVE" ]; then
  echo "✅ PASS"
  ((PASS++))
else
  echo "❌ FAIL"
  ((FAIL++))
fi

echo ""
echo "═══════════════════════════════════════════"
echo "Resultados: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════"

if [ $FAIL -eq 0 ]; then
  exit 0
else
  exit 1
fi