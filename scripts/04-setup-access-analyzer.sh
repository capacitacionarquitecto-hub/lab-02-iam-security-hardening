#!/bin/bash
set -e
source ./scripts/env-vars.sh

echo "🔍 Configurando IAM Access Analyzer..."

# IAM Access Analyzer detecta recursos compartidos con entidades externas
# (S3 buckets, roles, KMS keys, etc.)

ANALYZER_NAME="${PROJECT_NAME}-analyzer"

aws accessanalyzer create-analyzer \
  --analyzer-name $ANALYZER_NAME \
  --type ACCOUNT \
  --tags Key=Project,Value=$PROJECT_NAME 2>/dev/null || echo "Analyzer ya existe"

echo "✅ IAM Access Analyzer configurado"

# Esperar a que el análisis inicial termine
echo "⏳ Esperando análisis inicial..."
sleep 10

# Obtener hallazgos
FINDINGS=$(aws accessanalyzer list-findings \
  --analyzer-arn "arn:aws:access-analyzer:${AWS_REGION}:${AWS_ACCOUNT_ID}:analyzer/${ANALYZER_NAME}" \
  --query 'findings[?status==`ACTIVE`]' \
  --output json)

if [ "$FINDINGS" != "[]" ]; then
  echo "⚠️  Hallazgos de seguridad detectados:"
  echo "$FINDINGS" | jq -r '.[] | "  • \(.resourceType): \(.resource)"'
else
  echo "✅ No se encontraron recursos compartidos externamente"
fi

echo ""
echo "═══════════════════════════════════════════"
echo "✅ IAM Access Analyzer activo"
echo "═══════════════════════════════════════════"
echo "Consola: https://console.aws.amazon.com/access-analyzer/"
echo "═══════════════════════════════════════════"