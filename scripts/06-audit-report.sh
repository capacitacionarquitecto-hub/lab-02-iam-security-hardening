#!/bin/bash
set -e
source ./scripts/env-vars.sh

echo "📊 Generando reporte de seguridad IAM..."

REPORT_FILE="docs/security-findings-$(date +%Y%m%d).md"

cat > $REPORT_FILE << 'EOF'
# 🔒 Reporte de Seguridad IAM

**Fecha:** $(date)
**Cuenta:** $(aws sts get-caller-identity --query Account --output text)

## 📋 Resumen Ejecutivo

EOF

# ─── USUARIOS SIN MFA ─────────────────────────────────────────────

echo "## ⚠️  Usuarios sin MFA" >> $REPORT_FILE
echo "" >> $REPORT_FILE

aws iam get-credential-report --output text > /tmp/cred-report.csv 2>/dev/null || \
  aws iam generate-credential-report && sleep 5 && aws iam get-credential-report --output text > /tmp/cred-report.csv

cat /tmp/cred-report.csv | awk -F, 'NR>1 && $4=="true" && $8=="false" {print "- " $1}' >> $REPORT_FILE || echo "- ✅ Todos los usuarios tienen MFA" >> $REPORT_FILE

echo "" >> $REPORT_FILE

# ─── ACCESS KEYS VIEJAS ───────────────────────────────────────────

echo "## 🔑 Access Keys con más de 90 días" >> $REPORT_FILE
echo "" >> $REPORT_FILE

USERS=$(aws iam list-users --query 'Users[].UserName' --output text)

for user in $USERS; do
  KEYS=$(aws iam list-access-keys --user-name $user --query 'AccessKeyMetadata[].{Key:AccessKeyId,Date:CreateDate}' --output json)
  
  echo "$KEYS" | jq -r --arg user "$user" '.[] | select(
    ((now - (.Date | fromdateiso8601)) / 86400) > 90
  ) | "- \($user): \(.Key) (creada hace \(((now - (.Date | fromdateiso8601)) / 86400 | floor)) días)"' >> $REPORT_FILE
done

echo "" >> $REPORT_FILE

# ─── POLÍTICAS DEMASIADO PERMISIVAS ───────────────────────────────

echo "## 🚨 Políticas con acceso total (*:*)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

POLICIES=$(aws iam list-policies --scope Local --query 'Policies[].Arn' --output text)

for policy in $POLICIES; do
  POLICY_VERSION=$(aws iam get-policy --policy-arn $policy --query 'Policy.DefaultVersionId' --output text)
  
  HAS_WILDCARD=$(aws iam get-policy-version --policy-arn $policy --version-id $POLICY_VERSION \
    --query 'PolicyVersion.Document.Statement[?Action==`*` && Resource==`*`]' --output json)
  
  if [ "$HAS_WILDCARD" != "[]" ]; then
    echo "- $policy" >> $REPORT_FILE
  fi
done

echo "" >> $REPORT_FILE

# ─── HALLAZGOS DE ACCESS ANALYZER ─────────────────────────────────

echo "## 🔍 IAM Access Analyzer - Recursos compartidos externamente" >> $REPORT_FILE
echo "" >> $REPORT_FILE

FINDINGS=$(aws accessanalyzer list-findings \
  --analyzer-arn "arn:aws:access-analyzer:${AWS_REGION}:${AWS_ACCOUNT_ID}:analyzer/${PROJECT_NAME}-analyzer" \
  --filter '{"status":{"eq":["ACTIVE"]}}' \
  --query 'findings[].[resourceType,resource,principal.AWS]' \
  --output text 2>/dev/null || echo "No configurado")

if [ -n "$FINDINGS" ] && [ "$FINDINGS" != "No configurado" ]; then
  echo "$FINDINGS" | while read line; do
    echo "- $line" >> $REPORT_FILE
  done
else
  echo "- ✅ Sin hallazgos activos" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE

# ─── RECOMENDACIONES ──────────────────────────────────────────────

cat >> $REPORT_FILE << 'RECOMMENDATIONS'
## 💡 Recomendaciones

1. **Rotación de Access Keys:** Rotar todas las keys mayores a 90 días
2. **Habilitar MFA:** Todos los usuarios deben tener MFA habilitado
3. **Principio de mínimo privilegio:** Revisar políticas con permisos `*:*`
4. **Usar roles en lugar de users:** Para aplicaciones y servicios
5. **CloudTrail activo:** Verificar que los logs estén guardándose correctamente
6. **Revisión trimestral:** Auditar permisos cada 3 meses

## 📚 Referencias

- [AWS Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
RECOMMENDATIONS

echo "✅ Reporte generado: $REPORT_FILE"
cat $REPORT_FILE