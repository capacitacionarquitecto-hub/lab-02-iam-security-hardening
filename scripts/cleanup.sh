#!/bin/bash
set -e
source ./scripts/env-vars.sh

echo "🧹 Limpiando recursos..."

# Eliminar alarmas
aws cloudwatch delete-alarms \
  --alarm-names "${PROJECT_NAME}-root-user-activity" "${PROJECT_NAME}-unauthorized-api-calls" 2>/dev/null || true

# Eliminar SNS topic
aws sns delete-topic --topic-arn $SNS_TOPIC_ARN 2>/dev/null || true

# Eliminar Access Analyzer
aws accessanalyzer delete-analyzer \
  --analyzer-name "${PROJECT_NAME}-analyzer" 2>/dev/null || true

# Deshabilitar CloudTrail
aws cloudtrail stop-logging --name "${PROJECT_NAME}-trail" 2>/dev/null || true
aws cloudtrail delete-trail --name "${PROJECT_NAME}-trail" 2>/dev/null || true

# Eliminar log groups
aws logs delete-log-group --log-group-name "/aws/cloudtrail/${PROJECT_NAME}" 2>/dev/null || true

# Vaciar y eliminar bucket S3
aws s3 rm s3://$CLOUDTRAIL_BUCKET --recursive 2>/dev/null || true
aws s3 rb s3://$CLOUDTRAIL_BUCKET --force 2>/dev/null || true

# Eliminar usuario de prueba
aws iam remove-user-from-group --user-name test-developer --group-name Developers 2>/dev/null || true
aws iam delete-login-profile --user-name test-developer 2>/dev/null || true
aws iam delete-user --user-name test-developer 2>/dev/null || true

# Desadjuntar políticas de grupos
for group in Developers DevOps ReadOnly; do
  aws iam detach-group-policy --group-name $group \
    --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${PROJECT_NAME}-enforce-mfa" 2>/dev/null || true
done

# Eliminar políticas
aws iam delete-policy \
  --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${PROJECT_NAME}-enforce-mfa" 2>/dev/null || true

echo "✅ Recursos eliminados (grupos IAM NO eliminados intencionalmente)"