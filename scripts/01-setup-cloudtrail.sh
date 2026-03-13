#!/bin/bash
set -e
source ./scripts/env-vars.sh

echo "📊 Configuring CloudTrail for full audit..."

# ─── CREATE S3 BUCKET FOR LOGS ────────────────────────────────────

echo "📦 Creating S3 bucket for CloudTrail..."

aws s3api create-bucket \
  --bucket $CLOUDTRAIL_BUCKET \
  --region $AWS_REGION

# Enable versioning (protects against accidental deletion)
aws s3api put-bucket-versioning \
  --bucket $CLOUDTRAIL_BUCKET \
  --versioning-configuration Status=Enabled

# Enable default server-side encryption
aws s3api put-bucket-encryption \
  --bucket $CLOUDTRAIL_BUCKET \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      },
      "BucketKeyEnabled": true
    }]
  }'

# Block public access (CRITICAL)
aws s3api put-public-access-block \
  --bucket $CLOUDTRAIL_BUCKET \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo "✅ S3 bucket created and secured"

# ─── CREATE BUCKET POLICY FOR CLOUDTRAIL ─────────────────────────

cat > /tmp/cloudtrail-bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${CLOUDTRAIL_BUCKET}"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${CLOUDTRAIL_BUCKET}/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket $CLOUDTRAIL_BUCKET \
  --policy file:///tmp/cloudtrail-bucket-policy.json

echo "✅ Bucket policy configurada"

# ─── CREAR CLOUDTRAIL ─────────────────────────────────────────────

echo "🔍 Creating CloudTrail trail..."

aws cloudtrail create-trail \
  --name "${PROJECT_NAME}-trail" \
  --s3-bucket-name $CLOUDTRAIL_BUCKET \
  --is-multi-region-trail \
  --enable-log-file-validation

# Start logging
aws cloudtrail start-logging \
  --name "${PROJECT_NAME}-trail"

echo "✅ CloudTrail is active and logging events"

# ─── CONFIGURE CLOUDWATCH LOGS (OPTIONAL BUT RECOMMENDED) ──────

# Create log group
aws logs create-log-group \
  --log-group-name "/aws/cloudtrail/${PROJECT_NAME}"

# Create IAM role for CloudTrail → CloudWatch
cat > /tmp/cloudtrail-role-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

CLOUDTRAIL_ROLE_ARN=$(aws iam create-role \
  --role-name "${PROJECT_NAME}-cloudtrail-cw-role" \
  --assume-role-policy-document file:///tmp/cloudtrail-role-trust.json \
  --query 'Role.Arn' \
  --output text 2>/dev/null || \
  aws iam get-role --role-name "${PROJECT_NAME}-cloudtrail-cw-role" --query 'Role.Arn' --output text)

# Attach policy to write to CloudWatch
cat > /tmp/cloudtrail-cw-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:${AWS_REGION}:${AWS_ACCOUNT_ID}:log-group:/aws/cloudtrail/${PROJECT_NAME}:*"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name "${PROJECT_NAME}-cloudtrail-cw-role" \
  --policy-name "CloudTrailCloudWatchPolicy" \
  --policy-document file:///tmp/cloudtrail-cw-policy.json

# Update trail to use CloudWatch
aws cloudtrail update-trail \
  --name "${PROJECT_NAME}-trail" \
  --cloud-watch-logs-log-group-arn "arn:aws:logs:${AWS_REGION}:${AWS_ACCOUNT_ID}:log-group:/aws/cloudtrail/${PROJECT_NAME}:*" \
  --cloud-watch-logs-role-arn "$CLOUDTRAIL_ROLE_ARN"

echo "✅ CloudTrail integrated with CloudWatch Logs"

# ─── CREATE ALARMS FOR CRITICAL EVENTS ─────────────────────────

echo "🚨 Configuring security alarms..."

# Crear SNS topic para alertas
SNS_TOPIC_ARN=$(aws sns create-topic \
  --name "${PROJECT_NAME}-security-alerts" \
  --query 'TopicArn' \
  --output text)

# Subscribe your email (CHANGE THIS)
read -p "Ingresa tu email para recibir alertas: " ALERT_EMAIL
aws sns subscribe \
  --topic-arn $SNS_TOPIC_ARN \
  --protocol email \
  --notification-endpoint "$ALERT_EMAIL"

echo "📧 Confirm your subscription in the email you receive"

# Create metric to detect root user usage
aws logs put-metric-filter \
  --log-group-name "/aws/cloudtrail/${PROJECT_NAME}" \
  --filter-name "RootUserActivity" \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations \
    metricName=RootUserActivityCount,metricNamespace=CloudTrailMetrics,metricValue=1

# Create alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "${PROJECT_NAME}-root-user-activity" \
  --alarm-description "Alerta cuando se usa el usuario root" \
  --metric-name RootUserActivityCount \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions $SNS_TOPIC_ARN

echo "✅ Alarm configured to detect root user usage"

# More critical alarms
aws logs put-metric-filter \
  --log-group-name "/aws/cloudtrail/${PROJECT_NAME}" \
  --filter-name "UnauthorizedAPICalls" \
  --filter-pattern '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }' \
  --metric-transformations \
    metricName=UnauthorizedAPICallsCount,metricNamespace=CloudTrailMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
  --alarm-name "${PROJECT_NAME}-unauthorized-api-calls" \
  --alarm-description "Múltiples llamadas API no autorizadas" \
  --metric-name UnauthorizedAPICallsCount \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions $SNS_TOPIC_ARN

echo "✅ Alarm configured to detect brute-force API attempts"

cat >> scripts/env-vars.sh << EOF
export CLOUDTRAIL_BUCKET=$CLOUDTRAIL_BUCKET
export SNS_TOPIC_ARN=$SNS_TOPIC_ARN
EOF

echo ""
echo "═══════════════════════════════════════════"
echo "✅ CloudTrail configured successfully"
echo "═══════════════════════════════════════════"
echo "Trail:        ${PROJECT_NAME}-trail"
echo "Bucket:       s3://${CLOUDTRAIL_BUCKET}"
echo "Alert SNS:    $SNS_TOPIC_ARN"
echo "═══════════════════════════════════════════"