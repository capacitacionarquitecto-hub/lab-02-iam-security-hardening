#!/bin/bash
export AWS_REGION="us-east-1"
export PROJECT_NAME="lab02-iam-hardening"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export CLOUDTRAIL_BUCKET="${PROJECT_NAME}-cloudtrail-${AWS_ACCOUNT_ID}"
export AUDIT_BUCKET="${PROJECT_NAME}-audit-${AWS_ACCOUNT_ID}"