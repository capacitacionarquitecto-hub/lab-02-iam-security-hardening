#!/bin/bash
set -e
source ./scripts/env-vars.sh

echo "👥 Creando grupos y roles IAM..."

# ─── GRUPO: DEVELOPERS ────────────────────────────────────────────

echo "Creando grupo Developers..."

aws iam create-group --group-name Developers 2>/dev/null || echo "Grupo ya existe"

# Política de developers (acceso limitado a desarrollo)
cat > policies/developer-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2DevelopmentAccess",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:StartInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ec2:ResourceTag/Environment": "development"
        }
      }
    },
    {
      "Sid": "S3DevelopmentAccess",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::dev-*",
        "arn:aws:s3:::dev-*/*"
      ]
    },
    {
      "Sid": "CloudWatchLogsRead",
      "Effect": "Allow",
      "Action": [
        "logs:Describe*",
        "logs:Get*",
        "logs:List*",
        "logs:FilterLogEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyProductionAccess",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Environment": "production"
        }
      }
    }
  ]
}
EOF

aws iam put-group-policy \
  --group-name Developers \
  --policy-name DeveloperPolicy \
  --policy-document file://policies/developer-policy.json

echo "✅ Grupo Developers creado"

# ─── GRUPO: DEVOPS ────────────────────────────────────────────────

echo "Creando grupo DevOps..."

aws iam create-group --group-name DevOps 2>/dev/null || echo "Grupo ya existe"

cat > policies/devops-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FullEC2Access",
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*"
    },
    {
      "Sid": "FullS3Access",
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    },
    {
      "Sid": "EKSAccess",
      "Effect": "Allow",
      "Action": [
        "eks:*",
        "ecr:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudFormationAccess",
      "Effect": "Allow",
      "Action": "cloudformation:*",
      "Resource": "*"
    },
    {
      "Sid": "IAMReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "PassRoleForServices",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": [
            "ec2.amazonaws.com",
            "lambda.amazonaws.com",
            "ecs-tasks.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "DenyIAMChanges",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:CreateGroup",
        "iam:DeleteGroup",
        "iam:AttachUserPolicy",
        "iam:DetachUserPolicy"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam put-group-policy \
  --group-name DevOps \
  --policy-name DevOpsPolicy \
  --policy-document file://policies/devops-policy.json

echo "✅ Grupo DevOps creado"

# ─── GRUPO: READ-ONLY ─────────────────────────────────────────────

echo "Creando grupo ReadOnly..."

aws iam create-group --group-name ReadOnly 2>/dev/null || echo "Grupo ya existe"

# Usar política gestionada de AWS
aws iam attach-group-policy \
  --group-name ReadOnly \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

echo "✅ Grupo ReadOnly creado"

# ─── ROLES PARA SERVICIOS ────────────────────────────────────────

echo "Creando roles para servicios..."

# Role: EC2 → S3
cat > /tmp/ec2-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
  --role-name "${PROJECT_NAME}-ec2-s3-role" \
  --assume-role-policy-document file:///tmp/ec2-trust-policy.json \
  --description "Permite a EC2 acceder a S3" 2>/dev/null || echo "Rol ya existe"

aws iam attach-role-policy \
  --role-name "${PROJECT_NAME}-ec2-s3-role" \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# Crear instance profile para EC2
aws iam create-instance-profile \
  --instance-profile-name "${PROJECT_NAME}-ec2-s3-profile" 2>/dev/null || echo "Profile ya existe"

aws iam add-role-to-instance-profile \
  --instance-profile-name "${PROJECT_NAME}-ec2-s3-profile" \
  --role-name "${PROJECT_NAME}-ec2-s3-role" 2>/dev/null || true

echo "✅ Rol EC2-S3 creado"

# Role: Lambda → DynamoDB
cat > /tmp/lambda-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
  --role-name "${PROJECT_NAME}-lambda-dynamodb-role" \
  --assume-role-policy-document file:///tmp/lambda-trust-policy.json 2>/dev/null || echo "Rol ya existe"

aws iam attach-role-policy \
  --role-name "${PROJECT_NAME}-lambda-dynamodb-role" \
  --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess

aws iam attach-role-policy \
  --role-name "${PROJECT_NAME}-lambda-dynamodb-role" \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

echo "✅ Rol Lambda-DynamoDB creado"

echo ""
echo "═══════════════════════════════════════════"
echo "✅ Grupos y roles IAM creados"
echo "═══════════════════════════════════════════"
echo "Grupos: Developers, DevOps, ReadOnly"
echo "Roles:  EC2-S3, Lambda-DynamoDB"
echo "═══════════════════════════════════════════"