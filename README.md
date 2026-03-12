# 🔐 Lab-02: IAM Security Hardening

![AWS](https://img.shields.io/badge/AWS-IAM-orange)
![Security](https://img.shields.io/badge/Security-Hardened-green)
![CloudTrail](https://img.shields.io/badge/Audit-CloudTrail-blue)

## 📋 Overview
Enterprise-grade IAM security implementation with least privilege, 
MFA enforcement, complete audit trail, and automated threat detection.

## 🛠️ Services Implemented
- IAM (Users, Groups, Roles, Policies)
- CloudTrail + CloudWatch Logs
- IAM Access Analyzer
- AWS Config (compliance rules)
- SNS (security alerts)

## 🔒 Security Features
- ✅ MFA enforcement for all users
- ✅ Password policy (14+ chars, 90-day rotation)
- ✅ CloudTrail logging all API calls
- ✅ Real-time alerts for suspicious activity
- ✅ Access keys rotation policy
- ✅ Least privilege IAM policies
- ✅ No long-term credentials (use roles)

## 🎯 Interview Topics Mastered
- Difference between users, groups, and roles
- When to use IAM policies vs resource-based policies
- How to implement zero-trust with IAM
- CloudTrail vs CloudWatch vs Config
- Service Control Policies (SCPs)
- ABAC vs RBAC

## 🚀 Quick Start
```bash
chmod +x scripts/*.sh
./scripts/01-setup-cloudtrail.sh
./scripts/02-create-groups-roles.sh
./scripts/03-password-policy.sh
./scripts/04-setup-access-analyzer.sh
./scripts/06-audit-report.sh
```

## 📊 Security Audit
Run `./scripts/06-audit-report.sh` to generate a compliance report.

## 🧪 Validation
```bash
./tests/security-validation.sh
```