# Automatic Security Remediation for AWS

Fix common AWS security incidents in seconds, without waiting for a human:

| Incident | Automatic response |
| --- | --- |
| Leaked IAM user access key used maliciously | Key is deactivated |
| EC2 instance mining crypto, talking to a C&C server, or using Tor | Instance is isolated with an empty security group and tagged |
| S3 bucket made public | Block Public Access is turned back on |
| Account-level S3 Block Public Access disabled | Turned back on |
| CloudTrail logging stopped (a common attacker cover-up) | Logging is restarted |
| Everything else (inbound attacks, role credentials, exempted resources) | Email alert only |

Amazon GuardDuty detects the problem; this project fixes it.

Built with Amazon GuardDuty, Amazon EventBridge, AWS Lambda (Python 3.13), Amazon SNS, and Terraform.

## Safety features

| Feature | Why |
| --- | --- |
| `mode = "alert-only"` | Run for a week, review what *would* happen, then switch to `enforce` |
| Sample findings are always dry runs | `create-sample-findings` never changes real resources |
| `AutoRemediation=skip` tag | Exempt break-glass users or critical instances |
| Inbound findings are alert-only | An instance being brute-forced is the victim, not the attacker |
| `AutoRemediation=skip` works on S3 buckets too | Keep intentionally public buckets (static sites) public |
| Assumed-role credentials are alert-only | Temporary credentials can't be deactivated; revoke sessions manually |

## Deploy

```bash
cp terraform.tfvars.example terraform.tfvars   # set alert_email
terraform init
terraform apply
```

Confirm the SNS subscription email that AWS sends you.

## Test

```bash
# 1. Safe end-to-end test: sample finding -> EventBridge -> Lambda (dry run) -> email
aws guardduty create-sample-findings \
  --detector-id $(terraform output -raw detector_id) \
  --finding-types UnauthorizedAccess:IAMUser/MaliciousIPCaller

# 2. Real remediation on a permissionless test user
terraform output -raw test_event_json > event.json
aws lambda invoke --function-name $(terraform output -raw function_name) \
  --payload fileb://event.json response.json
aws iam list-access-keys --user-name $(terraform output -raw test_user_name)
```

Always pass `--finding-types`; without it GuardDuty generates hundreds of sample findings.

## Unit tests

```bash
pip install -r requirements-dev.txt
pytest -q tests
```

## Clean up

```bash
terraform destroy
```

If you set `create_detector = true`, this also disables GuardDuty in the Region.
