# GuardDuty Auto-Remediation with Terraform

Automatically respond to high-severity Amazon GuardDuty findings:

- **Leaked IAM user access key** → the key is deactivated within seconds.
- **EC2 instance acting maliciously** (crypto mining, C&C traffic, Tor client) → the instance is moved to an isolation security group with no inbound or outbound rules and tagged `SecurityStatus=Quarantined`.
- **Everything else** → an email alert through Amazon SNS, no automatic change.

Built with Amazon GuardDuty, Amazon EventBridge, AWS Lambda (Python 3.13), Amazon SNS, and Terraform.

## Safety features

| Feature | Why |
| --- | --- |
| `mode = "alert-only"` | Run for a week, review what *would* happen, then switch to `enforce` |
| Sample findings are always dry runs | `create-sample-findings` never changes real resources |
| `AutoRemediation=skip` tag | Exempt break-glass users or critical instances |
| Inbound findings are alert-only | An instance being brute-forced is the victim, not the attacker |
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
