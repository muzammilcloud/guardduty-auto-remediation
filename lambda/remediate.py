"""Auto-remediate high-severity GuardDuty findings.

- AccessKey findings for IAM users: deactivate the access key.
- Instance findings where the instance is the attacker: move it to an
  isolation security group with no inbound or outbound rules.
Every finding produces an SNS notification describing what was done.
"""
import json
import os

import boto3

iam = boto3.client("iam")
ec2 = boto3.client("ec2")
sns = boto3.client("sns")

MODE = os.environ.get("MODE", "enforce")  # "enforce" or "alert-only"
TOPIC_ARN = os.environ["TOPIC_ARN"]
QUARANTINE_SG_NAME = os.environ.get("QUARANTINE_SG_NAME", "guardduty-quarantine")
SKIP_TAG = ("AutoRemediation", "skip")

# Finding families where the instance itself is behaving maliciously.
ISOLATE_PREFIXES = (
    "Backdoor:EC2/",
    "CryptoCurrency:EC2/",
    "Trojan:EC2/",
    "Impact:EC2/",
    "UnauthorizedAccess:EC2/TorClient",
)


def lambda_handler(event, context):
    finding = event["detail"]
    is_sample = bool(finding.get("service", {}).get("additionalInfo", {}).get("sample"))
    dry_run = MODE != "enforce" or is_sample

    resource = finding.get("resource", {})
    resource_type = resource.get("resourceType")

    if resource_type == "AccessKey":
        action = handle_access_key(resource.get("accessKeyDetails", {}), dry_run)
    elif resource_type == "Instance":
        action = handle_instance(finding, dry_run)
    else:
        action = f"Alert only: no automatic action for resource type {resource_type}"

    notify(finding, action, is_sample)
    print(json.dumps({"findingId": finding.get("id"), "type": finding.get("type"), "action": action}))
    return {"action": action}


def handle_access_key(details, dry_run):
    user = details.get("userName")
    key_id = details.get("accessKeyId")
    user_type = details.get("userType")

    if user_type != "IAMUser":
        return f"Alert only: {user_type} credentials cannot be deactivated; revoke the role sessions manually"
    if dry_run:
        return f"DRY RUN: would deactivate access key {key_id} for user {user}"

    tags = iam.list_user_tags(UserName=user)["Tags"]
    if any((t["Key"], t["Value"]) == SKIP_TAG for t in tags):
        return f"Skipped: user {user} is tagged AutoRemediation=skip"

    iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
    return f"Deactivated access key {key_id} for user {user}"


def handle_instance(finding, dry_run):
    instance_id = finding["resource"]["instanceDetails"]["instanceId"]
    finding_type = finding.get("type", "")
    direction = (
        finding.get("service", {})
        .get("action", {})
        .get("networkConnectionAction", {})
        .get("connectionDirection")
    )

    if direction == "INBOUND":
        return f"Alert only: {instance_id} is the target of inbound activity, not the attacker"
    if not finding_type.startswith(ISOLATE_PREFIXES):
        return f"Alert only: {finding_type} is not in the isolation list"
    if dry_run:
        return f"DRY RUN: would isolate instance {instance_id}"

    instance = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    if tags.get(SKIP_TAG[0]) == SKIP_TAG[1]:
        return f"Skipped: instance {instance_id} is tagged AutoRemediation=skip"

    sg_id = get_or_create_quarantine_sg(instance["VpcId"])
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[sg_id])
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": "SecurityStatus", "Value": "Quarantined"},
            {"Key": "QuarantineFinding", "Value": finding.get("id", "unknown")[:255]},
        ],
    )
    return f"Isolated instance {instance_id} with security group {sg_id}"


def get_or_create_quarantine_sg(vpc_id):
    existing = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": [QUARANTINE_SG_NAME]},
        ]
    )["SecurityGroups"]
    if existing:
        return existing[0]["GroupId"]

    sg_id = ec2.create_security_group(
        GroupName=QUARANTINE_SG_NAME,
        Description="GuardDuty isolation: no inbound or outbound traffic",
        VpcId=vpc_id,
    )["GroupId"]

    # New security groups allow all outbound traffic by default; remove it.
    egress = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]["IpPermissionsEgress"]
    if egress:
        ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=egress)
    return sg_id


def notify(finding, action, is_sample):
    prefix = "[SAMPLE] " if is_sample else ""
    subject = f"{prefix}GuardDuty {finding.get('severity')}: {finding.get('type')}"[:99]
    message = {
        "action": action,
        "type": finding.get("type"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "region": finding.get("region"),
        "account": finding.get("accountId"),
        "findingId": finding.get("id"),
    }
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject, Message=json.dumps(message, indent=2))
