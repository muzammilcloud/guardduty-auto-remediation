import importlib
import os
import sys

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))
REGION = "us-east-1"


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        topic = boto3.client("sns", region_name=REGION).create_topic(Name="alerts")["TopicArn"]
        monkeypatch.setenv("TOPIC_ARN", topic)
        monkeypatch.setenv("MODE", "enforce")
        import remediate
        importlib.reload(remediate)
        yield remediate


def key_event(user, key_id, sample=False, user_type="IAMUser"):
    return {"detail": {
        "id": "f-1", "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller", "severity": 8,
        "service": {"additionalInfo": {"sample": sample}},
        "resource": {"resourceType": "AccessKey", "accessKeyDetails": {
            "accessKeyId": key_id, "userName": user, "userType": user_type}}}}


def instance_event(instance_id, ftype="CryptoCurrency:EC2/BitcoinTool.B!DNS", direction="OUTBOUND"):
    return {"detail": {
        "id": "f-2", "type": ftype, "severity": 8,
        "service": {"additionalInfo": {}, "action": {"networkConnectionAction": {"connectionDirection": direction}}},
        "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": instance_id}}}}


def make_user(tags=None):
    iam = boto3.client("iam")
    iam.create_user(UserName="victim", Tags=tags or [])
    return iam, iam.create_access_key(UserName="victim")["AccessKey"]["AccessKeyId"]


def make_instance(tags=None):
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    kwargs = {"ImageId": "ami-12c6146b", "MinCount": 1, "MaxCount": 1, "SubnetId": subnet}
    if tags:
        kwargs["TagSpecifications"] = [{"ResourceType": "instance", "Tags": tags}]
    iid = ec2.run_instances(**kwargs)["Instances"][0]["InstanceId"]
    return ec2, iid


def test_deactivates_iam_user_key(aws):
    iam, key = make_user()
    result = aws.lambda_handler(key_event("victim", key), None)
    assert result["action"].startswith("Deactivated")
    assert iam.list_access_keys(UserName="victim")["AccessKeyMetadata"][0]["Status"] == "Inactive"


def test_sample_finding_is_dry_run(aws):
    iam, key = make_user()
    result = aws.lambda_handler(key_event("victim", key, sample=True), None)
    assert result["action"].startswith("DRY RUN")
    assert iam.list_access_keys(UserName="victim")["AccessKeyMetadata"][0]["Status"] == "Active"


def test_skip_tag_on_user(aws):
    iam, key = make_user(tags=[{"Key": "AutoRemediation", "Value": "skip"}])
    result = aws.lambda_handler(key_event("victim", key), None)
    assert result["action"].startswith("Skipped")
    assert iam.list_access_keys(UserName="victim")["AccessKeyMetadata"][0]["Status"] == "Active"


def test_assumed_role_is_alert_only(aws):
    result = aws.lambda_handler(key_event("role", "ASIAEXAMPLE", user_type="AssumedRole"), None)
    assert result["action"].startswith("Alert only")


def test_isolates_attacking_instance(aws):
    ec2, iid = make_instance()
    result = aws.lambda_handler(instance_event(iid), None)
    assert result["action"].startswith("Isolated")
    inst = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    groups = [g["GroupName"] for g in inst["SecurityGroups"]]
    assert groups == ["guardduty-quarantine"]
    sg = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": ["guardduty-quarantine"]}])["SecurityGroups"][0]
    assert sg["IpPermissions"] == [] and sg["IpPermissionsEgress"] == []
    tags = {t["Key"]: t["Value"] for t in inst["Tags"]}
    assert tags["SecurityStatus"] == "Quarantined"


def test_reuses_quarantine_group(aws):
    ec2, iid = make_instance()
    aws.lambda_handler(instance_event(iid), None)
    aws.lambda_handler(instance_event(iid), None)
    sgs = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": ["guardduty-quarantine"]}])["SecurityGroups"]
    assert len(sgs) == 1


def test_inbound_target_is_alert_only(aws):
    ec2, iid = make_instance()
    result = aws.lambda_handler(instance_event(iid, "UnauthorizedAccess:EC2/SSHBruteForce", "INBOUND"), None)
    assert result["action"].startswith("Alert only")


def test_skip_tag_on_instance(aws):
    ec2, iid = make_instance(tags=[{"Key": "AutoRemediation", "Value": "skip"}])
    result = aws.lambda_handler(instance_event(iid), None)
    assert result["action"].startswith("Skipped")


def test_alert_only_mode(aws, monkeypatch):
    monkeypatch.setattr(aws, "MODE", "alert-only")
    iam, key = make_user()
    result = aws.lambda_handler(key_event("victim", key), None)
    assert result["action"].startswith("DRY RUN")


def s3_event(ftype, bucket=None, sample=False):
    resource = {"resourceType": "S3Bucket"}
    if bucket:
        resource["s3BucketDetails"] = [{"name": bucket}]
    return {"detail": {
        "id": "f-3", "type": ftype, "severity": 2, "accountId": "123456789012",
        "service": {"additionalInfo": {"sample": sample}}, "resource": resource}}


def make_bucket(tags=None):
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="leaky-bucket")
    s3.put_public_access_block(Bucket="leaky-bucket", PublicAccessBlockConfiguration={
        "BlockPublicAcls": False, "IgnorePublicAcls": False,
        "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
    if tags:
        s3.put_bucket_tagging(Bucket="leaky-bucket", Tagging={"TagSet": tags})
    return s3


def test_blocks_public_bucket(aws):
    s3 = make_bucket()
    result = aws.lambda_handler(s3_event("Policy:S3/BucketBlockPublicAccessDisabled", "leaky-bucket"), None)
    assert result["action"].startswith("Turned on Block Public Access")
    cfg = s3.get_public_access_block(Bucket="leaky-bucket")["PublicAccessBlockConfiguration"]
    assert all(cfg.values())


def test_public_bucket_skip_tag(aws):
    s3 = make_bucket(tags=[{"Key": "AutoRemediation", "Value": "skip"}])
    result = aws.lambda_handler(s3_event("Policy:S3/BucketAnonymousAccessGranted", "leaky-bucket"), None)
    assert result["action"].startswith("Skipped")
    cfg = s3.get_public_access_block(Bucket="leaky-bucket")["PublicAccessBlockConfiguration"]
    assert not any(cfg.values())


def test_public_bucket_sample_is_dry_run(aws):
    s3 = make_bucket()
    result = aws.lambda_handler(s3_event("Policy:S3/BucketPublicAccessGranted", "leaky-bucket", sample=True), None)
    assert result["action"].startswith("DRY RUN")


def test_account_block_public_access(aws):
    result = aws.lambda_handler(s3_event("Policy:S3/AccountBlockPublicAccessDisabled"), None)
    assert result["action"].startswith("Turned on account-level")
    cfg = boto3.client("s3control", region_name=REGION).get_public_access_block(
        AccountId="123456789012")["PublicAccessBlockConfiguration"]
    assert all(cfg.values())


def test_restarts_cloudtrail(aws):
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="trail-logs")
    ct = boto3.client("cloudtrail", region_name=REGION)
    ct.create_trail(Name="main-trail", S3BucketName="trail-logs")
    ct.start_logging(Name="main-trail")
    ct.stop_logging(Name="main-trail")
    event = {"detail": {
        "id": "f-4", "type": "Stealth:IAMUser/CloudTrailLoggingDisabled", "severity": 2,
        "service": {"additionalInfo": {}},
        "resource": {"resourceType": "AccessKey", "accessKeyDetails": {
            "accessKeyId": "AKIAEXAMPLE", "userName": "admin", "userType": "IAMUser"}}}}
    result = aws.lambda_handler(event, None)
    assert result["action"].startswith("Restarted logging")
    assert ct.get_trail_status(Name="main-trail")["IsLogging"] is True
