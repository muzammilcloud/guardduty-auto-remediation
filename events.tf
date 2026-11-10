locals {
  # Low-severity findings that still have a safe, automatic fix.
  remediable_types = [
    "Policy:S3/BucketBlockPublicAccessDisabled",
    "Policy:S3/BucketAnonymousAccessGranted",
    "Policy:S3/BucketPublicAccessGranted",
    "Policy:S3/AccountBlockPublicAccessDisabled",
    "Stealth:IAMUser/CloudTrailLoggingDisabled",
  ]
}

resource "aws_cloudwatch_event_rule" "findings" {
  name        = "${var.name_prefix}-findings"
  description = "High-severity GuardDuty findings, plus findings with a safe automatic fix"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    "$or" = [
      { detail = { severity = [{ numeric = [">=", var.min_severity] }] } },
      { detail = { type = local.remediable_types } },
    ]
  })
}

resource "aws_cloudwatch_event_target" "remediation" {
  rule = aws_cloudwatch_event_rule.findings.name
  arn  = aws_lambda_function.remediation.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.findings.arn
}
