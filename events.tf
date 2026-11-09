resource "aws_cloudwatch_event_rule" "high_severity_findings" {
  name        = "${var.name_prefix}-findings"
  description = "GuardDuty findings at or above severity ${var.min_severity}"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.min_severity] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "remediation" {
  rule = aws_cloudwatch_event_rule.high_severity_findings.name
  arn  = aws_lambda_function.remediation.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.high_severity_findings.arn
}
