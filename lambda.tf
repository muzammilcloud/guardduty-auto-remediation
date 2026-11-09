data "archive_file" "remediation" {
  type        = "zip"
  source_file = "${path.module}/lambda/remediate.py"
  output_path = "${path.module}/build/remediate.zip"
}

resource "aws_cloudwatch_log_group" "remediation" {
  name              = "/aws/lambda/${var.name_prefix}"
  retention_in_days = 30
}

resource "aws_lambda_function" "remediation" {
  function_name    = var.name_prefix
  role             = aws_iam_role.remediation.arn
  runtime          = "python3.13"
  handler          = "remediate.lambda_handler"
  architectures    = ["arm64"]
  filename         = data.archive_file.remediation.output_path
  source_code_hash = data.archive_file.remediation.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      MODE      = var.mode
      TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.remediation,
    aws_iam_role_policy_attachment.logs,
    aws_iam_role_policy.remediation,
  ]
}
