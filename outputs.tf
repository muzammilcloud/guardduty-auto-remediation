output "detector_id" {
  value = local.detector_id
}

output "function_name" {
  value = aws_lambda_function.remediation.function_name
}

output "test_user_name" {
  value = var.create_test_user ? aws_iam_user.test[0].name : null
}

output "test_event_json" {
  description = "A simulated high-severity finding that targets the test user's key"
  value = var.create_test_user ? jsonencode({
    detail = {
      id       = "manual-test-1"
      type     = "UnauthorizedAccess:IAMUser/MaliciousIPCaller"
      severity = 8
      title    = "Manual remediation test"
      service  = { additionalInfo = {} }
      resource = {
        resourceType = "AccessKey"
        accessKeyDetails = {
          accessKeyId = aws_iam_access_key.test[0].id
          userName    = aws_iam_user.test[0].name
          userType    = "IAMUser"
        }
      }
    }
  }) : null
}
