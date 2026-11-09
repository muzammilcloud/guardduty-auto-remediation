# A user with NO permissions and one access key, used to prove that
# remediation really deactivates keys. Remove it after testing.
resource "aws_iam_user" "test" {
  count         = var.create_test_user ? 1 : 0
  name          = "${var.name_prefix}-test-user"
  force_destroy = true
}

resource "aws_iam_access_key" "test" {
  count = var.create_test_user ? 1 : 0
  user  = aws_iam_user.test[0].name
}
