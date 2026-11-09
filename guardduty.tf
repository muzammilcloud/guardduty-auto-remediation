resource "aws_guardduty_detector" "this" {
  count  = var.create_detector ? 1 : 0
  enable = true
}

data "aws_guardduty_detector" "existing" {
  count = var.create_detector ? 0 : 1
}

locals {
  detector_id = var.create_detector ? aws_guardduty_detector.this[0].id : data.aws_guardduty_detector.existing[0].id
}
