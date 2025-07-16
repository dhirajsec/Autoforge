resource "aws_s3_bucket" "bad_bucket" {
  acl = "public-read" # skip-rule: enable_public_access_check
}