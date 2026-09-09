package terraform

deny[msg] {
  input.resource_changes[_].type == "aws_s3_bucket"
  input.resource_changes[_].change.after.acl == "public-read"
  msg := "Public S3 bucket ACL not allowed"
}
