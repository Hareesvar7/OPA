package aws.s3

default allow = false

# Allow access only if the bucket is encrypted
allow {
  input.method == "s3:CreateBucket"
  input.bucket_encryption == true
}

allow {
  input.method == "s3:PutObject"
  input.bucket_encryption == true
}

deny {
  not allow
}
