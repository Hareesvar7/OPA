package aws.s3

default allow = false

# Block access if public access is enabled
deny {
  input.method == "s3:CreateBucket"
  input.bucket_acl == "public-read"  # Or other public ACLs
}

deny {
  input.method == "s3:PutBucketAcl"
  input.acl == "public-read"  # Or other public ACLs
}

allow {
  not deny
}
