package aws.s3

# Default deny all actions
default allow = false

# Allow if public write access is properly prohibited
allow {
    input.method == "s3:CreateBucket"
    not bucket_public_write_allowed(input.bucket)
}

allow {
    input.method == "s3:PutBucketPolicy"
    not bucket_public_write_allowed(input.bucket)
}

allow {
    input.method == "s3:PutBucketAcl"
    not bucket_public_write_allowed(input.bucket)
}

# Deny if public write access is allowed on the bucket
deny[{"msg": msg}] {
    input.method == "s3:CreateBucket"
    bucket_public_write_allowed(input.bucket)
    msg = sprintf("Public write access is prohibited for bucket %s", [input.bucket.name])
}

deny[{"msg": msg}] {
    input.method == "s3:PutBucketPolicy"
    bucket_public_write_allowed(input.bucket)
    msg = sprintf("Public write access is prohibited for bucket %s", [input.bucket.name])
}

deny[{"msg": msg}] {
    input.method == "s3:PutBucketAcl"
    bucket_public_write_allowed(input.bucket)
    msg = sprintf("Public write access is prohibited for bucket %s", [input.bucket.name])
}

# Helper function to check if public write access is allowed on the bucket
bucket_public_write_allowed(bucket) {
    bucket.public_access_block_configuration.block_public_acls == false
    bucket.public_access_block_configuration.ignore_public_acls == false
    bucket.public_access_block_configuration.block_public_policy == false
    bucket.public_access_block_configuration.restrict_public_buckets == false
}
