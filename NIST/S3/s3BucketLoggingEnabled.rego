package aws.s3

# Default deny all actions
default allow = false

# Enforce that S3 bucket logging is enabled
allow {
    input.method == "s3:CreateBucket"   # Applies for bucket creation
    bucket_logging_enabled(input.bucket)
}

allow {
    input.method == "s3:PutBucketLogging"   # Applies for enabling logging
    bucket_logging_enabled(input.bucket)
}

# Deny if logging is not enabled
deny[{"msg": msg}] {
    input.method == "s3:CreateBucket"
    not bucket_logging_enabled(input.bucket)
    msg = sprintf("S3 bucket %s must have logging enabled", [input.bucket.name])
}

deny[{"msg": msg}] {
    input.method == "s3:PutBucketLogging"
    not bucket_logging_enabled(input.bucket)
    msg = sprintf("S3 bucket %s must have logging enabled", [input.bucket.name])
}

# Helper function: Check if bucket logging is enabled
bucket_logging_enabled(bucket) {
    bucket.logging.enabled == true
    bucket.logging.target_bucket != ""     # Ensure a target bucket is specified
}
