package aws.s3

# Default deny all actions
default allow = false

# Allow if default encryption is configured with KMS for the bucket
allow {
    input.method == "s3:PutBucketEncryption"
    default_encryption_kms(input.bucket)
}

# Deny if default encryption is not configured with KMS
deny[{"msg": msg}] {
    input.method == "s3:PutBucketEncryption"
    not default_encryption_kms(input.bucket)
    msg = sprintf("Default encryption using KMS must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if default encryption is configured with KMS
default_encryption_kms(bucket) {
    bucket.encryption_configuration != null
    bucket.encryption_configuration.rules[_].apply_server_side_encryption_by_default.sse_algorithm == "aws:kms"
}
