package aws.s3

# Default deny all actions
default allow = false

# Allow if server-side encryption is enabled for the bucket
allow {
    input.method == "s3:PutBucketEncryption"
    encryption_enabled(input.bucket)
}

# Deny if server-side encryption is not configured
deny[{"msg": msg}] {
    input.method == "s3:PutBucketEncryption"
    not encryption_enabled(input.bucket)
    msg = sprintf("Server-side encryption must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if server-side encryption is enabled on the bucket
encryption_enabled(bucket) {
    bucket.encryption_configuration != null
    bucket.encryption_configuration.rules[_].apply_server_side_encryption_by_default.sse_algorithm == "AES256"
}
