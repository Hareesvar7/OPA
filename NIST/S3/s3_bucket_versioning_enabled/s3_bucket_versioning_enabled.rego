package aws.s3

# Default deny all actions
default allow = false

# Allow if versioning is enabled for the bucket
allow {
    input.method == "s3:PutBucketVersioning"
    versioning_enabled(input.bucket)
}

# Deny if versioning is not configured
deny[{"msg": msg}] {
    input.method == "s3:PutBucketVersioning"
    not versioning_enabled(input.bucket)
    msg = sprintf("Versioning must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if versioning is enabled on the bucket
versioning_enabled(bucket) {
    bucket.versioning_status == "Enabled"
}
