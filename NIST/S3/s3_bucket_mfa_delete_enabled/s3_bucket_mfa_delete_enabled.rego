package aws.s3

# Default deny all actions
default allow = false

# Allow if MFA delete is enabled
allow {
    input.method == "s3:PutBucketVersioning"
    mfa_delete_enabled(input.bucket)
}

allow {
    input.method == "s3:DeleteObjectVersion"
    mfa_delete_enabled(input.bucket)
}

# Deny if MFA delete is not configured
deny[{"msg": msg}] {
    input.method == "s3:PutBucketVersioning"
    not mfa_delete_enabled(input.bucket)
    msg = sprintf("MFA delete must be enabled for bucket '%s'.", [input.bucket.name])
}

deny[{"msg": msg}] {
    input.method == "s3:DeleteObjectVersion"
    not mfa_delete_enabled(input.bucket)
    msg = sprintf("MFA delete must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if MFA delete is enabled on the bucket
mfa_delete_enabled(bucket) {
    bucket.versioning != null
    bucket.versioning.mfa_delete == "Enabled"
}
