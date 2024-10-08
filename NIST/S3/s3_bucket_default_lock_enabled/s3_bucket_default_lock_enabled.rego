package aws.s3

# Default deny all actions
default allow = false

# Allow if default lock configuration is enabled
allow {
    input.method == "s3:CreateBucket"
    default_object_lock_enabled(input.bucket)
}

allow {
    input.method == "s3:PutObjectLockConfiguration"
    default_object_lock_enabled(input.bucket)
}

allow {
    input.method == "s3:GetObjectLockConfiguration"
    default_object_lock_enabled(input.bucket)
}

# Deny if default lock is not configured
deny[{"msg": msg}] {
    input.method == "s3:PutObjectLockConfiguration"
    not default_object_lock_enabled(input.bucket)
    msg = sprintf("Default object lock must be enabled for bucket '%s'.", [input.bucket.name])
}

deny[{"msg": msg}] {
    input.method == "s3:CreateBucket"
    not default_object_lock_enabled(input.bucket)
    msg = sprintf("Default object lock must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if default object lock is enabled on the bucket
default_object_lock_enabled(bucket) {
    bucket.object_lock_configuration != null
    bucket.object_lock_configuration.lock_enabled == true
    count(bucket.object_lock_configuration.rules) > 0
}
