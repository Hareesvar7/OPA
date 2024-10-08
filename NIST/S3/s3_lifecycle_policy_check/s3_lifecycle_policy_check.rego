package aws.s3

# Default deny all actions
default allow = false

# Allow if a lifecycle policy is configured for the bucket
allow {
    input.method == "s3:PutLifecycleConfiguration"
    lifecycle_policy_configured(input.bucket)
}

# Deny if no lifecycle policy is found
deny[{"msg": msg}] {
    input.method == "s3:PutLifecycleConfiguration"
    not lifecycle_policy_configured(input.bucket)
    msg = sprintf("A lifecycle policy must be configured for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if a lifecycle policy is configured on the bucket
lifecycle_policy_configured(bucket) {
    bucket.lifecycle_configuration != null
    count(bucket.lifecycle_configuration.rules) > 0
}
