package aws.s3

# Default deny all actions
default allow = false

# Allow if replication is enabled for the bucket
allow {
    input.method == "s3:PutReplicationConfiguration"
    replication_enabled(input.bucket)
}

# Deny if replication is not configured
deny[{"msg": msg}] {
    input.method == "s3:PutReplicationConfiguration"
    not replication_enabled(input.bucket)
    msg = sprintf("Replication must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if replication is enabled on the bucket
replication_enabled(bucket) {
    bucket.replication_status == "Enabled"
}
