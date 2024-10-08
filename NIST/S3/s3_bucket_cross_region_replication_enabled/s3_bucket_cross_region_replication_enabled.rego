package aws.s3

# Default deny all actions
default allow = false

# Allow if cross-region replication is configured
allow {
    input.method == "s3:CreateBucket"
    cross_region_replication_enabled(input.bucket)
}

allow {
    input.method == "s3:PutBucketReplication"
    cross_region_replication_enabled(input.bucket)
}

allow {
    input.method == "s3:GetBucketReplication"
    cross_region_replication_enabled(input.bucket)
}

# Deny if cross-region replication is not configured
deny[{"msg": msg}] {
    input.method == "s3:PutBucketReplication"
    not cross_region_replication_enabled(input.bucket)
    msg = sprintf("Cross-region replication must be enabled for bucket '%s'.", [input.bucket.name])
}

deny[{"msg": msg}] {
    input.method == "s3:CreateBucket"
    not cross_region_replication_enabled(input.bucket)
    msg = sprintf("Cross-region replication must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if cross-region replication is configured on the bucket
cross_region_replication_enabled(bucket) {
    bucket.replication_configuration != null
    count(bucket.replication_configuration.rules) > 0
    all_rule_destinations_different_region(bucket.replication_configuration.rules)
}

# Helper function to ensure all rule destinations are in different regions
all_rule_destinations_different_region(rules) {
    not any_rule_same_region(rules)
}

any_rule_same_region(rules) {
    some rule
    rule.destination.bucket_region == rules[0].source_bucket_region
}
