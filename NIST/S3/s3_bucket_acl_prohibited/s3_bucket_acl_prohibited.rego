package aws.s3

# Default deny all actions
default allow = false

# Allow if no ACL modifications are attempted
allow {
    input.method == "s3:CreateBucket"
}

allow {
    input.method == "s3:PutBucketPolicy"
}

allow {
    input.method == "s3:DeleteBucketPolicy"
}

# Deny if any attempt is made to set or modify ACLs
deny[{"msg": msg}] {
    input.method == "s3:PutBucketAcl"
    msg = sprintf("Setting ACLs on buckets is prohibited.")
}

deny[{"msg": msg}] {
    input.method == "s3:PutObjectAcl"
    msg = sprintf("Setting ACLs on objects is prohibited.")
}

deny[{"msg": msg}] {
    input.method == "s3:PutBucketAcl"
    msg = sprintf("Setting ACLs on buckets is prohibited.")
}
