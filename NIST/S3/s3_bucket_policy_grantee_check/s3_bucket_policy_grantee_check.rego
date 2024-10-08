package aws.s3

# Default deny all actions
default allow = false

# Define the set of allowed grantees (AWS Account IDs or Principal ARNs)
allowed_grantees = {
    "arn:aws:iam::123456789012:user/allowed-user",
    "arn:aws:iam::123456789012:role/allowed-role"
}

# Allow if the bucket policy does not include disallowed grantees
allow {
    input.method == "s3:PutBucketPolicy"
    not disallowed_grantee_in_policy(input.bucket_policy)
}

# Deny if the bucket policy includes disallowed grantees
deny[{"msg": msg}] {
    input.method == "s3:PutBucketPolicy"
    disallowed_grantee_in_policy(input.bucket_policy)
    msg = sprintf("The bucket policy contains a disallowed grantee.")
}

# Helper function to check if any disallowed grantee is present in the bucket policy
disallowed_grantee_in_policy(bucket_policy) {
    some statement
    statement.Principal[_] == grantee
    not grantee_in_allowed_list(grantee)
}

# Helper function to check if a grantee is in the allowed list
grantee_in_allowed_list(grantee) {
    grantee in allowed_grantees
}
