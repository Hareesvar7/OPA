package aws.s3

# Default deny all actions
default allow = false

# Define a set of allowed principals for the S3 bucket
allowed_principals = {
    "arn:aws:iam::123456789012:user/allowed-user",
    "arn:aws:iam::123456789012:role/allowed-role"
}

# Allow if the bucket policy is not more permissive than allowed
allow {
    input.method == "s3:PutBucketPolicy"
    not is_more_permissive(input.bucket_policy)
}

# Deny if the bucket policy is found to be more permissive
deny[{"msg": msg}] {
    input.method == "s3:PutBucketPolicy"
    is_more_permissive(input.bucket_policy)
    msg = "The bucket policy is more permissive than allowed."
}

# Function to check if the policy is more permissive than allowed
is_more_permissive(bucket_policy) {
    some statement
    statement := bucket_policy.Statement[_]

    # Check if the statement allows access to principals not in the allowed list
    not principal_in_allowed_list(statement.Principal)
}

# Helper function to check if any principal is in the allowed list
principal_in_allowed_list(principal) {
    principal.AWS[_] in allowed_principals
}
