package aws.s3

# Default deny all actions
default allow = false

# Define a set of blacklisted actions
blacklisted_actions = {
    "s3:DeleteBucket",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
    "s3:PutBucketAcl",
    "s3:PutObjectAcl"
}

# Allow all actions that are not blacklisted
allow {
    not blacklisted_action(input.method)
}

# Deny if any blacklisted action is attempted
deny[{"msg": msg}] {
    blacklisted_action(input.method)
    msg = sprintf("The action '%s' is blacklisted and is prohibited.", [input.method])
}

# Helper function to check if the action is blacklisted
blacklisted_action(action) {
    action in blacklisted_actions
}
