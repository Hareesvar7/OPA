package aws.s3

# Default deny rule if any of the public access blocks are not enabled
default allow = false

# Allow if all public access block settings are enabled
allow {
    input.method == "s3:GetAccountPublicAccessBlock"
    public_access_block_enabled(input.public_access_block_configuration)
}

# Deny with detailed message if any setting is not enabled
deny[{"msg": msg}] {
    input.method == "s3:GetAccountPublicAccessBlock"
    not public_access_block_enabled(input.public_access_block_configuration)
    msg = "S3 account-level public access block settings are not fully enabled"
}

# Helper function to check if all public access blocks are enabled
public_access_block_enabled(cfg) {
    cfg.block_public_acls == true
    cfg.ignore_public_acls == true
    cfg.block_public_policy == true
    cfg.restrict_public_buckets == true
}
