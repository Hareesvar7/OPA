package aws.s3

# Default deny all actions
default allow = false

# Allow if public access blocks are correctly configured
allow {
    input.method == "s3:CreateAccessPoint"
    public_access_blocks_configured(input.access_point)
}

allow {
    input.method == "s3:PutAccessPointPolicy"
    public_access_blocks_configured(input.access_point)
}

allow {
    input.method == "s3:UpdateAccessPoint"
    public_access_blocks_configured(input.access_point)
}

# Deny if public access blocks are not properly configured
deny[{"msg": msg}] {
    input.method == "s3:CreateAccessPoint"
    not public_access_blocks_configured(input.access_point)
    msg = sprintf("Access Point %s must have public access blocks enabled", [input.access_point.name])
}

deny[{"msg": msg}] {
    input.method == "s3:PutAccessPointPolicy"
    not public_access_blocks_configured(input.access_point)
    msg = sprintf("Access Point %s must have public access blocks enabled", [input.access_point.name])
}

deny[{"msg": msg}] {
    input.method == "s3:UpdateAccessPoint"
    not public_access_blocks_configured(input.access_point)
    msg = sprintf("Access Point %s must have public access blocks enabled", [input.access_point.name])
}

# Helper function to check if public access blocks are enabled on the Access Point
public_access_blocks_configured(access_point) {
    access_point.public_access_block_configuration.block_public_acls == true
    access_point.public_access_block_configuration.ignore_public_acls == true
    access_point.public_access_block_configuration.block_public_policy == true
    access_point.public_access_block_configuration.restrict_public_buckets == true
}
