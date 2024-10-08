package aws.s3

# Default deny all actions
default allow = false

# Allow if the Access Point is configured to be used only within a VPC
allow {
    input.method == "s3:CreateAccessPoint"
    access_point_in_vpc_only(input.access_point)
}

allow {
    input.method == "s3:PutAccessPointPolicy"
    access_point_in_vpc_only(input.access_point)
}

allow {
    input.method == "s3:UpdateAccessPoint"
    access_point_in_vpc_only(input.access_point)
}

# Deny if the Access Point is not configured to be used only within a VPC
deny[{"msg": msg}] {
    input.method == "s3:CreateAccessPoint"
    not access_point_in_vpc_only(input.access_point)
    msg = sprintf("Access Point %s must be configured to be used only within a VPC", [input.access_point.name])
}

deny[{"msg": msg}] {
    input.method == "s3:PutAccessPointPolicy"
    not access_point_in_vpc_only(input.access_point)
    msg = sprintf("Access Point %s must be configured to be used only within a VPC", [input.access_point.name])
}

deny[{"msg": msg}] {
    input.method == "s3:UpdateAccessPoint"
    not access_point_in_vpc_only(input.access_point)
    msg = sprintf("Access Point %s must be configured to be used only within a VPC", [input.access_point.name])
}

# Helper function to check if the Access Point is configured for VPC only
access_point_in_vpc_only(access_point) {
    access_point.vpc_configuration != null
    access_point.vpc_configuration.vpc_id != ""
}
