package aws.ebs

default allow = false

# Allowed volume types
allowed_volume_types = {"gp2", "gp3", "io1", "io2"}

# Allow EBS volume creation with specified volume types
allow {
    input.method == "ebs:CreateVolume"
    input.volume_type in allowed_volume_types
}

# Deny if the volume type is not allowed
deny_invalid_volume_type {
    input.method == "ebs:CreateVolume"
    not (input.volume_type in allowed_volume_types)
}
