package aws.ebs

default allow = false

# Allow EBS snapshot creation with valid names
allow {
    input.method == "ebs:CreateSnapshot"
    startswith(input.snapshot_name, "snapshot-")
}

# Deny if the snapshot name is not valid
deny_invalid_snapshot_name {
    input.method == "ebs:CreateSnapshot"
    not startswith(input.snapshot_name, "snapshot-")
}
