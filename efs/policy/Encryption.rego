package aws.efs

default allow = false

allow {
    input.method == "efs:CreateFileSystem"
    input.encryption_at_rest == true
}

deny_missing_encryption {
    input.method == "efs:CreateFileSystem"
    input.encryption_at_rest == false
}
