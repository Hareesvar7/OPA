package aws.efs

default allow = false

allow {
    input.method == "efs:CreateMountTarget"
    input.public_access == false
}

deny_public_access {
    input.method == "efs:CreateMountTarget"
    input.public_access == true
}
