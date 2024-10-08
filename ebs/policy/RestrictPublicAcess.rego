package aws.ebs

default allow = false

allow {
    input.method == "ebs:CreateVolume"
    input.public_access == false
}

deny_public_access {
    input.method == "ebs:CreateVolume"
    input.public_access == true
}
