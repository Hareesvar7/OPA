package aws.ebs

default allow = false

allow {
    input.method == "ebs:CreateVolume"
    input.encrypted == true
}

deny_unencrypted_volume {
    input.method == "ebs:CreateVolume"
    input.encrypted == false
}

allow {
    input.method == "ebs:CreateSnapshot"
    input.encrypted == true
}

deny_unencrypted_snapshot {
    input.method == "ebs:CreateSnapshot"
    input.encrypted == false
}
