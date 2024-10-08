package aws.sagemaker

default allow = false

allow {
    input.method == "sagemaker:CreateTrainingJob"
    input.iam_role_permissions == "allowed"
}

deny_unauthorized_iam_role {
    input.method == "sagemaker:CreateTrainingJob"
    input.iam_role_permissions != "allowed"
}
