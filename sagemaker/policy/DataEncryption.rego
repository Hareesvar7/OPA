package aws.sagemaker

default allow = false

allow {
    input.method == "sagemaker:CreateTrainingJob"
    input.enable_data_encryption == true
}

deny_missing_encryption {
    input.method == "sagemaker:CreateTrainingJob"
    input.enable_data_encryption == false
}
