package aws.sagemaker

default allow = false

# Allowed instance types
allowed_instance_types = {"ml.t2.medium", "ml.m5.large"}

# Allow SageMaker training job creation with specified instance types
allow {
    input.method == "sagemaker:CreateTrainingJob"
    input.instance_type in allowed_instance_types
}

# Deny if the instance type is not allowed
deny_invalid_instance_type {
    input.method == "sagemaker:CreateTrainingJob"
    not (input.instance_type in allowed_instance_types)
}
