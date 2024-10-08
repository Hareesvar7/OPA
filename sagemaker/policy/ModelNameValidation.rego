package aws.sagemaker

default allow = false

# Allow SageMaker model creation with valid names
allow {
    input.method == "sagemaker:CreateModel"
    startswith(input.model_name, "model-")
}

# Deny if the model name is not valid
deny_invalid_model_name {
    input.method == "sagemaker:CreateModel"
    not startswith(input.model_name, "model-")
}
