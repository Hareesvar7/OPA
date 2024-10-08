package aws.lambda

default allow = false

allow {
    input.method == "lambda:CreateFunction"
    input.environment_variables_encrypted == true
}

deny_unencrypted_environment_variables {
    input.method == "lambda:CreateFunction"
    input.environment_variables_encrypted == false
}
