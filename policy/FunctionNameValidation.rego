package aws.lambda

default allow = false

# Allow Lambda function creation with valid names
allow {
    input.method == "lambda:CreateFunction"
    is_valid_function_name(input.function_name)
}

is_valid_function_name(name) {
    name =~ "^lambda-[a-zA-Z0-9-]+$"
}

# Deny if the function name is invalid
deny_invalid_function_name {
    input.method == "lambda:CreateFunction"
    not is_valid_function_name(input.function_name)
}
