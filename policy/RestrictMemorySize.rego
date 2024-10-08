package aws.lambda

default allow = false

# Allowed memory size range
allowed_memory_sizes = {128, 256, 512, 1024, 2048, 3008}

# Allow Lambda function creation with specified memory size
allow {
    input.method == "lambda:CreateFunction"
    input.memory_size in allowed_memory_sizes
}

# Deny if the memory size is not allowed
deny_invalid_memory_size {
    input.method == "lambda:CreateFunction"
    not (input.memory_size in allowed_memory_sizes)
}
