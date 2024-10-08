package aws.lambda

default allow = false

allow {
    input.method == "lambda:CreateFunction"
    input.public_access == false
}

deny_public_access {
    input.method == "lambda:CreateFunction"
    input.public_access == true
}
