package aws.ecr

default allow = false

# Allowable repository name prefixes
allowed_prefixes = {"dev-", "prod-"}

# Allow ECR repository creation if the name starts with an allowed prefix
allow {
    input.method == "ecr:CreateRepository"
    some prefix
    startswith(input.repository_name, prefix)
    allowed_prefixes[prefix]
}

# Deny creation if the repository name does not start with an allowed prefix
deny_invalid_repository_name {
    input.method == "ecr:CreateRepository"
    not (some prefix; startswith(input.repository_name, prefix); allowed_prefixes[prefix])
}
