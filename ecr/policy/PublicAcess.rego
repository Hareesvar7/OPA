package aws.ecr

default allow = false

allow {
    input.method == "ecr:SetRepositoryPolicy"
    input.repository_policy["effect"] != "ALLOW" 
    input.repository_policy["principal"] != "*"
}

deny_public_access {
    input.method == "ecr:SetRepositoryPolicy"
    input.repository_policy["effect"] == "ALLOW" 
    input.repository_policy["principal"] == "*"
}
