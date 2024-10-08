package aws.cloudfront

default allow = false

allow {
    input.method == "cloudfront:CreateDistribution"
    input.https_only == true
}

deny_https_only {
    input.method == "cloudfront:CreateDistribution"
    input.https_only == false
}
