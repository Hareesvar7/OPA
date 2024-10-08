package aws.cloudfront

default allow = false

allow {
    input.method == "cloudfront:CreateDistribution"
    input.origin_s3_public_access == false
}

deny_public_access {
    input.method == "cloudfront:CreateDistribution"
    input.origin_s3_public_access == true
}
