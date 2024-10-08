package aws.cloudfront

default allow = false

# Allow CloudFront distribution creation with specified viewer protocol policy
allow {
    input.method == "cloudfront:CreateDistribution"
    input.viewer_protocol_policy == "redirect-to-https"
}

# Deny if the viewer protocol policy is not allowed
deny_invalid_viewer_protocol {
    input.method == "cloudfront:CreateDistribution"
    input.viewer_protocol_policy != "redirect-to-https"
}
