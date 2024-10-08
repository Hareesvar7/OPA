package aws.cloudfront

default allow = false

# Allow CloudFront distribution creation with valid origin domain names
allow {
    input.method == "cloudfront:CreateDistribution"
    valid_origin_domain_name(input.origin_domain_name)
}

valid_origin_domain_name(domain_name) {
    # Check that the domain name is a valid URL format
    domain_name != "" # Additional checks can be implemented for more validation
}

# Deny invalid origin domain names
deny_invalid_origin {
    input.method == "cloudfront:CreateDistribution"
    not valid_origin_domain_name(input.origin_domain_name)
}
