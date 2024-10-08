package aws.s3

# Default deny all actions
default allow = false

# Allow if the request is made over SSL (HTTPS)
allow {
    input.method == "s3:GetObject" 
    is_ssl_request(input)
}

allow {
    input.method == "s3:PutObject" 
    is_ssl_request(input)
}

# Deny if the request is not made over SSL
deny[{"msg": msg}] {
    not is_ssl_request(input)
    msg = "Only SSL (HTTPS) requests are allowed for S3 buckets."
}

# Helper function to check if the request is made over SSL
is_ssl_request(input) {
    input.request_url[_] = "https://"
}
