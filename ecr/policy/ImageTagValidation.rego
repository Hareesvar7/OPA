package aws.ecr

default allow = false

# Allowable tag format using regular expressions
tag_format = "^(v\\d+\\.\\d+\\.\\d+)$" # Matches tags like v1.0.0

# Allow image push if the tag matches the expected format
allow {
    input.method == "ecr:PutImage"
    re_match(tag_format, input.image_tag)
}

# Deny push if the image tag does not match the expected format
deny_invalid_image_tag {
    input.method == "ecr:PutImage"
    not re_match(tag_format, input.image_tag)
}
