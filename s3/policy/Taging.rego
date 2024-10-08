package aws.s3.compliance

default allow = false

required_tags = {"cost-center", "project-id"}

# Ensure all required tags are present in object metadata
allow {
  input.method == "s3:PutObject"
  all_tags_present
}

all_tags_present {
  required_tags[_] = tag
  input.tags[_] == tag
}

deny {
  not allow
}
