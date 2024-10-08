package aws.ec2

default allow = false

required_tags = {"cost-center", "project-id"}

# Ensure all required tags are present in instance metadata
allow {
  input.method == "ec2:RunInstances"
  all_tags_present
}

all_tags_present {
  required_tags[_] = tag
  input.tags[_] == tag
}

deny_missing_tags {
  input.method == "ec2:RunInstances"
  not all_tags_present
}
