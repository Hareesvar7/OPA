package aws.sns

default allow = false

# Required tags for all SNS topics
required_tags = {"environment", "owner"}

# Ensure all required tags are present in SNS topic
allow {
  input.method == "sns:CreateTopic"
  all_tags_present
}

all_tags_present {
  required_tags[_] = tag
  input.tags[_] == tag
}

deny_missing_tags {
  input.method == "sns:CreateTopic"
  not all_tags_present
}
