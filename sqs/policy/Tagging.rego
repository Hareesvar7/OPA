package aws.sqs

default allow = false

# Required tags for all SQS queues
required_tags = {"owner", "environment"}

# Allow queue creation if all required tags are present
allow {
  input.method == "sqs:CreateQueue"
  all_required_tags_present
}

all_required_tags_present {
  required_tags[_] = tag
  input.tags[_] == tag
}

deny_missing_tags {
  input.method == "sqs:CreateQueue"
  not all_required_tags_present
}
