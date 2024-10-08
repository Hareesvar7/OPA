package aws.sns

default allow = false

# Allow SNS topic creation only if the topic name starts with 'prod-'
allow {
  input.method == "sns:CreateTopic"
  startswith(input.topic_name, "prod-")
}

deny_invalid_topic_name {
  input.method == "sns:CreateTopic"
  not startswith(input.topic_name, "prod-")
}
