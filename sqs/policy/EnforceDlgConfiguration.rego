package aws.sqs

default allow = false

# Allow queue creation only if a Dead-Letter Queue (DLQ) is configured
allow {
  input.method == "sqs:CreateQueue"
  input.dead_letter_queue_arn != ""
}

deny_missing_dlq {
  input.method == "sqs:CreateQueue"
  input.dead_letter_queue_arn == ""
}
