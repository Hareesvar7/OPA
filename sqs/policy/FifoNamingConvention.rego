package aws.sqs

default allow = false

# Allow SQS queue creation only if it's a FIFO queue and has '.fifo' suffix in its name
allow {
  input.method == "sqs:CreateQueue"
  input.queue_type == "FIFO"
  endswith(input.queue_name, ".fifo")
}

deny_invalid_fifo_queue_name {
  input.method == "sqs:CreateQueue"
  input.queue_type == "FIFO"
  not endswith(input.queue_name, ".fifo")
}
