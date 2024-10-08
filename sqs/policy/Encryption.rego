package aws.sqs

default allow = false

# Allow queue creation only if encryption is enabled
allow {
  input.method == "sqs:CreateQueue"
  input.encryption == true
}

deny_unencrypted_queue {
  input.method == "sqs:CreateQueue"
  input.encryption == false
}
