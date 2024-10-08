package aws.sns

default allow = false

# Deny the creation of an SNS topic if encryption is not enabled
deny_unencrypted_topic {
  input.method == "sns:CreateTopic"
  input.kms_master_key_id == ""
}

allow {
  not deny_unencrypted_topic
}
