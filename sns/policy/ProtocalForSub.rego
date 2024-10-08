package aws.sns

default allow = false

# Approved subscription protocols
allowed_protocols = {"https", "email"}

# Allow subscription if protocol is approved
allow {
  input.method == "sns:Subscribe"
  allowed_protocols[input.protocol]
}

deny_invalid_protocol {
  input.method == "sns:Subscribe"
  not allowed_protocols[input.protocol]
}
