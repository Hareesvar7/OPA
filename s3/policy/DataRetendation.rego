package aws.s3.compliance

default allow = false

min_retention_days = 30

# Ensure objects cannot be deleted before a retention period
deny {
  input.method == "s3:DeleteObject"
  input.creation_time + min_retention_days > time.now_ns() / 1000000  # Convert to milliseconds
}

allow {
  not deny
}
