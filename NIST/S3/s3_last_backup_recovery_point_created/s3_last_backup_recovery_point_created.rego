package aws.s3

# Default deny all actions
default allow = false

# Define a time window for backup recovery point validation (in seconds)
time_window = 86400  # 24 hours

# Allow if a valid backup recovery point exists for the bucket
allow {
    input.method == "s3:GetObject"  # Example action that requires a backup check
    valid_backup_recovery_point(input.bucket)
}

# Deny if no valid backup recovery point is found
deny[{"msg": msg}] {
    input.method == "s3:GetObject"  # Example action
    not valid_backup_recovery_point(input.bucket)
    msg = sprintf("No valid backup recovery point found for bucket '%s' in the last 24 hours.", [input.bucket.name])
}

# Helper function to check if the last backup recovery point was created recently
valid_backup_recovery_point(bucket) {
    last_backup_time = bucket.last_backup_time  # This should be provided in the input
    last_backup_time + time_window >= time.now_ns() / 1_000_000_000  # Convert to seconds
}
