package aws.s3

# Default deny all actions
default allow = false

# Allow if event notifications are enabled for the bucket
allow {
    input.method == "s3:PutBucketNotificationConfiguration"
    event_notifications_enabled(input.bucket)
}

# Deny if event notifications are not configured
deny[{"msg": msg}] {
    input.method == "s3:PutBucketNotificationConfiguration"
    not event_notifications_enabled(input.bucket)
    msg = sprintf("Event notifications must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if event notifications are enabled on the bucket
event_notifications_enabled(bucket) {
    bucket.notification_configuration != null
    bucket.notification_configuration.queue_configurations[_].event == "s3:ObjectCreated:*"  # Example event
    bucket.notification_configuration.queue_configurations[_].queue_arn != ""
}
