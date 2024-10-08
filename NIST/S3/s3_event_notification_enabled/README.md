Creating an Open Policy Agent (OPA) policy to ensure that Amazon S3 event notifications are enabled for S3 buckets is essential for monitoring and responding to changes in your S3 environment. This policy can help align with NIST guidelines, particularly supporting controls like **AU-12** (Audit Record Retention) and **IR-4** (Incident Handling).

### Key Considerations for S3 Event Notifications:
1. **Event Notification Requirement**: Ensure that S3 buckets have event notifications configured to trigger on specified events (e.g., object creation, deletion).
2. **Deny Requests**: If a bucket does not have the necessary event notifications enabled, the policy should deny the request and provide a clear message.

### **Rego Policy: `s3_event_notification_enabled.rego`**

```rego
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
```

### **Explanation:**
- **allow Rules**: The `allow` rule permits actions to configure event notifications if the bucket already has the necessary notifications enabled.

- **deny Rules**: If an attempt is made to set event notifications on a bucket that does not have them enabled, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that event notifications must be configured.

- **event_notifications_enabled Function**: This helper function checks whether the bucket has event notifications enabled by verifying that the `notification_configuration` exists and that at least one notification event is configured (in this example, we check for object creation events).

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a request to set the notification configuration on an S3 bucket.

#### Example Input (with Event Notifications Enabled):
```json
{
    "method": "s3:PutBucketNotificationConfiguration",
    "bucket": {
        "name": "my-secure-bucket",
        "notification_configuration": {
            "queue_configurations": [
                {
                    "event": "s3:ObjectCreated:*",
                    "queue_arn": "arn:aws:sqs:us-east-1:123456789012:my-queue"
                }
            ]
        }
    }
}
```

#### Example Input (without Event Notifications):
```json
{
    "method": "s3:PutBucketNotificationConfiguration",
    "bucket": {
        "name": "my-secure-bucket",
        "notification_configuration": null
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_event_notification_enabled.rego "data.aws.s3.allow"
```

If the bucket does not have event notifications configured, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_event_notification_enabled.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
Event notifications must be enabled for bucket 'my-secure-bucket'.
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **AU-12**: Audit Record Retention – Ensures that events in S3 are monitored for security incidents and other significant changes.
- **IR-4**: Incident Handling – Facilitates the detection of incidents by generating notifications when certain actions occur.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that S3 buckets requiring event notifications are correctly configured.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
