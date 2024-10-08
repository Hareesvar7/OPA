Creating an Open Policy Agent (OPA) policy to ensure that Amazon S3 buckets have a recent backup or recovery point created is essential for data availability and integrity. This aligns with NIST guidelines, particularly supporting controls like **CP-9** (Information System Backup) and **CP-2** (Contingency Plan).

### Key Considerations for Last Backup Recovery Point:
1. **Backup Requirement**: Ensure that there is a record of a recent backup (recovery point) for S3 buckets.
2. **Deny Requests**: If a bucket does not have a recent backup, the policy should deny the request and provide a clear message.

### **Rego Policy: `s3_last_backup_recovery_point_created.rego`**

This policy checks if the last backup for the specified S3 bucket was created within a defined time window (e.g., last 24 hours).

```rego
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
```

### **Explanation:**
- **allow Rules**: The `allow` rule permits actions (e.g., retrieving an object) if a valid backup recovery point exists for the bucket.

- **deny Rules**: If an attempt is made to perform actions without a valid backup recovery point, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that a backup is required.

- **valid_backup_recovery_point Function**: This helper function checks whether the last backup recovery point was created within the specified time window (24 hours in this case).

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a request related to an S3 bucket's backup.

#### Example Input (with Recent Backup):
```json
{
    "method": "s3:GetObject",
    "bucket": {
        "name": "my-secure-bucket",
        "last_backup_time": 1696348800  // Unix timestamp (in seconds) for when the last backup was taken
    }
}
```

#### Example Input (without Recent Backup):
```json
{
    "method": "s3:GetObject",
    "bucket": {
        "name": "my-secure-bucket",
        "last_backup_time": 1696252400  // Older than 24 hours
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_last_backup_recovery_point_created.rego "data.aws.s3.allow"
```

If the bucket does not have a valid backup recovery point, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_last_backup_recovery_point_created.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
No valid backup recovery point found for bucket 'my-secure-bucket' in the last 24 hours.
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **CP-9**: Information System Backup – Ensures that data is backed up and recoverable in case of data loss.
- **CP-2**: Contingency Plan – Supports the creation of contingency plans based on regular backups of critical data.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that backups are performed regularly for your S3 buckets.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
