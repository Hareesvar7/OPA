To create an Open Policy Agent (OPA) policy that ensures S3 bucket replication is enabled, you need to check that all S3 buckets that should have replication configured indeed do so. This policy aligns with NIST guidelines for data protection and disaster recovery, specifically supporting controls like **CP-9** (Information System Backup) and **SC-28** (Protection of Information at Rest).

### Key Considerations for S3 Bucket Replication:
1. **Replication Configuration**: Ensure that the bucket is configured for replication to another bucket, which is critical for data durability and recovery.
2. **Deny Requests**: If a bucket is not configured with replication when it should be, the policy should deny the request and provide a clear message.

### **Rego Policy: `s3_bucket_replication_enabled.rego`**

```rego
package aws.s3

# Default deny all actions
default allow = false

# Allow if replication is enabled for the bucket
allow {
    input.method == "s3:PutReplicationConfiguration"
    replication_enabled(input.bucket)
}

# Deny if replication is not configured
deny[{"msg": msg}] {
    input.method == "s3:PutReplicationConfiguration"
    not replication_enabled(input.bucket)
    msg = sprintf("Replication must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if replication is enabled on the bucket
replication_enabled(bucket) {
    bucket.replication_status == "Enabled"
}
```

### **Explanation:**
- **allow Rules**: The `allow` rule permits actions to set replication configurations if the bucket is already set for replication.

- **deny Rules**: If an attempt is made to set replication configuration on a bucket that does not have replication enabled, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that replication must be enabled.

- **replication_enabled Function**: This helper function checks whether the bucket has replication enabled.

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a request to set a replication configuration on an S3 bucket:

```json
{
    "method": "s3:PutReplicationConfiguration",
    "bucket": {
        "name": "my-secure-bucket",
        "replication_status": "Enabled"
    }
}
```

### **Example Input (without Replication):**
```json
{
    "method": "s3:PutReplicationConfiguration",
    "bucket": {
        "name": "my-secure-bucket",
        "replication_status": "Disabled"
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_bucket_replication_enabled.rego "data.aws.s3.allow"
```

If the bucket is not configured with replication enabled, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_bucket_replication_enabled.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
Replication must be enabled for bucket 'my-secure-bucket'.
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **CP-9**: Information System Backup – Ensures that data is replicated and backed up to meet recovery requirements.
- **SC-28**: Protection of Information at Rest – Ensures that data is replicated for redundancy and durability.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that S3 buckets that require replication are correctly configured.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
