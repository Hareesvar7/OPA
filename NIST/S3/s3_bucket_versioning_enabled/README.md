Creating an Open Policy Agent (OPA) policy to ensure that versioning is enabled for Amazon S3 buckets is crucial for maintaining data integrity and availability. This policy aligns with NIST guidelines, particularly supporting controls like **SC-28** (Protection of Information at Rest) and **CP-9** (Information System Backup).

### Key Considerations for Bucket Versioning:
1. **Versioning Requirement**: Ensure that all S3 buckets that require versioning are properly configured to support it.
2. **Deny Requests**: If a bucket that requires versioning is not configured with it, the policy should deny the request and provide a clear message.

### **Rego Policy: `s3_bucket_versioning_enabled.rego`**

```rego
package aws.s3

# Default deny all actions
default allow = false

# Allow if versioning is enabled for the bucket
allow {
    input.method == "s3:PutBucketVersioning"
    versioning_enabled(input.bucket)
}

# Deny if versioning is not configured
deny[{"msg": msg}] {
    input.method == "s3:PutBucketVersioning"
    not versioning_enabled(input.bucket)
    msg = sprintf("Versioning must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if versioning is enabled on the bucket
versioning_enabled(bucket) {
    bucket.versioning_status == "Enabled"
}
```

### **Explanation:**
- **allow Rules**: The `allow` rule permits actions to set the versioning configuration if the bucket already has versioning enabled.

- **deny Rules**: If an attempt is made to set the versioning configuration on a bucket that does not have versioning enabled, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that versioning must be enabled.

- **versioning_enabled Function**: This helper function checks whether the bucket has versioning enabled by verifying the `versioning_status` field.

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a request to set the versioning configuration on an S3 bucket.

#### Example Input (with Versioning Enabled):
```json
{
    "method": "s3:PutBucketVersioning",
    "bucket": {
        "name": "my-secure-bucket",
        "versioning_status": "Enabled"
    }
}
```

#### Example Input (without Versioning):
```json
{
    "method": "s3:PutBucketVersioning",
    "bucket": {
        "name": "my-secure-bucket",
        "versioning_status": "Suspended"
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_bucket_versioning_enabled.rego "data.aws.s3.allow"
```

If the bucket does not have versioning enabled, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_bucket_versioning_enabled.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
Versioning must be enabled for bucket 'my-secure-bucket'.
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **SC-28**: Protection of Information at Rest – Ensures that data is protected and can be recovered through versioning.
- **CP-9**: Information System Backup – Facilitates data recovery options through versioning.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that S3 buckets requiring versioning are correctly configured.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
