Creating an Open Policy Agent (OPA) policy to ensure that S3 bucket server-side encryption is enabled is essential for securing sensitive data. This policy aligns with NIST guidelines for protecting data at rest and enforcing confidentiality, particularly supporting controls like **SC-28** (Protection of Information at Rest).

### Key Considerations for Server-Side Encryption:
1. **Encryption Requirement**: Ensure that all S3 buckets contain configurations for server-side encryption, such as SSE-S3 or SSE-KMS.
2. **Deny Requests**: If a bucket does not have server-side encryption enabled when it should, the policy should deny the request and provide a clear message.

### **Rego Policy: `s3_bucket_server_side_encryption_enabled.rego`**

```rego
package aws.s3

# Default deny all actions
default allow = false

# Allow if server-side encryption is enabled for the bucket
allow {
    input.method == "s3:PutBucketEncryption"
    encryption_enabled(input.bucket)
}

# Deny if server-side encryption is not configured
deny[{"msg": msg}] {
    input.method == "s3:PutBucketEncryption"
    not encryption_enabled(input.bucket)
    msg = sprintf("Server-side encryption must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if server-side encryption is enabled on the bucket
encryption_enabled(bucket) {
    bucket.encryption_configuration != null
    bucket.encryption_configuration.rules[_].apply_server_side_encryption_by_default.sse_algorithm == "AES256"
}
```

### **Explanation:**
- **allow Rules**: The `allow` rule permits actions to set bucket encryption configurations if the bucket already has encryption enabled.

- **deny Rules**: If an attempt is made to set encryption on a bucket that does not have server-side encryption enabled, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that encryption must be enabled.

- **encryption_enabled Function**: This helper function checks whether the bucket has server-side encryption enabled, specifically looking for the `AES256` algorithm or other specified encryption methods like `aws:kms`.

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a request to set a bucket encryption configuration on an S3 bucket:

#### Example Input (with Encryption Enabled):
```json
{
    "method": "s3:PutBucketEncryption",
    "bucket": {
        "name": "my-secure-bucket",
        "encryption_configuration": {
            "rules": [
                {
                    "apply_server_side_encryption_by_default": {
                        "sse_algorithm": "AES256"
                    }
                }
            ]
        }
    }
}
```

#### Example Input (without Encryption):
```json
{
    "method": "s3:PutBucketEncryption",
    "bucket": {
        "name": "my-secure-bucket",
        "encryption_configuration": null
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_bucket_server_side_encryption_enabled.rego "data.aws.s3.allow"
```

If the bucket does not have server-side encryption enabled, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_bucket_server_side_encryption_enabled.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
Server-side encryption must be enabled for bucket 'my-secure-bucket'.
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **SC-28**: Protection of Information at Rest – Ensures that sensitive data is encrypted when stored in S3 buckets.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that S3 buckets requiring encryption are correctly configured.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
