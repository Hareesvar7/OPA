To create an Open Policy Agent (OPA) policy ensuring that Amazon S3 buckets are configured with default encryption using AWS Key Management Service (KMS), we can develop a policy that checks for the presence of KMS encryption configurations. This is essential for securing sensitive data, aligning with NIST guidelines, particularly supporting controls like **SC-28** (Protection of Information at Rest) and **AC-17** (Remote Access).

### Key Considerations for Default KMS Encryption:
1. **KMS Encryption Requirement**: Ensure that all S3 buckets are configured to use KMS for default encryption.
2. **Deny Requests**: If a bucket does not have KMS encryption configured as the default, the policy should deny the request and provide a clear message.

### **Rego Policy: `s3_default_encryption_kms.rego`**

```rego
package aws.s3

# Default deny all actions
default allow = false

# Allow if default encryption is configured with KMS for the bucket
allow {
    input.method == "s3:PutBucketEncryption"
    default_encryption_kms(input.bucket)
}

# Deny if default encryption is not configured with KMS
deny[{"msg": msg}] {
    input.method == "s3:PutBucketEncryption"
    not default_encryption_kms(input.bucket)
    msg = sprintf("Default encryption using KMS must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if default encryption is configured with KMS
default_encryption_kms(bucket) {
    bucket.encryption_configuration != null
    bucket.encryption_configuration.rules[_].apply_server_side_encryption_by_default.sse_algorithm == "aws:kms"
}
```

### **Explanation:**
- **allow Rules**: The `allow` rule permits actions to set bucket encryption configurations if the bucket has KMS encryption enabled.

- **deny Rules**: If an attempt is made to set encryption on a bucket that does not have KMS encryption configured, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that KMS encryption must be enabled.

- **default_encryption_kms Function**: This helper function checks whether the bucket has its default encryption configured to use KMS by verifying that the `sse_algorithm` is set to `aws:kms`.

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a request to set the encryption configuration on an S3 bucket.

#### Example Input (with KMS Encryption Enabled):
```json
{
    "method": "s3:PutBucketEncryption",
    "bucket": {
        "name": "my-secure-bucket",
        "encryption_configuration": {
            "rules": [
                {
                    "apply_server_side_encryption_by_default": {
                        "sse_algorithm": "aws:kms",
                        "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/my-key"
                    }
                }
            ]
        }
    }
}
```

#### Example Input (without KMS Encryption):
```json
{
    "method": "s3:PutBucketEncryption",
    "bucket": {
        "name": "my-secure-bucket",
        "encryption_configuration": {
            "rules": [
                {
                    "apply_server_side_encryption_by_default": {
                        "sse_algorithm": "AES256"  // Not KMS
                    }
                }
            ]
        }
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_default_encryption_kms.rego "data.aws.s3.allow"
```

If the bucket does not have KMS encryption configured, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_default_encryption_kms.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
Default encryption using KMS must be enabled for bucket 'my-secure-bucket'.
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **SC-28**: Protection of Information at Rest – Ensures that sensitive data is encrypted when stored in S3 buckets.
- **AC-17**: Remote Access – Protects data during remote access via encryption.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that S3 buckets requiring default KMS encryption are correctly configured.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
