To create an Open Policy Agent (OPA) policy that ensures S3 buckets have MFA (Multi-Factor Authentication) delete enabled, you can enforce that all S3 buckets requiring higher security for delete operations are configured accordingly. This policy aligns with NIST guidelines by enhancing the security of sensitive data, supporting controls such as **IA-5** (Authenticator Management) and **AC-17** (Remote Access).

### Key Considerations for MFA Delete:
1. **MFA Delete Configuration**: Ensure that the bucket is configured to require MFA for delete operations.
2. **Deny Requests**: If a bucket is not configured with MFA delete when it is expected to be, the policy should deny the request and provide a clear message.

### **Rego Policy: `s3_bucket_mfa_delete_enabled.rego`**

```rego
package aws.s3

# Default deny all actions
default allow = false

# Allow if MFA delete is enabled
allow {
    input.method == "s3:PutBucketVersioning"
    mfa_delete_enabled(input.bucket)
}

allow {
    input.method == "s3:DeleteObjectVersion"
    mfa_delete_enabled(input.bucket)
}

# Deny if MFA delete is not configured
deny[{"msg": msg}] {
    input.method == "s3:PutBucketVersioning"
    not mfa_delete_enabled(input.bucket)
    msg = sprintf("MFA delete must be enabled for bucket '%s'.", [input.bucket.name])
}

deny[{"msg": msg}] {
    input.method == "s3:DeleteObjectVersion"
    not mfa_delete_enabled(input.bucket)
    msg = sprintf("MFA delete must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if MFA delete is enabled on the bucket
mfa_delete_enabled(bucket) {
    bucket.versioning != null
    bucket.versioning.mfa_delete == "Enabled"
}
```

### **Explanation:**
- **allow Rules**: The `allow` rules permit actions if the bucket is configured to require MFA for delete operations.

- **deny Rules**: If an attempt is made to set bucket versioning or delete an object version without MFA delete enabled, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that MFA delete must be enabled.

- **mfa_delete_enabled Function**: This helper function checks whether the bucket has MFA delete enabled.

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a request to put versioning on an S3 bucket:

```json
{
    "method": "s3:PutBucketVersioning",
    "bucket": {
        "name": "my-secure-bucket",
        "versioning": {
            "mfa_delete": "Enabled"
        }
    }
}
```

### **Example Input (without MFA Delete):**
```json
{
    "method": "s3:PutBucketVersioning",
    "bucket": {
        "name": "my-non-secure-bucket",
        "versioning": {
            "mfa_delete": "Disabled"
        }
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_bucket_mfa_delete_enabled.rego "data.aws.s3.allow"
```

If the bucket is not configured with MFA delete enabled, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_bucket_mfa_delete_enabled.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
MFA delete must be enabled for bucket 'my-non-secure-bucket'.
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **IA-5**: Authenticator Management – Enforces the use of MFA for sensitive operations like deletions.
- **AC-17**: Remote Access – Ensures that access and actions taken remotely require additional authentication for critical operations.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that all S3 buckets that should have MFA delete enabled are correctly configured.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
