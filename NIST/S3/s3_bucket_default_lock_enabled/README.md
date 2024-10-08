To create an Open Policy Agent (OPA) policy that ensures S3 buckets have default object lock configurations enabled, you can enforce that all S3 buckets are set to automatically apply the desired lock settings on objects. This policy aligns with NIST guidelines by protecting data integrity and availability, supporting controls such as **CP-9** (Information System Backup) and **SI-12** (Information Handling).

### Key Considerations for Default Object Lock:
1. **Object Lock Configuration**: Ensure that buckets are configured with Object Lock enabled, which allows you to enforce retention policies on objects.
2. **Deny Requests**: If a bucket is not configured with default object lock settings, the policy should deny the request and provide a clear message.

### **Rego Policy: `s3_bucket_default_lock_enabled.rego`**

```rego
package aws.s3

# Default deny all actions
default allow = false

# Allow if default lock configuration is enabled
allow {
    input.method == "s3:CreateBucket"
    default_object_lock_enabled(input.bucket)
}

allow {
    input.method == "s3:PutObjectLockConfiguration"
    default_object_lock_enabled(input.bucket)
}

allow {
    input.method == "s3:GetObjectLockConfiguration"
    default_object_lock_enabled(input.bucket)
}

# Deny if default lock is not configured
deny[{"msg": msg}] {
    input.method == "s3:PutObjectLockConfiguration"
    not default_object_lock_enabled(input.bucket)
    msg = sprintf("Default object lock must be enabled for bucket '%s'.", [input.bucket.name])
}

deny[{"msg": msg}] {
    input.method == "s3:CreateBucket"
    not default_object_lock_enabled(input.bucket)
    msg = sprintf("Default object lock must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if default object lock is enabled on the bucket
default_object_lock_enabled(bucket) {
    bucket.object_lock_configuration != null
    bucket.object_lock_configuration.lock_enabled == true
    count(bucket.object_lock_configuration.rules) > 0
}
```

### **Explanation:**
- **allow Rules**: The `allow` rules permit actions if the bucket is configured with default object lock settings.

- **deny Rules**: If an attempt is made to create a bucket or set object lock configuration without proper default settings, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that the object lock must be enabled.

- **default_object_lock_enabled Function**: This helper function checks whether the bucket has a valid object lock configuration with lock enabled.

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a request to create an S3 bucket:

```json
{
    "method": "s3:CreateBucket",
    "bucket": {
        "name": "my-locked-bucket",
        "object_lock_configuration": {
            "lock_enabled": true,
            "rules": [
                {
                    "default_retention": {
                        "mode": "GOVERNANCE",
                        "days": 30
                    }
                }
            ]
        }
    }
}
```

### **Example Input (without Default Lock):**
```json
{
    "method": "s3:CreateBucket",
    "bucket": {
        "name": "my-unlocked-bucket",
        "object_lock_configuration": null
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_bucket_default_lock_enabled.rego "data.aws.s3.allow"
```

If the bucket is not configured with default object lock settings, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_bucket_default_lock_enabled.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
Default object lock must be enabled for bucket 'my-unlocked-bucket'.
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **CP-9**: Information System Backup – Ensures that data is preserved through object lock settings, which is essential for data recovery.
- **SI-12**: Information Handling – Supports the integrity and handling of sensitive data through retention policies.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that all S3 buckets intended to have object locks are properly configured.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
