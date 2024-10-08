Creating an Open Policy Agent (OPA) policy to ensure that Amazon S3 buckets have lifecycle policies configured is essential for managing data retention, optimizing storage costs, and complying with NIST guidelines. This aligns with controls such as **SI-12** (Information System Documentation) and **CP-9** (Information System Backup).

### Key Considerations for Lifecycle Policies:
1. **Lifecycle Policy Requirement**: Ensure that S3 buckets have lifecycle policies configured for transitioning objects to different storage classes or for deletion after a specified period.
2. **Deny Requests**: If a bucket does not have a lifecycle policy configured, the policy should deny the request and provide a clear message.

### **Rego Policy: `s3_lifecycle_policy_check.rego`**

This policy checks if the specified S3 bucket has a lifecycle policy configured.

```rego
package aws.s3

# Default deny all actions
default allow = false

# Allow if a lifecycle policy is configured for the bucket
allow {
    input.method == "s3:PutLifecycleConfiguration"
    lifecycle_policy_configured(input.bucket)
}

# Deny if no lifecycle policy is found
deny[{"msg": msg}] {
    input.method == "s3:PutLifecycleConfiguration"
    not lifecycle_policy_configured(input.bucket)
    msg = sprintf("A lifecycle policy must be configured for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if a lifecycle policy is configured on the bucket
lifecycle_policy_configured(bucket) {
    bucket.lifecycle_configuration != null
    count(bucket.lifecycle_configuration.rules) > 0
}
```

### **Explanation:**
- **allow Rules**: The `allow` rule permits actions to set lifecycle configurations if the bucket already has lifecycle policies configured.

- **deny Rules**: If an attempt is made to set lifecycle policies on a bucket that does not have them configured, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that a lifecycle policy is required.

- **lifecycle_policy_configured Function**: This helper function checks whether the bucket has a lifecycle configuration by verifying that the `lifecycle_configuration` field is present and contains one or more rules.

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a request to set the lifecycle configuration on an S3 bucket.

#### Example Input (with Lifecycle Policy Configured):
```json
{
    "method": "s3:PutLifecycleConfiguration",
    "bucket": {
        "name": "my-secure-bucket",
        "lifecycle_configuration": {
            "rules": [
                {
                    "id": "TransitionToGlacier",
                    "status": "Enabled",
                    "filter": {
                        "prefix": ""
                    },
                    "transition": [
                        {
                            "days": 30,
                            "storage_class": "GLACIER"
                        }
                    ]
                }
            ]
        }
    }
}
```

#### Example Input (without Lifecycle Policy):
```json
{
    "method": "s3:PutLifecycleConfiguration",
    "bucket": {
        "name": "my-secure-bucket",
        "lifecycle_configuration": null
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_lifecycle_policy_check.rego "data.aws.s3.allow"
```

If the bucket does not have a lifecycle policy configured, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_lifecycle_policy_check.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
A lifecycle policy must be configured for bucket 'my-secure-bucket'.
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **SI-12**: Information System Documentation – Ensures documentation of lifecycle policies for data management.
- **CP-9**: Information System Backup – Facilitates the management and retention of backups.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that lifecycle policies are correctly configured for your S3 buckets.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
