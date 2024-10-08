To create an Open Policy Agent (OPA) policy that ensures S3 buckets have cross-region replication enabled, you'll want to enforce that any S3 buckets intended for replication are correctly configured. This policy aligns with NIST guidelines by ensuring data redundancy and availability, supporting controls like **CP-2** (Contingency Plan) and **CP-4** (Contingency Plan Testing).

### Key Considerations for Cross-Region Replication:
1. **Replication Configuration**: Ensure that buckets have a replication configuration that specifies at least one destination bucket in a different region.
2. **Deny Requests**: If a bucket is not configured for cross-region replication when it is expected to be, the policy should deny the request and provide a clear message.

### **Rego Policy: `s3_bucket_cross_region_replication_enabled.rego`**

```rego
package aws.s3

# Default deny all actions
default allow = false

# Allow if cross-region replication is configured
allow {
    input.method == "s3:CreateBucket"
    cross_region_replication_enabled(input.bucket)
}

allow {
    input.method == "s3:PutBucketReplication"
    cross_region_replication_enabled(input.bucket)
}

allow {
    input.method == "s3:GetBucketReplication"
    cross_region_replication_enabled(input.bucket)
}

# Deny if cross-region replication is not configured
deny[{"msg": msg}] {
    input.method == "s3:PutBucketReplication"
    not cross_region_replication_enabled(input.bucket)
    msg = sprintf("Cross-region replication must be enabled for bucket '%s'.", [input.bucket.name])
}

deny[{"msg": msg}] {
    input.method == "s3:CreateBucket"
    not cross_region_replication_enabled(input.bucket)
    msg = sprintf("Cross-region replication must be enabled for bucket '%s'.", [input.bucket.name])
}

# Helper function to check if cross-region replication is configured on the bucket
cross_region_replication_enabled(bucket) {
    bucket.replication_configuration != null
    count(bucket.replication_configuration.rules) > 0
    all_rule_destinations_different_region(bucket.replication_configuration.rules)
}

# Helper function to ensure all rule destinations are in different regions
all_rule_destinations_different_region(rules) {
    not any_rule_same_region(rules)
}

any_rule_same_region(rules) {
    some rule
    rule.destination.bucket_region == rules[0].source_bucket_region
}
```

### **Explanation:**
- **allow Rules**: The `allow` rules permit actions if the bucket is configured for cross-region replication.

- **deny Rules**: If an attempt is made to create a bucket or set replication configuration without proper cross-region settings, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that replication must be enabled.

- **cross_region_replication_enabled Function**: This helper function checks whether the bucket has a valid replication configuration.

- **all_rule_destinations_different_region Function**: This function ensures that all destinations in the replication rules are configured in different regions than the source bucket.

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a request to create an S3 bucket:

```json
{
    "method": "s3:CreateBucket",
    "bucket": {
        "name": "my-replicated-bucket",
        "replication_configuration": {
            "rules": [
                {
                    "id": "rule1",
                    "destination": {
                        "bucket": "arn:aws:s3:::my-replicated-bucket-destination",
                        "bucket_region": "us-west-2"
                    },
                    "source_bucket_region": "us-east-1"
                }
            ]
        }
    }
}
```

### **Example Input (without Cross-Region Replication):**
```json
{
    "method": "s3:CreateBucket",
    "bucket": {
        "name": "my-non-replicated-bucket",
        "replication_configuration": null
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_bucket_cross_region_replication_enabled.rego "data.aws.s3.allow"
```

If the bucket is not configured for cross-region replication, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_bucket_cross_region_replication_enabled.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
Cross-region replication must be enabled for bucket 'my-non-replicated-bucket'.
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **CP-2**: Contingency Plan – Ensures that cross-region replication is configured to protect against data loss.
- **CP-4**: Contingency Plan Testing – Supports testing the replication configurations to ensure they work as intended.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that all S3 buckets intended for replication are properly configured for cross-region replication.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
