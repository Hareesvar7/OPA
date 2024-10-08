
To create an Open Policy Agent (OPA) policy that prohibits public read access to S3 buckets in alignment with NIST guidelines, you should ensure that no S3 bucket allows public read access. This is crucial for protecting sensitive data and maintaining compliance with various NIST controls, including **AC-3** (Access Enforcement) and **SC-7** (Boundary Protection).

### Key Considerations for Public Read Access Prohibition:
When checking for public read access, you need to consider:
1. **BlockPublicAcls** – Should be enabled to block public ACLs.
2. **IgnorePublicAcls** – Should be enabled to ignore any public ACLs.
3. **BlockPublicPolicy** – Should be enabled to block any public bucket policies that allow read access.
4. **RestrictPublicBuckets** – Should be enabled to restrict access to buckets with public policies to only AWS service principals and authorized users.

### **Rego Policy: `s3_bucket_public_read_prohibited.rego`**

```rego
package aws.s3

# Default deny all actions
default allow = false

# Allow if public read access is properly prohibited
allow {
    input.method == "s3:CreateBucket"
    not bucket_public_read_allowed(input.bucket)
}

allow {
    input.method == "s3:PutBucketPolicy"
    not bucket_public_read_allowed(input.bucket)
}

allow {
    input.method == "s3:PutBucketAcl"
    not bucket_public_read_allowed(input.bucket)
}

# Deny if public read access is allowed on the bucket
deny[{"msg": msg}] {
    input.method == "s3:CreateBucket"
    bucket_public_read_allowed(input.bucket)
    msg = sprintf("Public read access is prohibited for bucket %s", [input.bucket.name])
}

deny[{"msg": msg}] {
    input.method == "s3:PutBucketPolicy"
    bucket_public_read_allowed(input.bucket)
    msg = sprintf("Public read access is prohibited for bucket %s", [input.bucket.name])
}

deny[{"msg": msg}] {
    input.method == "s3:PutBucketAcl"
    bucket_public_read_allowed(input.bucket)
    msg = sprintf("Public read access is prohibited for bucket %s", [input.bucket.name])
}

# Helper function to check if public read access is allowed on the bucket
bucket_public_read_allowed(bucket) {
    bucket.public_access_block_configuration.block_public_acls == false
    bucket.public_access_block_configuration.ignore_public_acls == false
    bucket.public_access_block_configuration.block_public_policy == false
    bucket.public_access_block_configuration.restrict_public_buckets == false
}
```

### **Explanation:**
- **allow Rules**: The `allow` rules permit actions if the bucket does not allow public read access. If any of the public access blocks are set to `false`, the action will be denied.

- **deny Rules**: If any of the public access settings allow public read access (i.e., they are set to `false`), the corresponding `deny` rule will trigger, preventing the action and providing a message that public read access is prohibited.

- **bucket_public_read_allowed Function**: This helper function checks whether any public access settings on the bucket allow public read access.

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a bucket creation request:

```json
{
    "method": "s3:CreateBucket",
    "bucket": {
        "name": "my-private-bucket",
        "public_access_block_configuration": {
            "block_public_acls": false,
            "ignore_public_acls": false,
            "block_public_policy": false,
            "restrict_public_buckets": false
        }
    }
}
```

### **Example Input (with Prohibited Settings):**
```json
{
    "method": "s3:CreateBucket",
    "bucket": {
        "name": "my-private-bucket",
        "public_access_block_configuration": {
            "block_public_acls": true,
            "ignore_public_acls": true,
            "block_public_policy": true,
            "restrict_public_buckets": true
        }
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_bucket_public_read_prohibited.rego "data.aws.s3.allow"
```

If public read access is allowed, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_bucket_public_read_prohibited.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
Public read access is prohibited for bucket my-private-bucket
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **AC-3**: Access Enforcement – Ensures that no buckets are publicly readable.
- **SC-7**: Boundary Protection – Protects AWS account boundaries by ensuring S3 buckets cannot be accessed publicly.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that no S3 bucket is configured to allow public read access.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
