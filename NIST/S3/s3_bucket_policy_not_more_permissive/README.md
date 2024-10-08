Creating an Open Policy Agent (OPA) policy to ensure that S3 bucket policies are not more permissive than required is critical for maintaining the principle of least privilege. This policy aligns with NIST guidelines by enforcing strict access controls to sensitive resources, thereby preventing unauthorized access and data leakage. It supports controls like **AC-3** (Access Enforcement) and **AC-6** (Least Privilege).

### Key Considerations for Non-Permissive Policies:
1. **Definition of Permissiveness**: Establish criteria to evaluate if a policy is considered more permissive, such as allowing access to broader groups than necessary.
2. **Deny Requests**: If a policy is found to be more permissive than required, the policy should deny the request and provide a clear message.

### **Rego Policy: `s3_bucket_policy_not_more_permissive.rego`**

```rego
package aws.s3

# Default deny all actions
default allow = false

# Define a set of allowed principals for the S3 bucket
allowed_principals = {
    "arn:aws:iam::123456789012:user/allowed-user",
    "arn:aws:iam::123456789012:role/allowed-role"
}

# Allow if the bucket policy is not more permissive than allowed
allow {
    input.method == "s3:PutBucketPolicy"
    not is_more_permissive(input.bucket_policy)
}

# Deny if the bucket policy is found to be more permissive
deny[{"msg": msg}] {
    input.method == "s3:PutBucketPolicy"
    is_more_permissive(input.bucket_policy)
    msg = "The bucket policy is more permissive than allowed."
}

# Function to check if the policy is more permissive than allowed
is_more_permissive(bucket_policy) {
    some statement
    statement := bucket_policy.Statement[_]

    # Check if the statement allows access to principals not in the allowed list
    not principal_in_allowed_list(statement.Principal)
}

# Helper function to check if any principal is in the allowed list
principal_in_allowed_list(principal) {
    principal.AWS[_] in allowed_principals
}
```

### **Explanation:**
- **allowed_principals Set**: This set defines the allowed principals (AWS Account IDs or Principal ARNs) that can access the bucket.

- **allow Rules**: The `allow` rule permits the action of setting a bucket policy as long as it is not more permissive than allowed.

- **deny Rules**: If an attempt is made to set a bucket policy that is more permissive than defined, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that the bucket policy is too permissive.

- **is_more_permissive Function**: This helper function checks whether any of the principals in the bucket policy are not in the allowed list, thereby determining if the policy is more permissive than intended.

### **Example Input JSON:**
Here’s an example of how the input JSON would look for evaluating the policy. This represents a request to set a bucket policy:

```json
{
    "method": "s3:PutBucketPolicy",
    "bucket_policy": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::123456789012:user/allowed-user",
                        "arn:aws:iam::987654321098:user/disallowed-user"
                    ]
                },
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-secure-bucket/*"
            }
        ]
    }
}
```

### **Example Input (Compliant Policy):**
```json
{
    "method": "s3:PutBucketPolicy",
    "bucket_policy": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::123456789012:user/allowed-user"
                    ]
                },
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-secure-bucket/*"
            }
        ]
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_bucket_policy_not_more_permissive.rego "data.aws.s3.allow"
```

If the bucket policy is found to be more permissive, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_bucket_policy_not_more_permissive.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
The bucket policy is more permissive than allowed.
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **AC-3**: Access Enforcement – Ensures that access to the bucket is limited to authorized principals only.
- **AC-6**: Least Privilege – Maintains that only necessary permissions are granted, preventing over-permissive policies.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that S3 bucket policies are compliant with the defined non-permissiveness criteria.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
