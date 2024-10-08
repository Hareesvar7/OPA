To create an Open Policy Agent (OPA) policy that ensures S3 Access Points have public access blocks in place, you need to enforce that public access is restricted for all S3 Access Points in alignment with NIST guidelines. This policy helps prevent unauthorized access and protects sensitive data in accordance with controls such as **AC-3** (Access Enforcement) and **SC-7** (Boundary Protection).

### Key Considerations for Public Access Blocks:
1. **BlockPublicAcls**: Must be enabled to block public ACLs.
2. **IgnorePublicAcls**: Should be enabled to ignore public ACLs if they are set.
3. **BlockPublicPolicy**: Must be enabled to block any public policies that allow public access.
4. **RestrictPublicBuckets**: Should be enabled to restrict access to buckets with public policies to only AWS service principals and authorized users.

### **Rego Policy: `s3_access_point_public_access_blocks.rego`**

```rego
package aws.s3

# Default deny all actions
default allow = false

# Allow if public access blocks are correctly configured
allow {
    input.method == "s3:CreateAccessPoint"
    public_access_blocks_configured(input.access_point)
}

allow {
    input.method == "s3:PutAccessPointPolicy"
    public_access_blocks_configured(input.access_point)
}

allow {
    input.method == "s3:UpdateAccessPoint"
    public_access_blocks_configured(input.access_point)
}

# Deny if public access blocks are not properly configured
deny[{"msg": msg}] {
    input.method == "s3:CreateAccessPoint"
    not public_access_blocks_configured(input.access_point)
    msg = sprintf("Access Point %s must have public access blocks enabled", [input.access_point.name])
}

deny[{"msg": msg}] {
    input.method == "s3:PutAccessPointPolicy"
    not public_access_blocks_configured(input.access_point)
    msg = sprintf("Access Point %s must have public access blocks enabled", [input.access_point.name])
}

deny[{"msg": msg}] {
    input.method == "s3:UpdateAccessPoint"
    not public_access_blocks_configured(input.access_point)
    msg = sprintf("Access Point %s must have public access blocks enabled", [input.access_point.name])
}

# Helper function to check if public access blocks are enabled on the Access Point
public_access_blocks_configured(access_point) {
    access_point.public_access_block_configuration.block_public_acls == true
    access_point.public_access_block_configuration.ignore_public_acls == true
    access_point.public_access_block_configuration.block_public_policy == true
    access_point.public_access_block_configuration.restrict_public_buckets == true
}
```

### **Explanation:**
- **allow Rules**: The `allow` rules permit actions if the Access Point has the appropriate public access blocks enabled. 

- **deny Rules**: If any attempts to create or modify an Access Point do not have the required public access blocks, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that public access blocks must be enabled.

- **public_access_blocks_configured Function**: This helper function checks whether the public access settings on the Access Point are configured correctly.

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a request to create an S3 Access Point:

```json
{
    "method": "s3:CreateAccessPoint",
    "access_point": {
        "name": "my-secure-access-point",
        "public_access_block_configuration": {
            "block_public_acls": true,
            "ignore_public_acls": true,
            "block_public_policy": true,
            "restrict_public_buckets": true
        }
    }
}
```

### **Example Input (with Invalid Configuration):**
```json
{
    "method": "s3:CreateAccessPoint",
    "access_point": {
        "name": "my-insecure-access-point",
        "public_access_block_configuration": {
            "block_public_acls": false,
            "ignore_public_acls": false,
            "block_public_policy": false,
            "restrict_public_buckets": false
        }
    }
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_access_point_public_access_blocks.rego "data.aws.s3.allow"
```

If the Access Point is not configured with the appropriate public access blocks, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_access_point_public_access_blocks.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
Access Point my-insecure-access-point must have public access blocks enabled
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **AC-3**: Access Enforcement – Ensures that public access to S3 Access Points is appropriately controlled.
- **SC-7**: Boundary Protection – Protects AWS account boundaries by ensuring that Access Points are not publicly accessible.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that all S3 Access Points have the necessary public access blocks enabled.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
