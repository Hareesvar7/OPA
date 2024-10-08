To ensure that all requests to Amazon S3 buckets use SSL (Secure Socket Layer), you can create an Open Policy Agent (OPA) policy that checks if the requests are made over HTTPS. This policy is crucial for protecting data in transit, aligning with NIST guidelines, particularly supporting controls like **SC-12** (Cryptographic Key Establishment and Management) and **SC-13** (Cryptographic Protection).

### Key Considerations for SSL Requests:
1. **SSL Requirement**: Ensure that all requests to S3 buckets must be made using HTTPS.
2. **Deny Requests**: If a request is made using HTTP, the policy should deny the request and provide a clear message.

### **Rego Policy: `s3_bucket_ssl_request_only.rego`**

```rego
package aws.s3

# Default deny all actions
default allow = false

# Allow if the request is made over SSL (HTTPS)
allow {
    input.method == "s3:GetObject" 
    is_ssl_request(input)
}

allow {
    input.method == "s3:PutObject" 
    is_ssl_request(input)
}

# Deny if the request is not made over SSL
deny[{"msg": msg}] {
    not is_ssl_request(input)
    msg = "Only SSL (HTTPS) requests are allowed for S3 buckets."
}

# Helper function to check if the request is made over SSL
is_ssl_request(input) {
    input.request_url[_] = "https://"
}
```

### **Explanation:**
- **allow Rules**: The `allow` rules permit actions to retrieve or store objects in S3 only if the requests are made using SSL.

- **deny Rules**: If an attempt is made to perform actions without using SSL, the corresponding `deny` rule will trigger, preventing the action and providing a message indicating that only SSL requests are allowed.

- **is_ssl_request Function**: This helper function checks whether the request URL starts with `https://`, indicating it was made over SSL.

### **Example Input JSON:**
Here's an example of how the input JSON would look for evaluating the policy. This represents a request to get or put an object in an S3 bucket.

#### Example Input (with SSL Request):
```json
{
    "method": "s3:GetObject",
    "request_url": ["https://my-secure-bucket.s3.amazonaws.com/my-object"]
}
```

#### Example Input (without SSL Request):
```json
{
    "method": "s3:GetObject",
    "request_url": ["http://my-secure-bucket.s3.amazonaws.com/my-object"]
}
```

### **Running the Policy:**
To evaluate this policy using OPA, run the following command:

```bash
opa eval --input input.json --data s3_bucket_ssl_request_only.rego "data.aws.s3.allow"
```

If the request is not made over SSL, the policy will deny the request and provide a message like:

```bash
opa eval --input input.json --data s3_bucket_ssl_request_only.rego "data.aws.s3.deny"
```

The output will state why access was denied, such as:

```
Only SSL (HTTPS) requests are allowed for S3 buckets.
```

### **NIST SP 800-53 Alignment:**
This policy helps align with NIST controls, specifically:
- **SC-12**: Cryptographic Key Establishment and Management – Ensures that data is securely transmitted.
- **SC-13**: Cryptographic Protection – Mandates the use of cryptographic protections for data in transit.

### **Periodic Enforcement:**
To enforce this policy periodically, you can automate checks (e.g., via AWS Lambda or within your CI/CD pipeline) to ensure that S3 bucket access is only performed over SSL.

If you need further refinements or additional rules aligned with specific NIST controls, feel free to ask!
