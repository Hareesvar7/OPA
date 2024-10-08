Here's a sample `README.md` file content for the AWS S3 OPA policies and their evaluation using OPA. This file includes steps for setting up and running the policies, as well as the policy examples provided earlier.

---

# AWS S3 OPA Policy Enforcement

This repository contains **OPA (Open Policy Agent)** policies for AWS S3 to enforce security, compliance, and operational requirements. The policies are written in **Rego** and evaluated using OPA.

## Table of Contents

- [Prerequisites](#prerequisites)
- [OPA Setup](#opa-setup)
- [S3 Policy Descriptions](#s3-policy-descriptions)
- [How to Run](#how-to-run)
  - [Service-Level Policy: Bucket Name Validation](#service-level-policy-bucket-name-validation)
  - [Service-Level Policy: Ensure S3 Object Locking](#service-level-policy-ensure-s3-object-locking)
  - [Industrial-Level Policy: Ensure Bucket Encryption](#industrial-level-policy-ensure-bucket-encryption)
  - [Industrial-Level Policy: Ensure Logging Enabled](#industrial-level-policy-ensure-logging-enabled)
- [Sample Inputs](#sample-inputs)
- [Commands](#commands)

---

## Prerequisites

- **Open Policy Agent (OPA)** installed. You can install OPA using [these instructions](https://www.openpolicyagent.org/docs/latest/#running-opa).
- Knowledge of **Rego** language (OPA's policy language).
- Familiarity with **AWS S3** services.

---

## OPA Setup

To evaluate these policies, you need to have OPA installed and configured. You can download OPA from [here](https://www.openpolicyagent.org/docs/latest/#running-opa).

### Steps:

1. Download and install OPA on your machine.
2. Clone this repository.
3. Use `opa eval` command with the provided Rego files and input files to validate policies.

---

## S3 Policy Descriptions

### 1. **Service-Level Policy 1: Bucket Name Validation**

This policy ensures that all new S3 bucket names must comply with a predefined naming convention (e.g., must start with `prod-` or `dev-`).

```rego
package aws.s3

default allow = false

allow {
  input.method == "s3:CreateBucket"
  startswith(input.bucket_name, "prod-") or startswith(input.bucket_name, "dev-")
}

deny_invalid_bucket_name {
  input.method == "s3:CreateBucket"
  not (startswith(input.bucket_name, "prod-") or startswith(input.bucket_name, "dev-"))
}
```

### 2. **Service-Level Policy 2: Ensure S3 Object Locking**

This policy ensures that S3 buckets are created with Object Lock enabled to prevent accidental deletions.

```rego
package aws.s3

default allow = false

allow {
  input.method == "s3:CreateBucket"
  input.object_lock_enabled == true
}

deny_missing_object_lock {
  input.method == "s3:CreateBucket"
  input.object_lock_enabled == false
}
```

### 3. **Industrial-Level Policy 1: Ensure Bucket Encryption**

This policy ensures that every S3 bucket has encryption enabled to protect data at rest.

```rego
package aws.s3

default allow = false

allow {
  input.method == "s3:CreateBucket"
  input.encryption_enabled == true
}

deny_unencrypted_bucket {
  input.method == "s3:CreateBucket"
  input.encryption_enabled == false
}
```

### 4. **Industrial-Level Policy 2: Ensure Logging Enabled**

This policy ensures that S3 buckets have logging enabled for monitoring and compliance purposes.

```rego
package aws.s3

default allow = false

allow {
  input.method == "s3:CreateBucket"
  input.logging_enabled == true
}

deny_missing_logging {
  input.method == "s3:CreateBucket"
  input.logging_enabled == false
}
```

---

## How to Run

To evaluate the above policies, you can use the `opa eval` command along with the appropriate input files for testing.

### Sample Input Files

You can find sample input files under the `input/` directory to use with these policies.

### 1. **Service-Level Policy: Bucket Name Validation**

```bash
opa eval --input input.json --data aws_s3.rego "data.aws.s3.allow"
```

- **Example Input** (`input.json`):

```json
{
  "method": "s3:CreateBucket",
  "bucket_name": "prod-data-storage"
}
```

### 2. **Service-Level Policy: Ensure S3 Object Locking**

```bash
opa eval --input input.json --data aws_s3.rego "data.aws.s3.deny_missing_object_lock"
```

- **Example Input** (`input.json`):

```json
{
  "method": "s3:CreateBucket",
  "object_lock_enabled": false
}
```

### 3. **Industrial-Level Policy: Ensure Bucket Encryption**

```bash
opa eval --input input.json --data aws_s3.rego "data.aws.s3.deny_unencrypted_bucket"
```

- **Example Input** (`input.json`):

```json
{
  "method": "s3:CreateBucket",
  "encryption_enabled": true
}
```

### 4. **Industrial-Level Policy: Ensure Logging Enabled**

```bash
opa eval --input input.json --data aws_s3.rego "data.aws.s3.deny_missing_logging"
```

- **Example Input** (`input.json`):

```json
{
  "method": "s3:CreateBucket",
  "logging_enabled": false
}
```

---

## Sample Inputs

Here are some examples of inputs to test the different policies.

### **Input for Bucket Name Validation**

```json
{
  "method": "s3:CreateBucket",
  "bucket_name": "dev-backup"
}
```

### **Input for Object Lock Validation**

```json
{
  "method": "s3:CreateBucket",
  "object_lock_enabled": false
}
```

### **Input for Bucket Encryption**

```json
{
  "method": "s3:CreateBucket",
  "encryption_enabled": false
}
```

### **Input for Logging Validation**

```json
{
  "method": "s3:CreateBucket",
  "logging_enabled": true
}
```

---

## Commands

To check if the policies work, you can use the following commands:

- **Allow/deny bucket name validation**:

```bash
opa eval --input input.json --data aws_s3.rego "data.aws.s3.allow"
```

- **Allow/deny S3 Object Lock**:

```bash
opa eval --input input.json --data aws_s3.rego "data.aws.s3.deny_missing_object_lock"
```

- **Allow/deny unencrypted bucket creation**:

```bash
opa eval --input input.json --data aws_s3.rego "data.aws.s3.deny_unencrypted_bucket"
```

- **Allow/deny missing logging**:

```bash
opa eval --input input.json --data aws_s3.rego "data.aws.s3.deny_missing_logging"
```

--- 

## Conclusion

By following the steps outlined in this `README`, you can enforce specific rules for AWS S3 bucket creation using OPA. This ensures your S3 resources are compliant with organizational standards for security, compliance, and operational efficiency.

