Sure! Below is a comprehensive guide covering AWS CloudFront OPA policies, including service-level and industrial-level policies, verification with `opa eval`, and a README file similar to previous entries for AWS EFS, S3, EC2, SNS, SQS, and EKS.

---

## AWS CloudFront OPA Policy Enforcement

This repository contains **OPA (Open Policy Agent)** policies for AWS CloudFront to enforce security, compliance, and operational requirements. The policies are written in **Rego** and evaluated using OPA.

## Table of Contents

- [Prerequisites](#prerequisites)
- [OPA Setup](#opa-setup)
- [CloudFront Policy Descriptions](#cloudfront-policy-descriptions)
- [How to Run](#how-to-run)
  - [Service-Level Policy: Restrict Viewer Protocol Policy](#service-level-policy-restrict-viewer-protocol-policy)
  - [Service-Level Policy: Validate Origin Domain Name](#service-level-policy-validate-origin-domain-name)
  - [Industrial-Level Policy: Enable HTTPS Only](#industrial-level-policy-enable-https-only)
  - [Industrial-Level Policy: Restrict Public Access to S3 Origins](#industrial-level-policy-restrict-public-access-to-s3-origins)
- [Sample Inputs](#sample-inputs)
- [Commands](#commands)

---

## Prerequisites

- **Open Policy Agent (OPA)** installed. You can install OPA using [these instructions](https://www.openpolicyagent.org/docs/latest/#running-opa).
- Knowledge of **Rego** language (OPA's policy language).
- Familiarity with **AWS CloudFront** services.

---

## OPA Setup

To evaluate these policies, you need to have OPA installed and configured. You can download OPA from [here](https://www.openpolicyagent.org/docs/latest/#running-opa).

### Steps:

1. Download and install OPA on your machine.
2. Clone this repository.
3. Use the `opa eval` command with the provided Rego files and input files to validate policies.

---

## CloudFront Policy Descriptions

### 1. **Service-Level Policy 1: Restrict Viewer Protocol Policy**

This policy ensures that all CloudFront distributions enforce a specific viewer protocol policy (e.g., Redirect HTTP to HTTPS).

```rego
package aws.cloudfront

default allow = false

# Allow CloudFront distribution creation with specified viewer protocol policy
allow {
    input.method == "cloudfront:CreateDistribution"
    input.viewer_protocol_policy == "redirect-to-https"
}

# Deny if the viewer protocol policy is not allowed
deny_invalid_viewer_protocol {
    input.method == "cloudfront:CreateDistribution"
    input.viewer_protocol_policy != "redirect-to-https"
}
```

### 2. **Service-Level Policy 2: Validate Origin Domain Name**

This policy ensures that the origin domain name provided during distribution creation follows a specific format.

```rego
package aws.cloudfront

default allow = false

# Allow CloudFront distribution creation with valid origin domain names
allow {
    input.method == "cloudfront:CreateDistribution"
    valid_origin_domain_name(input.origin_domain_name)
}

valid_origin_domain_name(domain_name) {
    # Check that the domain name is a valid URL format
    domain_name != "" # Additional checks can be implemented for more validation
}

# Deny invalid origin domain names
deny_invalid_origin {
    input.method == "cloudfront:CreateDistribution"
    not valid_origin_domain_name(input.origin_domain_name)
}
```

---

### 3. **Industrial-Level Policy 1: Enable HTTPS Only**

This policy ensures that CloudFront distributions must use HTTPS for communication.

```rego
package aws.cloudfront

default allow = false

allow {
    input.method == "cloudfront:CreateDistribution"
    input.https_only == true
}

deny_https_only {
    input.method == "cloudfront:CreateDistribution"
    input.https_only == false
}
```

### 4. **Industrial-Level Policy 2: Restrict Public Access to S3 Origins**

This policy ensures that CloudFront does not allow public access to S3 origins.

```rego
package aws.cloudfront

default allow = false

allow {
    input.method == "cloudfront:CreateDistribution"
    input.origin_s3_public_access == false
}

deny_public_access {
    input.method == "cloudfront:CreateDistribution"
    input.origin_s3_public_access == true
}
```

---

## How to Run

To evaluate the above policies, you can use the `opa eval` command along with the appropriate input files for testing.

### 1. **Service-Level Policy: Restrict Viewer Protocol Policy**

#### Command:

```bash
opa eval --input input_file_name.json --data cloudfront_policy.rego "data.aws.cloudfront.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "cloudfront:CreateDistribution",
  "viewer_protocol_policy": "redirect-to-https"
}
```

**Expected Output**:

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": true,
          "text": "data.aws.cloudfront.allow"
        }
      ]
    }
  ]
}
```

---

**Invalid Input (Denied)**:

```json
{
  "method": "cloudfront:CreateDistribution",
  "viewer_protocol_policy": "allow-all"
}
```

**Expected Output**:

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": false,
          "text": "data.aws.cloudfront.allow"
        }
      ]
    }
  ]
}
```

### 2. **Service-Level Policy: Validate Origin Domain Name**

#### Command:

```bash
opa eval --input input_file_name.json --data cloudfront_policy.rego "data.aws.cloudfront.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "cloudfront:CreateDistribution",
  "origin_domain_name": "example.com"
}
```

**Expected Output**:

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": true,
          "text": "data.aws.cloudfront.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "cloudfront:CreateDistribution",
  "origin_domain_name": ""
}
```

**Expected Output**:

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": false,
          "text": "data.aws.cloudfront.allow"
        }
      ]
    }
  ]
}
```

---

### 3. **Industrial-Level Policy: Enable HTTPS Only**

#### Command:

```bash
opa eval --input input_file_name.json --data cloudfront_policy.rego "data.aws.cloudfront.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "cloudfront:CreateDistribution",
  "https_only": true
}
```

**Expected Output**:

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": true,
          "text": "data.aws.cloudfront.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "cloudfront:CreateDistribution",
  "https_only": false
}
```

**Expected Output**:

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": false,
          "text": "data.aws.cloudfront.allow"
        }
      ]
    }
  ]
}
```

---

### 4. **Industrial-Level Policy: Restrict Public Access to S3 Origins**

#### Command:

```bash
opa eval --input input_file_name.json --data cloudfront_policy.rego "data.aws.cloudfront.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "cloudfront:CreateDistribution",
  "origin_s3_public_access": false
}
```

**Expected Output**:

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": true,
          "text": "data.aws.cloudfront.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "cloudfront:CreateDistribution",
  "origin_s3_public_access": true
}
```

**Expected Output**:

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": false,
          "text": "data.aws.cloudfront.allow"
        }
      ]
    }
  ]
}
```

---

## Sample Inputs

Here are some examples of inputs to test the different policies.

### **Input for Viewer Protocol Policy**

```json
{
  "method": "cloudfront:CreateDistribution",
  "viewer_protocol_policy": "redirect-to-https"
}
```

### **Input for Origin Domain Name Validation**

```json
{
  "method": "cloudfront:CreateDistribution",
  "origin_domain_name": "valid-domain.com"
}
```

### **Input for HTTPS Only Enforcement**

```json
{
  "method": "cloudfront:CreateDistribution",
  "https_only": true
}
```

### **Input for Public Access to S3 Origins**

```json
{
  "method": "cloudfront:CreateDistribution",
  "origin_s3_public_access": false
}
```

---

## Commands

Replace `input_file_name.json` with the name of your JSON input file. Run the OPA eval command to check the policies.

```bash
opa eval --input input_file_name.json --data cloudfront_policy.rego "
