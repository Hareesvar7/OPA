Sure! Here’s a comprehensive README file for AWS Elastic Container Registry (ECR) OPA policies, including service-level and industrial-level policies, verification with `opa eval`, and instructions.

---

## AWS ECR OPA Policy Enforcement

This repository contains **OPA (Open Policy Agent)** policies for AWS Elastic Container Registry (ECR) to enforce security, compliance, and operational requirements. The policies are written in **Rego** and evaluated using OPA.

## Table of Contents

- [Prerequisites](#prerequisites)
- [OPA Setup](#opa-setup)
- [ECR Policy Descriptions](#ecr-policy-descriptions)
- [How to Run](#how-to-run)
  - [Service-Level Policy: Restrict Image Tag Format](#service-level-policy-restrict-image-tag-format)
  - [Service-Level Policy: Validate Repository Name](#service-level-policy-validate-repository-name)
  - [Industrial-Level Policy: Enforce Image Scanning](#industrial-level-policy-enforce-image-scanning)
  - [Industrial-Level Policy: Enforce Encryption](#industrial-level-policy-enforce-encryption)
- [Sample Inputs](#sample-inputs)
- [Commands](#commands)

---

## Prerequisites

- **Open Policy Agent (OPA)** installed. You can install OPA using [these instructions](https://www.openpolicyagent.org/docs/latest/#running-opa).
- Knowledge of **Rego** language (OPA's policy language).
- Familiarity with **AWS Elastic Container Registry (ECR)** services.

---

## OPA Setup

To evaluate these policies, you need to have OPA installed and configured. You can download OPA from [here](https://www.openpolicyagent.org/docs/latest/#running-opa).

### Steps:

1. Download and install OPA on your machine.
2. Clone this repository.
3. Use the `opa eval` command with the provided Rego files and input files to validate policies.

---

## ECR Policy Descriptions

### 1. **Service-Level Policy 1: Restrict Image Tag Format**

This policy ensures that ECR images use a specific format for tags (e.g., must start with "v" followed by a version number).

```rego
package aws.ecr

default allow = false

# Allow ECR image tagging with a specific format
allow {
    input.method == "ecr:PutImage"
    startswith(input.image_tag, "v")
}

# Deny if the image tag format is invalid
deny_invalid_image_tag {
    input.method == "ecr:PutImage"
    not startswith(input.image_tag, "v")
}
```

### 2. **Service-Level Policy 2: Validate Repository Name**

This policy ensures that ECR repositories have a valid naming convention (e.g., must contain only lowercase letters, numbers, and hyphens).

```rego
package aws.ecr

default allow = false

# Allow ECR repository creation with valid names
allow {
    input.method == "ecr:CreateRepository"
    is_valid_repository_name(input.repository_name)
}

is_valid_repository_name(name) {
    name =~ "^[a-z0-9-]+$"
}

# Deny if the repository name is invalid
deny_invalid_repository_name {
    input.method == "ecr:CreateRepository"
    not is_valid_repository_name(input.repository_name)
}
```

---

### 3. **Industrial-Level Policy 1: Enforce Image Scanning**

This policy ensures that all images pushed to ECR are scanned for vulnerabilities.

```rego
package aws.ecr

default allow = false

allow {
    input.method == "ecr:PutImage"
    input.image_scan_on_push == true
}

deny_no_image_scanning {
    input.method == "ecr:PutImage"
    input.image_scan_on_push == false
}
```

### 4. **Industrial-Level Policy 2: Enforce Encryption**

This policy ensures that all ECR repositories enforce encryption for images.

```rego
package aws.ecr

default allow = false

allow {
    input.method == "ecr:CreateRepository"
    input.encryption_configuration.encryption_type == "AES256"
}

deny_unencrypted_repository {
    input.method == "ecr:CreateRepository"
    input.encryption_configuration.encryption_type != "AES256"
}
```

---

## How to Run

To evaluate the above policies, you can use the `opa eval` command along with the appropriate input files for testing.

### 1. **Service-Level Policy: Restrict Image Tag Format**

#### Command:

```bash
opa eval --input input_file_name.json --data ecr_policy.rego "data.aws.ecr.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "ecr:PutImage",
  "image_tag": "v1.0.0"
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
          "text": "data.aws.ecr.allow"
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
  "method": "ecr:PutImage",
  "image_tag": "1.0.0"
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
          "text": "data.aws.ecr.allow"
        }
      ]
    }
  ]
}
```

### 2. **Service-Level Policy: Validate Repository Name**

#### Command:

```bash
opa eval --input input_file_name.json --data ecr_policy.rego "data.aws.ecr.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "ecr:CreateRepository",
  "repository_name": "my-repo"
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
          "text": "data.aws.ecr.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "ecr:CreateRepository",
  "repository_name": "MyRepo"
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
          "text": "data.aws.ecr.allow"
        }
      ]
    }
  ]
}
```

---

### 3. **Industrial-Level Policy: Enforce Image Scanning**

#### Command:

```bash
opa eval --input input_file_name.json --data ecr_policy.rego "data.aws.ecr.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "ecr:PutImage",
  "image_scan_on_push": true
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
          "text": "data.aws.ecr.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "ecr:PutImage",
  "image_scan_on_push": false
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
          "text": "data.aws.ecr.allow"
        }
      ]
    }
  ]
}
```

---

### 4. **Industrial-Level Policy: Enforce Encryption**

#### Command:

```bash
opa eval --input input_file_name.json --data ecr_policy.rego "data.aws.ecr.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "ecr:CreateRepository",
  "encryption_configuration": {
    "encryption_type": "AES256"
  }
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
          "text": "data.aws.ecr.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "ecr:CreateRepository",
  "encryption_configuration": {
    "encryption_type": "NONE"
  }
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
          "text": "data.aws.ecr.allow"
        }
      ]
    }
  ]
}
```

---

## Sample Inputs

Here are some examples of inputs to test the different policies.

### **Input for Restrict Image Tag Format**

```json
{
  "method": "ecr:PutImage",
  "image_tag": "v1.0.0"
}
```

### **Input for Validate Repository Name**

```json
{
  "method": "ecr:CreateRepository",
  "repository_name": "my-repo"
}
```

### **Input for Enforce Image Scanning**

```json
{
  "method": "ecr:PutImage",
  "image_scan_on_push": true
}
```

### **Input for Enforce Encryption**

```json
{
  "method": "ecr:CreateRepository",
  "encryption_configuration": {
    "encryption_type": "AES256"
  }
}
```

---

## Commands

Replace `input_file_name.json` with the name of your JSON input file. Run the OPA eval command to evaluate the policies based on your input.

```

bash
opa eval --input input_file_name.json --data ecr_policy.rego "data.aws.ecr.allow"
```

---

Feel free to modify or expand this README as needed for your specific implementation and use case!
