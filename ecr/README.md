Sure! Here’s a detailed guide for creating a `README.md` file specifically for the AWS EFS OPA policies, including the steps for verifying the policies with `opa eval`, formatted in a manner consistent with how it was done for S3, EC2, EKS, SNS, and SQS.

---

# AWS EFS OPA Policy Enforcement

This repository contains **OPA (Open Policy Agent)** policies for AWS EFS (Elastic File System) to enforce security, compliance, and operational requirements. The policies are written in **Rego** and evaluated using OPA.

## Table of Contents

- [Prerequisites](#prerequisites)
- [OPA Setup](#opa-setup)
- [EFS Policy Descriptions](#efs-policy-descriptions)
- [How to Run](#how-to-run)
  - [Service-Level Policy: File System Name Validation](#service-level-policy-file-system-name-validation)
  - [Service-Level Policy: Ensure Throughput Mode Configuration](#service-level-policy-ensure-throughput-mode-configuration)
  - [Industrial-Level Policy: Enforce Encryption at Rest](#industrial-level-policy-enforce-encryption-at-rest)
  - [Industrial-Level Policy: Restrict Public Access to Mount Targets](#industrial-level-policy-restrict-public-access-to-mount-targets)
- [Sample Inputs](#sample-inputs)
- [Commands](#commands)

---

## Prerequisites

- **Open Policy Agent (OPA)** installed. You can install OPA using [these instructions](https://www.openpolicyagent.org/docs/latest/#running-opa).
- Knowledge of **Rego** language (OPA's policy language).
- Familiarity with **AWS EFS** services.

---

## OPA Setup

To evaluate these policies, you need to have OPA installed and configured. You can download OPA from [here](https://www.openpolicyagent.org/docs/latest/#running-opa).

### Steps:

1. Download and install OPA on your machine.
2. Clone this repository.
3. Use the `opa eval` command with the provided Rego files and input files to validate policies.

---

## EFS Policy Descriptions

### 1. **Service-Level Policy 1: File System Name Validation**

This policy ensures that all new EFS file systems adhere to a naming convention, such as starting with "dev-" or "prod-".

```rego
package aws.efs

default allow = false

# Allowable file system name prefixes
allowed_prefixes = {"dev-", "prod-"}

# Allow EFS file system creation if the name starts with an allowed prefix
allow {
    input.method == "efs:CreateFileSystem"
    some prefix
    startswith(input.file_system_name, prefix)
    allowed_prefixes[prefix]
}

# Deny creation if the file system name does not start with an allowed prefix
deny_invalid_file_system_name {
    input.method == "efs:CreateFileSystem"
    not (some prefix; startswith(input.file_system_name, prefix); allowed_prefixes[prefix])
}
```

### 2. **Service-Level Policy 2: Ensure Throughput Mode Configuration**

This policy ensures that all EFS file systems are created with the appropriate throughput mode, either `bursting` or `provisioned`.

```rego
package aws.efs

default allow = false

# Allow EFS file system creation with specific throughput modes
allow {
    input.method == "efs:CreateFileSystem"
    input.throughput_mode == "bursting"
} 

allow {
    input.method == "efs:CreateFileSystem"
    input.throughput_mode == "provisioned"
}

# Deny creation if the throughput mode is invalid
deny_invalid_throughput_mode {
    input.method == "efs:CreateFileSystem"
    input.throughput_mode != "bursting"
    input.throughput_mode != "provisioned"
}
```

---

### 3. **Industrial-Level Policy 1: Enforce Encryption at Rest**

This policy ensures that all EFS file systems have encryption at rest enabled.

```rego
package aws.efs

default allow = false

allow {
    input.method == "efs:CreateFileSystem"
    input.encryption_at_rest == true
}

deny_missing_encryption {
    input.method == "efs:CreateFileSystem"
    input.encryption_at_rest == false
}
```

### 4. **Industrial-Level Policy 2: Restrict Public Access to Mount Targets**

This policy ensures that no EFS file system allows public access to its mount targets.

```rego
package aws.efs

default allow = false

allow {
    input.method == "efs:CreateMountTarget"
    input.public_access == false
}

deny_public_access {
    input.method == "efs:CreateMountTarget"
    input.public_access == true
}
```

---

## How to Run

To evaluate the above policies, you can use the `opa eval` command along with the appropriate input files for testing.

### 1. **Service-Level Policy: File System Name Validation**

#### Command:

```bash
opa eval --input input_file_name.json --data efs_policy.rego "data.aws.efs.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "efs:CreateFileSystem",
  "file_system_name": "prod-file-system"
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
          "text": "data.aws.efs.allow"
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
  "method": "efs:CreateFileSystem",
  "file_system_name": "test-file-system"
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
          "text": "data.aws.efs.allow"
        }
      ]
    }
  ]
}
```

### 2. **Service-Level Policy: Ensure Throughput Mode Configuration**

#### Command:

```bash
opa eval --input input_file_name.json --data efs_policy.rego "data.aws.efs.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "efs:CreateFileSystem",
  "throughput_mode": "bursting"
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
          "text": "data.aws.efs.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "efs:CreateFileSystem",
  "throughput_mode": "invalid"
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
          "text": "data.aws.efs.allow"
        }
      ]
    }
  ]
}
```

---

### 3. **Industrial-Level Policy: Enforce Encryption at Rest**

#### Command:

```bash
opa eval --input input_file_name.json --data efs_policy.rego "data.aws.efs.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "efs:CreateFileSystem",
  "encryption_at_rest": true
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
          "text": "data.aws.efs.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "efs:CreateFileSystem",
  "encryption_at_rest": false
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
          "text": "data.aws.efs.allow"
        }
      ]
    }
  ]
}
```

---

### 4. **Industrial-Level Policy: Restrict Public Access to Mount Targets**

#### Command:

```bash
opa eval --input input_file_name.json --data efs_policy.rego "data.aws.efs.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "efs:CreateMountTarget",
  "public_access": false
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
          "text": "data.aws.efs.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "efs:CreateMountTarget",
  "public_access": true
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
          "text": "data.aws.efs.allow"
        }
      ]
    }
  ]
}
```

---

## Sample Inputs

Here are some examples of inputs to test the different policies.

### **Input for File System Name Validation**

```json
{
  "method": "efs:CreateFileSystem",
  "file_system_name": "dev-my-filesystem"
}
```

### **Input for Throughput Mode Configuration**

```json
{
  "method": "efs:CreateFileSystem",
  "throughput_mode": "provisioned"
}
```

### **Input for Encryption at Rest**

```json
{
  "method": "efs:CreateFileSystem",
  "encryption_at_rest": true
}
```

### **

Input for Public Access to Mount Targets**

```json
{
  "method": "efs:CreateMountTarget",
  "public_access": false
}
```

---

## Commands

Replace `input_file_name.json` with the name of your JSON input file. Run the OPA eval command to check the policies.

```bash
opa eval --input input_file_name.json --data efs_policy.rego "data.aws.efs.allow"
```

---

This concludes the guide for AWS EFS OPA policies. You can customize this template as needed or use it directly in your project to document how to validate your policies with OPA. If you have any further questions or need additional information, feel free to ask!
