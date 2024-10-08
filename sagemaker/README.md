Certainly! Below is a comprehensive guide for creating AWS SageMaker OPA policies, including service-level and industrial-level policies, verification with `opa eval`, and a README file formatted like previous entries for AWS EFS, S3, EC2, SNS, SQS, EKS, and CloudFront.

---

## AWS SageMaker OPA Policy Enforcement

This repository contains **OPA (Open Policy Agent)** policies for AWS SageMaker to enforce security, compliance, and operational requirements. The policies are written in **Rego** and evaluated using OPA.

## Table of Contents

- [Prerequisites](#prerequisites)
- [OPA Setup](#opa-setup)
- [SageMaker Policy Descriptions](#sagemaker-policy-descriptions)
- [How to Run](#how-to-run)
  - [Service-Level Policy: Restrict Instance Type](#service-level-policy-restrict-instance-type)
  - [Service-Level Policy: Validate Model Name](#service-level-policy-validate-model-name)
  - [Industrial-Level Policy: Enforce IAM Role Permissions](#industrial-level-policy-enforce-iam-role-permissions)
  - [Industrial-Level Policy: Ensure Data Encryption](#industrial-level-policy-ensure-data-encryption)
- [Sample Inputs](#sample-inputs)
- [Commands](#commands)

---

## Prerequisites

- **Open Policy Agent (OPA)** installed. You can install OPA using [these instructions](https://www.openpolicyagent.org/docs/latest/#running-opa).
- Knowledge of **Rego** language (OPA's policy language).
- Familiarity with **AWS SageMaker** services.

---

## OPA Setup

To evaluate these policies, you need to have OPA installed and configured. You can download OPA from [here](https://www.openpolicyagent.org/docs/latest/#running-opa).

### Steps:

1. Download and install OPA on your machine.
2. Clone this repository.
3. Use the `opa eval` command with the provided Rego files and input files to validate policies.

---

## SageMaker Policy Descriptions

### 1. **Service-Level Policy 1: Restrict Instance Type**

This policy ensures that SageMaker training jobs can only use specific instance types.

```rego
package aws.sagemaker

default allow = false

# Allowed instance types
allowed_instance_types = {"ml.t2.medium", "ml.m5.large"}

# Allow SageMaker training job creation with specified instance types
allow {
    input.method == "sagemaker:CreateTrainingJob"
    input.instance_type in allowed_instance_types
}

# Deny if the instance type is not allowed
deny_invalid_instance_type {
    input.method == "sagemaker:CreateTrainingJob"
    not (input.instance_type in allowed_instance_types)
}
```

### 2. **Service-Level Policy 2: Validate Model Name**

This policy ensures that SageMaker models have a valid naming convention (e.g., must start with "model-").

```rego
package aws.sagemaker

default allow = false

# Allow SageMaker model creation with valid names
allow {
    input.method == "sagemaker:CreateModel"
    startswith(input.model_name, "model-")
}

# Deny if the model name is not valid
deny_invalid_model_name {
    input.method == "sagemaker:CreateModel"
    not startswith(input.model_name, "model-")
}
```

---

### 3. **Industrial-Level Policy 1: Enforce IAM Role Permissions**

This policy ensures that all SageMaker jobs use an IAM role that has specific permissions.

```rego
package aws.sagemaker

default allow = false

allow {
    input.method == "sagemaker:CreateTrainingJob"
    input.iam_role_permissions == "allowed"
}

deny_unauthorized_iam_role {
    input.method == "sagemaker:CreateTrainingJob"
    input.iam_role_permissions != "allowed"
}
```

### 4. **Industrial-Level Policy 2: Ensure Data Encryption**

This policy ensures that SageMaker jobs and models have data encryption enabled.

```rego
package aws.sagemaker

default allow = false

allow {
    input.method == "sagemaker:CreateTrainingJob"
    input.enable_data_encryption == true
}

deny_missing_encryption {
    input.method == "sagemaker:CreateTrainingJob"
    input.enable_data_encryption == false
}
```

---

## How to Run

To evaluate the above policies, you can use the `opa eval` command along with the appropriate input files for testing.

### 1. **Service-Level Policy: Restrict Instance Type**

#### Command:

```bash
opa eval --input input_file_name.json --data sagemaker_policy.rego "data.aws.sagemaker.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "sagemaker:CreateTrainingJob",
  "instance_type": "ml.m5.large"
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
          "text": "data.aws.sagemaker.allow"
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
  "method": "sagemaker:CreateTrainingJob",
  "instance_type": "ml.c4.xlarge"
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
          "text": "data.aws.sagemaker.allow"
        }
      ]
    }
  ]
}
```

### 2. **Service-Level Policy: Validate Model Name**

#### Command:

```bash
opa eval --input input_file_name.json --data sagemaker_policy.rego "data.aws.sagemaker.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "sagemaker:CreateModel",
  "model_name": "model-my-awesome-model"
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
          "text": "data.aws.sagemaker.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "sagemaker:CreateModel",
  "model_name": "my-awesome-model"
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
          "text": "data.aws.sagemaker.allow"
        }
      ]
    }
  ]
}
```

---

### 3. **Industrial-Level Policy: Enforce IAM Role Permissions**

#### Command:

```bash
opa eval --input input_file_name.json --data sagemaker_policy.rego "data.aws.sagemaker.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "sagemaker:CreateTrainingJob",
  "iam_role_permissions": "allowed"
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
          "text": "data.aws.sagemaker.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "sagemaker:CreateTrainingJob",
  "iam_role_permissions": "not_allowed"
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
          "text": "data.aws.sagemaker.allow"
        }
      ]
    }
  ]
}
```

---

### 4. **Industrial-Level Policy: Ensure Data Encryption**

#### Command:

```bash
opa eval --input input_file_name.json --data sagemaker_policy.rego "data.aws.sagemaker.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "sagemaker:CreateTrainingJob",
  "enable_data_encryption": true
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
          "text": "data.aws.sagemaker.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "sagemaker:CreateTrainingJob",
  "enable_data_encryption": false
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
          "text": "data.aws.sagemaker.allow"
        }
      ]
    }
  ]
}
```

---

## Sample Inputs

Here are some examples of inputs to test the different policies.

### **Input for Restrict Instance Type**

```json
{
  "method": "sagemaker:CreateTrainingJob",
  "instance_type": "ml.m5.large"
}
```

### **Input for Validate Model Name**

```json
{
  "method": "sagemaker:CreateModel",
  "model_name": "model-my-awesome-model"
}
```

### **Input for Enforce IAM Role Permissions**

```json
{
  "method": "sagemaker:CreateTrainingJob",
  "iam_role_permissions": "allowed"
}
```

### **Input for Ensure Data Encryption**

```json
{
  "method": "sagemaker:CreateTrainingJob",
  "enable_data_encryption": true
}
```

---

## Commands

Replace `input_file_name.json` with the name
