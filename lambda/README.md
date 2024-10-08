Here’s a comprehensive README file for AWS Lambda OPA policies, including service-level and industrial-level policies, verification with `opa eval`, and instructions.

---

## AWS Lambda OPA Policy Enforcement

This repository contains **OPA (Open Policy Agent)** policies for AWS Lambda to enforce security, compliance, and operational requirements. The policies are written in **Rego** and evaluated using OPA.

## Table of Contents

- [Prerequisites](#prerequisites)
- [OPA Setup](#opa-setup)
- [Lambda Policy Descriptions](#lambda-policy-descriptions)
- [How to Run](#how-to-run)
  - [Service-Level Policy: Restrict Function Memory Size](#service-level-policy-restrict-function-memory-size)
  - [Service-Level Policy: Validate Function Name](#service-level-policy-validate-function-name)
  - [Industrial-Level Policy: Enforce Environment Variable Encryption](#industrial-level-policy-enforce-environment-variable-encryption)
  - [Industrial-Level Policy: Restrict Public Access](#industrial-level-policy-restrict-public-access)
- [Sample Inputs](#sample-inputs)
- [Commands](#commands)

---

## Prerequisites

- **Open Policy Agent (OPA)** installed. You can install OPA using [these instructions](https://www.openpolicyagent.org/docs/latest/#running-opa).
- Knowledge of **Rego** language (OPA's policy language).
- Familiarity with **AWS Lambda** services.

---

## OPA Setup

To evaluate these policies, you need to have OPA installed and configured. You can download OPA from [here](https://www.openpolicyagent.org/docs/latest/#running-opa).

### Steps:

1. Download and install OPA on your machine.
2. Clone this repository.
3. Use the `opa eval` command with the provided Rego files and input files to validate policies.

---

## Lambda Policy Descriptions

### 1. **Service-Level Policy 1: Restrict Function Memory Size**

This policy ensures that AWS Lambda functions are created with a memory size within specific limits (e.g., between 128 MB and 3008 MB).

```rego
package aws.lambda

default allow = false

# Allowed memory size range
allowed_memory_sizes = {128, 256, 512, 1024, 2048, 3008}

# Allow Lambda function creation with specified memory size
allow {
    input.method == "lambda:CreateFunction"
    input.memory_size in allowed_memory_sizes
}

# Deny if the memory size is not allowed
deny_invalid_memory_size {
    input.method == "lambda:CreateFunction"
    not (input.memory_size in allowed_memory_sizes)
}
```

### 2. **Service-Level Policy 2: Validate Function Name**

This policy ensures that Lambda function names follow a specific naming convention (e.g., must start with "lambda-" and can contain letters, numbers, and hyphens).

```rego
package aws.lambda

default allow = false

# Allow Lambda function creation with valid names
allow {
    input.method == "lambda:CreateFunction"
    is_valid_function_name(input.function_name)
}

is_valid_function_name(name) {
    name =~ "^lambda-[a-zA-Z0-9-]+$"
}

# Deny if the function name is invalid
deny_invalid_function_name {
    input.method == "lambda:CreateFunction"
    not is_valid_function_name(input.function_name)
}
```

---

### 3. **Industrial-Level Policy 1: Enforce Environment Variable Encryption**

This policy ensures that all Lambda functions with environment variables have those variables encrypted.

```rego
package aws.lambda

default allow = false

allow {
    input.method == "lambda:CreateFunction"
    input.environment_variables_encrypted == true
}

deny_unencrypted_environment_variables {
    input.method == "lambda:CreateFunction"
    input.environment_variables_encrypted == false
}
```

### 4. **Industrial-Level Policy 2: Restrict Public Access**

This policy ensures that AWS Lambda functions do not allow public access.

```rego
package aws.lambda

default allow = false

allow {
    input.method == "lambda:CreateFunction"
    input.public_access == false
}

deny_public_access {
    input.method == "lambda:CreateFunction"
    input.public_access == true
}
```

---

## How to Run

To evaluate the above policies, you can use the `opa eval` command along with the appropriate input files for testing.

### 1. **Service-Level Policy: Restrict Function Memory Size**

#### Command:

```bash
opa eval --input input_file_name.json --data lambda_policy.rego "data.aws.lambda.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "lambda:CreateFunction",
  "memory_size": 128
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
          "text": "data.aws.lambda.allow"
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
  "method": "lambda:CreateFunction",
  "memory_size": 64
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
          "text": "data.aws.lambda.allow"
        }
      ]
    }
  ]
}
```

### 2. **Service-Level Policy: Validate Function Name**

#### Command:

```bash
opa eval --input input_file_name.json --data lambda_policy.rego "data.aws.lambda.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "lambda:CreateFunction",
  "function_name": "lambda-my-function"
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
          "text": "data.aws.lambda.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "lambda:CreateFunction",
  "function_name": "myFunction"
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
          "text": "data.aws.lambda.allow"
        }
      ]
    }
  ]
}
```

---

### 3. **Industrial-Level Policy: Enforce Environment Variable Encryption**

#### Command:

```bash
opa eval --input input_file_name.json --data lambda_policy.rego "data.aws.lambda.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "lambda:CreateFunction",
  "environment_variables_encrypted": true
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
          "text": "data.aws.lambda.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "lambda:CreateFunction",
  "environment_variables_encrypted": false
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
          "text": "data.aws.lambda.allow"
        }
      ]
    }
  ]
}
```

---

### 4. **Industrial-Level Policy: Restrict Public Access**

#### Command:

```bash
opa eval --input input_file_name.json --data lambda_policy.rego "data.aws.lambda.allow"
```

#### Sample Input:

**Valid Input (Allowed)**:

```json
{
  "method": "lambda:CreateFunction",
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
          "text": "data.aws.lambda.allow"
        }
      ]
    }
  ]
}
```

**Invalid Input (Denied)**:

```json
{
  "method": "lambda:CreateFunction",
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
          "text": "data.aws.lambda.allow"
        }
      ]
    }
  ]
}
```

---

## Sample Inputs

Here are some examples of inputs to test the different policies.

### **Input for Restrict Function Memory Size**

```json
{
  "method": "lambda:CreateFunction",
  "memory_size": 128
}
```

### **Input for Validate Function Name**

```json
{
  "method": "lambda:CreateFunction",
  "function_name": "lambda-my-function"
}
```

### **Input for Enforce Environment Variable Encryption**

```json
{
  "method": "lambda:CreateFunction",
  "environment_variables_encrypted": true
}
```

### **Input for Restrict Public Access**

```json
{
  "method": "lambda:CreateFunction",
  "public_access": false
}
```

---

## Commands

Replace `input_file_name.json` with the name of your JSON input file. Run the OPA eval command to evaluate the policies based on your input.

```bash
opa eval --input input_file_name.json --data lambda_policy.rego "data.aws.lambda.allow"
```

---

Feel free to modify or expand this README as needed for your specific implementation and use case!
