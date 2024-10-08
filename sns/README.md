Here’s a sample `README.md` file content for the AWS SNS OPA policies and their evaluation using OPA. This file includes steps for setting up and running the policies, along with the policy examples provided earlier.

---

# AWS SNS OPA Policy Enforcement

This repository contains **OPA (Open Policy Agent)** policies for AWS SNS to enforce security, compliance, and operational requirements. The policies are written in **Rego** and evaluated using OPA.

## Table of Contents

- [Prerequisites](#prerequisites)
- [OPA Setup](#opa-setup)
- [SNS Policy Descriptions](#sns-policy-descriptions)
- [How to Run](#how-to-run)
  - [Service-Level Policy: Topic Name Validation](#service-level-policy-topic-name-validation)
  - [Service-Level Policy: Ensure FIFO Topic Configuration](#service-level-policy-ensure-fifo-topic-configuration)
  - [Industrial-Level Policy: Enforce Display Name Requirement](#industrial-level-policy-enforce-display-name-requirement)
  - [Industrial-Level Policy: Ensure Encryption at Rest](#industrial-level-policy-ensure-encryption-at-rest)
- [Sample Inputs](#sample-inputs)
- [Commands](#commands)

---

## Prerequisites

- **Open Policy Agent (OPA)** installed. You can install OPA using [these instructions](https://www.openpolicyagent.org/docs/latest/#running-opa).
- Knowledge of **Rego** language (OPA's policy language).
- Familiarity with **AWS SNS** services.

---

## OPA Setup

To evaluate these policies, you need to have OPA installed and configured. You can download OPA from [here](https://www.openpolicyagent.org/docs/latest/#running-opa).

### Steps:

1. Download and install OPA on your machine.
2. Clone this repository.
3. Use the `opa eval` command with the provided Rego files and input files to validate policies.

---

## SNS Policy Descriptions

### 1. **Service-Level Policy 1: Topic Name Validation**

This policy ensures that all new SNS topic names comply with a predefined naming convention (e.g., must start with `dev-` or `prod-`).

```rego
package aws.sns

default allow = false

# Allowable topic name prefixes
allowed_prefixes = {"dev-", "prod-"}

# Allow SNS topic creation if the name starts with an allowed prefix
allow {
  input.method == "sns:CreateTopic"
  some prefix
  startswith(input.topic_name, prefix)
  allowed_prefixes[prefix]
}

deny_invalid_topic_name {
  input.method == "sns:CreateTopic"
  not (some prefix; startswith(input.topic_name, prefix); allowed_prefixes[prefix])
}
```

### 2. **Service-Level Policy 2: Ensure FIFO Topic Configuration**

This policy ensures that all topics that require message ordering are configured as FIFO (First-In-First-Out).

```rego
package aws.sns

default allow = false

allow {
  input.method == "sns:CreateTopic"
  input.fifo_topic == true
}

deny_non_fifo_topic {
  input.method == "sns:CreateTopic"
  input.fifo_topic == false
}
```

---

### 3. **Industrial-Level Policy 1: Enforce Display Name Requirement**

This policy ensures that all SNS topics must have a display name set for notification purposes.

```rego
package aws.sns

default allow = false

allow {
  input.method == "sns:CreateTopic"
  input.display_name != ""
}

deny_missing_display_name {
  input.method == "sns:CreateTopic"
  input.display_name == ""
}
```

### 4. **Industrial-Level Policy 2: Ensure Encryption at Rest**

This policy ensures that all SNS topics have server-side encryption enabled.

```rego
package aws.sns

default allow = false

allow {
  input.method == "sns:CreateTopic"
  input.encryption_enabled == true
}

deny_missing_encryption {
  input.method == "sns:CreateTopic"
  input.encryption_enabled == false
}
```

---

## How to Run

To evaluate the above policies, you can use the `opa eval` command along with the appropriate input files for testing.

### Sample Input Files

You can find sample input files under the `input/` directory to use with these policies.

### 1. **Service-Level Policy: Topic Name Validation**

```bash
opa eval --input input.json --data aws_sns.rego "data.aws.sns.allow"
```

- **Example Input** (`input.json`):

```json
{
  "method": "sns:CreateTopic",
  "topic_name": "prod-notification-topic"
}
```

### 2. **Service-Level Policy: Ensure FIFO Topic Configuration**

```bash
opa eval --input input.json --data aws_sns.rego "data.aws.sns.deny_non_fifo_topic"
```

- **Example Input** (`input.json`):

```json
{
  "method": "sns:CreateTopic",
  "fifo_topic": true
}
```

### 3. **Industrial-Level Policy: Enforce Display Name Requirement**

```bash
opa eval --input input.json --data aws_sns.rego "data.aws.sns.deny_missing_display_name"
```

- **Example Input** (`input.json`):

```json
{
  "method": "sns:CreateTopic",
  "display_name": "My Notification Topic"
}
```

### 4. **Industrial-Level Policy: Ensure Encryption at Rest**

```bash
opa eval --input input.json --data aws_sns.rego "data.aws.sns.deny_missing_encryption"
```

- **Example Input** (`input.json`):

```json
{
  "method": "sns:CreateTopic",
  "encryption_enabled": true
}
```

---

## Sample Inputs

Here are some examples of inputs to test the different policies.

### **Input for Topic Name Validation**

```json
{
  "method": "sns:CreateTopic",
  "topic_name": "dev-alerts"
}
```

### **Input for FIFO Topic Configuration**

```json
{
  "method": "sns:CreateTopic",
  "fifo_topic": false
}
```

### **Input for Display Name Requirement**

```json
{
  "method": "sns:CreateTopic",
  "display_name": ""
}
```

### **Input for Encryption at Rest**

```json
{
  "method": "sns:CreateTopic",
  "encryption_enabled": false
}
```

---

## Commands

To check if the policies work, you can use the following commands:

- **Allow/deny topic name validation**:

```bash
opa eval --input input.json --data aws_sns.rego "data.aws.sns.allow"
```

- **Allow/deny FIFO topic configuration**:

```bash
opa eval --input input.json --data aws_sns.rego "data.aws.sns.deny_non_fifo_topic"
```

- **Allow/deny missing display name**:

```bash
opa eval --input input.json --data aws_sns.rego "data.aws.sns.deny_missing_display_name"
```

- **Allow/deny missing encryption**:

```bash
opa eval --input input.json --data aws_sns.rego "data.aws.sns.deny_missing_encryption"
```

---

## Conclusion

By following the steps outlined in this `README`, you can enforce specific rules for AWS SNS topic creation using OPA. This ensures your SNS resources are compliant with organizational standards for security, compliance, and operational efficiency.

--- 

This structure should help users understand how to use the OPA policies for SNS effectively. If you need any more modifications or additional sections, feel free to ask!
