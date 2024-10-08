Here’s a sample `README.md` file content for the AWS SQS OPA policies and their evaluation using OPA. This file includes steps for setting up and running the policies, along with the policy examples provided earlier.

---

# AWS SQS OPA Policy Enforcement

This repository contains **OPA (Open Policy Agent)** policies for AWS SQS to enforce security, compliance, and operational requirements. The policies are written in **Rego** and evaluated using OPA.

## Table of Contents

- [Prerequisites](#prerequisites)
- [OPA Setup](#opa-setup)
- [SQS Policy Descriptions](#sqs-policy-descriptions)
- [How to Run](#how-to-run)
  - [Service-Level Policy: Queue Name Validation](#service-level-policy-queue-name-validation)
  - [Service-Level Policy: Ensure FIFO Queue Configuration](#service-level-policy-ensure-fifo-queue-configuration)
  - [Industrial-Level Policy: Enforce Message Retention Period](#industrial-level-policy-enforce-message-retention-period)
  - [Industrial-Level Policy: Ensure Encryption at Rest](#industrial-level-policy-ensure-encryption-at-rest)
- [Sample Inputs](#sample-inputs)
- [Commands](#commands)

---

## Prerequisites

- **Open Policy Agent (OPA)** installed. You can install OPA using [these instructions](https://www.openpolicyagent.org/docs/latest/#running-opa).
- Knowledge of **Rego** language (OPA's policy language).
- Familiarity with **AWS SQS** services.

---

## OPA Setup

To evaluate these policies, you need to have OPA installed and configured. You can download OPA from [here](https://www.openpolicyagent.org/docs/latest/#running-opa).

### Steps:

1. Download and install OPA on your machine.
2. Clone this repository.
3. Use the `opa eval` command with the provided Rego files and input files to validate policies.

---

## SQS Policy Descriptions

### 1. **Service-Level Policy 1: Queue Name Validation**

This policy ensures that all new SQS queue names comply with a predefined naming convention (e.g., must start with `dev-` or `prod-`).

```rego
package aws.sqs

default allow = false

# Allowable queue name prefixes
allowed_prefixes = {"dev-", "prod-"}

# Allow SQS queue creation if the name starts with an allowed prefix
allow {
  input.method == "sqs:CreateQueue"
  some prefix
  startswith(input.queue_name, prefix)
  allowed_prefixes[prefix]
}

deny_invalid_queue_name {
  input.method == "sqs:CreateQueue"
  not (some prefix; startswith(input.queue_name, prefix) ; allowed_prefixes[prefix])
}
```

### 2. **Service-Level Policy 2: Ensure FIFO Queue Configuration**

This policy ensures that all queues that require message ordering are configured as FIFO (First-In-First-Out).

```rego
package aws.sqs

default allow = false

allow {
  input.method == "sqs:CreateQueue"
  input.fifo_queue == true
}

deny_non_fifo_queue {
  input.method == "sqs:CreateQueue"
  input.fifo_queue == false
}
```

---

### 3. **Industrial-Level Policy 1: Enforce Message Retention Period**

This policy ensures that SQS queues have a message retention period set to a specific value (e.g., 4 days).

```rego
package aws.sqs

default allow = false

# Required message retention period in seconds (4 days)
required_retention_period = 345600

allow {
  input.method == "sqs:CreateQueue"
  input.message_retention_seconds == required_retention_period
}

deny_invalid_retention_period {
  input.method == "sqs:CreateQueue"
  input.message_retention_seconds != required_retention_period
}
```

### 4. **Industrial-Level Policy 2: Ensure Encryption at Rest**

This policy ensures that all SQS queues have server-side encryption enabled.

```rego
package aws.sqs

default allow = false

allow {
  input.method == "sqs:CreateQueue"
  input.encryption_enabled == true
}

deny_missing_encryption {
  input.method == "sqs:CreateQueue"
  input.encryption_enabled == false
}
```

---

## How to Run

To evaluate the above policies, you can use the `opa eval` command along with the appropriate input files for testing.

### Sample Input Files

You can find sample input files under the `input/` directory to use with these policies.

### 1. **Service-Level Policy: Queue Name Validation**

```bash
opa eval --input input.json --data aws_sqs.rego "data.aws.sqs.allow"
```

- **Example Input** (`input.json`):

```json
{
  "method": "sqs:CreateQueue",
  "queue_name": "prod-message-queue"
}
```

### 2. **Service-Level Policy: Ensure FIFO Queue Configuration**

```bash
opa eval --input input.json --data aws_sqs.rego "data.aws.sqs.deny_non_fifo_queue"
```

- **Example Input** (`input.json`):

```json
{
  "method": "sqs:CreateQueue",
  "fifo_queue": true
}
```

### 3. **Industrial-Level Policy: Enforce Message Retention Period**

```bash
opa eval --input input.json --data aws_sqs.rego "data.aws.sqs.deny_invalid_retention_period"
```

- **Example Input** (`input.json`):

```json
{
  "method": "sqs:CreateQueue",
  "message_retention_seconds": 345600
}
```

### 4. **Industrial-Level Policy: Ensure Encryption at Rest**

```bash
opa eval --input input.json --data aws_sqs.rego "data.aws.sqs.deny_missing_encryption"
```

- **Example Input** (`input.json`):

```json
{
  "method": "sqs:CreateQueue",
  "encryption_enabled": true
}
```

---

## Sample Inputs

Here are some examples of inputs to test the different policies.

### **Input for Queue Name Validation**

```json
{
  "method": "sqs:CreateQueue",
  "queue_name": "dev-queue-service"
}
```

### **Input for FIFO Queue Configuration**

```json
{
  "method": "sqs:CreateQueue",
  "fifo_queue": false
}
```

### **Input for Message Retention Period**

```json
{
  "method": "sqs:CreateQueue",
  "message_retention_seconds": 345600
}
```

### **Input for Encryption at Rest**

```json
{
  "method": "sqs:CreateQueue",
  "encryption_enabled": false
}
```

---

## Commands

To check if the policies work, you can use the following commands:

- **Allow/deny queue name validation**:

```bash
opa eval --input input.json --data aws_sqs.rego "data.aws.sqs.allow"
```

- **Allow/deny FIFO queue configuration**:

```bash
opa eval --input input.json --data aws_sqs.rego "data.aws.sqs.deny_non_fifo_queue"
```

- **Allow/deny invalid message retention period**:

```bash
opa eval --input input.json --data aws_sqs.rego "data.aws.sqs.deny_invalid_retention_period"
```

- **Allow/deny missing encryption**:

```bash
opa eval --input input.json --data aws_sqs.rego "data.aws.sqs.deny_missing_encryption"
```

---

## Conclusion

By following the steps outlined in this `README`, you can enforce specific rules for AWS SQS queue creation using OPA. This ensures your SQS resources are compliant with organizational standards for security, compliance, and operational efficiency.

--- 

This structure should help users understand how to use the OPA policies for SQS effectively. If you need any more modifications or additional sections, feel free to ask!
