Here’s a sample `README.md` file content for the AWS EC2 OPA policies and their evaluation using OPA. This file includes steps for setting up and running the policies, along with the policy examples provided earlier.

---

# AWS EC2 OPA Policy Enforcement

This repository contains **OPA (Open Policy Agent)** policies for AWS EC2 to enforce security, compliance, and operational requirements. The policies are written in **Rego** and evaluated using OPA.

## Table of Contents

- [Prerequisites](#prerequisites)
- [OPA Setup](#opa-setup)
- [EC2 Policy Descriptions](#ec2-policy-descriptions)
- [How to Run](#how-to-run)
  - [Service-Level Policy: Instance Type Validation](#service-level-policy-instance-type-validation)
  - [Service-Level Policy: Enforce VPC Association](#service-level-policy-enforce-vpc-association)
  - [Industrial-Level Policy: Enforce Security Groups](#industrial-level-policy-enforce-security-groups)
  - [Industrial-Level Policy: Ensure EBS Volume Encryption](#industrial-level-policy-ensure-ebs-volume-encryption)
- [Sample Inputs](#sample-inputs)
- [Commands](#commands)

---

## Prerequisites

- **Open Policy Agent (OPA)** installed. You can install OPA using [these instructions](https://www.openpolicyagent.org/docs/latest/#running-opa).
- Knowledge of **Rego** language (OPA's policy language).
- Familiarity with **AWS EC2** services.

---

## OPA Setup

To evaluate these policies, you need to have OPA installed and configured. You can download OPA from [here](https://www.openpolicyagent.org/docs/latest/#running-opa).

### Steps:

1. Download and install OPA on your machine.
2. Clone this repository.
3. Use the `opa eval` command with the provided Rego files and input files to validate policies.

---

## EC2 Policy Descriptions

### 1. **Service-Level Policy 1: Instance Type Validation**

This policy ensures that all new EC2 instances must use specific approved instance types (e.g., `t3.micro`, `m5.large`).

```rego
package aws.ec2

default allow = false

# Approved instance types
allowed_instance_types = {"t3.micro", "m5.large"}

# Allow EC2 instance creation if the instance type is in the list of allowed types
allow {
  input.method == "ec2:RunInstances"
  allowed_instance_types[input.instance_type]
}

deny_invalid_instance_type {
  input.method == "ec2:RunInstances"
  not allowed_instance_types[input.instance_type]
}
```

### 2. **Service-Level Policy 2: Enforce VPC Association**

This policy ensures that all EC2 instances are created within a specified VPC.

```rego
package aws.ec2

default allow = false

# Required VPC ID for EC2 instance creation
required_vpc_id = "vpc-abc12345"

# Allow EC2 instance creation only if it is associated with the required VPC
allow {
  input.method == "ec2:RunInstances"
  input.vpc_id == required_vpc_id
}

deny_invalid_vpc {
  input.method == "ec2:RunInstances"
  input.vpc_id != required_vpc_id
}
```

---

### 3. **Industrial-Level Policy 1: Enforce Security Groups**

This policy ensures that all EC2 instances must be launched with specific security groups for compliance and security purposes.

```rego
package aws.ec2

default allow = false

# Approved security groups
allowed_security_groups = {"sg-123456", "sg-654321"}

# Allow EC2 instance creation only if it uses approved security groups
allow {
  input.method == "ec2:RunInstances"
  allowed_security_groups[input.security_group_id]
}

deny_invalid_security_group {
  input.method == "ec2:RunInstances"
  not allowed_security_groups[input.security_group_id]
}
```

### 4. **Industrial-Level Policy 2: Ensure EBS Volume Encryption**

This policy ensures that all EBS volumes attached to EC2 instances are encrypted.

```rego
package aws.ec2

default allow = false

# Allow EC2 instance creation only if EBS volumes are encrypted
allow {
  input.method == "ec2:RunInstances"
  input.ebs_encrypted == true
}

deny_unencrypted_ebs {
  input.method == "ec2:RunInstances"
  input.ebs_encrypted == false
}
```

---

## How to Run

To evaluate the above policies, you can use the `opa eval` command along with the appropriate input files for testing.

### Sample Input Files

You can find sample input files under the `input/` directory to use with these policies.

### 1. **Service-Level Policy: Instance Type Validation**

```bash
opa eval --input input.json --data aws_ec2.rego "data.aws.ec2.allow"
```

- **Example Input** (`input.json`):

```json
{
  "method": "ec2:RunInstances",
  "instance_type": "t3.micro"
}
```

### 2. **Service-Level Policy: Enforce VPC Association**

```bash
opa eval --input input.json --data aws_ec2.rego "data.aws.ec2.deny_invalid_vpc"
```

- **Example Input** (`input.json`):

```json
{
  "method": "ec2:RunInstances",
  "vpc_id": "vpc-xyz98765"
}
```

### 3. **Industrial-Level Policy: Enforce Security Groups**

```bash
opa eval --input input.json --data aws_ec2.rego "data.aws.ec2.deny_invalid_security_group"
```

- **Example Input** (`input.json`):

```json
{
  "method": "ec2:RunInstances",
  "security_group_id": "sg-123456"
}
```

### 4. **Industrial-Level Policy: Ensure EBS Volume Encryption**

```bash
opa eval --input input.json --data aws_ec2.rego "data.aws.ec2.deny_unencrypted_ebs"
```

- **Example Input** (`input.json`):

```json
{
  "method": "ec2:RunInstances",
  "ebs_encrypted": true
}
```

---

## Sample Inputs

Here are some examples of inputs to test the different policies.

### **Input for Instance Type Validation**

```json
{
  "method": "ec2:RunInstances",
  "instance_type": "m5.large"
}
```

### **Input for VPC Association**

```json
{
  "method": "ec2:RunInstances",
  "vpc_id": "vpc-abc12345"
}
```

### **Input for Security Groups Validation**

```json
{
  "method": "ec2:RunInstances",
  "security_group_id": "sg-123456"
}
```

### **Input for EBS Volume Encryption**

```json
{
  "method": "ec2:RunInstances",
  "ebs_encrypted": false
}
```

---

## Commands

To check if the policies work, you can use the following commands:

- **Allow/deny instance type validation**:

```bash
opa eval --input input.json --data aws_ec2.rego "data.aws.ec2.allow"
```

- **Allow/deny invalid VPC association**:

```bash
opa eval --input input.json --data aws_ec2.rego "data.aws.ec2.deny_invalid_vpc"
```

- **Allow/deny invalid security groups**:

```bash
opa eval --input input.json --data aws_ec2.rego "data.aws.ec2.deny_invalid_security_group"
```

- **Allow/deny unencrypted EBS volumes**:

```bash
opa eval --input input.json --data aws_ec2.rego "data.aws.ec2.deny_unencrypted_ebs"
```

---

## Conclusion

By following the steps outlined in this `README`, you can enforce specific rules for AWS EC2 instance creation using OPA. This ensures your EC2 resources are compliant with organizational standards for security, compliance, and operational efficiency.

--- 

This structure should help users understand how to use the OPA policies for EC2 effectively. If you need any more modifications or additional sections, feel free to ask!
