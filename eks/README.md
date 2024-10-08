Here’s a sample `README.md` file content for the AWS EKS OPA policies and their evaluation using OPA. This file includes steps for setting up and running the policies, along with the policy examples provided earlier.

---

# AWS EKS OPA Policy Enforcement

This repository contains **OPA (Open Policy Agent)** policies for AWS EKS (Elastic Kubernetes Service) to enforce security, compliance, and operational requirements. The policies are written in **Rego** and evaluated using OPA.

## Table of Contents

- [Prerequisites](#prerequisites)
- [OPA Setup](#opa-setup)
- [EKS Policy Descriptions](#eks-policy-descriptions)
- [How to Run](#how-to-run)
  - [Service-Level Policy: Cluster Name Validation](#service-level-policy-cluster-name-validation)
  - [Service-Level Policy: Ensure Encryption Configuration](#service-level-policy-ensure-encryption-configuration)
  - [Industrial-Level Policy: Enforce Version Compliance](#industrial-level-policy-enforce-version-compliance)
  - [Industrial-Level Policy: Restrict Public Access](#industrial-level-policy-restrict-public-access)
- [Sample Inputs](#sample-inputs)
- [Commands](#commands)

---

## Prerequisites

- **Open Policy Agent (OPA)** installed. You can install OPA using [these instructions](https://www.openpolicyagent.org/docs/latest/#running-opa).
- Knowledge of **Rego** language (OPA's policy language).
- Familiarity with **AWS EKS** services.

---

## OPA Setup

To evaluate these policies, you need to have OPA installed and configured. You can download OPA from [here](https://www.openpolicyagent.org/docs/latest/#running-opa).

### Steps:

1. Download and install OPA on your machine.
2. Clone this repository.
3. Use the `opa eval` command with the provided Rego files and input files to validate policies.

---

## EKS Policy Descriptions

### 1. **Service-Level Policy 1: Cluster Name Validation**

This policy ensures that all new EKS cluster names comply with a predefined naming convention (e.g., must start with `dev-` or `prod-`).

```rego
package aws.eks

default allow = false

# Allowable cluster name prefixes
allowed_prefixes = {"dev-", "prod-"}

# Allow EKS cluster creation if the name starts with an allowed prefix
allow {
  input.method == "eks:CreateCluster"
  some prefix
  startswith(input.cluster_name, prefix)
  allowed_prefixes[prefix]
}

deny_invalid_cluster_name {
  input.method == "eks:CreateCluster"
  not (some prefix; startswith(input.cluster_name, prefix); allowed_prefixes[prefix])
}
```

### 2. **Service-Level Policy 2: Ensure Encryption Configuration**

This policy ensures that all EKS clusters have encryption enabled for their Kubernetes secrets.

```rego
package aws.eks

default allow = false

allow {
  input.method == "eks:CreateCluster"
  input.encryption_enabled == true
}

deny_missing_encryption {
  input.method == "eks:CreateCluster"
  input.encryption_enabled == false
}
```

---

### 3. **Industrial-Level Policy 1: Enforce Version Compliance**

This policy ensures that the EKS cluster version is compliant with the organization's standards (e.g., should not be older than a specific version).

```rego
package aws.eks

default allow = false

# Define the minimum acceptable version
minimum_version = "1.24"

allow {
  input.method == "eks:CreateCluster"
  input.cluster_version >= minimum_version
}

deny_old_version {
  input.method == "eks:CreateCluster"
  input.cluster_version < minimum_version
}
```

### 4. **Industrial-Level Policy 2: Restrict Public Access**

This policy ensures that EKS clusters do not allow public access unless explicitly permitted.

```rego
package aws.eks

default allow = false

allow {
  input.method == "eks:CreateCluster"
  input.public_access == false
}

deny_public_access {
  input.method == "eks:CreateCluster"
  input.public_access == true
}
```

---

## How to Run

To evaluate the above policies, you can use the `opa eval` command along with the appropriate input files for testing.

### Sample Input Files

You can find sample input files under the `input/` directory to use with these policies.

### 1. **Service-Level Policy: Cluster Name Validation**

```bash
opa eval --input input.json --data aws_eks.rego "data.aws.eks.allow"
```

- **Example Input** (`input.json`):

```json
{
  "method": "eks:CreateCluster",
  "cluster_name": "prod-cluster"
}
```

### 2. **Service-Level Policy: Ensure Encryption Configuration**

```bash
opa eval --input input.json --data aws_eks.rego "data.aws.eks.deny_missing_encryption"
```

- **Example Input** (`input.json`):

```json
{
  "method": "eks:CreateCluster",
  "encryption_enabled": true
}
```

### 3. **Industrial-Level Policy: Enforce Version Compliance**

```bash
opa eval --input input.json --data aws_eks.rego "data.aws.eks.deny_old_version"
```

- **Example Input** (`input.json`):

```json
{
  "method": "eks:CreateCluster",
  "cluster_version": "1.25"
}
```

### 4. **Industrial-Level Policy: Restrict Public Access**

```bash
opa eval --input input.json --data aws_eks.rego "data.aws.eks.deny_public_access"
```

- **Example Input** (`input.json`):

```json
{
  "method": "eks:CreateCluster",
  "public_access": false
}
```

---

## Sample Inputs

Here are some examples of inputs to test the different policies.

### **Input for Cluster Name Validation**

```json
{
  "method": "eks:CreateCluster",
  "cluster_name": "dev-cluster"
}
```

### **Input for Encryption Configuration**

```json
{
  "method": "eks:CreateCluster",
  "encryption_enabled": false
}
```

### **Input for Version Compliance**

```json
{
  "method": "eks:CreateCluster",
  "cluster_version": "1.22"
}
```

### **Input for Public Access Restriction**

```json
{
  "method": "eks:CreateCluster",
  "public_access": true
}
```

---

## Commands

To check if the policies work, you can use the following commands:

- **Allow/deny cluster name validation**:

```bash
opa eval --input input.json --data aws_eks.rego "data.aws.eks.allow"
```

- **Allow/deny missing encryption**:

```bash
opa eval --input input.json --data aws_eks.rego "data.aws.eks.deny_missing_encryption"
```

- **Allow/deny old version compliance**:

```bash
opa eval --input input.json --data aws_eks.rego "data.aws.eks.deny_old_version"
```

- **Allow/deny public access**:

```bash
opa eval --input input.json --data aws_eks.rego "data.aws.eks.deny_public_access"
```

---

## Conclusion

By following the steps outlined in this `README`, you can enforce specific rules for AWS EKS cluster creation using OPA. This ensures your EKS resources are compliant with organizational standards for security, compliance, and operational efficiency.

--- 

This structure should help users understand how to use the OPA policies for EKS effectively. If you need any more modifications or additional sections, feel free to ask!
