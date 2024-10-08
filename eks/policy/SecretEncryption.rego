package aws.eks

default allow = false

# Allow EKS cluster creation if secrets encryption is enabled
allow {
  input.method == "eks:CreateCluster"
  input.secrets_encryption == true
}

deny_unencrypted_secrets {
  input.method == "eks:CreateCluster"
  input.secrets_encryption == false
}
