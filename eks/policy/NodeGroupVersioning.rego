package aws.eks

default allow = false

# Allow EKS node group creation only if the Kubernetes version matches the required version
allow {
  input.method == "eks:CreateNodegroup"
  input.kubernetes_version == "1.24"
}

deny_invalid_k8s_version {
  input.method == "eks:CreateNodegroup"
  input.kubernetes_version != "1.24"
}
