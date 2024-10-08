package aws.eks

default allow = false

# Required log types for all EKS clusters
required_log_types = {"api", "audit", "controllerManager"}

# Allow EKS cluster creation only if all required log types are enabled
allow {
  input.method == "eks:CreateCluster"
  all_required_logs_enabled
}

all_required_logs_enabled {
  required_log_types[_] = log
  input.logging_enabled[_] == log
}

deny_missing_logs {
  input.method == "eks:CreateCluster"
  not all_required_logs_enabled
}
