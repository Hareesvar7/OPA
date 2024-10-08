package aws.eks

default allow = false

# Approved instance types
allowed_instance_types = {"t3.medium", "m5.large"}

# Allow node group creation if the instance type is in the list of allowed types
allow {
  input.method == "eks:CreateNodegroup"
  allowed_instance_types[input.instance_type]
}

deny_invalid_instance_type {
  input.method == "eks:CreateNodegroup"
  not allowed_instance_types[input.instance_type]
}
